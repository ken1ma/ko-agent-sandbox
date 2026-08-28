# Plan: upstream corporate proxy and corporate DNS

## Outcome

Add an explicit launch option that sends every policy-admitted origin connection through one
host-chosen corporate HTTP or HTTPS CONNECT proxy:

```text
sandbox -> per-run policy proxy -> corporate proxy -> origin
```

The per-run proxy remains the only destination-policy and audit authority. The corporate proxy is
a transport selected by the host user; it cannot add a destination, bypass inspection, or provide
a direct fallback. Its endpoint, credentials, trust roots and optional DNS resolvers never enter
the sandbox or project.

Support explicit corporate DNS in this increment. Only the trusted per-run policy proxy and
one-shot egress checker use it. Corporate DNS changes who answers a lookup, not which addresses
are admissible: every origin answer must still pass the existing public-destination check. Only
the host-selected corporate transport dependencies--the proxy endpoint and explicit DNS
resolvers--may use private addresses; neither exception applies to an origin.

Do not add DNS over HTTPS (DoH) in this increment. A future corporate requirement can reopen the
closed contract under "Deferred encrypted DNS" below.

## Invariants

1. The sandbox remains attached only to its internal no-gateway network, with DNS disabled. It sees
   the per-run policy proxy under the same fixed name and receives no corporate endpoint,
   credential, resolver or CA private material.
2. `authorizeRequest`, the resolved egress policy and `authorizeInspectedRequest` decide exactly the
   same requests in direct and upstream modes. Transport selection runs only after authorization.
3. A locally refused CONNECT causes no origin DNS query, corporate-proxy connection or credential
   transmission. Resolving the configured corporate endpoint at proxy startup is independent of a
   sandbox request.
4. Every origin hostname is resolved once for one connection. Every returned address must be
   public, and the upstream CONNECT names one of those validated numeric addresses. The corporate
   proxy never re-resolves the origin name.
5. The original hostname remains the TLS identity: client SNI must equal it, an inspected origin
   connection sends it as SNI and validates its certificate for that name, and an opaque tunnel
   forwards the client's original ClientHello unchanged after validation.
6. An upstream failure never falls back to a direct origin connection, another proxy, an OS proxy
   or another resolver. It is an audited transport error and a 502 to the sandbox.
7. Proxy authentication is read from one host file and mounted only into the per-run proxy. It is
   absent from arguments, environment values, banners, logs, errors, retained TLS material and the
   sandbox filesystem.
8. A corporate interception CA is separate from the endpoint CA. The endpoint CA trusts the proxy
   service only; the interception CA extends origin trust in the proxy and sandbox and therefore
   makes corporate inspection of opaque model traffic explicit.
9. A running session keeps the profile snapshot it started with. Editing or deleting the host
   profile affects only a later launch and cannot break the mounted per-run copies.
10. Direct mode retains its existing socket, DNS, TLS, audit and failure behavior byte for byte
    except where a shared transport interface necessarily changes internal structure.

## Command-line contract

```text
--upstream-proxy=<absolute-profile-directory>
```

- No option means direct origin connections, the standing behavior.
- The equals form is required. Split at the first `=` so later equals characters are path data.
- Resolve the directory to its canonical existing path before reading it. Refuse a relative path,
  non-directory, symlinked directory, directory inside the project, or directory the current user
  cannot read.
- The option is host launch authority. A project policy, agent configuration, persistent stage or
  resumed conversation cannot select it.
- Management verbs reject it unless their contract below consumes it. Once the sandbox command
  begins, a token with the same spelling is an agent argument under the launcher's existing
  first-non-option rule.
- `--egress-effective` remains an answer about policy and rejects the option; transport changes no
  entry in that answer.
- `--egress-check=<host>` accepts the option. It uses the profile, resolver and proxy image a launch
  would use and reports policy, resolution and whether an upstream tunnel could be established.
  It sends no TLS application request to the origin.

Do not inherit `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, OS proxy settings or a PAC
file. Ambient settings would silently change a security boundary and exclusion rules would create
a second route around it. Do not add `direct` as a profile value: absence of the option already has
one unambiguous meaning.

## Profile directory

The directory is a closed namespace. Apart from dot-named editor and OS metadata, it contains only:

```text
endpoint                 required
authorization            optional, secret
endpoint-ca.pem          optional
interception-ca.pem      optional
dns                      optional
```

An unknown entry refuses the launch. Every named entry must be a regular file, not a symlink,
device, socket or directory. Read all entries and copy the needed bytes into a private per-run
directory before creating either container. Podman mounts only those copies.

Enumerate and read the complete directory twice through its opened canonical directory, without
following a child symlink. Require the same names, types, identities, sizes, modification times,
modes and bytes in both reads; access time is irrelevant. Retry a bounded number of times, then
refuse a profile changing during launch. This keeps an endpoint from one generation from being
paired with another generation's authorization or CA.

`endpoint` contains one line:

```text
http://proxy.corp.example:3128
https://proxy.corp.example:8443
```

- Accept only `http` and `https`, an exact hostname or IP literal, and an explicit port.
- Refuse user information, path other than `/`, query, fragment, whitespace and trailing data.
- Normalize a hostname with the egress proxy's hostname normalizer. An IP literal is permitted for
  this host-owned transport endpoint, unlike an origin target.
- Resolve the endpoint once when the proxy starts and retain that address set for the run. The
  endpoint may resolve private because reaching it is the feature. Origin resolution never shares
  that exception.
- HTTPS verifies the configured endpoint hostname or IP against its certificate before sending
  authentication. `endpoint-ca.pem` extends only that trust store.

`authorization` contains one static `Proxy-Authorization` field value without the field name. Bound
it to 8 KiB, require printable ASCII, and refuse every control character and leading or trailing
whitespace. Internal spaces permit a scheme and credential, such as `Basic <value>`. Never
challenge-negotiate or copy a response field into the next request. Accept this file only with an
HTTPS endpoint; a plaintext connection would disclose it on the network.

On POSIX, refuse an `authorization` file readable by group or other. On Windows, copying it into the
per-run owner-only directory is the enforced storage boundary; document that the source inherits
the user's chosen ACL. An absent file means no `Proxy-Authorization` field.

`endpoint-ca.pem` and `interception-ca.pem` each contain one or more PEM certificates and no private
key or unrelated PEM object. Parse every certificate before creating resources. A malformed or
empty present file refuses the launch.

`dns` contains one to three IPv4 or IPv6 literals, one per non-comment line. Refuse hostnames,
ports, prefixes, search suffixes, resolver options and an empty present file. Standard port 53 over
the container resolver's ordinary UDP-with-TCP-fallback behavior is the whole initial contract.

## Connection establishment

Replace the direct `connect(addresses, port)` call with one canonical origin transport selected at
proxy startup:

```text
Direct.connect(origin-host, validated-addresses, 443)
Corporate.connect(origin-host, validated-addresses, 443, profile)
```

Both receive only an already-authorized hostname and addresses returned by `resolvePublic`.
Neither performs origin DNS. `Direct` retains the existing address retry loop. `Corporate` performs
the following for each validated address until one succeeds:

1. Connect to one pinned corporate-proxy endpoint address with the standing connect timeout.
2. For an HTTPS endpoint, complete TLS and verify the endpoint identity.
3. Send one bounded HTTP/1.1 CONNECT request whose request target and Host field are the numeric
   origin authority: `<ipv4>:443` or `[<ipv6>]:443`.
4. Add the static authorization value when configured and a fixed, versionless
   `Via: 1.1 ko-agent-sandbox` field. The Via exception replaces `DESIGN.md`, "No Via header", only
   for this newly created proxy-to-proxy message; inspected origin requests retain their existing
   shape inside the established tunnel.
5. Parse one response head within the existing header budget and handshake timeout. Accept any 2xx
   final status. Refuse an informational response, Upgrade, malformed framing or excess bytes before
   the tunnel begins.
6. Discard every response field. A 407 becomes the fixed diagnostic "upstream proxy authentication
   required"; other non-2xx statuses report only the status, never the response body.
7. Return the tunnel socket to the existing SNI and restricted-or-opaque flow.

The client receives `200 Connection Established` only after the corporate tunnel exists. Retrying
an origin address creates a fresh corporate connection. A proxy refusal, authentication failure,
timeout or exhausted address set ends the attempt; there is no direct retry.

Some corporate proxies authorize only hostname-form CONNECT and will reject numeric authorities.
Report that incompatibility. Do not send the hostname and trust the corporate proxy to resolve it:
that would sever the existing proof that the address checked for private ranges is the one reached.
A hostname-only mode would place the corporate proxy's resolver and private-address enforcement in
the trusted computing base and requires a separate security-model decision.

## Corporate DNS

Support corporate DNS because a corporate proxy name and public origins may resolve only while a
VPN or enterprise resolver is in use. The feature does not grant access to corporate origins.

When `dns` is absent, the proxy and `--egress-check` use the same Podman-provided resolver path they
use without an upstream profile. When present, give only the egress-proxy container and the
one-shot check container the exact nameservers and an empty search domain. The sandbox retains
`--dns=none`.

The configured resolvers serve two consumers:

- the corporate endpoint resolver, whose pinned answers may be private;
- `resolvePublic` for origin hostnames, whose complete answer set must remain public.

Do not add suffix search, single-label expansion, split policy by suffix, or a private-address
allowlist. A corporate resolver returning an internal mirror for a public package hostname causes a
clear refusal naming the non-public answer. Reaching an internal registry or service would expose
an intranet to untrusted repository code; if required, design exact host-and-address authority as a
separate host-owned feature rather than treating corporate DNS as permission.

The resolver list is fixed per run. A failed query may try the next configured resolver according
to the system resolver, but it never falls back to Podman, the host, a public resolver or DoH. DNS
answers carry no authority of their own: policy admission happens by hostname and address admission
happens through `resolvePublic` after every lookup.

No DNSSEC-validation claim is made. The explicitly selected corporate resolver and its network are
trusted to answer DNS; TLS certificate validation still binds the origin identity after resolution.

## TLS interception

Without `interception-ca.pem`, origin TLS trust remains the image's public roots. A corporate proxy
that replaces origin certificates therefore causes a certificate failure rather than an automatic
trust import.

With it, append the supplied certificates to these existing launch-built stores:

- the egress proxy's origin TLS trust, used for restricted hosts;
- the sandbox PEM bundle and every environment variable pointing at it;
- the image JDK's merged `cacerts` store, used by opaque JVM clients;
- the certificate supplied to `sandbox-jdk-use-proxy` for a JDK installed during the session.

Keep the project's inspection CA separate and continue mounting only its leaf and leaf key into the
proxy. The corporate CA is public material, but its inclusion is authority: it lets the corporate
proxy read and change TLS for opaque model endpoints. Every affected launch prints:

```text
egress transport: corporate proxy; origin interception CA trusted
```

The appended agent instructions say the same. Do not copy a workstation trust store wholesale;
only the exact certificates in the selected profile are added.

## Audit and diagnostics

Keep the stable audit-line head. A successful upstream connection records the validated origin IP,
not the corporate endpoint address:

```text
allow github.com GET /owner/repo -> 140.82.112.3 via corporate
error github.com CONNECT upstream proxy returned 403
```

`deny` remains exclusively a local policy decision. DNS failure, corporate-proxy refusal, 407,
endpoint TLS failure and origin TLS failure are `error`: the local policy admitted the request but
transport did not complete it. Never include an upstream response body or authorization value.

At startup, log and print:

- direct or corporate transport;
- the canonical profile directory;
- HTTP or HTTPS endpoint and normalized authority, without authorization;
- system or explicit corporate resolver addresses;
- whether endpoint and interception CAs were added;
- the existing effective policy digest and complete resolved policy.

`--egress-check` must call the same profile parser, resolver functions, `authorizeRequest` and
origin transport used by a real proxy. Its successful upstream probe establishes a CONNECT tunnel
to a validated address and closes it before TLS application data. Prediction code is not an
acceptable substitute.

## Lifecycle and ownership

The launcher validates the profile and copies its files before creating resources. The proxy
resolves and pins the endpoint and loads its trust material before opening its listening socket,
and exits with the reason otherwise; the launcher's readiness gate
(`AgentSandboxLauncher.awaitProxyReady`) turns that exit into a failed launch carrying the
proxy's own message, as it does every refusal the proxy makes before `bind`.

Each HTTPS connection verifies endpoint identity before sending authentication.

Per-run copies live beside the run's existing TLS material, under the same owner-only host state,
and are removed by normal cleanup, failed launch cleanup, `--reset` and `--reset-all`. They use a
reserved run name already owned by the launcher; no profile directory is ever removed or changed.

The corporate endpoint connection leaves through the proxy container's egress network. Rootless
Podman provides no portable destination firewall on that network, so "only the corporate endpoint"
is enforced by the trusted proxy process, as destination policy already is. No agent-controlled
code runs in that container.

A profile edit during a run cannot change mounted copies, pinned endpoint addresses, resolvers or
trust stores. Concurrent launches take independent snapshots and share no proxy container,
credential mount or audit file.

## Deferred encrypted DNS

DoH is not useful merely because it encrypts queries. The sandbox already has no resolver, the
selected corporate resolver is an intended recipient, and the corporate proxy still observes
destination IPs and TLS names. A public DoH service would bypass enterprise split DNS and DNS
policy. Any DoH service also becomes an additional recipient of every hostname resolved through it
and therefore needs explicit host authority and audit treatment.

DoH also adds an HTTP/TLS client, DNS wire parser, bootstrap addresses, redirect policy, response
and cache bounds, endpoint authentication and a decision about whether the DoH request itself uses
the corporate proxy. None buys a property required by this increment.

If a concrete corporate resolver is available only as DoH, add it to this profile rather than as a
project egress host, with all of these requirements:

- one explicit host-owned HTTPS URI and exact bootstrap IP set;
- no automatic discovery, DDR, OS selection, public fallback or redirects;
- endpoint TLS identity and a resolver-only CA scope;
- RFC 8484 POST with `application/dns-message`, one question and bounded request and response;
- only IN A and AAAA queries, with bounded CNAME depth, TTL and cache size;
- routing through the selected corporate proxy when one is configured, without a direct fallback;
- the same all-answers-public check before any origin CONNECT;
- the same live code path in launch, `--egress-check` and tests.

DNS over TLS, DNS over QUIC and SOCKS remote resolution remain excluded under the same reasoning.

## Deliberate exclusions

- **OS proxy discovery, environment inheritance and PAC:** each makes ambient or executable host
  state choose a launch's transport without that authority appearing on its command line.
- **`NO_PROXY` and per-origin direct exceptions:** either creates a second path around the upstream
  transport and makes failure capable of widening authority.
- **More than one upstream hop:** proxy-chain selection, loop detection, authentication scope and
  audit attribution need a concrete deployment before entering the enforcement point.
- **SOCKS:** the initial requirement is corporate HTTP CONNECT. Adding another handshake, DNS mode
  and authentication grammar buys no property here.
- **Credentials in a URL or environment value:** process listings, shell history, exception text
  and inherited environments are all unnecessary secret consumers.
- **NTLM, Kerberos, Negotiate and interactive challenges:** these require a host identity broker and
  platform-specific lifecycle. A static header in the isolated proxy is the only authentication in
  this increment.
- **Hostname-form upstream CONNECT:** the corporate proxy would resolve the origin independently,
  breaking the checked-address-equals-connected-address invariant.
- **Private origin addresses and internal services:** the corporate endpoint and resolver are
  transport dependencies, not permission for untrusted project code to reach the intranet.
- **Standalone resolver override:** corporate DNS belongs to the selected corporate transport in
  this increment. Direct mode retains Podman's resolver until a separate requirement exists.
- **Dynamic reload:** policy, resolver, endpoint, credentials and trust remain one immutable launch
  snapshot whose audit meaning does not change mid-run.

References:

- RFC 8484, DNS Queries over HTTPS: https://www.rfc-editor.org/rfc/rfc8484
- RFC 9110, CONNECT and intermediary behavior: https://www.rfc-editor.org/rfc/rfc9110
- RFC 9462, Discovery of Designated Resolvers: https://www.rfc-editor.org/rfc/rfc9462
- Docker upstream-proxy comparison point:
  https://docs.docker.com/ai/sandboxes/configuration/upstream-proxy/

## Verification

### Profile and launcher

- Test every accepted and refused endpoint URI component, IPv4 and IPv6 authority, port boundary,
  path spelling and normalization result.
- Test missing, extra, symlinked, non-regular, unreadable and concurrently replaced profile entries;
  profile-directory overlap with the workspace; and per-run copy cleanup after every launch edge.
- Test authorization size, characters, whitespace, mode, HTTPS requirement and absence from every
  constructed command, environment, banner, log and error.
- Test empty, malformed, mixed and private-key-bearing CA files and distinct endpoint versus origin
  trust scopes.
- Test zero, one, three and excessive resolver entries; IPv4, IPv6, hostname, port and search-domain
  inputs; and the exact Podman DNS arguments on the proxy and check containers only.
- Test option parsing before and after the sandbox command, management-verb rejection and concurrent
  launches reading different coherent snapshots of a changing profile.

### Proxy unit and adversarial tests

- Preserve the complete direct-mode suite against the transport abstraction.
- Assert a local policy refusal makes zero resolver and upstream calls and sends no authorization.
- Assert every origin answer is checked, mixed public/private answers fail whole, and corporate
  CONNECT authorities are only the selected validated numeric addresses.
- Test endpoint DNS pinning, address retry, connect and handshake timeout, HTTP and HTTPS endpoints,
  hostname and IP certificate identity, and endpoint CA scoping.
- Test 2xx, 1xx, 3xx, 4xx, 407 and 5xx responses; duplicate and oversized headers; early body bytes;
  malformed status and framing; close at every byte; and no response field forwarded to the client.
- Test authorization appears on an authenticated corporate CONNECT only, never an origin request,
  retry log, exception, TLS diagnostic or audit line.
- Test the original hostname through client SNI, inspected upstream SNI and certificate validation,
  while the corporate CONNECT remains numeric.
- Run every restricted allowance and refusal and every opaque-tunnel test through direct, HTTP
  corporate and HTTPS corporate transport.
- Assert each upstream failure produces 502 and no direct connection attempt.
- Test corporate interception with no CA, endpoint CA only, interception CA only and both; verify
  restricted and opaque clients and every generated trust store.

### Container and platform tests

- Use controlled DNS and CONNECT-proxy fixtures to prove the production proxy container, internal
  network, egress network, resolver file and audit mount together.
- Prove unsetting sandbox proxy variables still restores no route, the sandbox cannot query either
  corporate or Podman DNS, and only the proxy container reaches the configured resolver.
- Prove a private corporate endpoint works while the same address remains forbidden as an origin.
- Prove profile deletion and replacement after launch do not affect the run, and normal exit,
  Ctrl-C, failed create/start and both resets remove every per-run copy and runtime resource.
- Run the matrix on native Linux and in the macOS and Windows Podman machines. Record whether each
  venue can route to VPN/private resolver and proxy addresses; a venue that cannot must fail launch,
  never bypass the upstream.

## Delivery order

1. Add the closed profile parser, path validation and tests without passing any value to a
   container.
2. Introduce the origin-transport interface, keep direct behavior fixed, and prove the corporate
   CONNECT state machine against adversarial fixtures.
3. Carry per-run endpoint, authorization and CA snapshots into the proxy; add endpoint TLS,
   interception trust and audit output.
4. Add explicit corporate DNS to proxy startup and `--egress-check`, preserving public-origin
   validation and sandbox `--dns=none`.
5. Run the full container/platform matrix, then update README, launcher help, SECURITY.md, agent
   instructions and `DESIGN.md` in the same distributable change. Replace the terminal-proxy premise
   under "No Via header" with the narrow upstream-CONNECT rule rather than stating both facts.

Do not expose the option as complete until authentication redaction, DNS non-fallback, numeric
CONNECT, origin TLS identity, direct-mode regression and cleanup all pass at the production
container boundary.
