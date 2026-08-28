# Plan: provider credential mediation at the egress proxy

## Outcome

Add a host-selected service layer above the substitution primitive in
`PLAN-CREDENTIAL-BROKER-PROXY.md`:

```text
credential instance -> source and lifecycle
service definition   -> sandbox adapter and approved injection targets
egress policy        -> whether each target is reachable
```

The existing plan remains canonical for placeholder construction, exact-token header
substitution, per-request auditing and the rule that a real value never enters the sandbox. This
plan owns what that primitive does not: one service spanning several domains, persistent host
custody, dynamic sources, expiry and refresh, explicit mechanism choice and provider endpoints
whose writable traffic must be TLS-terminated before a header can be mediated.

An existing `--env=NAME@HOST` binding remains a one-run, one-host binding. Provider mediation is a
separate launch authority; it neither changes that grammar nor turns a stored credential on by
itself.

## Document boundary

Facts have one binding site:

- `PLAN-CREDENTIAL-BROKER-PROXY.md` owns the proxy's placeholder-to-value rewrite and its tests.
- This document owns service composition, credential sources, refresh and mediated TLS.
- `PLAN-PATH-PREFIX-ALLOWANCE.md` owns literal path-prefix matching. A credential target may refer
  to that matcher but does not define another one.
- The resolved egress policy owns reachability. A credential service never adds a host.
- `SECURITY.md` owns the resulting trust model once implementation ships.

If both plans are accepted before either is implemented, replace the original plan's Copilot
special case with a pointer here. Copilot is a provider instance, not a second response-rewriting
framework. Qualify its one-host invariant as applying to explicit `--env` bindings; service
instances use the finite target list defined here.

## Required use cases

1. Store or resolve one GitHub credential once, select it for a run and use it at the exact GitHub
   API and Git HTTPS targets its service definition names.
2. Give two projects or concurrent runs the same stored instance without sharing a proxy,
   placeholder, per-run value file or audit log.
3. Resolve a short-lived access token with a host executable, refresh it before expiry and keep the
   refresh token or provider login outside the sandbox.
4. Select one credential mechanism for a model provider without an unrelated stored service or
   project file changing that choice.
5. Mediate an API-key or OAuth-backed model provider only when the installed client accepts the
   launch CA and the host explicitly accepts plaintext proxy visibility for that run.

Registry login, SSH agent forwarding and cloud request re-signing are different protocols and are
not requirements of this plan.

## Invariants

1. A credential has two independent authorities: the resolved egress policy admits a destination,
   and the host launch selects a credential instance. Neither authority implies the other.
2. A repository, agent command, persisted agent state and service response cannot create, select,
   retarget or refresh a credential instance.
3. One instance selects exactly one service and mechanism. It may inject into the service's finite
   exact-target list; no wildcard, redirect or response can add a target.
4. Every active instance has a fresh per-run placeholder. Two instances have different
   placeholders even when they use the same service, host, header, source value or run.
5. Injection still requires equality with the complete placeholder in the declared header shape.
   It never rewrites a URL, query, body, response or arbitrary occurrence of the bytes.
6. A denied destination remains denied. A selected service with no admitted target is inert and
   refuses launch rather than widening egress or silently falling back to an unbrokered value.
7. The real value exists only in its host source, protected host store, launcher's bounded refresh
   memory, private per-run generation and proxy memory. It never enters sandbox-visible state.
8. Only the credential coordinator invokes or refreshes a source. Listing, policy inspection,
   diagnostics and a locally denied request are read-only and cannot trigger a refresh.
9. Refresh is single-flight per instance across concurrent launchers. A new generation becomes
   visible atomically; a reader sees the complete old or complete new generation, never a mixture.
10. Expiry never widens authority. If no usable generation exists, matching requests fail closed
    with a credential-unavailable response and no uncredentialed retry.
11. Selecting one service cannot change another service's mechanism, adapter, source, targets,
    placeholder or cache generation.
12. TLS mediation of an otherwise opaque provider endpoint is explicit in the launch banner and
    effective-policy output. Without a selected credential, its standing opaque behavior is
    unchanged.
13. The proxy never sends a real credential before origin TLS identity is validated, and never
    forwards it across an origin redirect unless the new target independently matches the service.
14. Removing or replacing a stored source affects future refreshes and launches. It does not make
    another instance inherit the source or reveal an already loaded value.

## Terms and data model

A **service definition** is trusted, versioned data shipped in the proxy image. It contains:

- a stable lowercase service identifier;
- its supported mechanisms, either `api-key` or a named built-in OAuth flow;
- sandbox adapters: environment names and any image-owned client configuration that carries the
  placeholder;
- injection targets, each an exact normalized host, one header and one fixed value format with a
  single placeholder slot;
- an optional standing literal path prefix and method set, using existing policy matchers;
- the client and image compatibility probes required before that service is offered.

A **credential instance** is host-owned state:

```text
<service>/<instance> -> mechanism + source reference + refresh policy
```

Both identifiers match `[a-z][a-z0-9-]{0,62}`. `default` is the omitted instance. The instance
separates accounts or scopes without copying a service definition: `github/work` and
`github/personal` may share targets but never a placeholder or source.

An **active binding** is the intersection of a selected instance's targets with the resolved
egress policy. Denied targets are removed first. Every remaining target must be TLS-inspected by
the existing restricted path or by the mediated-provider path below.

The service catalog is a closed image resource, parsed by `--print-policy` and the serving proxy.
The launcher consumes that answer and does not keep a second provider-domain table.

## Host command contract

Management verbs operate outside a project and consume no launch options:

```text
--credential-set=<service>[/<instance>]
--credential-import=<service>[/<instance>]@<environment-name>
--credential-exec=<service>[/<instance>]@<absolute-descriptor-path>
--credential-login=<service>[/<instance>]
--credential-list
--credential-remove=<service>[/<instance>]
```

- `--credential-set` reads one value without echo from the controlling terminal and stores it in
  the host credential backend as `api-key`. It refuses without a terminal; a secret is never an
  argument.
- `--credential-import` reads the named host environment value once and stores it. The environment
  name is recorded for provenance, not reread later. This also selects `api-key`.
- `--credential-exec` copies and validates a non-secret executable-source descriptor for the
  `api-key` mechanism. The host command remains the authority for any keychain, cloud secret
  manager or provider CLI it uses.
- `--credential-login` exists only for a shipped service with a host-side OAuth implementation.
  An unsupported service refuses rather than starting a generic flow with guessed endpoints.
- `--credential-list` prints instance, service, mechanism, source kind and usability metadata,
  never a value, placeholder, source output or OAuth subject unless the service deliberately makes
  that display name non-secret.
- `--credential-remove` removes the source and cache after taking the instance lock. A live run may
  use its current unexpired generation but cannot refresh it.

A launch selects instances explicitly and repeatably:

```text
--credential=<service>[/<instance>]
```

Do not infer credential selection from the agent command, provider egress group, environment,
checkout or presence in the store. Stored authority is dormant until the host selects it.

`--egress-effective` accepts `--credential` and shows every admitted injection target, excluded
target and TLS treatment without resolving a source. `--egress-check=<host>` may test reachability
and TLS compatibility but never spends or refreshes a credential.

## Service definitions

Each injection target declares:

```text
host api.github.com
header Authorization
format "Bearer %s"
methods GET,HEAD
path /
```

The serialized form is internal to the image, not project configuration. Its parser requires:

- an exact normalized hostname already present in the same image's provider or host catalog;
- a header from the base plan's closed set (its invariant 4);
- a format containing exactly one `%s`, no other conversion, and otherwise only visible ASCII
  and space: catalog text, trusted for the space `Bearer %s` needs, and the field is built by
  placing a value that has separately passed the raw-value grammar into the format;
- a method set and optional literal prefix that cannot be wider than the target's standing
  restricted policy;
- unique `(host, header, format, matcher)` entries inside one service.

For a standing unrestricted provider host, the target deliberately has no method or path policy:
the existing authority already permits writable traffic. Mediation parses enough HTTP to inject
and relay, but it does not claim to make model traffic read-only.

Multiple domains are one service only when the provider documents them as recipients of the same
credential. Convenience is not evidence. Authentication, token and resource endpoints are named
separately so a value intended for one is not automatically sent to all three.

The initial catalog work is limited to services needed by installed agents. A third-party kit or
repository cannot supply a definition. Add a host-owned custom-definition format only after a
concrete service cannot reasonably enter the reviewed catalog; it needs its own provenance and
approval design.

## Credential sources and custody

The host credential backend stores static values and OAuth refresh material. Prefer the operating
system keychain. On a headless Linux host without one, an owner-only file under the launcher's
global state is an explicit fallback announced when the value is stored; encryption by a key in
the same account would not add a boundary.

Source metadata and values are separate. Metadata contains the service, instance, mechanism,
source kind, descriptor digest and refresh times. The secret backend contains only the value or
OAuth material. Project state contains neither.

The backend write and the generation publish are the one gate for value shape: every value
passes the base plan's value grammar (its invariant 4) there, whatever produced it — `set`,
`import`, an executable result, an OAuth access token at issuance or refresh, a cached
generation being reused. A value that fails is refused at that producer with the byte's offset
and nothing is stored; a refresh that yields one is a refresh failure, and the current
generation stays until its expiry. Storage therefore never holds a value the proxy will refuse,
and the proxy's own re-check at load is a second reading of the same rule, not the first.

An executable source descriptor is bounded JSON:

```json
{
  "argv": ["/absolute/provider-helper", "access-token"],
  "passEnvironment": ["AWS_PROFILE"],
  "timeoutSeconds": 15,
  "refreshBeforeSeconds": 120,
  "maxAgeSeconds": 3300
}
```

- No shell interprets `argv`; element zero is an absolute regular executable outside the project.
- The child receives a fixed empty working directory, a minimal launcher-owned environment plus
  the exact named host variables, closed stdin and captured bounded stdout and stderr.
- No request host, path, header, account string or sandbox byte becomes an argument or environment
  value. Registering the descriptor is the host's explicit authority to execute it.
- Timeout kills the child. Stderr is discarded. Normal errors expose only an exit status and fixed
  remediation; `--show-credential-source-error` is a separate host action that reruns the source
  and streams bounded stderr to that terminal after warning that provider output can contain a
  secret.

Successful stdout is one bounded UTF-8 JSON object:

```json
{
  "version": 1,
  "token": "secret value",
  "expiresAt": "2026-08-28T18:00:00Z"
}
```

`expiresAt` is required unless the descriptor supplies `maxAgeSeconds`. Unknown fields, duplicate
keys, control bytes, an empty token, a past expiry and trailing data refuse the result. A provider
can instead return the fixed error codes `temporarily-unavailable` or `reauth-required`. After
decoding, the raw token passes the gate in "Credential sources and custody"; an escaped newline
cannot become header injection. Free-form provider text is never stored or put in a proxy
response.

## Refresh coordinator

The launcher owns one credential coordinator for the duration of a run. It resolves every selected
instance before containers are created and materializes a private per-run credential directory.
The proxy mounts that directory read-only.

Each generation is an owner-only directory containing a monotonically increasing number, service
and instance IDs, expiry, placeholder digest and value. The launcher writes and syncs a complete
new directory, then atomically replaces a small `current` pointer. A manifest records every file's
length and digest to detect a torn publication; the owner-only directory is the authenticity
boundary. The proxy opens and verifies one named generation at a request boundary. It does not
watch partially written files or retain an expired prior generation.

The coordinator refreshes at `expiresAt - refreshBeforeSeconds`, with bounded jitter. Static values
have no scheduled refresh. An executable value with `maxAgeSeconds` refreshes on that schedule.
There is no per-request host callback and therefore no request-triggered host execution.

All launchers coordinate through one lock per credential instance and one protected host cache:

1. Take the instance lock before source resolution or state mutation.
2. Reuse a complete cached generation if it remains outside its refresh window.
3. Otherwise invoke or refresh exactly once, validate the result and atomically publish the cache.
4. Copy the usable generation into each waiting run with that run's distinct placeholder.
5. Release the lock before any container operation.

A refresh failure retains the current generation only until its declared expiry. Retry uses bounded
backoff inside the remaining validity window. After expiry, the coordinator publishes an
unavailable status, the proxy refuses matching requests with 502 and the audit says
`credential unavailable`; it never injects an expired value or sends the placeholder as a retry.

Read-only commands never take the refresh path. Removal, import, login and refresh use the same
instance lock, so concurrent mutation cannot lose half an OAuth credential or let a stale API key
shadow a newly selected mechanism.

## OAuth mechanisms

OAuth is a provider implementation behind the same source interface, not a generic collection of
URLs in a project file. A shipped flow fixes its authorization server, public-client identity,
grant, scopes, token fields, refresh behavior and revocation semantics. The browser or device step
runs on the host; access and refresh tokens enter the host backend, never the sandbox.

The sandbox adapter supplies stable placeholders in the exact environment or credential-file
shape the installed client requires. Provider-specific expiry bookkeeping is generated from public
metadata only. The client sends the placeholder to a resource target and the common proxy rewrite
injects the current access token.

Do not reuse another application's private client identity or copy its refresh token. A service
without a project-owned public-client registration uses an executable source such as its official
host CLI, or remains unsupported.

The Copilot device flow in `PLAN-CREDENTIAL-BROKER-PROXY.md` may remain an evidence probe, but its
production implementation moves here: either a host OAuth mechanism or a `gh` executable source.
Do not add a generic response-body interceptor merely to imitate an agent's token cache. If one
provider can only work through intercepted OAuth responses, specify its endpoint, bounded JSON
fields, rotation and write mount as a provider adapter with separate security review.

## Mediated provider traffic

The resolved policy currently has two treatments:

```text
restricted   TLS-terminated; fixed read and named-operation policy
unrestricted opaque writable tunnel
```

A selected credential adds a per-run overlay, not a third project policy spelling:

```text
mediated     TLS-terminated writable relay for an admitted provider target
```

The overlay applies only to exact targets in the selected service. A denied host remains absent.
A restricted host stays restricted and is authorized before injection. An unrestricted host is
mediated only for that run and otherwise remains an opaque tunnel.

The launch leaf certificate names the union of restricted hosts and active mediated targets. The
effective-policy answer and startup banner list the mediated targets and say:

```text
credential mediation: proxy reads provider HTTP for <service>/<instance>: <hosts>
```

This is a privacy boundary: the trusted proxy sees model request and response bytes that were
previously opaque. It already owns egress authority, but plaintext model conversations are a new
asset in its memory. The proxy never logs bodies or headers; crash reports and exceptions must not
include them.

For one mediated connection:

1. Preserve CONNECT authorization, public-address validation, SNI equality and origin pinning.
2. Terminate client TLS and validate origin TLS for the original hostname.
3. Parse a bounded HTTP request head and select the target by host, method and literal path matcher.
4. Apply standing restricted authorization when the resolved policy says restricted.
5. Replace only the selected instance's complete placeholder in the declared header shape.
6. Relay request and response framing without interpreting provider bodies.
7. Emit one audit line after origin connection, with `inject=<service>/<instance>` only when spent.

Advertise only HTTP/1.1 initially. Server-sent events and bounded streaming bodies must work on the
existing relay. WebSocket upgrade, HTTP/2-only clients and certificate-pinned clients refuse the
service compatibility gate; they do not regain a real credential inside the sandbox.

The Codex client remains excluded from OpenAI mediation until its compiled-in trust behavior can
be made to accept the per-run CA without weakening certificate validation. Each other installed
agent gets the same measured compatibility gate before its service is listed as supported.

## Failure and audit contract

Credential failures are transport errors after local egress admission, never policy denials:

```text
error api.example.com POST /v1 credential unavailable service/instance
allow api.example.com POST /v1 -> <origin-ip> inject=service/instance
```

Use fixed client diagnostics for missing, expired, refresh-failed and reauthentication-required
states. They name the host management command to run, not source stderr. Origin 401 and 403 remain
origin responses; the proxy cannot infer whether they mean scope, revocation or application state.

The launch banner and `--egress-effective` show selected instance, mechanism, source kind, active
targets, excluded targets, refresh deadline and TLS mediation. They show no value, placeholder,
header contents, OAuth subject or executable output.

Retained audit lines make credential spending attributable but not replayable. A refresh event is a
host lifecycle line in the protected credential log, not a synthetic network request in the
project's proxy log.

## Lifecycle and cleanup

Global credential records live outside every project's state. Project `--reset` and `--reset-all`
remove per-run generations and agent state but do not silently revoke or delete global credentials;
`--credential-remove` is the only deletion authority.

Normal exit, Ctrl-C, failed create/start and reset remove every per-run value, placeholder mapping
and unavailable-status file. The host cache retains only what its source contract requires and is
removed with the instance.

Source rotation affects the next refresh. Service-definition changes require a rebuilt proxy image;
a running proxy and coordinator keep the catalog digest they started with. Launch refuses when the
launcher dry run, credential metadata, proxy image and mounted generation disagree on that digest.

## Deliberate exclusions

- **Automatic provider selection:** command-name inference chooses an egress group today, but a
  credential is stronger authority and requires explicit `--credential` selection.
- **Project or kit service declarations:** repository-controlled target or host-exec declarations
  would let untrusted input choose where a credential is spent or what runs on the host.
- **Wildcard targets:** every recipient is exact and reviewable; provider-controlled redirects do
  not extend the list.
- **Body, query and response injection:** header-only replacement remains the durable enforcement
  primitive. OAuth adapters do not make a general body rewriter.
- **Credential passthrough:** incompatibility fails the selected service; it never places the real
  value in the sandbox as a fallback.
- **On-demand execution from a request:** request traffic cannot cause host code execution. Refresh
  is scheduled by validated expiry metadata.
- **Repository or account scoping inferred by the proxy:** scope belongs in the issued credential.
  Literal request-path authority may narrow spending when a provider contract supports it.
- **Registry, SSH and cloud signing credentials:** their challenge, signing and socket protocols
  need separate brokers rather than exceptions in HTTP header substitution.
- **A generic OAuth DSL:** every supported flow is code with a reviewed provider contract and test
  fixture; arbitrary authorization endpoints and client identities are not configuration.
- **Transparent TLS pinning bypass:** a client that cannot trust the per-run CA remains unsupported.

## Verification

### Catalog and authority

- Test every catalog service as a population: identifiers, mechanisms, environment names, exact
  targets, header formats, path matchers and duplicate entries.
- Assert every target exists in the proxy's own host or provider catalog and every active target is
  admitted after denials; no service adds reachability.
- Test absent, repeated, unknown and colliding `--credential` selections and prove the project,
  agent command and stored-state presence cannot select one.
- Assert one service's source and mechanism are unchanged by adding, removing or resolving every
  other service.

### Placeholder and request path

- Reuse the base plan's entire substitution suite for every supported header shape.
- Generate many concurrent runs and instances; assert all placeholders are distinct, including
  multiple credentials for one host, and each selects only its own value.
- Run every target through denial, restricted authorization and mediated relay. Assert redirects,
  aliases, wrong paths and wrong headers receive no credential.
- Scan every sandbox environment, filesystem, persistent volume, argument, log, error and retained
  artifact for all real values and mappings after each lifecycle exit.

### Sources and refresh

- Test keychain and explicit Linux file backends, modes, corruption, unavailable backends, import,
  replacement, removal and absence from list output.
- Test executable descriptor parsing, absolute-path enforcement, no shell, environment allowlist,
  closed stdin, timeout, output bounds, malformed JSON, expiry and protected stderr.
- Test the value gate as a population over every producer — `set`, `import`, an executable
  result, OAuth issuance, OAuth refresh, a cached generation — with each byte the base plan's
  value grammar refuses: nothing is stored or published, the refusal names the offset and not
  the value, and a refreshed bad token leaves the prior generation in place. Test that a
  `Bearer %s` format with a conforming token yields one field, and that a format with `%s`
  twice, a control byte, or a byte outside visible ASCII and space fails catalog parsing.
- Use a process barrier across concurrent launchers to prove one source invocation per refresh and
  complete generation publication to every waiting run.
- Test refresh success, jitter, transient failure, backoff, expiry, reauthentication, removal races
  and clock movement. Read-only management and egress-check commands invoke the source zero times.
- Kill the coordinator at every write boundary and prove the next launch sees one valid generation
  or a clear unavailable state, never a truncated value or lost refresh token.

### TLS and clients

- Test restricted and standing-unrestricted targets with no credential, a selected credential and
  a denied overlay; no selection preserves byte-for-byte opaque behavior.
- Prove origin identity, SNI and public-address checks precede injection and remain the original
  hostname across every target and upstream-proxy mode.
- Exercise request and response framing, long server-sent-event streams, reconnects, cancellation,
  401/407/5xx and attempts to smuggle a second request or header.
- For each supported installed agent, test API-key and OAuth adapters in the production image on
  Linux, macOS and Windows. Certificate rejection or required HTTP/2 keeps that adapter unsupported.
- Assert bodies and sensitive headers are absent from audit output, exceptions and crash artifacts.

## Delivery order

1. Implement the service catalog, instance model and effective-authority display with no values,
   source execution, TLS changes or proxy substitution.
2. Implement host storage, management verbs and per-run generations for static API keys. Reuse the
   existing plan's exact-token rewrite on currently restricted hosts.
3. Generalize one instance to multiple exact targets and resolve the original plan's one-host and
   Copilot text with pointers to this document.
4. Add executable sources, cross-process single-flight caching and scheduled refresh. Pass the
   crash and concurrency matrix before adding OAuth.
5. Add the mediated-provider overlay and one TLS-compatible API-key client. Update `SECURITY.md`
   when plaintext provider traffic first enters proxy memory.
6. Add provider OAuth implementations one at a time, each with a host-owned client identity,
   compatibility fixture and refresh/revocation tests.
7. Update README, launcher help, agent instructions and the effective-policy reference. Remove
   completed plan facts after their canonical code and security sites bind them.

Do not expose provider mediation as complete until multi-domain isolation, cross-service
independence, single-flight refresh, expiry fail-closed, TLS compatibility, secret scanning and
production-container cleanup pass together.

## References

- Docker Sandboxes, credential management:
  https://docs.docker.com/ai/sandboxes/configuration/credentials/
- Docker Sandboxes, kit credential schema:
  https://docs.docker.com/ai/sandboxes/customize/kit-reference/
- docker/sbx-releases #213, shared sentinels confuse credentials on one host:
  https://github.com/docker/sbx-releases/issues/213
- docker/sbx-releases #344, unrelated service state changes the selected mechanism:
  https://github.com/docker/sbx-releases/issues/344
- docker/sbx-releases #402, refresh side effects and cross-process races:
  https://github.com/docker/sbx-releases/issues/402
- docker/sbx-releases #300, proposed expiring host-exec credential contract:
  https://github.com/docker/sbx-releases/issues/300
