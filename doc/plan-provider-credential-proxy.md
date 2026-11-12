# Plan: provider credential brokering at the egress proxy

## Outcome

Add a service layer, selected on the host, above the substitution primitive of `--egress-cred`
(`egress-proxy.md`, "Brokered credentials"):

```text
credential instance -> source and lifecycle
service definition   -> sandbox adapter and approved injection targets
egress ruleset       -> whether each target is reachable
```

`--egress-cred`'s documents stay the specification of these facts (`egress-proxy.md`, "Brokered
credentials"; SECURITY.md, "Who holds a brokered value"):

- how a placeholder is built;
- exact-token substitution in a declared header or a named query parameter;
- auditing of each request;
- the rule that a brokered value never enters the sandbox.

This plan specifies what that primitive does not:

- one service that spans several domains;
- credentials stored on the host across runs;
- dynamic sources;
- expiry and refresh;
- an explicit choice of mechanism;
- provider endpoints whose writable traffic must be TLS-terminated before a header or parameter can
  be brokered.

An `--egress-cred=NAME@HOST` binding stays a binding for one run and one host. Provider brokering is
a separate session option. That option neither changes the `--egress-cred` grammar nor turns a
stored credential on by itself.

## Document boundary

Each fact is specified in one place:

- `egress-proxy.md`, "Brokered credentials", specifies how the proxy rewrites a placeholder to a
  value.
- This document specifies service composition, credential sources, refresh and TLS termination at
  provider endpoints.
- The egress ruleset defines path matching. A credential target refers to that matcher and defines
  no other (`egress-proxy.md`, "Where the value goes", the `PREFIX` form).
- The egress ruleset alone decides reachability. A credential service never adds a host.
- `SECURITY.md` records the resulting trust model once the implementation ships.

## Required use cases

1. Store or resolve one GitHub credential once, select it for a run, and use it at the exact
   GitHub API and Git HTTPS targets that its service definition names.
2. Give two workspaces or concurrent runs the same stored instance, without sharing a proxy,
   placeholder or audit log.
3. Resolve a short-lived access token with a host executable, refresh it before expiry, and keep
   the refresh token or provider login outside the sandbox.
4. Select one credential mechanism for a model provider, so that no unrelated stored service or
   workspace file can change that choice.
5. Broker an API-key or OAuth-backed model provider only when the installed client accepts the
   launch CA and the host explicitly accepts, for that run, that the proxy sees plaintext.

Registry login, SSH agent forwarding and cloud request re-signing are different protocols. This
plan does not require them.

## Guarantees

1. A credential has two independent authorities: the egress ruleset allows a destination, and the
   host launch selects a credential instance. Neither authority implies the other.
2. A repository, agent command, persisted agent state or service response cannot create, select,
   retarget or refresh a credential instance.
3. One instance selects exactly one service and mechanism. The instance may inject only into the
   service's finite list of exact targets; no wildcard, redirect or response can add a target.
4. Every active instance has a fresh per-run placeholder. Two instances have different placeholders,
   even when they use the same service, host, header, source value or run.
5. Injection still requires equality with the complete placeholder in the declared header or named
   query parameter. Injection never rewrites a path, another parameter, a body, a response or an
   arbitrary occurrence of the bytes.
6. A denied destination stays denied. A selected service with no allowed target is inert: the
   launch refuses it, rather than widening egress or silently falling back to an unbrokered value.
7. The real value exists only in its host source, the protected host store, the launcher's bounded
   refresh memory, the private per-run generation and the proxy's memory. The value never enters
   sandbox-visible state.
8. Only the credential coordinator invokes or refreshes a source. Listing, ruleset inspection,
   diagnostics and a locally denied request are read-only, and cannot trigger a refresh.
9. Refresh is single-flight per instance across concurrent launchers. A new generation becomes
   visible atomically: a reader sees the complete old or the complete new generation, never a
   mixture.
10. Expiry never widens authority. If no usable generation exists, matching requests fail closed
    with a credential-unavailable response and no uncredentialed retry.
11. Selecting one service cannot change another service's mechanism, adapter, source, targets,
    placeholder or cache generation.
12. The launch banner and the `--egress-effective` output state TLS termination at an otherwise
    opaque provider endpoint. Without a selected credential, the endpoint keeps its configured
    opaque behavior.
13. The proxy never sends a real credential before it validates the origin's TLS identity. The proxy
    never forwards the credential across an origin redirect, unless the new target independently
    matches the service.
14. Removing or replacing a stored source affects future refreshes and launches. The change does not
    make another instance inherit the source, and does not reveal an already loaded value.

## Terms and data model

A **service definition** is trusted, versioned data shipped in the proxy image. A service
definition contains:

- a stable lowercase service identifier;
- its supported mechanisms, each either `api-key` or a named built-in OAuth flow;
- sandbox adapters: environment names, and any image-owned client configuration that holds the
  placeholder;
- injection targets, each an exact normalized host and one place: a header with a fixed value
  format that holds a single placeholder slot, or a named query parameter;
- an optional configured literal path prefix and method set, using the ruleset's existing matchers;
- the client and image compatibility probes that must pass before the service is offered.

A **credential instance** is host-owned state:

```text
<service>/<instance> -> mechanism + source reference + refresh policy
```

Both identifiers match `[a-z][a-z0-9-]{0,62}`, and an omitted instance means `default`. Instances
separate accounts or scopes without copying a service definition: `github/work` and
`github/personal` may share targets, but never a placeholder or source.

An **active binding** is the intersection of a selected instance's targets with the egress ruleset.

- Denied targets are removed first.
- Every remaining target must be TLS-inspected, either by the existing inspected treatment or by the
  brokered-provider path below.

The service catalog is a closed image resource, which `--print-ruleset` and the serving proxy
parse. The launcher consumes that answer and keeps no second table of provider domains.

## Launcher command-line contract

Management actions operate outside a workspace and consume no launch options:

```text
--credential-set=<service>[/<instance>]
--credential-import=<service>[/<instance>]@<environment-name>
--credential-exec=<service>[/<instance>]@<absolute-descriptor-path>
--credential-login=<service>[/<instance>]
--credential-list
--credential-remove=<service>[/<instance>]
```

- `--credential-set` reads one value from the controlling terminal without echo, and stores it in
  the host credential backend as `api-key`. The action refuses without a terminal; a secret is
  never an argument.
- `--credential-import` reads the named host environment variable once and stores its value. The
  launcher records the variable's name for provenance and does not read the variable again. This
  action also selects `api-key`.
- `--credential-exec` copies and validates a non-secret descriptor of an executable source, for the
  `api-key` mechanism. The host command stays the authority for any keychain, cloud secret manager
  or provider CLI that it uses.
- `--credential-login` exists only for a shipped service with a host-side OAuth implementation. For
  any other service the action refuses, rather than start a generic flow with guessed endpoints.
- `--credential-list` prints instance, service, mechanism, source kind and usability metadata.
  - The action never prints a value, placeholder or source output.
  - The action prints an OAuth subject only when the service deliberately makes that display name
    non-secret.
- `--credential-remove` takes the instance lock, then removes the source and cache. A live run may
  use its current unexpired generation, but cannot refresh it.

A launch selects instances explicitly, and the option repeats:

```text
--credential=<service>[/<instance>]
```

Do not infer the selection from the agent command, the selected model provider, the environment,
the workspace or the credential's presence in the store. A stored credential stays unused until the
host selects it.

- `--egress-effective` accepts `--credential`. Without resolving a source, `--egress-effective`
  shows every allowed injection target, every excluded target and the TLS treatment.
- `--egress-check=<host>` may test reachability and TLS compatibility, but never sends or refreshes
  a credential.

## Service definitions

Each injection target declares:

```text
host api.github.com
header Authorization
format "Bearer %s"
methods GET,HEAD
path /
```

The serialized form is internal to the image, not workspace configuration. Its parser requires:

- an exact normalized hostname that the same image's provider or host catalog already holds;
- a header name or query parameter name that the binding grammar admits (`egress-proxy.md`, "Where
  the value goes");
- with a header, a format that contains exactly one `%s`, no other conversion, and otherwise only
  visible ASCII and space:
  - the format is catalog text, trusted for the space that `Bearer %s` needs;
  - the proxy builds the header field by placing into the format a value that has separately passed
    the raw-value grammar;
- a method set and an optional literal prefix, neither wider than the target's configured inspected
  scope;
- unique `(host, place, format, matcher)` entries inside one service.

For a configured tunnel host, the target deliberately has no method or path grants: the existing
authority already permits writable traffic. Brokering parses enough HTTP to inject and relay, but
does not claim to make model traffic read-only.

Several domains form one service only when the provider documents them as recipients of the same
credential. Convenience is not evidence. Authentication, token and resource endpoints are named
separately, so that a value meant for one endpoint is not automatically sent to all of them.

The first catalog holds only services that installed agents need.

- A third-party kit or repository cannot supply a definition.
- Add a host-owned format for custom definitions only after a concrete service cannot reasonably
  enter the reviewed catalog. That format needs its own design for provenance and approval.

## Credential sources and storage

The host credential backend stores static values and OAuth refresh material.

- Prefer the operating system keychain.
- On a headless Linux host without a keychain, an owner-only file under the launcher's global state
  is an explicit fallback, announced when the value is stored.
- Encrypting that file with a key held in the same account would add no boundary.

Source metadata and values are stored apart:

- Metadata contains the service, instance, mechanism, source kind, descriptor digest and refresh
  times.
- The secret backend contains only the value or the OAuth material.
- Workspace state contains neither.

Validate every credential value before storing it and before publishing a generation. At those two
steps every value passes `--egress-cred`'s value grammar (`egress-proxy.md`, "Where the value
goes"), whatever produced it: `set`, `import`, an executable result, an OAuth access token at
issuance or refresh, or a cached generation being reused.

- A value that fails is refused at its producer with the offending byte's offset, and nothing is
  stored.
- A refresh that yields a failing value is a refresh failure, and the current generation stays
  until its expiry.
- Storage therefore never holds a value that the proxy will refuse. The proxy's own check at load
  reads the same rule a second time; it is not the first check.

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

- No shell interprets `argv`. Element zero is an absolute regular executable outside the workspace.
- The child gets a fixed empty working directory, a minimal launcher-owned environment plus the
  exact named host variables, a closed stdin, and captured bounded stdout and stderr.
- No request host, path, header, account string or sandbox byte becomes an argument or environment
  value. Registering the descriptor is the host's explicit authority to execute it.
- On timeout the launcher kills the child.
- The launcher discards stderr. An ordinary error shows only an exit status and a fixed
  remediation.
  - `--show-credential-source-error` is a separate host action. The action warns that provider
    output can contain a secret, then reruns the source and streams bounded stderr to that terminal.

Successful stdout is one bounded UTF-8 JSON object:

```json
{
  "version": 1,
  "token": "secret value",
  "expiresAt": "2026-08-28T18:00:00Z"
}
```

- `expiresAt` is required unless the descriptor supplies `maxAgeSeconds`.
- Unknown fields, duplicate keys, control bytes, an empty token, a past expiry or trailing data
  refuse the result.
- A provider can instead return one of the fixed error codes `temporarily-unavailable` or
  `reauth-required`.
- After decoding, the raw token is validated as above, so an escaped newline cannot become header
  injection.
- Free-form provider text is never stored, and never put in a proxy response.

## Refresh coordinator

The launcher owns one credential coordinator for the duration of a run.

- The coordinator resolves every selected instance before containers are created.
- The coordinator creates a private per-run credential directory, which the proxy mounts read-only.

Each generation is an owner-only directory. The directory holds a monotonically increasing number,
the service and instance IDs, the expiry, the placeholder digest and the value.

- The launcher writes and syncs a complete new directory, then atomically replaces a small `current`
  pointer.
- A manifest records every file's length and digest, to detect a torn publication. The owner-only
  directory is the authenticity boundary.
- The proxy opens and verifies one named generation at a request boundary. The proxy does not watch
  partially written files, and does not keep an expired earlier generation.

The coordinator refreshes at `expiresAt - refreshBeforeSeconds`, with bounded jitter.

- Static values have no scheduled refresh.
- An executable value with `maxAgeSeconds` refreshes on that schedule.
- No host callback runs per request, so no request triggers host execution.

All launchers coordinate through one lock per credential instance and one protected host cache:

1. Take the instance lock before source resolution or any state change.
2. Reuse a complete cached generation if it is still outside its refresh window.
3. Otherwise invoke or refresh exactly once, validate the result, and atomically publish the cache.
4. Copy the usable generation into each waiting run, with that run's distinct placeholder.
5. Release the lock before any container operation.

A refresh failure keeps the current generation only until its declared expiry. Retries use bounded
backoff inside the remaining validity window. After expiry:

- the coordinator publishes an unavailable status;
- the proxy refuses matching requests with 502, and the audit line says `credential unavailable`;
- the proxy never injects an expired value, and never sends the placeholder as a retry.

Read-only actions never take the refresh path. Removal, import, login and refresh take the same
instance lock, so concurrent changes cannot lose half an OAuth credential or let a stale API key
shadow a newly selected mechanism.

## OAuth mechanisms

OAuth is a provider implementation behind the same source interface, not a generic collection of
URLs in a workspace file.

- A shipped flow fixes its authorization server, public-client identity, grant, scopes, token
  fields, refresh behavior and revocation semantics.
- The browser or device step runs on the host. Access and refresh tokens enter the host backend,
  never the sandbox.

The sandbox adapter supplies stable placeholders, in the exact environment or credential-file
format that the installed client requires. Provider-specific expiry bookkeeping is generated from
public metadata only. The client sends the placeholder to a resource target, and the common proxy
rewrite injects the current access token.

Do not reuse another application's private client identity or copy its refresh token. A service
without a public-client registration that the project owns uses an executable source, such as its
official host CLI, or stays unsupported.

Copilot is one such service: it gets a host OAuth mechanism or a `gh` executable source, never a
response-body interceptor that imitates the CLI's token cache. If a provider can work only through
intercepted OAuth responses, specify it as a provider adapter with a separate security review: its
endpoint, bounded JSON fields, rotation and write mount.

Before building the Copilot adapter, measure which token reaches `api.githubcopilot.com`, from a
`--egress-log` of a `copilot` session on the installed CLI.

- Copilot clients generally exchange the GitHub OAuth token at
  `api.github.com/copilot_internal/v2/token` for a short-lived session token, and present only the
  session token to the model endpoint.
  - The exchange is on the inspected path, so the proxy substitutes the placeholder there, and
    `api.githubcopilot.com` stays an opaque tunnel.
  - If the built-in GitHub MCP server sends the OAuth token itself, brokering breaks that server
    alone. `--disable-builtin-mcps` is the documented switch.
- If the CLI sends the OAuth token straight to `api.githubcopilot.com`, an opaque tunnel cannot
  substitute it. That host is then brokered under "Brokered provider traffic", or Copilot stays
  unbrokered.

## Brokered provider traffic

The rule grammar's treatments are:

```text
inspected    TLS-terminated; the grants of its resolved scope
tunnel       opaque writable tunnel
```

A selected credential adds a per-run overlay, not a third treatment in the rule grammar:

```text
brokered     TLS-terminated writable relay for an allowed provider target
```

The overlay applies only to the exact targets of the selected service.

- A denied host stays absent.
- An inspected host stays inspected, and its authorization reads the rewritten head (steps 4 and 5
  below).
- A tunnel host is brokered only for that run, and otherwise stays an opaque tunnel.

The launch's leaf certificate names the union of inspected hosts and active brokered targets. The
`--egress-effective` answer and the startup banner list the brokered targets and say:

```text
credential brokering: proxy reads provider HTTP for <service>/<instance>: <hosts>
```

This is a privacy boundary: the trusted proxy sees model request and response bytes for brokered
hosts. Plaintext model conversations are an asset in the proxy's memory. The proxy never logs
bodies, and of headers only the start of the `User-Agent`; crash reports and exceptions must not
include them.

For one brokered connection:

1. Keep CONNECT authorization, public-address validation, SNI equality and the connection to the
   validated origin address.
2. Terminate client TLS, and validate origin TLS for the original hostname.
3. Parse a bounded HTTP request head, and select the target by host, method and literal path
   matcher.
4. Replace only the selected instance's complete placeholder in the declared header format or query
   parameter.
5. When the ruleset says inspected, apply the configured inspected authorization to the rewritten
   head (`egress-proxy.md`, "Where the value goes": authorization and the origin see the same
   head).
6. Relay request and response framing without interpreting provider bodies.
7. Emit one audit line after the origin connection, with `inject=<service>/<instance>` only when a
   value was substituted.

Advertise only HTTP/1.1 at first. Server-sent events and bounded streaming bodies must work on the
existing inspected path. Brokering does not support WebSocket upgrade, HTTP/2-only clients or
certificate-pinned clients; those clients do not regain a real credential inside the sandbox.

The Codex client accepts the inspection CA, and falls back from a refused websocket upgrade to HTTP
requests (`design.md`, "Credential brokering at the egress proxy", has the measurement). Codex stays
excluded from OpenAI brokering until one turn succeeds over an inspected connection. Each other
installed agent's TLS and HTTP compatibility is measured the same way before its service is listed
as supported.

## Failure and audit contract

Credential failures are transport errors after the local egress rules allowed the request, never
ruleset denials:

```text
error api.example.com POST /v1 credential unavailable service/instance
allow api.example.com POST /v1 inject=service/instance -> <origin-ip>
```

- Use fixed client diagnostics for the missing, expired, refresh-failed and
  reauthentication-required states. The diagnostics name the management action to run, not source
  stderr.
- Origin 401 and 403 stay origin responses. The proxy cannot infer whether they mean scope,
  revocation or application state.

The launch banner and `--egress-effective` show the selected instance, mechanism, source kind,
active targets, excluded targets, refresh deadline and TLS termination. Neither shows a value,
placeholder, header contents, OAuth subject or executable output.

Retained audit lines make credential use attributable, but not replayable. A refresh event is a host
lifecycle line in the protected credential log, not a synthetic network request in the workspace's
proxy log.

## Lifecycle and cleanup

Global credential records are stored outside every workspace's state.

- Workspace `--reset` and `--reset-all` remove per-run generations and agent state, but do not
  silently revoke or delete global credentials.
- Only `--credential-remove` deletes a global credential.

Normal exit, Ctrl-C, a failed create or start, and reset remove every per-run value, placeholder
mapping and unavailable-status file. The host cache keeps only what its source contract requires,
and is removed with the instance.

Source rotation affects the next refresh. A change to a service definition requires a rebuilt proxy
image:

- a running proxy and coordinator keep the catalog digest they started with;
- the launch refuses when the launcher dry run, the credential metadata, the proxy image and the
  mounted generation disagree on that digest.

## Deliberate exclusions

- **Automatic provider selection:** command-name inference selects a model provider, but a
  credential is a stronger authority and requires explicit `--credential` selection.
- **Workspace or kit service declarations:** a repository-controlled declaration of targets or
  host executables would let untrusted input choose where a credential is spent or what runs on the
  host.
- **Wildcard targets:** every recipient is exact and reviewable. Provider-controlled redirects do
  not extend the list.
- **Body and response injection, and rewriting every occurrence in a query:** replacement in a
  declared header or one named parameter stays the durable enforcement primitive. OAuth adapters do
  not make a general body rewriter.
- **Credential passthrough:** an incompatibility fails the selected service. The launch never
  places the real value in the sandbox as a fallback.
- **On-demand execution from a request:** request traffic cannot cause host code execution.
  Validated expiry metadata schedules refresh.
- **Repository or account scoping inferred by the proxy:** scope belongs in the issued credential.
  Literal request-path authority may narrow where a credential is sent, when a provider contract
  supports it.
- **Registry, SSH and cloud signing credentials:** their challenge, signing and socket protocols
  need separate brokers, rather than exceptions in HTTP header or parameter substitution.
- **A generic OAuth DSL:** every supported flow is code with a reviewed provider contract and a test
  fixture. Arbitrary authorization endpoints and client identities are not configuration.
- **Transparent TLS pinning bypass:** a client that cannot trust the inspection CA stays
  unsupported.

## Verification

### Catalog and authority

- Test every catalog service: identifiers, mechanisms, environment names, exact targets, header
  formats, path matchers and duplicate entries.
- Assert that every target exists in the proxy's own host or provider catalog, and that every active
  target is allowed after denials. No service adds reachability.
- Test absent, repeated, unknown and colliding `--credential` selections. Prove that the workspace,
  the agent command and the presence of stored state cannot select one.
- Assert that adding, removing or resolving any other service leaves one service's source and
  mechanism unchanged.

### Placeholder and request path

- Reuse `--egress-cred`'s substitution tests (`CredentialTest`) for every supported header format
  and parameter target.
- Generate many concurrent runs and instances. Assert that all placeholders are distinct, including
  those of several credentials for one host, and that each placeholder selects only its own value.
- Run every target through denial, inspected authorization and brokered relay. Assert that
  redirects, aliases, wrong paths and wrong headers or parameters receive no credential.
- After each lifecycle exit, scan every sandbox environment, filesystem, persistent volume,
  argument, log, error and retained artifact for all real values and mappings.

### Sources and refresh

- Test the keychain and explicit Linux file backends: modes, corruption, unavailable backends,
  import, replacement, removal and absence from list output.
- Test executable descriptor parsing, absolute-path enforcement, no shell, the environment
  allowlist, closed stdin, timeout, output bounds, malformed JSON, expiry and protected stderr.
- Test value validation at every producer: `set`, `import`, an executable result, OAuth issuance,
  OAuth refresh and a cached generation. Feed each byte that `--egress-cred`'s value grammar
  refuses, and assert:
  - nothing is stored or published;
  - the refusal names the offset and not the value;
  - a refreshed bad token leaves the prior generation in place.
- Test that a `Bearer %s` format with a conforming token yields one field. Test that a format with
  `%s` twice, a control byte, or a byte outside visible ASCII and space fails catalog parsing.
- Use a process barrier across concurrent launchers to prove one source invocation per refresh, and
  complete generation publication to every waiting run.
- Test refresh success, jitter, transient failure, backoff, expiry, reauthentication, removal races
  and clock movement. Read-only management and egress-check actions invoke the source zero times.
- Kill the coordinator at every write boundary. Prove that the next launch sees one valid generation
  or a clear unavailable state, never a truncated value or a lost refresh token.

### TLS and clients

- Test inspected and configured-tunnel targets with no credential, with a selected credential and
  with a denied overlay. With no selection, opaque behavior stays byte-for-byte the same.
- Prove that the origin identity, SNI and public-address checks precede injection, and stay on the
  original hostname across every target and upstream-proxy mode.
- Exercise request and response framing, long server-sent-event streams, reconnects, cancellation,
  401/407/5xx, and attempts to smuggle a second request or header.
- For each supported installed agent, test the API-key and OAuth adapters in the production image
  on Linux, macOS and Windows. Certificate rejection or a required HTTP/2 keeps that adapter
  unsupported.
- Assert that bodies and sensitive headers are absent from audit output, exceptions and crash
  artifacts.

## Delivery order

Each step starts on one of the "Required use cases" above. `TODO.md`, "Credential brokering", has
the order and its reason.

1. Implement the service catalog, the instance model and the effective-authority display, with no
   values, source execution, TLS changes or proxy substitution.
2. Implement host storage, management actions and per-run generations for static API keys. Reuse
   `--egress-cred`'s exact-token rewrite on inspected hosts.
3. Generalize one instance to several exact targets.
4. Add executable sources, cross-process single-flight caching and scheduled refresh. Pass the
   crash and concurrency matrix before adding OAuth.
5. Add the brokered-provider overlay and one TLS-compatible API-key client. Update `SECURITY.md`
   when plaintext provider traffic first enters the proxy's memory.
6. Add provider OAuth implementations one at a time, each with a host-owned client identity, a
   compatibility fixture, and refresh and revocation tests.
7. Update the README, the launcher help, the agent instructions and the `--egress-effective`
   reference. Remove completed plan facts after the code and `SECURITY.md` record them.

Do not expose provider brokering as complete until these pass together: multi-domain isolation,
cross-service independence, single-flight refresh, fail-closed expiry, TLS compatibility, secret
scanning and production-container cleanup.

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
- docker/sbx-releases #492, a removed credential still injected after the sandbox restarts:
  https://github.com/docker/sbx-releases/issues/492
- docker/sbx-releases #300, proposed expiring host-exec credential contract:
  https://github.com/docker/sbx-releases/issues/300
