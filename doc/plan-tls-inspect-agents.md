# Plan: TLS inspection of the agents' model traffic

## Outcome

The default rules inspect an agent's model hosts instead of tunnelling them, one agent at a time,
each after a measurement shows its client works over an inspected connection. The `tunnel` grant
stays for the hosts no measurement has cleared and for a project's own rules (`design.md`, "No
inspecting every allowed host").

Every model request is then logged with its method, path and size, so the log shows a call to an
endpoint the session should not use and a request far larger than a conversation turn.

This plan neither substitutes nor refuses a credential: that is `--egress-cred` (`egress-proxy.md`,
"Brokered credentials") and `plan-provider-credential-proxy.md`. An inspected model host is what the
provider plan's brokered overlay terminates anyway, so this plan brings that termination forward and
adds the log fields; the overlay's own steps are unchanged.

## Evidence and target

- The exfiltration SECURITY.md concedes at a model host: an injected instruction supplies the
  attacker's key, and any process in the session uploads project files under it ("Exfiltration
  through allowed network traffic", with two reported demonstrations). Under a tunnel the log
  holds one `CONNECT` line per connection and nothing distinguishes that upload from a turn.
- What the proxy sees for the more valuable credential today: forge tokens pass through the
  inspected `api.github.com` in plaintext, and `design.md`, "Credential brokering at the egress
  proxy", rates a forge token above a model token. The exposure that keeps the model
  hosts opaque is already accepted for the forge hosts.
- What inspection cannot do: read the conversation for intent (`design.md`, "No DLP/entropy/LLM
  firewall"), or refuse the foreign key, which needs the session's own key and so the brokered
  overlay (`TODO.md`, "Credential brokering", the `require-placeholder` item).
- Copilot's and agy's control-plane writes travel through the same tunnels as their model
  traffic and are indistinguishable there (SECURITY.md, "Not defended"). Inspected, each is a
  line with its path.

## Guarantees

1. An agent's model hosts move from `tunnel` to inspected only after the measurement below has
   passed for the installed client, and the defaults file names the measurement beside the line.
2. An inspected model host grants what the tunnel granted: `read` and every `method=` word at
   the root, so the change of treatment alone refuses no request the tunnel carried. Refusals on
   a model host come only from the relay's and `read`'s rules, listed under "Measurement".
3. The audit line never carries a credential value, a body byte or a header value outside the
   allowlist in "Audit line additions". A value outside the allowed character set is spelled `?`.
4. The proxy keeps no credential value for the credential index: it keeps a digest, in memory,
   for the proxy's lifetime.
5. A project keeps the opaque treatment through the existing rule: `deny defaults` and its own
   `tunnel` line, the whole-ruleset decision `egress-proxy.md`, "The rule file", requires for a
   host the defaults inspect.
6. The leaf certificate names the newly inspected hosts through the launcher's existing reading
   of the resolved ruleset (`EgressRules.inspectedHostsOf`); no second host list exists.

## The agents, in order

The order is the state of the evidence, best first. Each agent's "documented" and "reported" is
read; "measure" is what the change waits for, beyond the list under "Measurement". A report
establishes a transport that differed in the named release on the named platform, not the
installed client's behavior; the version beside each agent is the image's, read 2026-09-28.

The sandbox environment is the launcher's, not the host's: it sets the six proxy variables and
the CA variables itself (`AgentSandboxLauncher.scala`, the egress and CA arguments), so a client's
precedence among them, `https_proxy` before `HTTPS_PROXY` in Claude Code's case, decides nothing.

- `claude` 2.1.283, `api.anthropic.com`.
  - Documented: `HTTPS_PROXY`; a custom CA through `NODE_EXTRA_CA_CERTS`, which the launcher
    sets (`AgentSandboxLauncher.scala`); `CLAUDE_CODE_CERT_STORE` selecting the bundled Mozilla
    set, the OS store or both (https://code.claude.com/docs/en/network-config). A streamed
    response is `text/event-stream` (the gateway protocol page, "Response headers").
  - Remote Control, off unless a flag, a command or a setting turns it on, registers with the
    Anthropic API and polls for work; while it is connected, Anthropic stores the transcript
    (https://code.claude.com/docs/en/remote-control, "Connection and security"). `claude` holds a
    `wss://` URL for `bridge.claudeusercontent.com`, which no default rule allows (`design.md`,
    "No WebSocket on an inspected connection").
  - Measure: a session with tool calls, a subagent and a compaction; a stream that fails
    mid-turn, whose fallback is a non-streaming request to the same host and so a second `POST`
    line (`CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK` in the environment variables page turns
    the fallback off); with Remote Control on, the hosts and paths it calls, and whether it
    connects at all.
- `codex` 0.158.0, `api.openai.com` and `chatgpt.com`.
  - Documented: `CODEX_CA_CERTIFICATE`, falling back to `SSL_CERT_FILE`, for login, HTTPS and
    WebSocket alike (https://learn.chatgpt.com/docs/auth, "Custom CA bundles").
  - On `main`: the WebSocket client is built from the HTTP client's custom-CA configuration
    (`codex-rs/websocket-client/src/lib.rs`); one failed WebSocket disables WebSockets for the
    rest of the session (`codex-rs/core/src/client.rs`, `disable_websockets`); a client built
    outside that policy bypasses it, the source warns, which is why each transport is measured
    rather than inferred from a login.
  - 0.158.0's `client.rs` switches the session to HTTP when either WebSocket connect, the turn's
    prewarm or its stream, is answered `426 Upgrade Required`, and handles any other status as
    an error. The proxy answers a refused `Upgrade` with `403`.
  - Reported: 0.147.0 and 0.154.0 on macOS accept the custom CA for HTTP and reject it for the
    Responses WebSocket with `UnknownIssuer` (openai/codex #46489, open), and the WebSocket
    retries run out before the HTTP fallback (openai/codex #19821, open). 0.155.1 completed both
    handshakes against a local server (SECURITY.md, "Who holds the CA key").
  - Measure: one turn, then a second in the same session; the refusals and the seconds before
    the fallback under `403`, then under `426`, against a local server as `design.md`, "Credential
    brokering at the egress proxy", records,
    then through the relay.
  - Passes with refused upgrades when the first turn completes over inspected HTTP and no later
    turn in the session tries an upgrade again. The number of refusals is recorded, not
    required: 0.155.1 sent seven over about seven seconds (`design.md`, "Credential brokering at
    the egress proxy"). Retries that end the turn, or upgrades on a later turn, leave Codex a
    tunnel.
  - If `426` falls back on the first refusal and `403` does not, the proxy answers every refused
    `Upgrade` with `426` and the `Upgrade` header RFC 9110 requires of it.
- `copilot` 1.0.88, `api.githubcopilot.com` and the three plan hosts.
  - Documented: `proxyUrl` in the CLI's configuration reference, overridden by `HTTP_PROXY` or
    `HTTPS_PROXY`
    (https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference).
  - The changelog has the proxy variables from 0.0.336, custom CA certificates loaded at startup
    from 1.0.40, HTTP/1.1 as the default transport from 1.0.57 with `COPILOT_ENABLE_HTTP2=1` the
    opt-in, and mTLS to an HTTPS proxy from 1.0.83; it does not say how the CA is configured.
  - Copilot's network troubleshooting page says that on Linux Copilot reads
    `/etc/ssl/certs/ca-certificates.crt`, the file the launch mounts its bundle over, and does not
    say whether that covers the CLI
    (https://docs.github.com/en/copilot/how-tos/troubleshoot-copilot/troubleshoot-network-errors).
  - Session sync is on by default: `remote` "on" and `remoteExport` true in the configuration
    reference send the session to the user's GitHub account, and the session-data page says
    what a session holds (SECURITY.md, "Not defended", has the export and `--no-remote-export`).
  - Reported: a model call is `POST /chat/completions` on the plan's host,
    `api.individual.githubcopilot.com` for one plan (github/copilot-cli #454); the built-in GitHub
    MCP server is `/mcp/readonly` on the same plan host (github/copilot-cli #4408). Inspected, the
    two are distinct lines.
  - Measure: CA trust in this build; the plan host selected; the MCP server's paths; the session
    sync's host and paths; with `COPILOT_ENABLE_HTTP2` unset, that the model path stays HTTP/1.1.
- `agy` 1.2.12, `cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com`,
  `generativelanguage.googleapis.com`, `businessaicode.googleapis.com` and the `aiplatform` hosts.
  - Documented: nothing on a proxy or a CA in the 28 CLI pages under
    https://antigravity.google/docs/cli.
  - Reported: 1.0.2 on Windows sent `loadCodeAssist` past `HTTPS_PROXY`
    (google-antigravity/antigravity-cli #181, closed as a duplicate); 1.1.21 on Windows sent
    `loadCodeAssist` through the proxy and the model calls, `streamGenerateContent`, directly
    (#875, open).
  - Measure: whether the client trusts the launch CA at all, and the HTTP version each host
    negotiates: the reports show HTTP paths, and the relay refuses HTTP/2.
- `kiro-cli` 2.24.1, `runtime.us-east-1.kiro.dev`, `q.us-east-1.amazonaws.com` and
  `management.us-east-1.kiro.dev`, each also in `eu-central-1`.
  - Documented: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from v1.8.0
    (https://kiro.dev/docs/cli/quick-start, "Proxy configuration"); no CA setting there or on the
    firewall page.
  - The firewall page names the `runtime` and `q` hosts "Kiro service" and the `management`
    hosts "Configuration, access management", and says CLI application traffic, chat and
    completions included, follows the proxy settings
    (https://kiro.dev/docs/privacy-and-security/firewalls).
  - Reported: 2.8.1 on Windows spawned the `acp` child of interactive `chat` without the parent's
    proxy and certificate variables (kirodotdev/Kiro #9608, closed as completed); 2.10.0 under
    WSL failed behind a TLS-inspecting proxy in its v3 harness while v2 worked (#9860, closed as
    completed).
  - Measure: interactive and headless mode each; whether the client trusts the launch CA; that a
    SigV4-signed request passes the relay unchanged.

The login and token hosts (`claude.ai`, `platform.claude.com`, `auth.openai.com`, the Google and
AWS sign-in hosts) stay tunnels in this plan: their traffic is a sign-in or a refresh, and
inspecting it records nothing an exfiltration reader needs. Revisit with the provider plan's
OAuth step.

## Measurement

One launch per agent with the agent's model hosts inspected through a project rule file
(`deny defaults`, the defaults' other lines, the model hosts with
`read method=POST,PUT,PATCH,DELETE`), `--egress-log` on, and a session that exercises tool calls,
a subagent where the agent has one, and a compaction or long turn. Read from the log:

- every host the client called, login and refresh included, and every path on an inspected host,
  so the inspected hosts are the complete set and nothing moved to a host the defaults do not
  name; a tunnel shows its host alone;
- no `deny` line on a model host, except refusals an agent's entry above accepts: the relay's
  rules are one request per connection, no `Upgrade`, `http/1.1` alone and a bounded head, and
  `read`'s is a `GET` without a body or framing header, so each is a way the client could fail;
- a server-sent-event stream survives the relay for a whole long turn: a truncated stream shows
  as a `relay:` error line;
- the client trusts the launch CA on every connection, so no `origin:` or handshake error line;
- whether the client sends a `Content-Length` or a chunked body, which decides whether a request's
  size is on its `allow` line or on a `sent` line;
- a line for each model request, by its path, beside the completed turn: the sandbox has no route
  but the proxy, so a transport that ignores `HTTPS_PROXY` fails rather than escapes, and the log
  then shows what did connect.

Each result is recorded with the client's exact version and its mode, interactive or headless,
and any child process the mode spawns: a pass in one mode is no evidence for another where the
client has a second transport or a child of its own (Kiro's `acp`, agy's model transport).

For Claude Code also: whether the gateway hint headers arrive through the proxy. The gateway
protocol page says they are sent by default on a direct connection and off by default under a
custom base URL; a launch sets `HTTPS_PROXY`, not `ANTHROPIC_BASE_URL`, and which case that is
has not been measured (https://code.claude.com/docs/en/llm-gateway-protocol, "Gateway hint
headers").

A measurement that fails on a protocol rule leaves the agent a tunnel and records the failing
rule beside its line in the defaults file; "Deliberate exclusions" has why the relay does not
change.

## Audit line additions

The inspected `allow` line gains fields after the origin address, each `key=value`, in this
order, each present only when the request supplies it:

- `request=<bytes>` from a declared `Content-Length`, or `request=chunked`. The line prints when
  the origin leg connects, before the body is relayed (`AgentEgressProxy.scala`, the in-tunnel
  audit context), so a chunked request's total is not on this line.
  - A chunked body's end prints `sent <host> <method> <target> request=<bytes>`, the body bytes
    the relay counted, on every inspected host: the sender picks the framing, so an upload that
    avoids the size field needs only chunking.
  - A chunked body that ends early prints no `sent` line.
- `client=<token>` from the `User-Agent` header's first product token, so a `curl` or a
  `python-requests` on a model host reads as such beside the agent's own token.
- `credential=<n>`: the index of this request's credential among the distinct ones the proxy has
  seen since it started, in order of first sight, from the `Authorization` and `x-api-key` values
  together. A second index in a session is a refreshed token or a foreign key; the reader tells
  them apart by the path and the time. Absent when neither header is present.
- Claude Code's hint and identity headers, each under its own name with the `x-claude-code-`
  prefix removed: `session-id`, `prompt-id`, `request-class`, `agent-type`, `agent-id`,
  `parent-agent-id`, `compaction`, `context-compacted`. Not `prev-tool-durations`: up to 4 KB of
  timing data with no exfiltration signal.

A value is logged as sent when it matches `[A-Za-z0-9._:/-]{1,128}`; otherwise the field reads
`key=?`. This keeps the line's fields unambiguous without a quoting grammar, and bounds the line.

The fields are client-supplied, the size excepted: the relay forwards no more body than a declared
`Content-Length`, and counts a chunked body itself. An attacker's own client omits or copies the
other fields. They attribute a request to a prompt and a subagent and name a foreign client that
did not bother; they prove nothing.

## Implementation sites

- `container/ko-agent-egress-proxy/app/src/main/resources/defaults/model-provider/<name>`: the
  changed lines, each with the measurement's date and the client version beside it.
- `AgentEgressProxy.scala`: the fields on the inspected `allow` line, built from the parsed head
  before the origin leg connects; the credential index as a map from digest to index, owned by
  the proxy instance.
- `RulesetHelper.scala`'s `Upgrade` refusal and the `Refusal` handler in `AgentEgressProxy.scala`:
  a refused `Upgrade` answered `426`, if Codex's measurement adopts it.
- `LogHelper.auditLine`: unchanged; the fields are part of the tail.
- `EgressRules.scala`: unchanged; the banner's `N inspected, M tunnel` counts move by themselves.

## Tests

- `AgentEgressProxyTest`:
  - the fields on the allow line for a request with each header present, absent, and outside the
    character set; no field on a `CONNECT` or a deny line;
  - the credential index for two keys, a refreshed bearer, two concurrent first uses of one key,
    which share an index, and a request without a credential;
  - the `sent` line for a chunked body, and none for a `Content-Length` one;
  - if Codex's measurement adopts `426`, a refused `Upgrade` answered `426` with an `Upgrade`
    header, still logged as `deny`.
- `HostileInputTest`: a hint header value with a control character, U+202E, `=`, a space and
  4 KB of data reads back as `?` and never splits or reorders a line.
- `EgressSessionTest`: the changed defaults resolve with the model host inspected and the leaf
  naming it; the project override with `deny defaults` and a `tunnel` line restores the tunnel.
- The per-agent measurement is a recorded session, not a test: its log excerpt goes beside the
  defaults line as the evidence.

## Documentation

- `SECURITY.md`:
  - "Not defended", "What is inside TLS": the reason the model hosts stay opaque becomes the
    reason the unmeasured ones do;
  - "The audit line grammar" gains the fields, the `sent` line and the sentence that the fields
    are client-supplied;
  - "Reading without being able to write": the item "`Upgrade` is refused" gains the status, if
    Codex's measurement adopts `426`.
- `design.md`, "No inspecting every allowed host": the second cost and the revisit condition
  no longer tie inspection to brokering; they point here.
- `plan-provider-credential-proxy.md`, "Brokered provider traffic": "The proxy never logs bodies
  or headers" becomes "never logs bodies, and of headers only the audit line's allowlist".
- `TODO.md`, "Credential brokering": the "measure first" list moves here; the Codex item points
  here.
- `egress-proxy.md`, "Choosing an egress profile": the defaults' description of the provider
  rules.
- `README.md`, "Egress proxy": "tunnels to supported model providers" is reworded to name the
  inspected hosts and the hosts still tunnelled.

## Acceptance checklist

- [ ] Claude Code's measurement recorded, its model host inspected, a session's log showing an
  `allow` line per model request with `request=`, `client=`, `credential=` and the hint fields.
- [ ] A `curl` upload to the model host from inside the session shows as a line with
  `client=curl`, its size and a second credential index.
- [ ] The project override restores the tunnel and the banner says so.
- [ ] Each other agent's model hosts inspected, or left tunnels with the failing rule recorded,
  one commit per agent.
- [ ] The documents above changed in the same commit as Claude Code's.

## Deliberate exclusions

- Refusing paths on a model host, such as a Files API endpoint: a per-release contract with each
  CLI, which `design.md`, "Credential brokering at the egress proxy", declines, and a storage
  behavior added at an allowed endpoint reopens the attack (`TODO.md`, the `require-placeholder`
  item, has the rejection).
- Logging a credential value, its prefix or its digest: the index gives a reader the one fact
  needed, that the credential changed.
- Codex's and Copilot's request headers: neither agent's documentation names a request header
  (Codex's full documentation text and Copilot CLI's pages, read 2026-09-28). Revisit per agent
  with a documented header list.
- Any log field from a body, for any host.
- A relay change for a client the measurement fails: `design.md`, "No WebSocket on an inspected
  connection", records the one considered. The refused `Upgrade`'s status is an answer, not a
  relay change, and Codex's entry may change it.

## References

- https://code.claude.com/docs/en/llm-gateway-protocol — the gateway hint headers, their values
  and when Claude Code sends them; "Response headers" for the streamed content type
- openai/codex `codex-rs/http-client/src/custom_ca.rs`, `codex-rs/websocket-client/src/lib.rs`,
  `codex-rs/core/src/client.rs` — custom CA shared by HTTP and WebSocket; the session-wide
  fallback and the `426` that starts it at once
- openai/codex #46489, #19821 — the WebSocket rejecting the custom CA a release's HTTP accepted;
  the retries before the HTTP fallback
- github/copilot-cli `changelog.md`; #454, #4408 — proxy, CA and mTLS entries by version; a
  model path and the built-in MCP server's path on a plan host
- google-antigravity/antigravity-cli #181, #875 — request paths that ignored `HTTPS_PROXY` in
  released versions
- kirodotdev/Kiro #9608, #9860 — a child process without the proxy variables; a harness that
  failed behind a TLS-inspecting proxy
- https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/
- https://www.promptarmor.com/resources/claude-cowork-exfiltrates-files
