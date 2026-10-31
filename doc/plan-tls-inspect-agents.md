# Plan: TLS inspection of the agents' model traffic

## Outcome

The default rules inspect an agent's model hosts instead of tunnelling them.

- The change goes one agent at a time, each after a measurement shows that the agent's client works
  over an inspected connection.
- The `tunnel` grant stays for the hosts that no measurement has cleared, and for a workspace's own
  rules (`design.md`, "No inspecting every allowed host").

The proxy then logs every model request with its method, path and size. So the log shows a call to
an endpoint the session should not use, and a request far larger than a conversation turn.

This plan neither substitutes nor refuses a credential. `--egress-cred` substitutes credentials
(`egress-proxy.md`, "Brokered credentials"), and `plan-provider-credential-proxy.md` plans the rest.
The provider plan's brokered overlay terminates TLS on an inspected model host anyway. So this plan
brings that termination forward and adds the log fields, and the overlay's own steps stay as they
are.

## Evidence and target

- SECURITY.md concedes an exfiltration at a model host ("Exfiltration through allowed network
  traffic", with two reported demonstrations).
  - An injected instruction supplies the attacker's key, and any process in the session uploads
    workspace files under that key.
  - Under a tunnel, the log holds one `CONNECT` line per connection, and nothing distinguishes that
    upload from a turn.
- The proxy already sees the more valuable credential. Forge tokens pass through the inspected
  `api.github.com` in plaintext, and `design.md` rates a forge token above a model token
  ("Credential brokering at the egress proxy"). So the project already accepts for the forge hosts
  the exposure that keeps the model hosts opaque.
- Inspection cannot read the conversation for intent (`design.md`, "No DLP/entropy/LLM firewall").
- Inspection cannot refuse the foreign key either. Refusing that key needs the session's own key,
  and so the brokered overlay (`TODO.md`, "Credential brokering", the `require-placeholder` item).
- Copilot's and agy's control-plane writes travel through the same tunnels as their model traffic,
  and are indistinguishable there (SECURITY.md, "Not defended"). Under inspection, each write is a
  line with its path.

## Guarantees

1. An agent's model hosts move from `tunnel` to inspected only after the measurement below has
   passed for the installed client. The defaults file names the measurement beside the line.
2. An inspected model host grants what the tunnel granted: `read` and every `method=` word at the
   root. So the change of treatment alone refuses no request that the tunnel carried. Refusals on a
   model host come only from the relay's rules and from `read`'s rules, listed under "Measurement".
3. The audit line never carries a credential value, a body byte, or a header value outside the
   allowlist in "Audit line additions". A value outside the allowed character set is spelled `?`.
4. The proxy keeps no credential value for the credential index. The proxy keeps a digest, in
   memory, for its lifetime.
5. A workspace keeps the opaque treatment through the existing rule: `deny defaults` and its own
   `tunnel` line. `egress-proxy.md` requires that whole-ruleset decision for a host the defaults
   inspect ("The rule file").
6. The leaf certificate names the newly inspected hosts through the launcher's existing reading of
   the resolved ruleset (`EgressRules.inspectedHostsOf`). No second host list exists.

## The agents, in order

The order follows the state of the evidence, best first.

- Each agent's "Documented" and "Reported" items were read.
- "Measure" is what the change waits for, beyond the list under "Measurement".
- A report establishes a transport that differed in the named release on the named platform. A
  report does not establish the installed client's behavior.
- The version beside each agent is the image's, read on 2026-09-28.

The sandbox environment is the launcher's, not the host's. The launcher sets the six proxy
variables and the CA variables itself (`AgentSandboxLauncher.scala`, the egress and CA arguments).
So a client's precedence among those variables decides nothing; Claude Code, for example, reads
`https_proxy` before `HTTPS_PROXY`.

- `claude` 2.1.283, `api.anthropic.com`.
  - Documented: `HTTPS_PROXY`; a custom CA through `NODE_EXTRA_CA_CERTS`, which the launcher sets
    (`AgentSandboxLauncher.scala`); `CLAUDE_CODE_CERT_STORE`, which selects the bundled Mozilla
    set, the OS store or both (https://code.claude.com/docs/en/network-config). A streamed
    response is `text/event-stream` (the gateway protocol page, "Response headers").
  - Remote Control is off unless a flag, a command or a setting turns it on.
    - When on, Remote Control registers with the Anthropic API and polls for work. While it is
      connected, Anthropic stores the transcript
      (https://code.claude.com/docs/en/remote-control, "Connection and security").
    - `claude` holds a `wss://` URL for `bridge.claudeusercontent.com`, which no default rule
      allows (`design.md`, "No WebSocket on an inspected connection").
  - Measure:
    - a session with tool calls, a subagent and a compaction;
    - a stream that fails mid-turn. The fallback is a non-streaming request to the same host, and
      so a second `POST` line. `CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK` turns the fallback off
      (the environment variables page);
    - with Remote Control on, the hosts and paths it calls, and whether it connects at all.
- `codex` 0.158.0, `api.openai.com` and `chatgpt.com`.
  - Documented: `CODEX_CA_CERTIFICATE`, falling back to `SSL_CERT_FILE`, for login, HTTPS and
    WebSocket alike (https://learn.chatgpt.com/docs/auth, "Custom CA bundles").
  - On `main`:
    - the WebSocket client is built from the HTTP client's custom-CA configuration
      (`codex-rs/websocket-client/src/lib.rs`);
    - one failed WebSocket disables WebSockets for the rest of the session
      (`codex-rs/core/src/client.rs`, `disable_websockets`);
    - the source warns that a client built outside that policy bypasses the policy. So each
      transport is measured rather than inferred from a login.
  - In 0.158.0, `client.rs` switches the session to HTTP when either WebSocket connect is answered
    `426 Upgrade Required`: the turn's prewarm or its stream. `client.rs` handles any other status
    as an error. The proxy answers a refused `Upgrade` with `403`.
  - Reported:
    - 0.147.0 and 0.154.0 on macOS accept the custom CA for HTTP, and reject it for the Responses
      WebSocket with `UnknownIssuer` (openai/codex #46489, open).
    - The WebSocket retries run out before the HTTP fallback (openai/codex #19821, open).
    - 0.155.1 completed both handshakes against a local server (SECURITY.md, "Who holds the CA
      key").
  - Measure one turn, then a second turn in the same session. Measure the refusals and the seconds
    before the fallback, under `403` and then under `426`. Measure first against a local server, as
    `design.md` records ("Credential brokering at the egress proxy"), then through the relay.
  - Codex passes with refused upgrades when the first turn completes over inspected HTTP, and no
    later turn in the session tries an upgrade again.
    - The number of refusals is recorded, not required. 0.155.1 sent seven over about seven
      seconds (`design.md`, "Credential brokering at the egress proxy").
    - Retries that end the turn, or upgrades on a later turn, leave Codex a tunnel.
  - If `426` falls back on the first refusal and `403` does not, the proxy answers every refused
    `Upgrade` with `426`. The answer carries the `Upgrade` header that RFC 9110 requires of a
    `426`.
- `copilot` 1.0.88, `api.githubcopilot.com` and the three plan hosts.
  - Documented: `proxyUrl` in the CLI's configuration reference, overridden by `HTTP_PROXY` or
    `HTTPS_PROXY`
    (https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference).
  - The changelog lists:
    - the proxy variables from 0.0.336;
    - custom CA certificates loaded at startup from 1.0.40;
    - HTTP/1.1 as the default transport from 1.0.57, with `COPILOT_ENABLE_HTTP2=1` as the opt-in;
    - mTLS to an HTTPS proxy from 1.0.83.

    The changelog does not say how the CA is configured.
  - Copilot's network troubleshooting page says that on Linux Copilot reads
    `/etc/ssl/certs/ca-certificates.crt`, the file the launch mounts its bundle over. The page does
    not say whether that covers the CLI
    (https://docs.github.com/en/copilot/how-tos/troubleshoot-copilot/troubleshoot-network-errors).
  - Session sync is on by default. With `remote` "on" and `remoteExport` true in the configuration
    reference, Copilot sends the session to the user's GitHub account. The session-data page says
    what a session holds. SECURITY.md covers the export and `--no-remote-export` ("Not defended").
  - Reported:
    - A model call is `POST /chat/completions` on the plan's host,
      `api.individual.githubcopilot.com` for one plan (github/copilot-cli #454).
    - The built-in GitHub MCP server is `/mcp/readonly` on the same plan host (github/copilot-cli
      #4408).
    - Under inspection, the two are distinct lines.
  - Measure: CA trust in this build; the plan host selected; the MCP server's paths; the session
    sync's host and paths; with `COPILOT_ENABLE_HTTP2` unset, that the model path stays HTTP/1.1.
- `agy` 1.2.12, `cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com`,
  `generativelanguage.googleapis.com`, `businessaicode.googleapis.com` and the `aiplatform` hosts.
  - Documented: nothing on a proxy or a CA in the 28 CLI pages under
    https://antigravity.google/docs/cli.
  - Reported:
    - 1.0.2 on Windows sent `loadCodeAssist` past `HTTPS_PROXY`
      (google-antigravity/antigravity-cli #181, closed as a duplicate).
    - 1.1.21 on Windows sent `loadCodeAssist` through the proxy, and the model calls,
      `streamGenerateContent`, directly (#875, open).
  - Measure whether the client trusts the launch CA at all, and the HTTP version each host
    negotiates. The reports show HTTP paths, and the relay refuses HTTP/2.
- `kiro-cli` 2.24.1, `runtime.us-east-1.kiro.dev`, `q.us-east-1.amazonaws.com` and
  `management.us-east-1.kiro.dev`, each also in `eu-central-1`.
  - Documented: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from v1.8.0
    (https://kiro.dev/docs/cli/quick-start, "Proxy configuration"). Neither that page nor the
    firewall page has a CA setting.
  - The firewall page names the `runtime` and `q` hosts "Kiro service", and the `management` hosts
    "Configuration, access management". The page says that CLI application traffic, chat and
    completions included, follows the proxy settings
    (https://kiro.dev/docs/privacy-and-security/firewalls).
  - Reported:
    - 2.8.1 on Windows spawned the `acp` child of interactive `chat` without the parent's proxy and
      certificate variables (kirodotdev/Kiro #9608, closed as completed).
    - 2.10.0 under WSL failed behind a TLS-inspecting proxy in its v3 harness, while v2 worked
      (#9860, closed as completed).
  - Measure: interactive and headless mode each; whether the client trusts the launch CA; that a
    SigV4-signed request passes the relay unchanged.

The login and token hosts stay tunnels in this plan: `claude.ai`, `platform.claude.com`,
`auth.openai.com`, and the Google and AWS sign-in hosts. Their traffic is a sign-in or a refresh,
and inspecting it records nothing that an exfiltration reader needs. Revisit them with the provider
plan's OAuth step.

## Measurement

Each agent gets one launch with:

- the agent's model hosts inspected through a workspace rule file: `deny defaults`, the defaults'
  other lines, and the model hosts with `read method=POST,PUT,PATCH,DELETE`;
- `--egress-log` on;
- a session that exercises tool calls, a subagent where the agent has one, and a compaction or a
  long turn.

Read from the log:

- every host the client called, login and refresh included, and every path on an inspected host.
  - The hosts and paths show that the inspected hosts are the complete set, and that nothing moved
    to a host the defaults do not name.
  - A tunnel shows its host alone.
- no `deny` line on a model host, except refusals that an agent's entry above accepts. Each of
  these rules is a way the client could fail:
  - the relay's rules: one request per connection, no `Upgrade`, `http/1.1` alone, and a bounded
    head;
  - `read`'s rule: a `GET` without a body or framing header.
- a server-sent-event stream that survives the relay for a whole long turn. A truncated stream
  shows as a `relay:` error line.
- the client's trust of the launch CA on every connection, so no `origin:` or handshake error line.
- whether the client sends a `Content-Length` or a chunked body. The framing decides whether a
  request's size is on its `allow` line or on a `sent` line.
- a line for each model request, by its path, beside the completed turn.
  - The sandbox has no route but the proxy, so a transport that ignores `HTTPS_PROXY` fails rather
    than escapes. The log then shows what did connect.

Each result is recorded with the client's exact version, its mode (interactive or headless), and
any child process the mode spawns. A pass in one mode is no evidence for another mode where the
client has a second transport or a child of its own (Kiro's `acp`, agy's model transport).

For Claude Code, also measure whether the gateway hint headers arrive through the proxy.

- The gateway protocol page says Claude Code sends them by default on a direct connection, and not
  by default under a custom base URL
  (https://code.claude.com/docs/en/llm-gateway-protocol, "Gateway hint headers").
- A launch sets `HTTPS_PROXY`, not `ANTHROPIC_BASE_URL`. Which of the two cases that is has not
  been measured.

A measurement that fails on a protocol rule leaves the agent a tunnel, and the failing rule is
recorded beside the agent's line in the defaults file. "Deliberate exclusions" explains why the
relay does not change.

## Audit line additions

The inspected `allow` line gains fields after the origin address. Each field is `key=value`, the
fields come in this order, and each field is present only when the request supplies it:

- `request=<bytes>` from a declared `Content-Length`, or `request=chunked`.
  - The line prints when the origin leg connects, before the body is relayed
    (`AgentEgressProxy.scala`, the in-tunnel audit context). So a chunked request's total is not on
    this line.
  - A chunked body's end prints `sent <host> <method> <target> request=<bytes>`, with the body
    bytes the relay counted, on every inspected host. The sender picks the framing, so an upload
    that avoids the size field needs only chunking.
  - A chunked body that ends early prints no `sent` line.
- `client=<token>` from the `User-Agent` header's first product token. So a `curl` or a
  `python-requests` on a model host reads as such, beside the agent's own token.
- `credential=<n>`: the index of this request's credential among the distinct credentials the proxy
  has seen since it started, in order of first sight. The index counts the `Authorization` and
  `x-api-key` values together.
  - A second index in a session is a refreshed token or a foreign key. The reader tells the two
    apart by the path and the time.
  - The field is absent when neither header is present.
- Claude Code's hint and identity headers, each under its own name with the `x-claude-code-` prefix
  removed: `session-id`, `prompt-id`, `request-class`, `agent-type`, `agent-id`,
  `parent-agent-id`, `compaction`, `context-compacted`.
  - `prev-tool-durations` is left out: it is up to 4 KB of timing data with no exfiltration signal.

A value is logged as sent when it matches `[A-Za-z0-9._:/-]{1,128}`. Otherwise the field reads
`key=?`. This rule keeps the line's fields unambiguous without a quoting grammar, and bounds the
line.

The fields are client-supplied, except the size: the relay forwards no more body than a declared
`Content-Length`, and counts a chunked body itself.

- An attacker's own client omits or copies the other fields.
- The fields attribute a request to a prompt and a subagent, and name a foreign client that did not
  bother to copy them. The fields prove nothing.

## Implementation sites

- `container/ko-agent-egress-proxy/app/src/main/resources/defaults/model-provider/<name>`: the
  changed lines, each with the measurement's date and the client version beside it.
- `AgentEgressProxy.scala`: the fields on the inspected `allow` line, built from the parsed head
  before the origin leg connects. The credential index is a map from digest to index, owned by the
  proxy instance.
- `RulesetHelper.scala`'s `Upgrade` refusal and the `Refusal` handler in `AgentEgressProxy.scala`:
  a refused `Upgrade` answered `426`, if Codex's measurement adopts it.
- `LogHelper.auditLine`: unchanged, since the fields are part of the tail.
- `EgressRules.scala`: unchanged. The banner's `N inspected, M tunnel` counts follow the ruleset by
  themselves.

## Tests

- `AgentEgressProxyTest`:
  - the fields on the allow line for a request with each header present, absent, and outside the
    character set; no field on a `CONNECT` or a deny line;
  - the credential index for two keys, a refreshed bearer, two concurrent first uses of one key,
    which share an index, and a request without a credential;
  - the `sent` line for a chunked body, and no `sent` line for a `Content-Length` body;
  - if Codex's measurement adopts `426`, a refused `Upgrade` answered `426` with an `Upgrade`
    header, still logged as `deny`.
- `HostileInputTest`: a hint header value with a control character, U+202E, `=`, a space and 4 KB
  of data reads back as `?`, and never splits or reorders a line.
- `EgressSessionTest`: the changed defaults resolve with the model host inspected and the leaf
  naming it. The workspace override with `deny defaults` and a `tunnel` line restores the tunnel.
- The per-agent measurement is a recorded session, not a test. Its log excerpt goes beside the
  defaults line as the evidence.

## Documentation

- `SECURITY.md`:
  - "Not defended", "What is inside TLS": the reason the model hosts stay opaque becomes the reason
    the unmeasured model hosts stay opaque;
  - "The audit line grammar" gains the fields, the `sent` line, and the sentence that the fields
    are client-supplied;
  - "Reading without being able to write": if Codex's measurement adopts `426`, the item
    "`Upgrade` is refused" gains the status.
- `design.md`, "No inspecting every allowed host": the second cost and the revisit condition stop
  tying inspection to brokering, and point here instead.
- `plan-provider-credential-proxy.md`, "Brokered provider traffic": "The proxy never logs bodies
  or headers" becomes "never logs bodies, and of headers only the audit line's allowlist".
- `TODO.md`, "Credential brokering": the "measure first" list moves here, and the Codex item points
  here.
- `egress-proxy.md`, "Choosing an egress profile": the defaults' description of the provider
  rules.
- `README.md`, "Egress proxy": the words "tunnels to supported model providers" are reworded to
  name the inspected hosts and the hosts still tunnelled.

## Acceptance checklist

- [ ] Claude Code's measurement is recorded, and its model host is inspected. A session's log shows
  an `allow` line per model request, with `request=`, `client=`, `credential=` and the hint fields.
- [ ] A `curl` upload to the model host from inside the session shows as a line with
  `client=curl`, its size, and a second credential index.
- [ ] The workspace override restores the tunnel, and the banner says so.
- [ ] Each other agent's model hosts are inspected, or stay tunnels with the failing rule recorded,
  in one commit per agent.
- [ ] The documents above change in the same commit as Claude Code's change.

## Deliberate exclusions

- Refusing paths on a model host, such as a Files API endpoint.
  - Such a refusal is a per-release contract with each CLI, which `design.md` declines
    ("Credential brokering at the egress proxy").
  - A storage behavior added at an allowed endpoint reopens the attack. The `require-placeholder`
    item in `TODO.md` records the rejection.
- Logging a credential value, its prefix or its digest. The index gives a reader the one fact
  needed: that the credential changed.
- Codex's and Copilot's request headers. Neither agent's documentation names a request header
  (Codex's full documentation text and Copilot CLI's pages, read 2026-09-28). Revisit per agent
  with a documented header list.
- Any log field from a body, for any host.
- A relay change for a client that fails the measurement. `design.md` records the one change
  considered ("No WebSocket on an inspected connection").
  - The refused `Upgrade`'s status is an answer, not a relay change, and Codex's entry may change
    it.

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
