# Plan: TLS inspection of the agents' model traffic

## Outcome

The default rules inspect an agent's model hosts instead of tunnelling them.

- The audit line's new fields come first, in a commit of their own. They apply to every inspected
  host, so they are tested on the hosts the defaults inspect today, and wait for no agent.
- A new grant word, `upgrade=websocket`, lets one path of an inspected host carry a WebSocket.
  Claude Code's `/voice` needs it on `api.anthropic.com` ("The `upgrade=websocket` grant").
- The defaults then change one agent at a time, each after a measurement shows that the agent's
  client works over an inspected connection.
- The `tunnel` grant stays for the hosts that no measurement has cleared, and for a workspace's own
  rules (`design.md`, "No inspecting every allowed host").

The proxy then logs every model request sent over HTTP with its method, path and size. So the log
shows a call to an endpoint the session should not use, and a request far larger than a
conversation turn. A WebSocket that a line grants shows as its handshake and its byte totals, with
no line for a request inside it.

Default inspection is a decision of its own, not a step of credential brokering. It removes the
per-launch consent that `design.md` records as a cost ("No inspecting every allowed host"):

- The proxy holds the conversation and the provider token of every inspected model request in
  memory, in plaintext, whether or not the launch selects a credential.
- The launch banner gains no line for this. Its `N inspected, M tunnel` counts follow the
  ruleset, and inspecting a host implies the plaintext.
- Returning a host to a tunnel takes a workspace's whole ruleset ("Guarantees", 5). That cost is
  accepted: a client release that fails over inspection leaves the user no lighter way back.

This plan neither substitutes nor refuses a credential. `--egress-cred` substitutes credentials
(`egress-proxy.md`, "Brokered credentials"), and `plan-provider-credential-proxy.md` plans the rest.
On a host this plan inspects, the provider plan's overlay meets an inspected host, which its rules
already cover ("Brokered provider traffic": "An inspected host stays inspected").

The launcher refuses an `--egress-cred` binding at a tunnel host. So a binding at a model host,
such as `OPENAI_API_KEY@api.openai.com`, is accepted from the commit that inspects the host.

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

1. An agent's model and login hosts move from `tunnel` to inspected only after the measurement
   below has passed for one version of the agent's client.
   - The defaults file holds the measurement's record beside the lines ("Measurement").
   - The image installs every agent at its latest release (`Containerfile`), so a build can
     install a client newer than the measured one, and runs that client unmeasured.
   - A client at another version is measured again before its lines record that version. A client
     that fails returns its lines to `tunnel`.
   - `TODO.md` has the two checks for a newer client: CI's repeat of the measurement ("Before the
     first release — continuous integration"), and the note at `--build` ("TLS inspection of the
     agents' model traffic").
2. An inspected model or login host grants `read` and every `method=` word at the root. The
   treatment still fails requests that the tunnel carried, and a client that meets such a failure
   stays a tunnel. "Measurement" says how each failure shows.
   - The defaults grant `upgrade=websocket` at a path, never at a root, and only where a
     measurement shows that a feature, or the client's turn, fails without the WebSocket. A grant
     at the root would let any client move its traffic into streams that the log shows as one
     line each.
3. The fields this plan adds copy no value of a credential header and no body byte. The one
   header value they copy is the start of the `User-Agent`, which is the client's to choose.
   - The audit line prints the request target whole, query included (SECURITY.md, "The audit line
     grammar"). So a host whose client sends its credential in the query stays a tunnel.
4. The proxy keeps no credential value for the credential index. The proxy keeps at most 1024
   digests, in memory, for its lifetime.
5. Under `deny-unless-allowed`, a workspace keeps the opaque treatment through the existing rule:
   `deny defaults` and its own `tunnel` line. `egress-proxy.md` requires that whole-ruleset decision
   for a host the defaults inspect ("The rule file").
   - `deny-unless-model` ignores both lines ("Choosing an egress profile"). Under that profile a
     host this plan inspects has no way back to a tunnel.
6. The leaf certificate names the newly inspected hosts through the launcher's existing reading of
   the resolved ruleset (`EgressRules.inspectedHostsOf`). No second host list exists.

## The agents, in order

The order follows the state of the evidence, best first.

- Each agent's "Documented" pages were read on 2026-09-28. The issues under "Reported" were read
  again on 2026-11-11, and each state is that day's.
- "Measure" is what the change waits for, beyond the list under "Measurement".
- A report establishes a transport that differed in the named release on the named platform. A
  report does not establish the installed client's behavior.
- The version beside each agent is the image's on 2026-11-11.

- `claude` 2.1.319, `api.anthropic.com`.
  - `/voice` under `--audio=mic` streams the recording over a WebSocket to `api.anthropic.com`, at
    `/api/ws/speech_to_text/voice_stream` (`mic.md`, "Claude Code"). The defaults grant
    `upgrade=websocket` at that path.
  - The 2.1.319 binary builds other WebSocket URLs at run time: it holds
    `/v2/session_ingress/mcp/ws/` and several conversions of an `http` URL to `ws`. The
    measurement's session sent no other `Upgrade` to `api.anthropic.com`.
  - Documented: `HTTPS_PROXY`; a custom CA through `NODE_EXTRA_CA_CERTS`, which the launcher sets
    (`AgentSandboxLauncher.scala`); `CLAUDE_CODE_CERT_STORE`, which selects the bundled Mozilla set,
    the OS store or both (https://code.claude.com/docs/en/network-config). A streamed response is
    `text/event-stream` (the gateway protocol page, "Response headers").
  - Measured on 2026-11-13, and inspected by default: `defaults/model-provider/anthropic` holds
    the record. The session had tool calls, a subagent, a compaction, WebFetch, `/voice` under
    `--audio=mic` and a sign-in, and `claude -p` ran as `ko-review` runs the reviewer.
- `codex` 0.169.0, `api.openai.com` and `chatgpt.com`.
  - The defaults give these hosts no `upgrade=websocket` line while the HTTP fallback below
    works: with the line, Codex's model traffic would move into the WebSocket, and the log would
    show one handshake line per connection in place of a line per request. A workspace that
    prefers the WebSocket writes the line itself.
  - Documented: `CODEX_CA_CERTIFICATE`, falling back to `SSL_CERT_FILE`, for login, HTTPS and
    WebSocket alike (https://learn.chatgpt.com/docs/auth, "Custom CA bundles").
  - On `main`:
    - the WebSocket client is built from the HTTP client's custom-CA configuration
      (`codex-rs/websocket-client/src/lib.rs`);
    - one failed WebSocket disables WebSockets for the rest of the session
      (`codex-rs/core/src/client.rs`, `disable_websockets`);
    - the source warns that a client built outside that policy bypasses the policy. So each
      transport is measured rather than inferred from a login.
  - In 0.169.0, `client.rs` switches the session to HTTP when either WebSocket connect is answered
    `426 Upgrade Required`: the turn's prewarm or its stream. It retries after an authorization
    error that the provider can recover from, and returns any other failure as an error. The proxy
    answers a refused `Upgrade` with `403`, except at `chatgpt.com`'s Codex path (`design.md`,
    "WebSocket only at a path that a line names").
  - Reported:
    - 0.147.0 and 0.154.0 on macOS accept the custom CA for HTTP, and reject it for the Responses
      WebSocket with `UnknownIssuer` (openai/codex #46489, open).
    - The WebSocket retries run out before the HTTP fallback (openai/codex #19821, open).
    - 0.155.1 completed both handshakes against a local server (SECURITY.md, "Who holds the CA
      key").
  - Measured on 2026-11-13, and inspected by default: `defaults/model-provider/openai` holds the
    record. The TUI runs on the image's Codex, since the image turns off Codex's app-server daemon
    (`container/ko-agent-sandbox/codex/config.toml`).
  - Codex passes with refused upgrades when the first turn completes over inspected HTTP, and no
    later turn in the same process tries an upgrade again.
    - The number of refusals is recorded, not required. In each new process, `codex exec resume`
      and each subagent included, 0.169.0 sends one to `chatgpt.com`, which answers `426`, and
      seven over about seven seconds to `api.openai.com`, which answers `403`.
    - When retries end the turn, or a later turn tries an upgrade again, the hosts are inspected
      with `upgrade=websocket` at the path of Codex's WebSocket, which the refused upgrades' `deny`
      lines name. Codex is then measured again with that line, and passes on the WebSocket
      condition under "Measurement".
    - That treatment logs more than a tunnel: the handshake's path, client and credential, the
      stream's bytes, and a line for every other request on the host, such as a file upload.
    - `design.md` has why the proxy answers `426` at `chatgpt.com`'s Codex path alone, and
      "Deliberate exclusions" why the defaults set Codex no custom provider.
  - `/voice` is not served (`TODO.md`, "Codex's `/voice`"). That item reads the call's setup on
    `chatgpt.com`, which an inspected host logs by path.
- `copilot` 1.0.107, `api.githubcopilot.com` and the three plan hosts.
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
- `agy` 1.5.3, `cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com`,
  `generativelanguage.googleapis.com`, `businessaicode.googleapis.com` and the `aiplatform` hosts.
  - `aicode.googleapis.com` stays a tunnel: `/voice` streams there over gRPC, which needs HTTP/2
    (`model-provider/google`).
  - Documented: nothing on a proxy or a CA in the 28 CLI pages under
    https://antigravity.google/docs/cli.
  - Reported:
    - 1.0.2 on Windows sent `loadCodeAssist` past `HTTPS_PROXY`
      (google-antigravity/antigravity-cli #181, closed as a duplicate).
    - 1.1.21 on Windows sent `loadCodeAssist` through the proxy, and the model calls,
      `streamGenerateContent`, directly (#875, open).
  - Measure:
    - whether the client trusts the launch CA at all;
    - the HTTP version each host negotiates. The reports show HTTP paths, and the relay refuses
      HTTP/2;
    - where a `GEMINI_API_KEY` session sends the key. A key in the query, `?key=`, leaves
      `generativelanguage.googleapis.com` a tunnel ("Guarantees", 3).
- `kiro-cli` 3.1.0, `runtime.us-east-1.kiro.dev`, `q.us-east-1.amazonaws.com` and
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
  - Measure: interactive and headless mode each; whether the client trusts the launch CA; whether
    each model host's lines have `cred=`. A host whose lines lack the field may receive
    SigV4-signed requests, which the index does not count ("Audit line additions"). A completed
    turn shows that such a request passes the relay unchanged.

The login and token hosts are inspected too, each in its agent's commit, once the measurement
covers the agent's sign-in and a token refresh.
- The log then shows every request to them by path, so a request that no sign-in makes stands out.
- The proxy then holds the sign-in's codes and tokens in plaintext, refresh tokens included, which
  outlive the access tokens it sees on the model hosts.
- `auth.openai.com` is inspected. `claude.ai` and `platform.claude.com` wait for Claude Code's next
  measurement, and the Google and AWS sign-in hosts for their agents'.

## The `upgrade=websocket` grant

```text
allow https://api.anthropic.com/api/ws/speech_to_text/voice_stream upgrade=websocket
```

- The word grants a `GET` that carries `Upgrade: websocket`, at the line's path. It grants no
  other request: a plain `GET` at that path still needs `read`. `websocket` is the only value.
- The proxy forwards the handshake to the origin. It relays bytes both ways only after the origin
  answers `101` with `Upgrade: websocket` and the `Sec-WebSocket-Accept` that RFC 6455 derives
  from the request's key. A `101` without them ends the connection. Any other answer is relayed as
  a response, and the connection ends.
  - The check refuses an endpoint that answers `101` without computing the value. Past such an
    endpoint, a client could send HTTP requests that the proxy neither authorizes nor logs.
  - The check does not prove that the origin speaks WebSocket afterwards: an endpoint that
    reflects a client's headers can return the value, which the client can compute.
  - The request holds one `Upgrade` header whose value is `websocket`, and one
    `Sec-WebSocket-Key`. The proxy refuses a second or a conflicting header of either name, as it
    refuses ambiguous framing.
  - The proxy checks nothing else of the handshake: the origin validates its own.
- When either direction ends, the proxy closes both transports and prints the `websocket-end`
  line once. A tunnel instead half-closes and waits for the other direction, which a WebSocket
  peer may never end.
- The stream has no idle limit, as a tunnel has none: the relay's 300 seconds apply to each
  direction alone, and would end a dictation during which the origin sends nothing. The 300
  seconds still bound the wait for the origin's answer to the handshake.
- The connection still carries one HTTP request. After the `101` the proxy parses nothing, and
  applies no method or path grant to the stream.
- The log shows the handshake's `allow` line with `upgrade=websocket`, and a `websocket-end` line
  with the bytes each way when the stream ends ("Audit line additions"). The stream's content is
  unlogged, as a `POST` body is.
- A workspace's own `upgrade=websocket` line is in the launch's widening report and in
  `--egress-effective`, as a `POST` grant that allows a push is (SECURITY.md, "Adding hosts, not
  patterns").
- The defaults' line names a path of Claude Code's. A release that moves the endpoint ends
  `/voice`, and the log names the refused path.

`design.md`, "WebSocket only at a path that a line names", records this decision. The upgraded
stream is the third treatment that the section describes: opaque after an inspected handshake.

## Measurement

Each agent gets one launch with the agent's model hosts inspected. Its session exercises tool
calls, a subagent where the agent has one, and a compaction or a long turn.

- The launch's workspace rule file holds two lines for each model host. Narrowing a tunnel needs
  no `deny defaults` (SECURITY.md, "Adding hosts, not patterns"):

  ```text
  deny  https://HOST/
  allow https://HOST/ read method=POST,PUT,PATCH,DELETE
  ```

  An agent whose entry names an `upgrade=websocket` line adds that line. For Claude Code:

  ```text
  allow https://api.anthropic.com/api/ws/speech_to_text/voice_stream upgrade=websocket
  ```

- Every launch writes the proxy's log. `--egress-log` prints it after the session.

Read from the log:

- every host the client called, login and refresh included, and every path on an inspected host.
  - The hosts and paths show that the inspected hosts are the complete set, and that nothing moved
    to a host the defaults do not name.
  - A tunnel shows its host alone.
- no `deny` line on a model host, except refusals that an agent's entry above accepts. A `deny`
  line names the rule that the request broke (SECURITY.md, "The audit line grammar").
- no `error` line on a model host. Each of these is a way the client could fail:
  - a connection whose origin sends nothing for 300 seconds ends
    (`InspectedIdleTimeoutMillis`). A non-streaming request whose answer takes longer is the
    case to look for;
  - a server-sent-event stream that the relay truncates shows as a `relay:` line. The stream must
    survive a whole long turn;
  - a client that does not trust the launch CA, or that offers HTTP/2 alone, shows as a handshake
    error, and an origin failure as an `origin:` line.
- whether the client sends a `Content-Length` or a chunked body. The framing decides whether a
  request's size is on its `allow` line or on a `chunked-end` line.
- whether a model request's target holds a credential in its query, and whether the request's
  line has `cred=`.
  - A line without the field, on a request that the provider accepted, means a credential that
    the index does not count: another header, or a signing scheme.
  - The log names neither. The client's documentation or source does, and the index gains a
    header only from that reading.
- a line for each model request sent over HTTP, by its path, beside the completed turn.
  - The sandbox has no route but the proxy, so a transport that ignores `HTTPS_PROXY` fails rather
    than escapes. The log then shows what did connect.
- for a client whose model traffic runs in a granted WebSocket: each stream's handshake line and
  its `websocket-end` line with the byte totals, beside the completed turns. One stream carries
  several requests, and the log has no line for each.

The log misses one failure, which shows as the client's own error. A client that sends a second
request on a connection meets the closed socket, and can lose the end of the first response
(`HTTPHelper.toClientBytes`).

Each result is recorded beside the agent's lines in the defaults file:

- the client's exact version and the date;
- the mode, interactive or headless, and any child process the mode spawns;
- the hosts and paths the client called, and the refusals accepted. The next measurement compares
  its own with these.

The record holds paths, not log lines as printed: a printed line holds the whole target, query
included.

A pass in one mode is no evidence for another mode where the client has a second transport or a
child of its own (Kiro's `acp`, agy's model transport).

A feature that opens a transport of its own is measured as a mode: the agent's `/voice` under
`--audio=mic` (`mic.md`), and a remote-session feature.

A measurement that fails on a protocol rule leaves the agent a tunnel, and the record names the
failing rule. "Deliberate exclusions" explains why the relay does not change.

## The measurement suite

Each new client release needs the measurement again (Guarantees, 1), several times before CI repeats
it (`TODO.md`, "Before the first release — continuous integration"). So a suite runs the parts that
need no person, and a log reader compares the run with the record. Both come after Codex's commit,
and assume that the agents are signed in in the volume the suite names. CI later adds the sign-in.

- The suite runs on the host under `testWithPodman`, since the proxy log is out of a session's
  reach. A test per agent launches a session with the agent's measurement lines, then runs:
  - Claude Code: `claude -p` with a tool call and a subagent;
  - Codex: `codex exec`, `codex exec resume` and a turn that spawns a subagent;
  - for each: a `curl` upload under a foreign key to the model host, whole, and chunked and cut
    short.
- Each test fails when a turn does not complete, or when the reader finds a line that the record
  does not accept. A clean log alone does not show that a turn completed.
- The reader parses one run's proxy log into each host's methods and paths, with identifiers,
  tokens and query values normalized; every `deny` and `error` line, refused upgrades counted;
  the framing; the `cred=` indexes; and the `websocket-end` totals. It reports the paths and
  refusals that the record lacks, and the recorded paths that the run did not call.
- The record becomes a form the reader parses: a fixed list of paths and accepted refusals in each
  `defaults/model-provider/<name>`, beside the lines.
- Interactive turns, a compaction, `/voice` and a sign-in stay manual. The record names each manual
  item with the version it was measured at.

## Audit line additions

The inspected `allow` line gains fields on every inspected host. The fields come before the `->`,
after `inject=` where the line has one. Each field is `key=value` or, for `chunked`, a bare word.
The fields come in this order, and each field is present only when the request supplies it:

- `content-length=<bytes>` from a declared `Content-Length`, or `chunked`.
  - The line prints when the origin leg connects, before the body is relayed
    (`AgentEgressProxy.scala`, the in-tunnel audit context). So a chunked request's total is not on
    this line.
  - The relay forwards no more body than a declared `Content-Length`. So that field is the upper
    bound of what the origin received, and such a request prints no second line.
  - A chunked body prints `chunked-end <host> <method> <target> id=<n> send=<bytes>` when the body
    ends, on every inspected host. The sender picks the framing, so an upload that avoids the size
    field needs only chunking.
  - `<bytes>` counts the body's payload bytes that the relay wrote to the origin, without the
    chunk-size lines, as a `Content-Length` counts. The relay stops writing once the origin
    answers, and still reads the client (`Upload`).
  - A chunked body that ends without its last chunk prints the same line with `incomplete` after
    the count: a client's close, malformed chunking, or an origin that answered or closed early.
    The origin may keep what it received.
- `upgrade=websocket` on a handshake that an `upgrade=websocket` line allowed.
  - The stream's end prints `websocket-end <host> GET <target> id=<n> send=<bytes> recv=<bytes>`,
    with the bytes the relay wrote to the origin and to the client after the `101`.
- `id=<n>` on an `allow` line that a `chunked-end` or `websocket-end` line follows: a chunked
  body's, and a granted handshake's. The line that follows holds the same number.
  - `<n>` counts those requests from 1 in one proxy's log. Two requests to one host, method and
    target can end in either order, and the number says which of those lines belongs to which client
    and credential.
  - An `allow` line that neither line follows has no `id=`.
- `client=<token>`: the start of the `User-Agent` header, as far as its characters are in
  `[A-Za-z0-9._:/-]`, and at most 128 of them. So a `curl` or a `python-requests` on a model host
  reads as such, beside the agent's own token.
  - The field is absent when the header is absent or starts with another character.
  - What follows the token is not logged, and the line does not say that something followed. The
    one rule keeps the line's fields unambiguous without a quoting grammar, and bounds the line.
- `cred=<n>`: the index of this request's credential among the distinct credentials the proxy
  has seen since it started, in order of first sight.
  - The index counts static tokens together, as the client sent them: the values of `x-api-key`
    and `x-goog-api-key`, and an `Authorization` under `Bearer`, `token` or `Basic`, the schemes
    that `CredentialRewrite` substitutes in. So a placeholder of `--egress-cred` counts as one
    credential, and the proxy digests no brokered value.
  - An `Authorization` under any other scheme prints no field. A scheme that signs each request,
    as SigV4 does, sends a different value every time, and would count as a new credential per
    request.
  - A new index on a host that already had one is a refreshed token, another credential the user
    configured, or a foreign key. The index does not tell them apart; the path and the time are
    what a reader has.
  - After 1024 distinct credentials the field reads `cred=?` for a new one.
  - The field is absent when the request holds none of these. A credential in another header or
    in the query is not counted.

`client=` and `cred=` are client-supplied; the relay bounds or counts the sizes itself. An
attacker's own client omits or copies the two fields. They name a foreign client that did not
bother to, and prove nothing.

## Implementation sites

- `ko-agent-egress-proxy/app/src/main/resources/defaults/model-provider/<name>`: the
  changed lines, each agent's with its measurement's record beside them.
  - The `/voice` line lands in Claude Code's commit, with the lines that inspect
    `api.anthropic.com`. Beside the `tunnel` line it would fail every launch (`egress-proxy.md`,
    "The rule file").
- `RequestAudit.scala`: the fields on the inspected `allow` line, the `chunked-end` line, and the
  credential index and the `id=` counter, which each proxy run owns (`AgentEgressProxy.Run`).
- `AgentEgressProxy.scala`: `Upload`'s count of the payload bytes written to the origin.
- The grant:
  - `RulesetHelper.scala`: the word in the grammar, its place in a scope, and the handshake's
    authorization. `Grant.Forms`, `Grant.spelled` and `provenanceLines` list the grant words one
    by one, and each gains the word, or the printed ruleset and `--egress-effective` lose it. The
    widening comparison reads any word, and needs no change;
  - `HTTPHelper.scala`: `toOriginBytes` and `toClientBytes` drop `Upgrade` and `Connection` as
    hop-by-hop headers, and `toClientBytes` appends `Connection: close`. A granted handshake and
    its `101` keep the upgrade headers, through a serializer of their own;
  - `AgentEgressProxy.relayInspected`: the `101` and its `Sec-WebSocket-Accept`, the relay of the
    stream, and its `websocket-end` line. Without a granted handshake a `101` stays an error;
  - `Refusals.scala`: `RefusalAdvice.upgrade` tells the agent to use a plain request. It gains
    the next step for a WebSocket the work needs: the user adds the line for that path;
  - `LaunchMessages.scala`: the "Egress" text of the session's instructions lists what each grant
    word allows, and gains the word;
- `EgressRules.scala`: unchanged. The banner's `N inspected, M tunnel` counts follow the ruleset by
  themselves.
- `LogHelper.auditLine`: unchanged, since the fields are part of the tail.

## Tests

- `AgentEgressProxyTest`:
  - the fields on the allow line for a request with each header present and absent, and with a
    `User-Agent` that leaves the character set after its token; their place beside `inject=`; no
    field on a `CONNECT` or a deny line;
  - the credential index for two keys, a refreshed bearer, two concurrent first uses of one key,
    which share an index, a SigV4 `Authorization`, which prints no field, a placeholder, a request
    without a credential, and the credential after the 1024th;
  - the `chunked-end` line for a chunked body, and none for a `Content-Length` body;
  - one `id=` on a chunked request's `allow` line and its `chunked-end` line, different ids for two
    concurrent requests to one target, and no `id=` on a `Content-Length` request;
  - the `incomplete` line, with the payload bytes written to the origin, for a client that closes
    mid-body, for malformed chunking, and for an origin that answers before the body ends.
- `HostileInputTest`: a `User-Agent` that holds a control character, U+202E, a no-break space, `=`
  or 4 KB of data prints the characters before it, and never splits or reorders a line.
- The grant, in `AgentEgressProxyTest` and `HostileInputTest`:
  - a handshake at the granted path is relayed, and its stream's bytes are on the `websocket-end`
    line that holds the handshake's `id=`;
  - an `Upgrade` at another path, at the granted path under another spelling, with another
    protocol name, or on a `POST` is refused;
  - a `101` without the right `Sec-WebSocket-Accept`, and a `101` to a request that sent no
    `Upgrade`, give no stream;
  - a handshake with two `Upgrade` headers or two `Sec-WebSocket-Key` headers is refused;
  - the stream ends, with one `websocket-end` line, when the client closes, when the origin
    closes, and when one side closes while the other sends nothing;
  - an origin that answers `200` to the handshake gets one response and no second request;
  - a plain `GET` at a path that holds `upgrade=websocket` alone is refused;
  - a workspace's line is in the widening report;
  - a refused `Upgrade`'s `403` names the line to ask the user for.
- `EgressSessionTest`: the changed defaults resolve with the model host inspected and the leaf
  naming it. The workspace override with `deny defaults` and a `tunnel` line restores the tunnel.
- `SessionBoundaryTest`, "the two treatments are told apart": each of `api.anthropic.com` and
  `chatgpt.com` leaves the opaque list in its agent's commit.
- `EgressCredentialsTest`: a binding at a newly inspected model host is accepted, and the refusal
  of `ANTHROPIC_API_KEY@api.anthropic.com` ends in Claude Code's commit.
- The per-agent measurement is a session that a person runs, not a test. "Measurement" says what
  its record holds.

## Documentation

- `SECURITY.md`:
  - "Not defended", "What is inside TLS": the reason the model hosts stay opaque becomes the reason
    the unmeasured model hosts stay opaque, and the proxy's plaintext view of an inspected model
    host is stated there;
  - "Exfiltration through allowed network traffic" and "The web reached through the model
    provider": what the proxy sees of a model host, per treatment;
  - Copilot's and agy's items under "Not defended": the writes that become lines with a path;
  - "The audit line grammar" gains the fields, the `chunked-end` line, and the sentence that the
    fields are client-supplied;
  - "Who holds the CA key": the sentence that Codex meets no leaf of the launch CA;
  - "Reading without being able to write": the grant beside `method=`, and the one-request
    argument for a stream that follows a checked `101`;
  - "Adding hosts, not patterns": the grant among the widenings that a launch reports.
- `design.md`:
  - "No inspecting every allowed host": the consent cost and the revisit condition stop tying
    inspection to brokering, and point here instead;
  - "WebSocket only at a path that a line names": the decision for a WebSocket at a path that a
    line names, with the reasons that still refuse it elsewhere;
  - "Credential brokering at the egress proxy": the model-host bindings that the launcher accepts.
- `plan-provider-credential-proxy.md`:
  - use case 5 and guarantee 12: the consent and the banner apply to a host that is otherwise a
    tunnel, and an inspected model host is read without a selected credential;
  - "Brokered provider traffic": "The proxy never logs bodies or headers" becomes "never logs
    bodies, and of headers only the start of the `User-Agent`";
  - "TLS and clients": the opaque behavior without a selection applies to the hosts still
    tunnelled.
- `egress-proxy.md`:
  - "The rule file": the grant word in the grammar and among what a line grants;
  - "Choosing an egress profile": the defaults' description of the provider rules;
  - "Which credentials fit": the model providers whose hosts are inspected.
- `mic.md`, "Claude Code": the line that `/voice` depends on, in place of the tunnel.
- The comments in `defaults/model-provider/github` that describe the model host as opaque.
- `README.md`, "Egress proxy": the words "tunnels to supported model providers" are reworded to
  name the inspected hosts and the hosts still tunnelled.

## Acceptance checklist

- [x] The fields' commit: a session's log shows `client=` and `cred=` on the `allow` lines
  of a host the defaults inspect today, and `content-length=` on a workspace's `method=POST` line.
  SECURITY.md's "The audit line grammar" and the provider plan's sentence on logged headers change
  in that commit.
- [x] The grant's commit: a WebSocket at a path that a workspace's line names is relayed and
  logged with its bytes, and every other `Upgrade` is refused. `design.md`, SECURITY.md and
  `egress-proxy.md` change in that commit.
- [x] Claude Code's `/voice` works with `api.anthropic.com` inspected, and its handshake and
  `websocket-end` lines are in the log.
- [x] The first agent's measurement is recorded, and its model hosts are inspected. A session's log
  shows an `allow` line per model request sent over HTTP, with the fields.
- [x] A `curl` upload to that model host from inside the session shows as a line with
  `client=curl`, its size, and a second credential index. The same upload, chunked and cut short,
  shows as an `incomplete` line with its size.
- [x] The workspace override restores the tunnel, and the banner's counts say so.
- [ ] The measurement suite runs Claude Code's and Codex's parts that need no person, and its
  reader compares the log with each record.
- [ ] Each other agent's model hosts are inspected, or stay tunnels with the failing rule recorded,
  in one commit per agent.
- [ ] Each document above changes in the commit of the agent it names, and the others in the first
  agent's commit.

## Deliberate exclusions

- Refusing paths on a model host, such as a Files API endpoint.
  - Such a refusal is a per-release contract with each CLI, which `design.md` declines
    ("Credential brokering at the egress proxy").
  - A storage behavior added at an allowed endpoint reopens the attack. The `require-placeholder`
    item in `TODO.md` records the rejection.
- Logging a credential value, its prefix or its digest. The index gives a reader the one fact
  needed: that the credential changed.
- Removing query values from the logged target. The URL is the message that an allowed `GET`
  carries, and the log records it whole for that reason (SECURITY.md, "The audit line grammar").
- A launch option that returns the model hosts to tunnels. A host's treatment is chosen in the
  ruleset alone, where a reviewer of the rule file reads it.
- Claude Code's hint headers as fields (`TODO.md`, "Deferred — Claude Code's hint headers on the
  audit line").
- Codex's and Copilot's request headers. Neither agent's documentation names a request header
  (Codex's full documentation text and Copilot CLI's pages, read 2026-09-28). Revisit per agent
  with a documented header list.
- Any log field from a body, for any host.
- A relay change for a client that fails the measurement, beyond the `upgrade=websocket` grant.
- A custom `[model_providers.NAME]` with `supports_websockets = false` in the image's Codex
  configuration, to keep Codex off its WebSocket. The image would select a provider for every
  user and follow Codex's configuration schema across releases. Codex 0.155.1 refuses an override
  of the built-in provider (`design.md`, "WebSocket only at a path that a line names").
- Any `upgrade=` value but `websocket`. Cleartext HTTP/2 (`h2c`) would turn the one request into
  a stream of requests that the proxy does not read.
- Answering `426` to any refused `Upgrade` but Codex's handshake at `chatgpt.com`. RFC 9110
  requires a `426` to name, in `Upgrade`, a protocol the server would accept, and the relay
  accepts none. `design.md` has the one exception and when it ends.

## References

- https://code.claude.com/docs/en/llm-gateway-protocol — "Response headers" for the streamed
  content type
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
