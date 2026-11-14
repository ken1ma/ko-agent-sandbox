# Agent measurement

The defaults inspect each agent's model and login hosts once a measurement shows that the agent's
client works over an inspected connection. `design.md` records the decision and its costs ("Model
hosts inspected by default"). This document says how to measure a client release, and what each
agent's measurement covers.

## Rules

1. A model or login host moves from `tunnel` to inspected only after the measurement below has
   passed for one version of the agent's client.
   - The defaults file holds the measurement's record beside the lines ("Measurement").
   - The image installs every agent at its latest release (`Containerfile`), so a build can
     install a client newer than the measured one, and runs that client unmeasured.
   - A client at another version is measured again before its lines record that version. A client
     that fails returns its lines to `tunnel`.
   - `TODO.md` has the two checks for a newer client: CI's repeat of the measurement ("Before the
     first release — continuous integration"), and the note at `--build` ("TLS inspection of the
     agents' model traffic").
2. An inspected model or login host grants `read` and every `method=` word at the root. The
   treatment still fails requests that a tunnel carries, and a client that meets such a failure
   stays a tunnel. "Measurement" says how each failure shows.
   - The defaults grant `upgrade=websocket` at a path, never at a root, and only where a
     measurement shows that a feature, or the client's turn, fails without the WebSocket.
     `design.md` has the reason ("WebSocket only at a path that a line names").
3. A host whose client sends its credential in the query stays a tunnel: the audit line prints the
   request target whole (`design.md`, "Model hosts inspected by default").

## The measurement suite

Each new client release needs the measurement again ("Rules"), several times before CI repeats
it (`TODO.md`, "Before the first release — continuous integration"). So a driver runs the parts
that need no person, and a reader compares a run's log with the records. Both assume that the
agents are signed in in the session's persistent volume. CI later adds the sign-in.

For a release:

1. In a session, from the repository root, run the driver. Each mode prints its UTC start and end,
   and the driver exits 1 when a mode does not complete.

   ```sh
   scala $KO_AGENT_SANDBOX_JAVA_OPTS run --workspace ~/.cache/measure-agents \
       src/test/measurement/MeasureAgents.scala -- [claude] [codex] [agy] [kiro-cli] [copilot] \
       [opencode]
   ```

   - Claude Code: `claude -p` with a Bash call and a subagent that makes its own Bash call.
   - Codex: `codex exec` and `codex exec resume`, each with a shell command, and a turn whose
     subagent answers.
   - agy: `agy -p` with a shell call and a subagent that makes its own, and `agy --conversation -p`
     with a shell call. The subagent's calls are read from its transcript, which the stream names.
   - Kiro: `kiro-cli chat --v3 --no-interactive` with a shell call and a subagent that makes its
     own, and `--resume-id` with a shell call.
   - Copilot: `copilot -p` with a shell call and a subagent that makes its own, a resumed turn
     with a shell call, and a read through the built-in GitHub MCP server.
   - OpenCode: `opencode run` on the ChatGPT sign-in with a shell call and a subagent that makes
     its own, and `--session` with a shell call. The subagent's calls are read from its session,
     which `opencode export` prints.
   - For each: a `curl` upload under a foreign key to the model host, whole, and chunked and cut
     short. OpenCode's goes to `chatgpt.com`, which Codex's upload to `api.openai.com` misses.
   - A mode completes only when each of its calls succeeded and `curl` held the cut upload open
     until the cut (`AgentEvents.scala`, held to recorded events by `AgentEventsTest`). After a
     failed mode, the driver keeps the turns' event files and prints their directory.
1. Do the manual items that the driver lists: interactive turns, a compaction, `/voice`, a
   sign-out and sign-in, and a token refresh.
1. On the host, run `sbt "Test/runMain agentsandbox.launcher.MeasurementReport"`. It reads the
   workspace's latest run, or the `proxy.log` it is given, and exits 1 when a line matches no
   record. It writes the report to `log/measurement-report.log`, where the session's agent reads it.

The reader (`MeasurementReport.scala`):

- It lists each recorded host's methods and paths with their counts, `cred=` indexes and framing,
  and the recorded paths that the run did not call. A record with no `path` line is unmeasured.
- It counts the requests to every other host by method, such as an unmeasured record's hosts.
- A finding is a path on a recorded host that no record naming the host lists, or a `deny` or
  `error` line that no record accepts.
  - A record names the hosts of its `allow` and `path` lines. A host can belong to two records:
    agy reads a repository on `github.com`, where the `github` record has Copilot's sign-in.
  - A `refused` line accepts a refusal without naming its host. OpenCode is refused at
    `registry.npmjs.org`, where the packages that a session installs stay unjudged.
- `curl`'s requests and `ko-sandbox-egress-check`'s `HEAD` are probes. The report lists each probe
  with its framing, credential index and body end, and never judges them. A refusal of the check's
  `CONNECT` names no client, so it stays a finding.
- The records hold the reader's lines among their comments: `path <host> </path>...`,
  `refused <host> <method> [</path>]` and `error <host> <reason prefix>`. A `<name>` stands for one
  segment, part of one, or one label of a host.

`sbt "testWithPodman *AgentMeasurementTest"` runs the driver and the reader per agent:

- It launches this workspace, not a scratch one, so the session has the workspace's volume and the
  sign-ins there. `--persistent-volume` refuses the generated volume names.
- A test skips when its agent is not signed in in that volume. It fails on a turn that did not
  complete, on a finding, or when a probe's whole or cut upload is missing from the log.
- The turns run on the signed-in accounts.
- Each test writes the driver's output and the report to `log/measurement-report-<agent>.log`.

## Measurement

Each agent gets one launch with the agent's model hosts inspected. Its session exercises tool
calls, a subagent where the agent has one, and a compaction or a long turn.

- A host that the defaults do not name gets this line in the launch's workspace rule file. A host
  that the defaults inspect needs none.

  ```text
  allow https://HOST/ read method=POST,PUT,PATCH,DELETE
  ```

  An agent whose entry names an `upgrade=websocket` line adds that line too.

- Every launch writes the proxy's log. `--egress-log` prints it after the session.

Read from the log:

- every host the client called, login and refresh included, and every path on an inspected host.
  - The hosts and paths show that the inspected hosts are the complete set, and that nothing moved
    to a host the defaults do not name.
  - A tunnel shows its host alone.
- no `deny` line on a model host, except refusals that the agent's record accepts. A `deny`
  line names the rule that the request broke (SECURITY.md, "The audit line grammar").
- no `error` line on a model host. Each of these is a way the client could fail:
  - a connection whose origin sends nothing for 300 seconds ends
    (`InspectedIdleTimeoutMillis`). A non-streaming request whose answer takes longer is the
    case to look for;
  - a server-sent-event stream that the origin's side cuts shows as a `relay:` line without
    `client:`. The stream must survive a whole long turn;
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
child of its own (agy's model transport, Kiro's `acp`).

A feature that opens a transport of its own is measured as a mode: the agent's `/voice` under
`--audio=mic` (`mic.md`), and a remote-session feature.

A measurement that fails on a protocol rule leaves the agent a tunnel, and the record names the
failing rule. `design.md` says why the relay does not change ("Model hosts inspected by default").

## The agents, in order

The agents are measured in the README's order.

- Each agent's "Documented" pages were read on 2026-09-28. The issues under "Reported" were read
  again on 2026-11-11, and each state is that day's.
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
  - Measured on 2026-11-13 with 2.1.319 and 2.1.323, and inspected by default with
    `platform.claude.com`: `defaults/model-provider/anthropic` holds the record. The sessions had
    tool calls, a subagent, a compaction, WebFetch, `/voice` under `--audio=mic`, `/logout`, a
    sign-in and a token refresh, and `claude -p` ran as `ko-review` runs the reviewer.
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
      why the defaults set Codex no custom provider.
  - `/voice` is not served (`TODO.md`, "Codex's `/voice`"). That item reads the call's setup on
    `chatgpt.com`, which an inspected host logs by path.
- `agy` 1.5.3, `cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com`,
  `generativelanguage.googleapis.com`, and the `businessaicode` and `aiplatform` hosts.
  - `aicode.googleapis.com` has no line: `/voice` streams there over gRPC, which needs HTTP/2, so a
    workspace adds the host as a tunnel (`model-provider/google`; `TODO.md`, "Deferred — an HTTP/2
    relay for gRPC hosts"). Without the host, agy falls back for its flags, and its turns complete.
  - Documented: nothing on a proxy or a CA in the 28 CLI pages under
    https://antigravity.google/docs/cli.
  - Reported:
    - 1.0.2 on Windows sent `loadCodeAssist` past `HTTPS_PROXY`
      (google-antigravity/antigravity-cli #181, closed as a duplicate).
    - 1.1.21 on Windows sent `loadCodeAssist` through the proxy, and the model calls,
      `streamGenerateContent`, directly (#875, open).
  - Measured on 2026-11-14 with 1.5.8 under a consumer sign-in, and inspected by default with
    `cloudcode-pa.googleapis.com` and `oauth2.googleapis.com`: `defaults/model-provider/google`
    holds the record. The client trusted the launch CA, and every request went over HTTP/1.1.
    - Every model call went to `daily-cloudcode-pa.googleapis.com`, as `POST /v1internal:<method>`;
      `streamGenerateContent` sends a chunked body.
    - The TUI, with a compaction, a sign-out and a sign-in, passed. The sign-in sent
      `accounts.google.com` nothing, so the defaults have no line for that host.
    - In a repository, the TUI sends `github.com` a `HEAD` of the repository's path. Under
      `deny-unless-model` the proxy refuses it, and the turn completes.
  - The API-key and Business modes' hosts have no line, and a workspace adds them as tunnels
    (`model-provider/google`). Still to measure: the GCP-licensed accounts on `cloudcode-pa`, the
    Business sign-in, which waits for such an account, and where a `GEMINI_API_KEY` session sends
    the key, which waits for a key. A key in the query, `?key=`, keeps
    `generativelanguage.googleapis.com` out of inspection ("Rules").
- `kiro-cli` 3.1.0, `runtime.us-east-1.kiro.dev` and `management.us-east-1.kiro.dev`, each also
  in `eu-central-1`.
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
  - Measured on 2026-11-14 with 3.3.0 under a Google sign-in, and inspected by default with the
    sign-in hosts: `defaults/model-provider/aws` holds the record.
    - Every mode ran the V3 engine, in a Node child that kept the proxy and CA variables. Every
      client trusted the launch CA, and every request went over HTTP/1.1.
    - Every request to `runtime` and `management` carried `cred=`: a bearer token, not a SigV4
      signature.
    - V3's model calls are `POST /v1/responses` on `runtime`. Its other calls are `POST /`, which
      names its operation in a header, so their lines do not tell the operations apart.
    - Under `deny-unless-model`, which admits the provider file alone, a TUI turn completed.
    - The device-flow sign-in, a logout and a refresh at the token's expiry passed on the inspected
      sign-in host. A refresh forced before the expiry is answered `401`, and kiro-cli signs out.
  - The V2 engine, kiro-cli's own `acp` child, sends its model calls to
    `q.us-east-1.amazonaws.com`, and its turns completed under inspection. Kiro removes V2 in
    January, so `q` has no line, and a workspace that runs V2 adds it (README, `kiro-cli`).
  - Still to measure: `eu-central-1`, and the Builder ID, Identity Center and GitHub sign-ins.
- `copilot` 1.0.111, `api.githubcopilot.com` and the three plan hosts.
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
  - Measured on 2026-11-14 with 1.0.111 on an individual plan, and inspected by default:
    `defaults/model-provider/github` holds the record. The client trusted the launch CA, and every
    request went over HTTP/1.1 with `COPILOT_ENABLE_HTTP2` unset.
    - The model path is `POST /responses` on `api.individual.githubcopilot.com`, and the GitHub MCP
      server is `POST /mcp/readonly` there.
    - Copilot tries a WebSocket at `/responses` once per turn, and sends the turn over HTTP after
      the `403`. The defaults give it no `upgrade=websocket` line, for Codex's reason above.
    - Every request carried the same credential index on the plan host and on `api.github.com`. No
      mode called `/copilot_internal/v2/token`.
  - The interactive TUI, with a compaction and `/login`, passed. `/logout` fails in the sandbox
    before any request: the client deletes the token through the Secret Service, which the
    container lacks.
  - Under `deny-unless-model`, every message failed when the provider file granted only the
    token exchange on `api.github.com`. So the file grants the three `/copilot_internal/` reads
    that the client makes at every start, and a turn then completed. The TUI's repository reads
    stay refused under that profile.
  - Still to measure: session sync, which waits for an account whose organization allows it, and
    the business and enterprise hosts, which wait for an account on those plans.
- `opencode` 1.19.5, the image's on 2026-11-14. OpenCode has no provider file: a launch names the
  providers that OpenCode connects, and those providers' lines carry its traffic.
  - Documented: `HTTPS_PROXY`, `NO_PROXY`, and a custom CA through `NODE_EXTRA_CA_CERTS`, which
    the launcher sets (https://opencode.ai/docs/network/).
  - Measured on 2026-11-14 under a ChatGPT sign-in: `defaults/model-provider/openai` holds the
    record beside Codex's. Every request went to a path that Codex's record lists, and OpenCode
    tried no WebSocket.
    - The headless sign-in, the TUI with a compaction, and a token refresh forced by an earlier
      stored expiry passed. Under `deny-unless-model`, a TUI turn completed.
  - GitHub Copilot: the device sign-in passed, but no turn ran. OpenCode lists only the models that
    Copilot's `/models` marks for its model picker, and the account's answer marked none
    (`defaults/model-provider/github`).
  - Still to measure: a Copilot turn, which waits for an account whose answer marks a model, and
    the Anthropic and Google API keys, which wait for keys. OpenCode's Google provider posts to
    `generativelanguage.googleapis.com`, which the defaults refuse (README, `opencode`).

A login or token host is inspected once the measurement covers the agent's sign-in and a token
refresh.
- The log then shows every request to them by path, so a request that no sign-in makes stands out.
- The proxy then holds the sign-in's codes and tokens in plaintext, refresh tokens included, which
  outlive the access tokens it sees on the model hosts.
- `auth.openai.com`, `platform.claude.com`, `oauth2.googleapis.com` and Kiro's
  `prod.us-east-1.auth.desktop.kiro.dev` are inspected. `claude.ai` and `accounts.google.com` are
  absent, since Claude Code and agy send them no request (`defaults/model-provider/anthropic` and
  `google`). `cognito-identity.us-east-1.amazonaws.com` is absent too: Kiro's Google sign-in sent
  it nothing, and Kiro's turns complete with the host refused (`defaults/model-provider/aws`).
- `oidc.us-east-1.amazonaws.com`, for Kiro's Builder ID and Identity Center sign-ins, is inspected
  unmeasured, on the evidence of kiro-cli's AWS SDK at `management.us-east-1.kiro.dev`.

## References

- https://code.claude.com/docs/en/llm-gateway-protocol — "Response headers" for the streamed
  content type
- openai/codex `codex-rs/http-client/src/custom_ca.rs`, `codex-rs/websocket-client/src/lib.rs`,
  `codex-rs/core/src/client.rs` — custom CA shared by HTTP and WebSocket; the session-wide
  fallback and the `426` that starts it at once
- openai/codex #46489, #19821 — the WebSocket rejecting the custom CA a release's HTTP accepted;
  the retries before the HTTP fallback
- google-antigravity/antigravity-cli #181, #875 — request paths that ignored `HTTPS_PROXY` in
  released versions
- kirodotdev/Kiro #9608, #9860 — a child process without the proxy variables; a harness that
  failed behind a TLS-inspecting proxy
- github/copilot-cli `changelog.md`; #454, #4408 — proxy, CA and mTLS entries by version; a
  model path and the built-in MCP server's path on a plan host
- https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/
- https://www.promptarmor.com/resources/claude-cowork-exfiltrates-files
