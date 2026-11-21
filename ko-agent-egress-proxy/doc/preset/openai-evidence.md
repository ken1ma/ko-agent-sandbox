# Evidence for preset/openai

[The defaults file](../../app/src/main/resources/defaults/preset/openai) inspects
the hosts of Codex, and of OpenCode signed in with ChatGPT, on this evidence.
[`doc/agent-measurement.md`](../../../doc/agent-measurement.md) says how a client is measured,
and how much a report establishes.

## Codex

`codex` 0.169.0, the image's version on 2026-11-11, at `api.openai.com` and `chatgpt.com`. The
"Documented" pages were read on 2026-09-28, and the issues under "Reported" on 2026-11-11, with each
state as of that day.

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
  answers a refused `Upgrade` with `403`, except at `chatgpt.com`'s Codex path (`doc/design.md`,
  "WebSocket only at a path that a line names").
- Reported:
  - 0.147.0 and 0.154.0 on macOS accept the custom CA for HTTP, and reject it for the Responses
    WebSocket with `UnknownIssuer` (openai/codex #46489, open).
  - The WebSocket retries run out before the HTTP fallback (openai/codex #19821, open).
  - 0.155.1 completed both handshakes against a local server (SECURITY.md, "Who holds the CA
    key").
- The measurement below put the hosts under inspection by default. The TUI runs on the image's
  Codex, since the image turns off Codex's app-server daemon
  (`container/ko-agent-sandbox/codex/config.toml`).
- Codex passes with refused upgrades when the first turn completes over inspected HTTP, and no
  later turn in the same process tries an upgrade again.
  - The number of refusals is recorded, not required.
  - When retries end the turn, or a later turn tries an upgrade again, the hosts are inspected
    with `upgrade=websocket` at the path of Codex's WebSocket, which the refused upgrades' `deny`
    lines name. Codex is then measured again with that line, and passes on the WebSocket
    condition under `doc/agent-measurement.md`, "Measurement".
  - That treatment logs more than a tunnel: the handshake's path, client and credential, the
    stream's bytes, and a line for every other request on the host, such as a file upload.
  - `doc/design.md` has why the proxy answers `426` at `chatgpt.com`'s Codex path alone, and
    why the defaults set Codex no custom provider.
- `/voice` is not served (`doc/TODO.md`, "Codex's `/voice`"). That item reads the call's setup on
  `chatgpt.com`, which an inspected host logs by path.

## Measured with codex 0.169.0 on 2026-11-13

- Modes: the interactive TUI, with two turns and two compactions; `codex exec` with tool calls,
  `codex exec resume` and a turn that spawns a subagent. Signed in with ChatGPT, and `codex exec`
  also with an API key. `codex logout`, `codex login --device-auth`, and a token refresh that a
  rejected access token forced.
- Under an API key, `codex exec` also fetches `/backend-api/codex/models` from `chatgpt.com`,
  sending the same key.
- The device code login polls `/api/accounts/deviceauth/token` about every five seconds until the
  user approves. `auth.openai.com`'s codes and tokens travel in bodies, so its lines carry no
  `cred=`.
- Every request body declared a `Content-Length`. Every request to `chatgpt.com` and
  `api.openai.com` carried a credential, one index per key or token: the refreshed token shows as a
  new index.
- The error: `relay: client: Broken pipe` on `/backend-api/codex/responses`, as a `codex exec`
  process exited after its turn completed.
- The refusals:
  - the WebSocket upgrade at `/backend-api/codex/responses`, answered 426: each new `codex exec`
    process, `codex exec resume` and each subagent included, tries once and falls back to HTTPS for
    its turns. The TUI was measured while the proxy answered 403, when it tried 14 times before its
    first turn and never again;
  - the WebSocket upgrade at `/v1/responses`, answered 403: each new process tries 7 times over
    about 7 seconds before the same fallback (`doc/design.md`, "WebSocket only at a path that a line
    names");
  - `ab.chatgpt.com`, which the defaults file names as absent;
  - `sdmntpr<region>.oaiusercontent.com`, five CONNECTs at each `codex exec` start under a ChatGPT
    sign-in.
- Other hosts: `raw.githubusercontent.com`, the TUI's `/openai/codex/main/announcement_tip.toml`.
- On 2026-11-14, `codex exec` as ko-review's reviewer sent `/backend-api/codex/alpha/search` three
  times. Codex's standalone web search posts each `web.run` operation there with the conversation's
  tail: the previous user message, up to 1,000 tokens of assistant text after it, and the current
  one (rust-v0.169.0, `codex-rs/codex-api/src/endpoint/search.rs` and
  `codex-rs/ext/web-search/src/history.rs`).

## Measured with codex 0.169.0 on 2026-11-21: `CODEX_API_KEY` bound with `--egress-cred`

An API key bound as `CODEX_API_KEY@api.openai.com`, which binds `Authorization`, with
`--egress-preset=openai` and a new persistent volume; `codex exec --skip-git-repo-check "say ok"`.

- `POST /v1/responses` carried `inject=CODEX_API_KEY`, and the turn completed.
- The four `GET /backend-api/codex/models` requests to `chatgpt.com` carried the placeholder
  unsubstituted, with the same `cred=1` as `/v1/responses`. `chatgpt.com` answered each with 401,
  "Could not parse your authentication token", and Codex logged a failed model refresh.
- Seven refused WebSocket upgrades at `/v1/responses` over about six seconds preceded the HTTPS
  fallback; `ab.chatgpt.com` was refused.
- `git` fetched `github.com/openai/plugins.git` twice, without a credential.

## Measured with codex 0.169.0 on 2026-11-21: a sign-in, a forced refresh and a sign-out

On a new persistent volume with `--egress-preset=openai`.

- `codex login --device-auth` sent `POST /api/accounts/deviceauth/usercode`, polled
  `/api/accounts/deviceauth/token` about every five seconds until approval, then sent one
  `POST /oauth/token`. None of these lines named a client or carried `cred=`.
- `~/.codex/auth.json` holds `auth_mode`, `last_refresh`, and `tokens` with `id_token`,
  `access_token`, `refresh_token`, `oauth_provenance.issuer`, `oauth_provenance.client_id`,
  `login_owner_id` and `account_id`, all strings.
- The ID token's claims name the account by `sub`, `email` and, under
  `https://api.openai.com/auth`, `user_id`, `chatgpt_account_id` and `chatgpt_user_id`. That
  object also holds `groups`, `organizations` (each with `id`, `title`, `role`, and
  `is_default` on one), `chatgpt_plan_type` and the subscription's dates. The other claims are
  `name`, `email_verified`, `auth_provider`, `amr`, `iss`, `aud`, `auth_time`, `rat`, `sid`, `iat`,
  `exp`, `jti` and `at_hash`.
- With `tokens.access_token` set to `invalid`, `codex exec` sent requests to `chatgpt.com` with
  that value as `cred=1`, and `/backend-api/codex/models` answered 401. Then one
  `POST /oauth/token` from `codex_exec/0.169.0`, and the turn completed under `cred=2`.
  - Five requests after the refresh still carried `cred=1`.
  - Codex also logged two MCP transport errors in that run, `HTTP 451: no_biscuit_no_service`.
- A copy of the sign-in under another `CODEX_HOME`, with the ID token's signature replaced by
  `c2lnbmF0dXJl`, completed a turn without a refresh. So did a copy whose ID token also had the
  empty payload `e30`. The volume's own login worked afterwards.
- With a workspace line `deny https://auth.openai.com/ method=POST`, the proxy refused
  `POST /oauth/revoke`. `codex logout` printed "Successfully logged out", and `~/.codex/auth.json`
  no longer existed.

### The lines that MeasurementReport accepts for Codex

`MeasurementReport` reads this block (`doc/agent-measurement.md`, "The measurement suite").
Each `<...>` stands for one label of a host name.

```measurement-report
path chatgpt.com /backend-api/codex/responses /backend-api/codex/models
path chatgpt.com /backend-api/codex/analytics-events/events
path chatgpt.com /backend-api/wham/accounts/check /backend-api/wham/usage
path chatgpt.com /backend-api/wham/security-setup
path chatgpt.com /backend-api/wham/rate-limit-reset-credits /backend-api/wham/settings/user
path chatgpt.com /backend-api/ps/plugins/installed /backend-api/ps/plugins/suggested/codex
path chatgpt.com /backend-api/ps/plugins/list /backend-api/ps/mcp /backend-api/ps/apps/batch
path chatgpt.com /backend-api/codex/alpha/search
path api.openai.com /v1/responses
path auth.openai.com /oauth/revoke /api/accounts/deviceauth/usercode
path auth.openai.com /api/accounts/deviceauth/token /oauth/token
path github.com /openai/plugins.git/info/refs /openai/plugins.git/git-upload-pack
refused chatgpt.com GET /backend-api/codex/responses
refused api.openai.com GET /v1/responses
refused ab.chatgpt.com CONNECT
refused sdmntpr<region>.oaiusercontent.com CONNECT
error chatgpt.com relay: client: Broken pipe
```

## OpenCode

`opencode` 1.19.5, the image's version on 2026-11-14. OpenCode has no preset: a launch names
the presets of the providers that OpenCode connects, and those presets' lines carry its traffic.
The "Documented" page was read on 2026-09-28.

- Documented: `HTTPS_PROXY`, `NO_PROXY`, and a custom CA through `NODE_EXTRA_CA_CERTS`, which
  the launcher sets (https://opencode.ai/docs/network/).
- The measurement below covers the ChatGPT sign-in. The GitHub Copilot sign-in passed, but no turn
  ran: [`github-evidence.md`](github-evidence.md) records why.
- Still to measure: a Copilot turn, which waits for an account whose answer marks a model, and
  the Anthropic and Google API keys, which wait for keys. OpenCode's Google provider posts to
  `generativelanguage.googleapis.com`, which the defaults refuse (README, `opencode`).

## Measured with opencode 1.19.5 on 2026-11-14

Signed in with "ChatGPT Pro/Plus (headless)", on `openai/gpt-6-astra`, under
`deny-unless-allowed`.

- Modes: `opencode run` with a shell call and a subagent that makes its own shell call;
  `opencode run --session` with a shell call; the TUI in this repository, with two turns,
  `/compact` and a message; the sign-in; a turn after a token refresh, forced by moving
  `openai.expires` in `~/.local/share/opencode/auth.json` into the past; the TUI with a turn under
  `deny-unless-selected`.
- Every request went to a path that Codex's `path` lines list, as `opencode/1.19.5`: model calls to
  `/backend-api/codex/responses`, and the sign-in and the refresh to `auth.openai.com`. OpenCode
  tried no WebSocket.
- Every body declared a `Content-Length`. Every request to `chatgpt.com` carried a credential; the
  refreshed token shows as a new index.
- The TUI asks `registry.npmjs.org` for opencode's latest version at each start, and one of its
  connections sends no byte before closing.
- At its first start in the volume, opencode installed `@opencode-ai/plugin`, pinned to its own
  version, into `~/.config/opencode` with its own npm, and the install completed. The defaults'
  read-only line for the registry refused npm's audit, and one connection ended in the handshake.
- Under `deny-unless-selected`, opencode was refused at each start at its model catalog's host and at
  the registry, and the turn completed.
- One `opencode run`, started after the stored expiry moved, sent nothing after its catalog read
  from `models.opencode.ai`, and hung until killed after five minutes. The next run refreshed the
  token and completed.

### The lines that MeasurementReport accepts for OpenCode

In order: the TUI's version check, npm's audit and handshake, and the refusals under
`deny-unless-selected`.

```measurement-report
error registry.npmjs.org tunnel: expected 5 bytes, got 0
refused registry.npmjs.org POST /-/npm/v1/security/advisories/bulk
error registry.npmjs.org tunnel: Remote host terminated the handshake
refused models.opencode.ai CONNECT
refused registry.npmjs.org CONNECT
```

## References

- openai/codex `codex-rs/http-client/src/custom_ca.rs`, `codex-rs/websocket-client/src/lib.rs`,
  `codex-rs/core/src/client.rs` — custom CA shared by HTTP and WebSocket; the session-wide
  fallback and the `426` that starts it at once
- openai/codex #46489, #19821 — the WebSocket rejecting the custom CA a release's HTTP accepted;
  the retries before the HTTP fallback
