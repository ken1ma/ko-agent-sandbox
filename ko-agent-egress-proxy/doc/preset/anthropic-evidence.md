# Evidence for preset/anthropic

[The defaults file](../../app/src/main/resources/defaults/preset/anthropic) inspects
Claude Code's hosts on this evidence.
[`doc/agent-measurement.md`](../../../doc/agent-measurement.md) says how a client is measured,
and how much a report establishes.

## Claude Code

`claude` 2.1.319, the image's version on 2026-11-11, at `api.anthropic.com`. The "Documented" pages
were read on 2026-09-28.

- `/voice` under `--audio=mic` streams the recording over a WebSocket to `api.anthropic.com`, at
  `/api/ws/speech_to_text/voice_stream` (`doc/mic.md`, "Claude Code"). The defaults grant
  `upgrade=websocket` at that path.
- The 2.1.319 binary builds other WebSocket URLs at run time: it holds
  `/v2/session_ingress/mcp/ws/` and several conversions of an `http` URL to `ws`. The
  measurement's session sent no other `Upgrade` to `api.anthropic.com`.
- Documented: `HTTPS_PROXY`; a custom CA through `NODE_EXTRA_CA_CERTS`, which the launcher sets
  (`AgentSandboxLauncher.scala`); `CLAUDE_CODE_CERT_STORE`, which selects the bundled Mozilla set,
  the OS store or both (https://code.claude.com/docs/en/network-config). A streamed response is
  `text/event-stream` (the gateway protocol page, "Response headers").
- The measurement below put `api.anthropic.com` and `platform.claude.com` under inspection by
  default.

## Measured with claude 2.1.319 and 2.1.323 on 2026-11-13

- Modes: an interactive session with tool calls, a subagent, a compaction, WebFetch and `/voice`
  under `--audio=mic`; `claude -p`, as ko-review runs it. 2.1.323 repeated all but the subagent and
  WebFetch, and added `/logout`, a sign-in, and a token refresh forced by moving the token's expiry
  into the past.
- The refusals are of hosts that the defaults file names as absent. The errors: Claude Code reset
  three connections, two before the response head reached it and one mid-upload;
  `relay: client: Broken pipe` as a client exited.
- Requests without a credential: `/api/hello`, `/api/web/domain_info`, `/api/directory/plugins`,
  `/api/directory/server-urls` and `/mcp-registry/v0/servers`; one `/api/event_logging/v2/batch`
  after `/logout`; every request to `platform.claude.com`, whose codes and tokens travel in bodies.
- The WebSocket at `/api/ws/speech_to_text/voice_stream` opens once per recording.
- Every request body declared a `Content-Length`. Within each launch, every request that carried a
  credential showed one index per token: the sign-in's and the refreshed token each as a new index.
- A `/v1/messages` body names the previous response that it continues, and holds only the messages
  after it. The client sends the whole transcript when the server's thread is gone or idle, so a
  request's size is not the conversation's.
- The interactive mode's git child fetches the official plugin marketplace from `github.com`,
  without a credential.

## Measured with claude 2.1.326 on 2026-11-21: credentials bound with `--egress-cred`

Two sessions, each on a new persistent volume, with `--egress-preset=anthropic`.

- Setup, the API key: a Console key bound as `ANTHROPIC_API_KEY@api.anthropic.com:x-api-key`;
  interactive `claude` with the key approved, then `claude -p`; then a second launch on the same
  volume, with a new placeholder.
- Every `/v1/messages` request carried `inject=ANTHROPIC_API_KEY`, so Claude Code sends the key in
  `x-api-key`. The `-p` turn completed; the interactive turn got the account's "Credit balance too
  low".
- In the second launch, interactive `claude` asked to approve the key again, with "No
  (recommended)" preselected. `claude -p` did not ask.
- Requests without a credential: `GET` `/api/hello`, `/api/directory/server-urls` and
  `/api/directory/plugins`, and `POST` `/api/event_logging/v2/batch`. Each `POST` came before the
  launch's first request with the key.
- With the key, Claude Code also requested `/api/claude_code/policy_limits`,
  `/api/claude_code/settings`, `/api/claude_code/organizations/metrics_enabled` and
  `/api/claude_code/metrics`.
- Setup, the setup token: a `claude setup-token` token bound as
  `CLAUDE_CODE_OAUTH_TOKEN@api.anthropic.com`, which binds `Authorization`; `claude -p "say ok"`.
- Claude Code accepted the placeholder of 22 letters and digits, without the token's
  `sk-ant-oat01-` prefix, and the turn completed. Every request that carried a credential,
  `/v1/messages` included, carried `inject=CLAUDE_CODE_OAUTH_TOKEN`.
- The only request without a credential was `GET` `/api/directory/server-urls`; every
  `/api/event_logging/v2/batch` `POST` carried the token.

## Measured with claude 2.1.326 on 2026-11-21: a sign-in and a forced refresh

`/login` with a Claude subscription account on a new persistent volume, then
`claudeAiOauth.expiresAt` set to `0` and `claude -p "say ok"`.

- `~/.claude/.credentials.json` holds `claudeAiOauth` with `accessToken` and `refreshToken`
  (strings), `expiresAt` and `refreshTokenExpiresAt` (numbers), `scopes` (seven strings),
  `subscriptionType`, `subscriptionTypeSource`, `rateLimitTier`, `accountUuid` and
  `organizationUuid`.
- `oauthAccount` in `~/.claude/.claude.json` names the account by `accountUuid`, `emailAddress`
  and `organizationUuid`. Its other fields describe the plan, the profile and the organization.
- The sign-in sent one `POST /v1/oauth/token` to `platform.claude.com`, from `axios/1.15.2` and
  without a credential. The next request carried `cred=1`.
- The `-p` run sent two `POST /v1/oauth/token` requests, at 20:32:09 and 20:32:10 UTC, and each
  was followed by a new index, `cred=2` and then `cred=3`.
  - Four requests after the first refresh still carried `cred=1`. The turn completed under
    `cred=3`.
  - The log does not show which refresh token the second request sent.
- Requests without a credential: at `api.anthropic.com`, `GET` `/api/hello` and
  `/api/directory/server-urls`, and three `POST` `/api/event_logging/v2/batch` before the sign-in
  completed; at `platform.claude.com`, `GET` `/v1/oauth/hello` and each `POST /v1/oauth/token`.

## Measured with claude 2.1.326 on 2026-11-21: a sign-out whose revocation fails

On the sign-in's volume: `/logout` under a workspace line
`deny https://platform.claude.com/ method=POST`, then, without the line, a sign-in and a second
`/logout`.

- The proxy refused `POST /v1/oauth/token/revoke`. Claude Code printed "Logged out on this
  computer, but Anthropic didn't confirm the login was revoked. It may still work until you revoke
  it at https://claude.ai/settings/claude-code".
- At the next launch on the volume, `~/.claude/.credentials.json` did not exist.
- Without the line, the revoke request was allowed: `POST /v1/oauth/token/revoke` from
  `axios/1.15.2`, `content-length=205`, without a credential. Claude Code printed "Successfully
  logged out from your Anthropic account", and the credentials file did not exist afterwards.
- After each `/logout`, one `POST /api/event_logging/v2/batch` went to `api.anthropic.com` without
  a credential.

## Measured with claude 2.1.330 on 2026-11-22: the Console sign-in without a key

On a new volume: `/login`, "Anthropic Console account", "Sign in with your Console account
(recommended)"; then `claude -p "say ok"` after each change to the profile below; then `/logout`,
a sign-in, and `/logout` under a workspace line `deny https://platform.claude.com/ method=POST`.

- The sign-in sent one `POST /v1/oauth/token` to `platform.claude.com`, from `axios/1.15.2`,
  `content-length=325`, without a credential, and no `/api/oauth/claude_cli/create_api_key`. The
  next requests, `/api/oauth/profile` and `/api/oauth/claude_cli/roles` among them, carried
  `cred=1`.
- `~/.config/anthropic/credentials/default.json` holds `version`, `type`, `access_token`,
  `refresh_token`, `scope`, `organization_uuid`, `organization_name`, `account_email`,
  `workspace_id`, `workspace_name` and `created_by` (strings), and `expires_at` (a number).
- With `expires_at` set to `0`, the run sent `POST /v1/oauth/token` to `api.anthropic.com`, not
  `platform.claude.com`, from `claude-cli/2.1.330`, `content-length=208`, without a credential.
  The next requests carried `cred=2`, and the turn completed.
- With `access_token` replaced by 22 random letters and digits, the run's first requests carried a
  new index, `cred=3`. A `POST /v1/oauth/token` to `api.anthropic.com` followed, then `cred=4`,
  and the turn completed.
- With `refresh_token` replaced by 22 random letters and digits and `expires_at` set to `0`, the
  run sent `POST /v1/oauth/token` to `api.anthropic.com`, `content-length=122`. Claude Code
  printed "Login expired · Run /login to sign in again, or re-authenticate your Anthropic
  profile".
- `/logout` sent `POST /v1/oauth/token/revoke` to `platform.claude.com`, from `axios/1.15.2`,
  `content-length=205`, without a credential, and Claude Code printed "Successfully logged out
  from your Anthropic account."
- Under the `deny` line the proxy refused the revoke request, and Claude Code printed the same
  "Successfully logged out from your Anthropic account." Afterwards
  `~/.config/anthropic/credentials/` was empty, and `configs/default.json` remained.
- Requests without a credential: at `api.anthropic.com`, `GET` `/api/hello` and
  `/api/directory/server-urls`, each `POST /v1/oauth/token`, and `POST`
  `/api/event_logging/v2/batch` before the sign-in and after each `/logout`; at
  `platform.claude.com`, `GET` `/v1/oauth/hello` and each `POST`.
- Before the sign-in, `axios/1.15.2` fetched
  `raw.githubusercontent.com` `/anthropics/claude-code/refs/heads/main/CHANGELOG.md`.

## Measured with claude 2.1.330 on 2026-11-22: a refresh replaces the refresh token

On a new volume: `/login` with a Claude subscription account; then four runs of
`claude -p "say ok"`, each after setting `claudeAiOauth.expiresAt` to `0`:

1. about six hours after the sign-in;
2. a few minutes later, after saving the credentials file as A;
3. 17 seconds later, with A put back;
4. 15 seconds later, with the file that the second run left put back.

- Each run sent one `POST /v1/oauth/token` to `platform.claude.com`, from `axios/1.15.2`,
  `content-length=347`, without a credential. The sign-in's had `content-length=325`.
- The first and second runs each changed the SHA-256 hash of `claudeAiOauth.refreshToken`, so each
  refresh returned a new refresh token, and Claude Code stored it. Each turn completed.
- After the first refresh, four requests still carried the old access token, `cred=1`, and the next
  carried `cred=2`.
- The third run's refresh sent the token that the second run had replaced. Claude Code printed
  "Failed to authenticate: OAuth session expired and could not be refreshed".
- The fourth run's refresh was followed by a new index, and the turn completed: the refused reuse
  left the newer refresh token valid.

## Measured with claude 2.1.330 on 2026-11-22: `claude setup-token` and its token

`claude setup-token` in a launch whose volume held a sign-in; then the printed token bound as
`CLAUDE_CODE_OAUTH_TOKEN@api.anthropic.com` and an interactive turn in `claude`.

- `setup-token` printed a `claude.ai` authorize URL and read the code pasted back. It sent one
  `POST /v1/oauth/token` to `platform.claude.com`, from `axios/1.15.2`, `content-length=347`,
  without a credential, and printed a token "valid for 1 year" with the prefix `sk-ant-oat01-`.
  - The 2.1.326 binary sends `/login`'s `authorization_code` exchange to the same token URL, with
    `expires_in` added.
  - The next requests, `/api/oauth/profile`, `/api/claude_code/policy_limits`,
    `/api/claude_code/settings` and `POST /api/eval/sdk-<key>`, carried a new index, `cred=2`. The
    next `/api/event_logging/v2/batch` carried the sign-in's `cred=1`.
- With the token bound, `claude` asked for no approval, and the turn completed. Every request with
  a credential carried `inject=CLAUDE_CODE_OAUTH_TOKEN`, `GET /api/model_selector/cc` included.
- Requests without a credential: `GET /api/directory/server-urls`, and the
  `/api/event_logging/v2/batch` `POST` after the turn.

## Measured with claude 2.1.330 on 2026-11-22: Remote Control

`claude remote-control` in a launch whose volume held a `/login` sign-in, a turn sent from
claude.ai, and a stop; then `claude remote-control` with `CLAUDE_CODE_OAUTH_TOKEN` bound, on a new
volume. `<id>` stands for an environment or a session identifier.

- Under the sign-in, Remote Control connected, and `/v1/messages` requests and worker events
  followed the turn sent from claude.ai. Its requests carried three credentials:
  - the OAuth token, `cred=1`: `POST /v1/environments/bridge`, `POST`
    `/v1/environments/<id>/bridge/reconnect`, `POST /api/oauth/validate`,
    `GET /v1/code/sessions/<id>` and `/v1/messages`;
  - a token that appeared after `/api/oauth/validate`, `cred=2`:
    `GET /v1/environments/<id>/work/poll`, about every 15 seconds, `POST`
    `/v1/environments/<id>/work/<id>/stop` and `POST /v1/environments/bridge/<id>/offline`;
  - a token that appeared after the first poll, `cred=3`: `POST`
    `/v1/environments/<id>/work/<id>/ack` and `/heartbeat`; `GET`, `PUT` and `POST` under
    `/v1/code/sessions/<id>/worker`, including a `GET` event stream that stayed open until the
    stop; `POST /v2/ccr-sessions/<id>/mcp`.
- No request went to `platform.claude.com`, and no request upgraded to a WebSocket. The proxy
  refused `mcp-proxy.anthropic.com`, and Remote Control kept running.
- With the token bound, Claude Code printed "Error: Remote Control requires a full-scope login
  token. Long-lived tokens (from `claude setup-token` or CLAUDE_CODE_OAUTH_TOKEN) are limited to
  inference-only for security reasons." and exited.

### The lines that MeasurementReport accepts

`MeasurementReport` reads this block (`doc/agent-measurement.md`, "The measurement suite").
Each `<...>` stands for one segment or part of one; `<org>` is the organization's UUID, and `<id>`
an environment or a session identifier.

```measurement-report
path api.anthropic.com /v1/messages /v1/messages/count_tokens /v1/mcp_servers /v1/ultrareview/quota
path api.anthropic.com /v1/oauth/token
path api.anthropic.com /api/oauth/profile /api/oauth/claude_cli/roles /api/oauth/account/settings
path api.anthropic.com /api/oauth/organizations/<org>/skills/list-skills
path api.anthropic.com /api/oauth/organizations/<org>/skills/<name>/download
path api.anthropic.com /api/oauth/organizations/<org>/plugins/list-plugins
path api.anthropic.com /api/oauth/organizations/<org>/marketplaces
path api.anthropic.com /api/oauth/organizations/<org>/referral/eligibility
path api.anthropic.com /api/oauth/organizations/<org>/quirky-lollipop/link-offer
path api.anthropic.com /api/organization/claude_code_first_token_date
path api.anthropic.com /api/organizations/<org>/model_selector/cc /api/model_selector/cc
path api.anthropic.com /api/claude_cli/bootstrap /api/claude_code_grove
path api.anthropic.com /api/claude_code_penguin_mode
path api.anthropic.com /api/frame/contract/latest
path api.anthropic.com /api/claude_code/policy_limits /api/claude_code/settings
path api.anthropic.com /api/claude_code/organizations/metrics_enabled /api/claude_code/metrics
path api.anthropic.com /api/eval/sdk-<key> /api/event_logging/v2/batch /api/artifacts/mcp
path api.anthropic.com /api/hello /api/web/domain_info /api/directory/plugins
path api.anthropic.com /api/directory/server-urls
path api.anthropic.com /mcp-registry/v0/servers /api/ws/speech_to_text/voice_stream
path api.anthropic.com /api/oauth/validate /v1/environments/bridge
path api.anthropic.com /v1/environments/<id>/bridge/reconnect /v1/environments/bridge/<id>/offline
path api.anthropic.com /v1/environments/<id>/work/poll /v1/environments/<id>/work/<id>/ack
path api.anthropic.com /v1/environments/<id>/work/<id>/heartbeat
path api.anthropic.com /v1/environments/<id>/work/<id>/stop
path api.anthropic.com /v1/code/sessions/<id> /v1/code/sessions/<id>/worker
path api.anthropic.com /v1/code/sessions/<id>/worker/register
path api.anthropic.com /v1/code/sessions/<id>/worker/heartbeat
path api.anthropic.com /v1/code/sessions/<id>/worker/events
path api.anthropic.com /v1/code/sessions/<id>/worker/events/delivery
path api.anthropic.com /v1/code/sessions/<id>/worker/events/stream
path api.anthropic.com /v1/code/sessions/<id>/worker/internal-events
path api.anthropic.com /v2/ccr-sessions/<id>/mcp
path platform.claude.com /v1/oauth/hello /v1/oauth/token /v1/oauth/token/revoke
path github.com /anthropics/claude-plugins-official.git/info/refs
path github.com /anthropics/claude-plugins-official.git/git-upload-pack
refused mcp-proxy.anthropic.com CONNECT
refused downloads.claude.ai CONNECT
refused http-intake.logs.us5.datadoghq.com CONNECT
error api.anthropic.com client:
error api.anthropic.com relay: client: Broken pipe
error api.anthropic.com relay: client: Connection reset by peer
error github.com relay: client: Connection reset by peer
```

## References

- https://code.claude.com/docs/en/llm-gateway-protocol — "Response headers" for the streamed
  content type
