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

### The lines that MeasurementReport accepts

`MeasurementReport` reads this block (`doc/agent-measurement.md`, "The measurement suite").
Each `<...>` stands for one segment or part of one; `<org>` is the organization's UUID.

```measurement-report
path api.anthropic.com /v1/messages /v1/messages/count_tokens /v1/mcp_servers /v1/ultrareview/quota
path api.anthropic.com /api/oauth/profile /api/oauth/claude_cli/roles /api/oauth/account/settings
path api.anthropic.com /api/oauth/organizations/<org>/skills/list-skills
path api.anthropic.com /api/oauth/organizations/<org>/skills/<name>/download
path api.anthropic.com /api/oauth/organizations/<org>/plugins/list-plugins
path api.anthropic.com /api/oauth/organizations/<org>/marketplaces
path api.anthropic.com /api/oauth/organizations/<org>/referral/eligibility
path api.anthropic.com /api/oauth/organizations/<org>/quirky-lollipop/link-offer
path api.anthropic.com /api/organization/claude_code_first_token_date
path api.anthropic.com /api/organizations/<org>/model_selector/cc
path api.anthropic.com /api/claude_cli/bootstrap /api/claude_code_grove
path api.anthropic.com /api/claude_code_penguin_mode
path api.anthropic.com /api/frame/contract/latest
path api.anthropic.com /api/claude_code/policy_limits /api/claude_code/settings
path api.anthropic.com /api/claude_code/organizations/metrics_enabled /api/claude_code/metrics
path api.anthropic.com /api/eval/sdk-<key> /api/event_logging/v2/batch /api/artifacts/mcp
path api.anthropic.com /api/hello /api/web/domain_info /api/directory/plugins
path api.anthropic.com /api/directory/server-urls
path api.anthropic.com /mcp-registry/v0/servers /api/ws/speech_to_text/voice_stream
path platform.claude.com /v1/oauth/hello /v1/oauth/token /v1/oauth/token/revoke
path github.com /anthropics/claude-plugins-official.git/info/refs
path github.com /anthropics/claude-plugins-official.git/git-upload-pack
refused mcp-proxy.anthropic.com CONNECT
refused downloads.claude.ai CONNECT
refused http-intake.logs.us5.datadoghq.com CONNECT
error api.anthropic.com client:
error api.anthropic.com relay: client: Broken pipe
```

## References

- https://code.claude.com/docs/en/llm-gateway-protocol — "Response headers" for the streamed
  content type
