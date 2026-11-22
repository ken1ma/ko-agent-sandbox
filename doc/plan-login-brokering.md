# Plan: brokering the agents' own logins

## Outcome

An agent signs in inside the sandbox as it does today, but the persistent volume holds placeholders
instead of the tokens that the catalog declares. The proxy rewrites the tokens in each sign-in and
refresh response to the volume's placeholders, and puts the real token back at the declared API
hosts and in the refresh request. The real tokens live in a store on the host side, one per
persistent volume.

- Today any process in the session reads an agent's refresh token from the persistent volume
  (SECURITY.md, "Agents' own provider logins").
- With a brokered login, the session's own credential is the volume's placeholder. So the refusal
  of `plan-preset-credential-proxy.md` covers a signed-in session too, not only a static token.

This plan reverses `design.md`, "Credential brokering at the egress proxy", "Brokering the agents'
own logins". That section is rewritten when this plan is accepted.

## Why the earlier reasons no longer hold

- "The proxy would mirror that lifecycle per release": the client keeps its own sign-in, expiry and
  refresh. The proxy follows each release's token endpoint paths and token field names, as the
  presets already follow each release's hosts (`agent-measurement.md`). A moved endpoint fails
  closed, within the limits that "The rewrite" states.
- "A host-side OAuth flow needs a public-client registration": the client signs in and refreshes
  under its own client identity, and the proxy only rewrites what passes.
- "Hiding the model token does not pay": the refusal needs the session's own token, which only a
  brokered login gives a signed-in session.
- "Storing a credential on the host across runs" ("Left out"): the tokens already outlive the run,
  in a volume that the sandbox reads. The store moves them where the sandbox cannot read them. One
  placeholder per token kind keeps the store to one entry set per login, with no generations of
  placeholders to track (One placeholder per token kind); the store still needs the cleanup and the
  lock that "The store" describes.

## Prior art

- nono passes the client's requests and rewrites the token responses, with a random placeholder per
  captured token (`docs/cli/features/sandboxed-oauth-logins.mdx`).
  - Its store is a file that keeps tokens for 90 days, capped at 4096 placeholders.
  - Concurrent sessions break each other: a proxy loads the store once and writes its whole map
    without a lock (nolabs-ai/nono #2087, #2299; the fix, #2088, was open on 2026-11-21).
- Docker Sandboxes answers the token endpoint itself and refreshes on the host. The sandbox sees
  fixed sentinels such as `sk-ant-oat01-proxy-managed`, in a credentials file that the host renders
  (docker/sandbox-kit-spec, `credential@1.md`, `oauth`).
- Lens sandbox-core answers token and refresh requests with placeholders, and matches no
  `client_id`, since a public client sends one id for every user (lensapp/lens-sandbox-core #63).
- OpenShell's gateway alone refreshes, and requires a new sign-in after "an uncertain
  rotating-token exchange"
  (https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview.md).
  - A long-running process failed after a refresh, because its placeholder named the expired token
    (ai-openshell/openshell #2777). The fix gives each workload "an opaque, identity-stable handle
    whose resolver value advances to the current token" (#2780).
- Codex's app-server takes tokens from its client (`auth_mode` `chatgptAuthTokens`): the client
  holds the refresh token, and Codex asks it for fresh tokens (`ChatgptAuthTokensRefresh`,
  `codex-rs/app-server/src/external_auth.rs`). Not chosen:
  - the sandbox then holds a real access token until it expires;
  - the launcher would refresh under Codex's client identity;
  - the mode is experimental and serves app-server clients alone, not the TUI or `codex exec`
    (https://learn.chatgpt.com/docs/app-server.md, "Log in with externally managed ChatGPT
    tokens").

## The rewrite

nono's way, not Docker's: the proxy never builds a token request or writes a credentials file.
Answering the endpoint would make the proxy build each client's refresh request (client id, scope,
body format), render its credentials file, and call the endpoint under the agent's client identity,
all per release.

A closed catalog entry in the proxy image names, per agent login:

- the token endpoints, each an exact host and path, as the measurements list them: Claude Code's
  `platform.claude.com` `/v1/oauth/token`, and `api.anthropic.com` `/v1/oauth/token`, where its
  Console sign-in refreshes; Codex's `auth.openai.com` `/oauth/token` (`anthropic-evidence.md`,
  `openai-evidence.md`). Codex's device poll, `/api/accounts/deviceauth/token`, is no token
  endpoint: it answers with an authorization code that `/oauth/token` then exchanges
  (`codex-rs/login/src/device_code_auth.rs`, `CodeSuccessResp`);
- the paths that the check below reads: every path on the login hosts, `platform.claude.com` and
  `auth.openai.com`, and the paths under `/v1/oauth/` on `api.anthropic.com`, which streams model
  responses at its other paths;
- the revoke endpoints: those that the measured sign-outs called, Claude Code's
  `platform.claude.com` `/v1/oauth/token/revoke` and Codex's `auth.openai.com` `/oauth/revoke`;
  and `api.anthropic.com` `/v1/oauth/token/revoke`, where `ant auth logout` revokes the profile's
  refresh token and then its access token (anthropic-cli `pkg/cmd/cmd_auth_revoke.go`);
- the client's OAuth client IDs, which a public client sends in each token request's body. The
  proxy brokers only token requests that carry one: a refresh token is bound to the client that it
  was issued to (RFC 6749, section 6), so another client's grant must not share the login's
  placeholders. Another client's sign-in passes unbrokered, and its real tokens are refused as
  foreign once a login is approved there.
  - Claude Code's entry names two: its `CLIENT_ID`, which its subscription sign-in sends, and the
    Anthropic profile client, which its Console sign-in sends and writes into the profile
    (2.1.326's binary). `ant auth login` uses the profile client too (anthropic-cli
    `pkg/cmd/cmd_auth.go`, `oauthClientIDProd`), so the proxy brokers it as the Console sign-in
    (below).
  - The `client_id` selects the catalog rule and proves nothing: a client identifier is no secret
    (RFC 6749, section 2.2). The account binding and its approval establish trust.
  - A revoke request needs none: Codex revokes an access token without one
    (`codex-rs/login/src/auth/revoke.rs`, `RevokeTokenKind`). The proxy recognizes a revoke by its
    declared endpoint; a current placeholder in its token field decides whether the proxy resolves
    it and retires the login ("The store");
- the response fields that carry tokens, and the request fields where the client sends a token
  back, to refresh or to revoke it;
- the API hosts where the access placeholder resolves, in the places that
  `plan-preset-credential-proxy.md`'s catalog declares. A host outside the entry gets the
  placeholder unresolved, so a feature that sends the token there fails until a measurement adds
  the host (Open questions);
- the routes on an API host that answer with a new credential, which the proxy refuses before it
  forwards them. Claude Code's legacy Console sign-in, "Create an API key", sends `POST`
  `api.anthropic.com` `/api/oauth/claude_cli/create_api_key` with the access token, and stores the
  response's `raw_key`, a real API key; a subscription sign-in, whose token has the
  `user:inference` scope, skips it (2.1.326's binary).
  - That legacy sign-in then fails with "Unable to create API key". The recommended "Sign in with
    your Console account" creates no key (https://code.claude.com/docs/en/authentication, "Sign in
    without an API key").
  - The route is refused at every credential: Claude Code's authorize request asks for the
    `org:create_api_key` scope beside the claude.ai scopes, so a subscription token may carry it.
  - Codex's workspace switch sends `POST` `/backend-api/accounts/switch-workspace-token` at
    `chatgpt.com` with the access token, and saves the real `access_token` of the other workspace
    that the response carries (`codex-rs/login/src/auth/manager/workspace_switching.rs`,
    `exchange_workspace_token`). `/backend-api` is the path of Codex's production ChatGPT base URL
    (`codex-rs/agent-identity/src/lib.rs`). The entry refuses it: another workspace is another
    account, which the launcher action and a sign-in bring in.
  - Claude Code's Remote Control registers with `POST` `api.anthropic.com`
    `/v1/environments/bridge` under the access token, and reads `environment_secret` from the
    response, the credential of its later polls (2.1.326's binary, `anthropic-evidence.md`). The
    entry refuses it until the proxy captures that secret (Open questions), so Remote Control fails
    at its start.
  - A route that creates a credential and that the catalog does not list returns it unrewritten,
    as a response that echoes a credential does (SECURITY.md).

Claude Code's keyless Console sign-in belongs to Claude Code's login, as its subscription sign-in
does: a volume holds one login per client ("Which account the store accepts"). Claude Code keeps
the Console sign-in as an Anthropic profile, whose `credentials/<profile>.json` holds
`access_token`, `expires_at` and `refresh_token`
(https://platform.claude.com/docs/en/manage-claude/wif-reference, "Configuration directory"), and
refreshes it itself. The image links `~/.config/anthropic`, the profiles' directory, into the
persistent volume (`Containerfile`). Its sign-in and revoke go to `platform.claude.com`, and its
refresh to `api.anthropic.com` (`anthropic-evidence.md`); step 3's first run confirms the fields of
its token responses.

An `ant auth login` in the sandbox is the same login to the proxy, as it is to Claude Code: it
exchanges its code with the profile client at `api.anthropic.com` `/v1/oauth/token` (anthropic-cli
`exchangeCode`), and Claude Code takes a profile of that client as its own sign-in and refuses a
profile of any other (2.1.326's binary). `ant` sends that exchange form-encoded and Claude Code
JSON, so step 3's first run records each request's body format.

The proxy:

- reads each response at the catalog's checked paths whole, with any status, before it stores or
  forwards any part of it. They cover every path on the login hosts, since the presets grant
  `POST` at the roots of `platform.claude.com` and `auth.openai.com`:
  - the body is at most 64 KiB, enforced while the proxy reads a declared length, a chunked body
    or a body that the connection's close ends; a longer one is refused before any byte reaches
    the client. Open: the bound, until step 3's rewrite logs the largest response at each checked
    path that the measurements list, since the bound applies to every one of them;
  - the proxy asks for the body uncompressed (`Accept-Encoding: identity`) and refuses a compressed
    one, so that it reads what the client would;
- refuses the whole response when it holds a field named like a token (`access_token`,
  `refresh_token`, `id_token` or another `*_token`) that the entry does not declare for that path,
  a declared field beside it included. nono checks its capture hosts' unmatched paths and error
  responses for such fields (`docs/cli/features/sandboxed-oauth-logins.mdx`, "token_endpoints");
  - the check fails closed for a moved endpoint, an error response and a new token field, but not
    for a token under a name it does not recognize;
  - nor for a token response that a release moves out of `/v1/oauth/` on `api.anthropic.com`. A
    refresh moved there still fails, since the proxy resolves the refresh placeholder only at a
    token endpoint. A sign-in's exchange moved there brings real tokens into the volume until a
    measurement lists its path;
- refuses a response with an error status that holds any token field, declared or not, and stores
  nothing from it, so a failed exchange never replaces a working credential;
- otherwise, for a successful (`2xx`) response, replaces each declared token in a token endpoint's
  response with the volume's placeholder for that field, after it stores the real token. A
  refresh reaches the provider only with the volume's refresh placeholder, so a login binds only
  at a sign-in ("Which account the store accepts");
- puts the real refresh token in place of its placeholder in a token request, and the real access
  token in place of its placeholder at the API hosts.

A login host that a workspace made a tunnel gets no brokering, as a tunnel host gets no
substitution (`plan-preset-credential-proxy.md`, "Selection"). So while brokering is on for a
login on the volume, the proxy refuses a tunnel to that login's login host or an API host, and the
refusal names the rule and the launcher action below. A tunnel at the login host would let a
sign-in's real tokens into the volume, and one at an API host would pass foreign credentials beside
the refusal, as the preset plan refuses a tunnel at an entry's host.

- A launcher action turns brokering off for a login on the volume, and drops its binding and its
  login; only then may a proxy open a tunnel to those hosts. This keeps the way back that
  `design.md`, "Model hosts inspected by default", leaves for a client release that fails under
  inspection.
- The setting lives in the store, so it follows the store's volume, and every launch on the volume
  reads the same one whatever its launcher's state root. A new store starts with brokering on. A
  proxy whose store exists but cannot be read refuses to start, names the store, and leaves it for
  recovery, since it could enforce neither the setting nor the approvals.
- Each proxy holds a shared lock on a presence file in the store for its whole run, reads the
  setting under it at its start, and keeps the setting for its run. A proxy brokers nothing for a
  login whose brokering is off.
- The action takes the presence lock exclusively without waiting, and is refused, in either
  direction, while any proxy on the volume holds it, a paused launch's included. So the setting
  never changes under a proxy; a proxy that starts during the action waits for it and reads the
  new setting. The kernel releases a dead proxy's lock.
  - Every path takes the presence lock before the store's lock, so the two cannot deadlock.
  - Turning brokering off drops the login and its binding and records the setting in one write.
- Each launch creates the persistent volume before its proxy starts, with `podman volume create
  --ignore`, and passes the volume's creation time to the proxy; a new store records it. So the
  first launch has a time to record, and concurrent first launches share one volume and one time.
  - `--ignore` covers only podman's first lookup: a create that loses the race still fails with
    "already exists" (podman 6.1.4, `libpod/runtime_volume_common.go`, `newVolume`). On that error
    the launch inspects the volume by name and takes its time; any other failure ends the launch.
  Today the volume can appear after the proxy has started: the BPF backend's launch script creates
  it under the launch lock, after the start prompt (`KoAgentBpf.launchScript`), and on native Linux
  podman creates it with the sandbox's container.
- The proxy reports the volume creation time that its store records. After the sandbox's container
  is created, which holds the volume from then on, the launch compares that time with the
  volume's, and refuses on a mismatch before the container starts: a volume removed and created
  again during the start prompt would otherwise meet the old store's setting.
- The banner shows the setting from the launcher's saved reports, as it shows bindings, so a launch
  that tunnels such a host learns of the refusal when its proxy starts, before the sandbox's
  container starts. Tunnels at those hosts serve a client release that fails under inspection, so
  this is rare.
- Either change takes a sign-in. Off leaves the client's credentials holding placeholders that
  resolve nothing; on refuses the client's refresh of its real tokens ("Which account the store
  accepts").

Where a host of the catalog's token or revoke endpoints refuses other credentials, the sign-in,
refresh and revoke requests that it receives, which carry their codes and tokens in bodies with no
credential header, are among the writes that its entry lists as sent without one, such as Claude
Code's Console refresh and `ant`'s sign-in and revoke at `api.anthropic.com`
(`plan-preset-credential-proxy.md`, "Refusing another credential").

## One placeholder per token kind

Each volume's store holds, per login, one placeholder per token kind (access, refresh and, for
Codex, the ID token) and the current real token behind each. This is Docker's fixed sentinel,
scoped to the volume, and OpenShell's stable handle.

- A refresh replaces the real tokens behind the same placeholders, so the client's credentials file
  keeps the placeholders it has. Codex's JWT placeholders, below, keep their signature part, while
  their claims follow the refresh.
- No proxy meets a placeholder that another launch generated and it cannot resolve, which is
  nono's #2087.
- A client that refreshes with a stale file still sends the one refresh placeholder, which resolves
  to the current real refresh token.
- A refresh response lost after the store holds the new tokens costs nothing: the client keeps the
  placeholders that the store already maps to them. "The store" says what a proxy that dies before
  that write costs.
- The store holds one entry set per login, so it needs no expiry or cap; it ends with its volume.
- The placeholder is random per volume, not a constant like Docker's, for the reason that
  `egress-proxy.md` ("Where the value goes") gives for per-launch randomness: a string written
  before the volume existed equals it only by chance.
- The placeholder keeps the client's format, such as `sk-ant-oat01-`: pi chooses the header by that
  prefix (nolabs-ai/nono #1486).
- Codex compares the whole `auth.json` before it refreshes, so unchanged placeholders with a new
  `last_refresh` read as a change (`codex-rs/login/src/auth/manager.rs`,
  `auths_equal_for_refresh`).
- Codex's access token placeholder is built as its ID token placeholder is, below, since Codex
  reads the access token's claims: `exp` for its refresh before expiry, the account-user id and the
  workspace check (`codex-rs/login/src/auth/manager.rs`, `proactive_refresh_reason`,
  `get_chatgpt_account_user_id`; `manager/workspace_switching.rs`). Codex decodes the claims
  without checking the signature (`codex-rs/login/src/token_data.rs`, `decode_jwt_payload`).
  - Any access placeholder with the volume's signature part resolves to the current real access
    token, so a client that kept an older one is not stranded.
  - An opaque placeholder would cost a 401 at each expiry and break the workspace check.
- Codex's ID token placeholder keeps the current real token's header and claims, and puts the
  volume's random placeholder in the signature's place. So the claims follow each refresh, and the
  real signature never reaches the sandbox.
  - Codex parses the token locally, reads claims such as the plan type from a refreshed one, and
    its device sign-in checks the account claim against a workspace restriction before it stores
    the token (`codex-rs/login/src/token_data.rs`, `device_code_auth.rs`).
  - `codex exec` 0.169.0 and the TUI 0.171.0 completed turns with a stored ID token whose
    signature was replaced, and with one whose claims were empty, without a refresh
    (`openai-evidence.md`). With the claims empty, the TUI's `/status` showed the account as
    "Unknown" and no plan.
  - The proxy resolves the ID token placeholder nowhere. Codex sends the raw ID token in two places
    alone: the token exchange below, which the entry refuses, and its sign-in's local success page
    URL, which never passes the proxy (`codex-rs/login/src/success_page.rs`,
    `compose_success_url`).
- Codex's browser sign-in also sends the ID token back, as `subject_token` in a token exchange at
  `/oauth/token`, and receives an API key in `access_token`, the field that carries the access
  token in the same path's other responses (`codex-rs/login/src/server.rs`, `obtain_api_key`).
  - The proxy refuses that exchange before forwarding it. Captured by path and field, the key
    would replace the real access token behind the access placeholder.
  - The proxy tells the exchange by its body: the token-exchange `grant_type` with
    `requested_token=openai-api-key`. The sign-in and the refresh send `grant_type`
    `authorization_code` and `refresh_token` to the same path
    (`codex-rs/login/src/oauth/client.rs`).
  - Codex completes the sign-in without a key when the exchange fails (`obtain_api_key(...).ok()`),
    and the measured device sign-in stores none: `auth.json` held `auth_mode`, `last_refresh` and
    `tokens` alone (`openai-evidence.md`).
- Claude Code's `claude setup-token` sends the sign-in's `authorization_code` exchange to
  `platform.claude.com` `/v1/oauth/token`, and prints the one-year token from the response
  (`anthropic-evidence.md`).
  - The proxy refuses that exchange before forwarding it, and the refusal says to run
    `claude setup-token` outside the sandbox. Captured by path and field, the token would become
    the volume's login, and `setup-token` would print the placeholder in its place.
  - The proxy tells the exchange by its body: `setup-token` adds `expires_in`, which `/login`'s
    exchange does not send (the 2.1.326 binary).

## Which account the store accepts

A sign-in inside the sandbox could bring an attacker's account: a process could exchange an
authorization code that the attacker obtained for their own account, and the provider answers with
real tokens. Captured blindly, that account would stand behind the volume's placeholder, and the
refusal would pass uploads to it.

- The store binds a login to the account of the first sign-in that it captures in the volume.
  The banner names that account at every launch and whether the user approved it, or says that
  the login is unbound.
- The proxy binds under the store's exclusive lock, comparing and writing in one step, so of two
  launches that sign in at once to different accounts, one binds and the other's response is
  refused.
- A refresh keeps the placeholders. A token response for another account is refused, and nothing
  is stored. The refusal names the bound account and the launcher action below, so a user whose
  own sign-in meets another account's binding learns why and what to do.
- While brokering is on, the proxy refuses a token request that sends back a token other than the
  volume's placeholder, such as a real refresh token, bound or not. So a login from before the
  binding, or from before brokering, brings no real token into the volume: its next refresh fails,
  and the refusal says to sign in again, which brokers the login. A real access token works until
  it expires.
- Each entry declares the field that names the account in its sign-in responses. The proxy
  refuses a sign-in response without it, since it can neither bind nor compare that response.
- On the host, a launcher action drops the volume's binding and login: to change the account, to
  switch between Claude Code's subscription and Console sign-ins, to refuse a pending binding, or
  to sign out when the agent's own sign-out sent no revoke request. The next sign-in then binds
  anew and gets new placeholders.
- The binding holds a user, an organization, a workspace where the token is scoped to one, and
  the granted scopes, each where the credential has it; a change in any of them is another
  account. Claude Code keeps `accountUuid` and `organizationUuid` under `claudeAiOauth` in its
  credentials file; Codex's ID token names `sub` and `chatgpt_account_id` (`anthropic-evidence.md`,
  `openai-evidence.md`). Step 3's rewrite confirms the fields in the token responses.
  - The proxy compares scopes as sets, read where the entry declares that its sign-in responses
    carry them, such as a response field or a claim of a token in the response. A sign-in
    response without them is refused: the proxy never sees the authorize request that a missing
    field would repeat (RFC 6749, section 5.1).
  - A login whose entry can name no such place is not brokered until a measurement finds one, so
    that two grants of different authority never look alike to the store.
  - A refresh response without scopes keeps those that the refresh request named, or the bound
    ones when it named none (RFC 6749, section 6).
  - The scopes are part of it because a placeholder must not gain authority. Two Anthropic
    profiles of one user and organization can differ in workspace and scopes, such as a profile
    with `org:admin` (https://platform.claude.com/docs/en/cli-sdks-libraries/cli/authentication,
    "Admin access"). Claude Code reads the scopes from its token response (2.1.326's binary).
  - Profiles with the same identity share the login's placeholders, since they carry the same
    authority. A volume thus holds one identity per client. Claude Code's subscription and Console
    sign-ins differ in scopes, so a switch between them is another account; Claude Code's keyless
    sign-in itself signs out of the claude.ai login
    (https://code.claude.com/docs/en/authentication, "Sign in without an API key").
  - The prompt shows the whole identity, scopes included, with the email address and the
    organization's and workspace's names; the banner shows the email address and the names.
    Claude Code keeps `oauthAccount.emailAddress` and organization fields in
    `~/.claude/.claude.json`, and Codex's ID token has an `email` claim and each organization's
    `title`. Step 3 confirms where each token response carries them.
- A binding waits for the user's approval. The next launch under `--session-start=pause` names
  the pending account at its start prompt, and the user approves the binding or drops it with the
  login.
  - A launch that reads no answer leaves the binding pending, and its banner names the launcher
    action that approves it: under `immediate`, and under `pause` without a terminal, where the
    launch starts without a prompt, as for every consent that the start prompt carries
    (`AgentSandboxLauncher.startPrompt`).
  - Until the approval the login is brokered, but the refusal is off, as on an unbound volume.
  - An attacker who signs in first can write the placeholders it receives into the client's
    credentials file. The client then works under the attacker's account, and a binding that
    took effect at once would make the refusal protect that account.
  - The launcher records the approval in the store, and every proxy on the volume applies the
    refusal from then on.
  - The answer, an approval or a drop, names the binding that the prompt showed, by its identity
    and the binding's generation, which each new binding advances. The proxy compares both with
    the store's under the exclusive lock, and requires the binding to be still pending; it refuses
    a mismatch. So a prompt that showed a dropped binding approves no successor, and a second
    prompt for the same binding drops no login that the first approved.
  - Refusing writes until the approval is not chosen: every model call is a `POST`.

## The store

- One store per persistent volume, so that every launch whose agents share one credentials file
  shares the store. Two launches in one workspace share its volume, and so do a linked worktree
  that reuses its main worktree's volume and the workspaces that name one `--persistent-volume`.
- The sandbox cannot read the store. Removing the volume, `--reset` included, removes its store, so
  a removed login stops working (docker/sbx-releases #492).
  - A user can remove a named volume with `podman volume rm`, which the launcher never sees. So the
    store records its volume's creation time, and a launch discards a store whose volume is gone
    or was created again under the same name.
  - `--reset` and `--reset-all` remove the store of each volume they remove, and of each volume
    that is gone. A user-named volume, which both leave in place (README, "--persistent-volume"),
    keeps its store, so its login keeps working.
- The store keeps its lock on a file that it never replaces, and writes each change to a new file
  that it syncs and renames over the old one, then syncs the directory. So a proxy that dies
  mid-write, or a podman machine that stops, leaves the old state or the new one whole, and every
  proxy locks the same file.
- A proxy holds the store's lock exclusively from reading the real refresh token until it writes
  the new tokens. So refreshes serialize, and each one resolves the refresh placeholder to the
  newest real token.
  - One client can refresh twice in quick succession: one `claude -p` run of 2.1.326 sent two
    token requests a second apart, each followed by a new token (`anthropic-evidence.md`).
- A request that resolves a placeholder takes the lock shared, so it waits only while a refresh
  runs, and then gets the new token.
- Every refusal decision at a refusing host reads the bindings and their approvals under the
  shared lock, so an approval applies to the next request in every proxy, and no proxy decides
  from a copy it read earlier.
  - An approval governs later requests and WebSocket handshakes. A WebSocket opened before it runs
    on, since the proxy relays an upgraded stream without further decisions
    (`AgentEgressProxy.scala`).
- A revoke and the answer at the start prompt take the lock exclusively too, so an in-flight
  refresh cannot bring a retired login back: a refresh that holds the lock finishes before the
  retire, and one that starts after it finds no login. A launcher action meets no refresh: it runs
  only while no proxy holds the presence lock.
- The proxy bounds a refresh's exchange in time, since every request that resolves a placeholder
  waits for the lock meanwhile. It treats a timed-out exchange as one whose outcome it does not
  know, as for a proxy that dies (below).
- The lock cannot make the provider's rotation and the store's write one step. A proxy that dies
  after the provider answers and before the store holds the new tokens leaves the old refresh token
  in the store.
  - The next refresh sends the old token. Codex's refresh returns a new pair, and its provider
    accepts the old refresh token "on the order of an hour", by an OpenAI engineer's account
    (openai/codex #10332), so the login continues when the next refresh comes within that time.
  - Claude Code's provider refused a subscription login's old refresh token 17 seconds after the
    refresh (`anthropic-evidence.md`), so a refresh that late ends that login, and the agent signs
    in again. A sooner reuse, and the Console sign-in's, were not measured.
  - The proxy retries no exchange whose outcome it does not know, as OpenShell does. An exchange
    that never reached the provider leaves the old refresh token valid.
- A revoke request retires the login's tokens and placeholders once the proxy has resolved the
  request's placeholder, whatever the provider answers, so those placeholders authenticate nothing
  afterwards.
  - A revoke request whose token matches no current placeholder is forwarded unchanged and
    changes nothing in the store. It carries either a retired placeholder, such as
    `ant auth logout`'s second request, for the access token, after the first retired the login,
    which RFC 7009 has the provider answer with success (section 2.2), or a real token from
    before brokering, which the provider revokes.
  - A sign-in between `ant`'s two revoke requests gets new placeholders, so the second never
    reaches it. If that sign-in wrote the same profile, `ant` then deletes the file
    (anthropic-cli `authLogout`), and the client signs in again; the new login's store entries
    stay.
  - The volume keeps its bound account and its refusal: a later sign-in to the same account gets
    new placeholders, and one to another account is refused until the host-side action drops the
    binding ("Which account the store accepts").
  - Both clients delete their local credentials when the revoke request fails, so the store
    follows the request, not the answer: claude 2.1.326 warns that the login may still work, and
    codex 0.169.0 reports a successful logout (`anthropic-evidence.md`, `openai-evidence.md`).
  - A sign-out that sends no request leaves the login in the store until the next sign-in
    replaces it, the launcher action drops it, or the volume goes. claude 2.1.326's `/logout`
    called the revoke endpoint; a user reported in March 2026 that `claude logout` revoked
    nothing (anthropics/claude-code #34198).
  - A revoke request that a workspace rule refuses is such a sign-out: the client deletes its
    credentials all the same.
- Neither client serializes refreshes across sandboxes, so the store's lock does:
  - Claude Code takes a lock directory, `$CLAUDE_CONFIG_DIR.lock`, before it refreshes (nono's
    `docs/cli/clients/claude.mdx`). The image sets `CLAUDE_CONFIG_DIR` to `~/.claude`, a link into
    the persistent volume (`Containerfile`), so the lock is `~/.claude.lock`, in each container's
    own home.
  - Codex reloads `auth.json` before it refreshes and skips the refresh when the file changed. It
    saves under a file lock with a compare-and-save, and reloads after a 401. It holds no lock
    across the refresh request (`codex-rs/login/src/auth/manager.rs`, `refresh_token_with_reason`,
    `persist_tokens`).
- The store is a podman named volume per persistent volume, mounted into proxy containers alone.
  Step 2 measures its lock.
  - The launcher learns a binding from its proxy, which reports each binding during the run and
    the store's bindings at its start, so a binding whose proxy died before reporting it still
    reaches a later prompt. The launcher saves them, and each launch shows a saved pending binding
    right before its prompt, as it prints the BPF reconcile's saved notes: the proxy starts beside
    the prompt, so the prompt cannot wait for it (`design.md`, "What may move across the start
    prompt").
  - The launcher passes the answer to its launch's proxy, which writes it to the store. A launcher
    action runs while no proxy holds the store's presence lock, so no proxy is there: the
    launcher runs a short-lived container of the proxy image that mounts the store, takes the
    locks, writes the change and exits.
  - Every proxy then locks a file on one kernel: the podman machine's on macOS and Windows, the
    host's on Linux.
  - The store takes its name from its persistent volume, and a shared volume keeps its store.
  - The launcher reserves the stores' names: it refuses a `--persistent-volume` in their pattern,
    as it refuses one in the generated volumes' pattern (`LauncherState.sharedVolumeNameRefusal`).
    It creates each store with a label. It mounts no volume at a store's name that lacks the label,
    and `--reset` and `--reset-all` remove no such volume, so a volume that a user made there is
    neither adopted nor deleted.
  - At rest it is a plaintext file in podman's storage, where the persistent volume keeps the real
    tokens today; the sandbox only loses its read.
- Not chosen:
  - a file under the state root, mounted as the leaf key is: on macOS and Windows its lock would
    cross the podman machine's file sharing, the state root is per workspace rather than per
    volume, and host backups can copy it;
  - memory alone, in a store process per volume: every reboot would end every login;
  - the host's keychain: each refresh would cross from the proxy container to the launcher on the
    host, and Linux has no keychain that every host offers (`TODO.md`, "The brokered login store
    off disk").
- Run-on-host proxies get no store: the programs that run on the host (`sbt`, `mill`, `gradle`,
  `mvn`) need no agent's login.

## Selection and the refusal

- Brokering is on by default for every login that the catalog names. A problem found in delivery
  reopens this. Codex's login is on by default once the Codex TUI passes the production-image
  check (Verification).
- At each refusing host, the refusal accepts one set: the placeholders of the launch's preset
  entries and `--egress-cred` bindings there (`plan-preset-credential-proxy.md`, "Refusing another
  credential"), and the access placeholder of each approved login on the volume there. It applies
  once the set holds a preset entry or an approved login, signed out or not; until then the host
  keeps today's behavior.
  - Every value in the set is one that the user selected at launch or approved, so a foreign key
    stays refused. A pending login's placeholder, which may be an attacker's, is refused where the
    refusal applies; the refusal says to approve the login at the next launch, or with the launcher
    action under `immediate`.
  - Each refusal decision reads the approvals under the store's shared lock ("The store"), so an
    approval applies to the next request in every proxy. From then on the proxy refuses requests
    carrying an `--env` key at that host, which the launch's note says.
- A volume whose client already holds real tokens stays unbound until the client's next sign-in,
  which its refused refresh asks for ("Which account the store accepts"). The banner says the
  login is unbound.
  - Binding at a refresh is not chosen: it would rest on a refresh response that names the
    account, and the forced sign-in brokers the login at the first refresh as well.
  - Importing the tokens at launch is not chosen: the launcher would read and write each client's
    credentials file, which "The rewrite" leaves to the client.

## Open questions

- How Claude Code's Remote Control passes the refusal at `api.anthropic.com`. It needs a `/login`
  sign-in (https://code.claude.com/docs/en/remote-control). Under one, 2.1.330 sent two credentials
  besides the OAuth token, which the refusal refuses as foreign (`anthropic-evidence.md`):
  - an environment token, at `/v1/environments/<id>/work/poll`,
    `/v1/environments/<id>/work/<id>/stop` and `/v1/environments/bridge/<id>/offline`;
  - a session token, at `/v1/environments/<id>/work/<id>/ack` and `/heartbeat`, under
    `/v1/code/sessions/<id>/worker`, and at `/v2/ccr-sessions/<id>/mcp`;
  - the registration's response carries the environment token (2.1.326's binary), and the
    catalog refuses the registration meanwhile. The log shows no body, so which response issues
    the session token is open;
  - forwarding every token at those paths would admit one that an attacker's account obtained,
    and a session's events are data that the account reads back. Capturing the two tokens from the
    responses that issue them on this volume, as sign-in tokens are captured, would tell them
    apart.
- Which other hosts Claude Code sends its OAuth token to. 2.1.326 holds
  `https://mcp-proxy.anthropic.com` and `/v1/mcp/{server_id}` beside its OAuth endpoints, for
  claude.ai's connectors; the defaults refuse that host, so a workspace that allows it loses those
  connectors under brokering until a measurement adds it.
- Copilot's device-flow token and agy's and kiro-cli's logins: whether each refreshes, and through
  which endpoint.

## Delivery order

1. Measure each login's sign-in, refresh and sign-out, each sign-out with its revoke request
   succeeding and failing, with its hosts inspected: the endpoints, the headers at the API hosts,
   the account that each sign-in names, and whether the client accepts each placeholder. Claude
   Code's and Codex's logins were measured on 2026-11-21, and Claude Code's keyless Console
   sign-in on 2026-11-22.
   - The log shows no body, so step 3's first run supplies what a body holds. For every request
     to an entry's token endpoints, whichever `client_id` it carries, it records the names of the
     fields and token claims in request and response, the request's `client_id`, and which field
     or claim holds the account, the workspace and the scopes; never a token or an identifier's
     value. A login whose scopes that run finds nowhere stays unbrokered ("Which account the store
     accepts").
   - The proxy's log records no body field. The token fields come from Codex's source (a JSON
     refresh request with `client_id`, `grant_type` and `refresh_token`,
     `codex-rs/login/src/auth/manager.rs`) and, for Claude Code, from nono's and Docker's
     declarations. Step 3's first run confirms them, as the item above records.
   - Record the result in the preset's evidence file.
2. Measure the store's lock across two proxy containers on one named volume, on macOS, Windows
   and Linux, including a proxy killed while it holds the lock.
   - macOS, podman 6.1.4, 2026-11-21: a second container's `flock -n` exited 1 while the holder
     held the lock and 0 after the holder was killed.
   - Windows, podman 6.2.0, 2026-11-22: the same results. Linux remains.
3. Add the catalog, the store and the rewrite, without the refusal.
   Remote Control ships unsupported from this step, which refuses its registration, and the README
   says so, unless the proxy captures its tokens first (Open questions).
4. Let the refusal of `plan-preset-credential-proxy.md` use the access placeholder of each
   approved login on the volume.
5. Rewrite `design.md`'s section and SECURITY.md ("Agents' own provider logins", "Exfiltration
   through allowed network traffic"), and delete each plan fact once they record it. SECURITY.md
   lists a credential-creating route that the catalog does not list beside echoed credentials, and
   the README tells Console users to choose "Sign in with your Console account", and that "Create
   an API key (legacy)" fails in the sandbox.

## Verification

- Two launches sharing one volume both keep working through a sign-in and a refresh in either, in
  both orders. After one proxy is killed between a test provider's refresh answer and the store's
  write, the next refresh sends the old refresh token once: the login continues where the test
  provider accepts it, and ends with a refused refresh where it does not.
- A token response for an account other than the volume's is refused, names the bound account,
  and leaves the store with the volume's login.
- Two launches on one unbound volume that sign in at once to different accounts: one binds, and
  the other's response is refused and stores nothing.
- A new binding leaves the refusal off until the user approves it at a start prompt, and running
  proxies on the volume refuse from then on. Dropping it there removes the binding and the login.
  A launch under `immediate`, or under `pause` without a terminal, leaves it pending and names the
  launcher action.
- A revoke while a refresh holds the lock leaves no login afterwards. A refresh exchange past its
  time bound leaves the old token in the store and is not retried.
- A launcher action while a proxy on the volume runs is refused and leaves the login; after the
  proxy exits, the same action drops it.
- A first launch on a fresh volume starts, and two concurrent first launches on one name share a
  volume and its creation time.
- `--reset` during a delayed refresh exchange removes the proxy (`podman rm --force`) and the
  store, and leaves no store volume behind.
- A proxy killed at each point of a store write leaves the old state or the new one, whole.
- After the agent deletes its credentials without a revoke request, its placeholders keep working
  until the launcher action drops the login, and authenticate nothing afterwards.
- While brokering is on, a refresh request with a real refresh token is refused, on a bound or an
  unbound volume, and the refusal says to sign in again.
- Codex's token exchange for an API key is refused before it is forwarded, and the browser
  sign-in completes without a key; its authorization-code exchange and its refreshes pass and
  change only their own store entries.
- Codex's device poll answers pass unchanged, and bind nothing.
- Codex's workspace switch is refused before it is forwarded, and no token of another workspace
  reaches the volume.
- A login whose entry names no place for its scopes is not brokered.
- `create_api_key` is refused before it is forwarded, at the volume's placeholder and at any other
  credential, and no key reaches the volume. A keyless Console sign-in completes, survives the next
  launch, and leaves placeholders in its profile; its refresh at `api.anthropic.com` changes only
  its own store entries.
- `ant auth logout`'s first revoke request retires the login, and its second is forwarded
  unchanged. When another sandbox signs in between the two, that new login's placeholders keep
  resolving. A revoke carrying a real token from before brokering is forwarded unchanged, and
  neither case changes the store.
- Remote Control's registration is refused before it is forwarded, and no environment secret
  reaches the volume.
- An `ant auth login` binds as Claude Code's Console login, or is refused on a volume bound to the
  subscription login; Claude Code then uses that profile, and a refresh by either client changes
  only that login's store entries.
- Codex's API-key exchange and `claude setup-token`'s exchange are refused before they are
  forwarded. Codex's sign-in completes without a key, and the `setup-token` refusal says to run it
  outside the sandbox.
- A response under `/v1/oauth/` on `api.anthropic.com` with an undeclared token field is refused,
  and a `/v1/messages` stream passes as it arrives.
- With a preset entry and an approved login at one host, each placeholder passes, and a foreign
  token is refused. A pending login's placeholder there is refused and names the approval.
- A keyless Console sign-in on a volume bound to Claude Code's subscription login is refused and
  names the launcher action; after the action, it binds.
- A token response that changes the user, the organization, the workspace or the scopes is
  refused, and scopes in another order are no change. A sign-in response without scopes, where the
  entry declares them, is refused. A refresh response without scopes keeps the bound ones.
- A token request with another `client_id` passes unbrokered, and its response changes nothing in
  the store.
- The prompt shows a pending binding's scopes.
- An approval in one proxy applies to the next request in another running proxy.
- A sign-in response without the entry's account field is refused and stores nothing.
- While brokering is on for a login, a proxy refuses a tunnel to its login host or an API host and
  names the launcher action. The action, in either direction, is refused while any proxy on the
  volume runs, a paused launch's included.
- An action and a proxy's start, in both orders and from launchers with different state roots,
  leave every proxy with the setting that the store holds while it runs.
- A volume with brokering off, removed with `podman volume rm` or by `--reset` and created again
  under its name, starts with brokering on; so does a volume whose store is missing. A proxy whose
  store exists but cannot be read refuses to start and leaves the store.
- A volume removed and created again while a launch waits at its start prompt refuses that launch
  before its container starts.
- Codex's workspace switch at `/backend-api/accounts/switch-workspace-token` is refused.
- A launcher action with no session on the volume changes the store through its short-lived
  container, and leaves no container behind.
- A brokered login, turned off, then a tunneled launch and a sign-in, completes a request; turned
  back on, its refresh is refused, and a sign-in brokers it again.
- A volume whose client holds real tokens binds at the sign-in that its refused refresh asks
  for.
- A response with a token-like field at an undeclared path, with an error status, or beside a
  declared field at a token endpoint is refused, as is a body over the bound, whether its length is
  declared, chunked or ended by the connection's close. An error response that holds only declared
  token fields is refused and changes nothing in the store.
- After a sign-out, a sign-in to another account is refused until the host-side action drops the
  binding.
- A preset-credential launch keeps its credential accepted while a login at that host is pending
  or approved, and a sign-in in that launch binds as in any other. An `--env` session's real key is
  refused from the moment the user approves the volume's binding at another launch's start.
- On a volume with an approved binding, a launch with an `--egress-cred` binding to a refusing
  host starts, and the binding's placeholder passes there as the brokered login's does; a foreign
  token is refused.
- One client that sends two refreshes a second apart keeps working, and both responses carry the
  same placeholders.
- A refresh that changes a claim Codex reads, such as the plan type, reaches Codex's stored ID
  token. Codex refreshes before the access token's `exp` without a 401, and an older access
  placeholder still resolves.
- The launch after a sign-in shows the pending binding before its prompt. An approval for a
  binding that another launch dropped and replaced is refused, and the next prompt shows the
  replacement. After one prompt approves a binding, a drop from a second prompt that showed it is
  refused. A binding whose proxy died before reporting it appears at a later prompt.
- `--reset-all` keeps a user-named volume's store and removes the stores of removed and missing
  volumes.
- A store whose volume was removed with `podman volume rm`, or created again, is discarded.
- A `--persistent-volume` that names a store is refused. A volume at a store's name without the
  store's label is not mounted into a proxy, and `--reset-all` leaves it in place.
- A revoke request that a workspace rule refuses leaves the login until the launcher action
  drops it. Codex's revoke of an access token, which carries no `client_id`, retires the login.
- Once a login is bound, no real token of it reaches the sandbox's environment or persistent
  volume (`ProxyContainerTest`).
- Removing the volume removes its store, and a placeholder copied out of the session authenticates
  nothing elsewhere.
- In the production image, Claude Code, the Codex TUI and `codex exec` each sign in, refresh and
  complete a turn with brokering on, Codex once by its device sign-in and once by its browser
  sign-in.
