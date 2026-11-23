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
  in a volume that the sandbox reads. The store moves them where the sandbox cannot read them, in
  the same volume, so they need no cleanup of their own. One placeholder per token kind keeps the
  store to one entry set per login, with no generations of placeholders to track (One placeholder
  per token kind); the store still needs the lock that "The store" describes.

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
  - the proxy forwards the body, rewritten or not, with a `Content-Length` of its own length and no
    `Transfer-Encoding`, as it forwards a token request. A `204` goes without either header, which
    HTTP forbids on it (RFC 9110, section 8.6). A `304` or a response to `HEAD` keeps its headers,
    which describe a representation, not the body: the proxy rewrites only token and revoke
    responses, which answer `POST` (RFC 6749, section 3.2; RFC 7009, section 2.1). An interim
    head, such as `103 Early Hints`, reaches the client before the final head, as the relay
    forwards it today, but without either header, which HTTP forbids on every `1xx`;
- reads each request to a token or revoke endpoint whole before it forwards any part of it, so
  that it decides and substitutes on the bytes that it sends:
  - the body has a bound, enforced while the proxy reads a declared length or a chunked body, and a
    longer one is refused before any byte reaches the provider. Open: the bound, until step 3's
    first run logs the largest request at each endpoint; the measured token requests are 208 to
    347 bytes (`anthropic-evidence.md`);
  - the proxy forwards the substituted body with a `Content-Length` of its own length and no
    `Transfer-Encoding`, since a real token and its placeholder can differ in length;
  - the proxy answers `Expect: 100-continue` with its own `100` and forwards the request without
    `Expect`, since the provider sees nothing until the body has arrived. Elsewhere the relay sends
    no interim response of its own (`AgentEgressProxy.scala`, `relayInspected`);
- refuses a token or revoke request, or a response at a checked path, whose body repeats a field
  name, in a JSON object at any depth or in a form body, even with equal values:
  - RFC 6749 forbids a repeated parameter (section 3.2). A repeat could let the proxy read one
    value and the provider or client another, such as a second `grant_type` beside the exchange
    that the proxy refuses, or a second `access_token` beside the one it replaces;
  - OAuth extensions allow some repeats, such as `resource` in a token request (RFC 8707, section
    2.2). Refusing every repeat is this proxy's policy, and fails a client that repeats one, a
    client whose sign-in passes unbrokered included;
  - the proxy compares names after decoding JSON escapes and form percent-encoding, in this check
    and the token-name check below, so `"\u0061ccess_token"` repeats `access_token` and
    `client%5Fid` repeats `client_id`. It finds repeats while it parses, before a map could drop
    them, and refuses a request before forwarding it;
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
  inspection. A later launch that declares the login is refused ("Declaring the account").
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
- The store is in the persistent volume, so a volume removed and created again starts with a new
  store, brokering on, and podman removes no volume that a running proxy uses
  (`plan-preset-credential-proxy.md`, "The volume's store").
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

- The store binds a login to the account of the first sign-in that it captures in the volume;
  under a declaration, only a sign-in to the declared address binds ("Declaring the account"). The
  banner names that account at every launch and whether the user approved it, or says that the
  login is unbound.
- The proxy binds under the store's exclusive lock, comparing and writing in one step, so of two
  launches that sign in at once to different accounts, one binds and the other's response is
  refused.
- A refresh keeps the placeholders. A token response for another account is refused, and nothing
  is stored. The refusal names the bound account, the account that signed in and the launcher
  action below, so a user whose own sign-in meets another account's binding learns why and what to
  do.
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
  account. Claude Code 2.1.330 reads `account.uuid`, `organization.uuid` and `workspace.id` from
  its token response (the binary's `formatTokens`); Codex's ID token names `sub` and
  `chatgpt_account_id` (`openai-evidence.md`). Step 3's rewrite confirms the fields in the token
  responses.
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
  - A launch that reads no answer leaves the binding pending: under `immediate`, and under `pause`
    without a terminal, where the launch starts without a prompt, as for every consent that the
    start prompt carries (`AgentSandboxLauncher.startPrompt`). Its banner names two ways to
    approve the binding: `--egress-login` with the pending identity at a later launch, which needs
    no prompt ("Declaring the account"), and the launcher action, which is refused while any
    session on the volume runs.
  - Until the approval the login is brokered, but the refusal is off, as on an unbound volume
    ("What an undeclared login leaves open").
  - An attacker who signs in first can write the placeholders it receives into the client's
    credentials file. The client then works under the attacker's account, and a binding that
    took effect at once would make the refusal protect that account.
  - The launcher records the approval in the store, and every proxy on the volume applies the
    refusal from then on.
  - The answer, an approval or a drop, names the binding that the prompt showed by its identity.
    The proxy compares it with the store's under the exclusive lock, and requires the binding to
    be still pending; it refuses a mismatch. So a prompt that showed a dropped binding approves no
    successor of another identity, and a second prompt for the same binding drops no login that
    the first approved.
  - A successor of the same identity takes the answer: it carries the authority that the prompt
    showed, and the user approves that authority, not the placeholders.
  - Refusing writes until the approval is not chosen: every model call is a `POST`.

## Declaring the account

`--egress-login=LOGIN:IDENTITY`, such as `--egress-login=codex:me@example.com`, approves in
advance the binding of the login's next sign-in on the volume, so that the refusal protects the
session from its first request. The option is not required: a required declaration would ask every
user for each client's exact identity before the client first starts.

- `LOGIN` names a catalog login, `claude` or `codex`, and `IDENTITY` the user's email address at
  its provider. Each entry declares the response field or claim that carries the address, and
  cites the provider's evidence that it verifies the address and keeps it on one account. The
  launch refuses a declaration for a login whose entry lacks either.
  - The address matches only at the first sign-in, and when a declaration approves a pending
    binding. The binding then holds the provider's stable user identifier, as every binding does,
    since OpenID Connect lets a provider move an address to another subject (Core, section 5.7).
  - Codex's ID token has the claims `email`, `email_verified` and `sub` (`openai-evidence.md`),
    and the proxy requires `email_verified` to be true.
  - Claude Code 2.1.330 reads `account.email_address` from its token response, beside
    `account.uuid`, `organization.uuid`, `workspace.id` and `scope` (the binary's `formatTokens`).
    Step 3's first run confirms that each sign-in response holds them.
- The option comes from the command line or the options file, never from a repository file, as
  `--egress-preset-cred` does: a workspace's declaration would bind the attacker's account in
  advance.
  - In the options file, one declaration reaches every volume at its next launch, in every
    workspace and after `--reset`. The README recommends it there.
  - It merges as `--egress-cred` does: a command-line `--egress-login` replaces the file's entry
    for its login, and an empty value drops the file's entries. So a workspace with another
    account declares that account on its command line.
  - A launch that names one login twice, after the options file and the command line merge, is
    refused.
- A declaration writes nothing to the store by itself, so the store holds only what a sign-in and
  its approval leave:
  - The proxy keeps the launch's declarations in memory. It refuses at each declared login's API
    hosts from the session's first request, and accepts the login's access placeholder only while
    the volume's binding names the declared identity ("Selection and the refusal").
    - Another launch on the volume can bind another identity first. The refusal then names both
      identities, so this session never runs on an account that it did not declare.
  - The first sign-in to the declared address binds the login approved, without a prompt: the
    declaration is the approval. The store then holds what a sign-in and its approval at a later
    launch leave, which later launches keep without the option. An attacker cannot sign in as that
    address while the provider verifies it and keeps it on one account.
  - A sign-in to another address is refused, as any sign-in to another account is, and stores
    nothing ("Which account the store accepts"). So a mistyped declaration costs one relaunch.
  - A session without a sign-in leaves the store unchanged.
- At the launch, the proxy checks every declaration against the store under the exclusive lock
  before any takes effect, so a launch refused for one declaration approves nothing for another:
  - a declaration that names the identity of the volume's pending binding approves the binding.
    This is the one write that a declaration makes without a sign-in: the binding came from a
    sign-in at an earlier launch, so the store again holds what a sign-in and its approval leave;
  - one that names the identity of the volume's approved binding changes nothing;
  - one that names another identity than the volume's binding, pending or approved, refuses the
    launch, and the refusal names both identities and the launcher action that drops the binding
    and its login. Refusing makes an attacker's pending binding loud: every launch that declares
    the user's identity stops until the user drops it, which needs the sessions on the volume
    stopped;
  - one for a login whose brokering is off on the volume refuses the launch, and the refusal names
    the launcher action that turns brokering on: turning brokering off drops the binding, which a
    declared sign-in would otherwise bring back.
- A paused launch asks nothing at its start prompt about a login that it declares: the
  declaration decides that binding, and a mismatch refuses the launch.

## What an undeclared login leaves open

The default, a binding that waits for approval, leaves these risks for each login that the user
does not declare. SECURITY.md records them (Delivery order, step 5).

- A process that signs in before the user, on a volume where that login is unbound, binds its own
  account. The client works under that account for the rest of the session, and the refusal stays
  off at the login's hosts until a later launch approves the binding.
  - A launch that selects a preset credential at one of those hosts refuses there already, the
    pending login's placeholder included ("Selection and the refusal"), so the client fails there
    instead.
  - The user learns of it at the next launch's prompt, a concurrent launch's included. Within the
    session, the user learns of it only from a refused sign-in of their own, which names the bound
    account, or from the client's account display, such as `/status`.
  - The attack needs code that runs before the user's own sign-in, such as a workspace script,
    another agent with its own login, or an `--env` session: after that sign-in, a sign-in to
    another account is refused.
- A login that the user never signs in to stays open on the volume while it is unbound. The next
  prompt then shows a pending binding that the user never made.
- The approval rests on the user reading the identity at the prompt. Approving an attacker's
  lookalike address makes the refusal protect the attacker's account.
- At a refusing host where nothing is selected or approved, the refusal does not apply, and a
  foreign key passes ("Selection and the refusal").

A declaration closes the first three for its login, and the fourth at its login's hosts. On a
volume with an unbound login, the banner names `--egress-login` and says that a sign-in there runs
unprotected until a later launch approves it, or, at a host where the launch selected a preset
credential, that the proxy refuses the signed-in client's requests there until then.

## The store

- The store is the persistent volume's `store` subdirectory (`plan-preset-credential-proxy.md`,
  "The volume's store"), so every launch whose agents share one credentials file shares the
  store. Two launches in one workspace share its volume, and so do a linked worktree that reuses
  its main worktree's volume and the workspaces that name one `--persistent-volume`.
- The sandbox cannot read the store. Removing the volume, `--reset` or `podman volume rm`
  included, removes its store, so a removed login stops working (docker/sbx-releases #492).
  - A user-named volume, which `--reset` and `--reset-all` leave in place (README,
    "--persistent-volume"), keeps its store, so its login keeps working.
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
- The launcher reaches the store only through a proxy container:
  - The launcher learns a binding from its proxy, which reports each binding during the run and
    the store's bindings at its start, so a binding whose proxy died before reporting it still
    reaches a later prompt. The launcher saves them, and each launch shows a saved pending binding
    right before its prompt, as it prints the BPF reconcile's saved notes: the proxy starts beside
    the prompt, so the prompt cannot wait for it (`design.md`, "What may move across the start
    prompt").
  - The launcher passes the answer to its launch's proxy, which writes it to the store. A launcher
    action runs while no proxy holds the store's presence lock, so no proxy is there: the
    launcher runs a short-lived container of the proxy image that mounts the volume, takes the
    locks, writes the change and exits.
  - At rest it is a plaintext file in the persistent volume, where the real tokens are kept today;
    the sandbox only loses its read.
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
  credential"), and the access placeholder of each approved login on the volume there, except a
  login that the launch declares and whose binding names another identity. It applies once the
  set holds a preset entry or an approved login, signed out or not, or once the launch declares a
  login with an API host there; until then the host keeps today's behavior ("What an undeclared
  login leaves open").
  - Every value in the set is one that the user selected at launch or approved, so a foreign key
    stays refused. A pending login's placeholder, which may be an attacker's, is refused where the
    refusal applies; the refusal says to approve the login at the next launch, by its prompt or by
    `--egress-login`, or with the launcher action.
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
- Whether each provider treats an email address's letter case as significant, which decides
  whether a declaration's comparison ignores it ("Declaring the account").
- The rest of the providers' evidence that each verifies an account's address and keeps it on that
  account, which a declaration needs ("Declaring the account"). The help centers settle part:
  - Claude: "It's not possible to change the email address associated with your Claude account at
    this time"
    (https://support.claude.com/en/articles/8452276-how-do-i-change-the-email-address-associated-with-my-account).
    Open: a source that Claude's sign-in verifies the address.
  - OpenAI: a user who changes the address must reach the current and the new inbox, the new
    address "must not already belong to another OpenAI account", and the previous one "stays
    reserved for your account"
    (https://help.openai.com/en/articles/4936827-how-to-change-your-email-address). The same page
    has a Business, Enterprise or Edu workspace's administrator change a member's address in Admin
    Console. Open: whether that change reserves the previous address too.

## Delivery order

1. Measure each login's sign-in, refresh and sign-out, each sign-out with its revoke request
   succeeding and failing, with its hosts inspected: the endpoints, the headers at the API hosts,
   the account that each sign-in names, and whether the client accepts each placeholder. Claude
   Code's and Codex's logins were measured on 2026-11-21, and Claude Code's keyless Console
   sign-in on 2026-11-22.
   - The log shows no body, so step 3's first run supplies what a body holds. For every request
     to an entry's token endpoints, whichever `client_id` it carries, it records the names of the
     fields and token claims in request and response, the request's `client_id`, and which field
     or claim holds the account, the email address, the workspace and the scopes; never a token or
     an identifier's value. A login whose scopes that run finds nowhere stays unbrokered ("Which
     account the store accepts"), and one whose email address it finds nowhere, or whose
     provider's evidence does not show the address verified and kept on one account, cannot be
     declared ("Declaring the account").
   - The proxy's log records no body field. The token fields come from Codex's source (a JSON
     refresh request with `client_id`, `grant_type` and `refresh_token`,
     `codex-rs/login/src/auth/manager.rs`) and, for Claude Code, from nono's and Docker's
     declarations. Step 3's first run confirms them, as the item above records.
   - Record the result in the preset's evidence file.
2. The store and its lock come with `plan-preset-credential-proxy.md`, step 2, which measures the
   lock.
3. Add the catalog, the store and the rewrite, without the refusal.
   Remote Control ships unsupported from this step, which refuses its registration, and the README
   says so, unless the proxy captures its tokens first (Open questions).
4. Let the refusal of `plan-preset-credential-proxy.md` use the access placeholder of each
   approved login on the volume, and add `--egress-login`, which approves one in advance.
5. Rewrite `design.md`'s section and SECURITY.md ("Agents' own provider logins", "Exfiltration
   through allowed network traffic"), and delete each plan fact once they record it. SECURITY.md
   lists a credential-creating route that the catalog does not list beside echoed credentials, and
   the README tells Console users to choose "Sign in with your Console account", and that "Create
   an API key (legacy)" fails in the sandbox.
   - SECURITY.md records what an undeclared login leaves open and what a declaration closes. The
     README and the launcher help describe `--egress-login` and recommend it in the options file.

## Verification

- Two launches sharing one volume both keep working through a sign-in and a refresh in either, in
  both orders. After one proxy is killed between a test provider's refresh answer and the store's
  write, the next refresh sends the old refresh token once: the login continues where the test
  provider accepts it, and ends with a refused refresh where it does not.
- A token response for an account other than the volume's is refused, names the bound account and
  the account that signed in, and leaves the store with the volume's login.
- Two launches on one unbound volume that sign in at once to different accounts: one binds, and
  the other's response is refused and stores nothing.
- A new binding leaves the refusal off until the user approves it at a start prompt, and running
  proxies on the volume refuse from then on. Dropping it there removes the binding and the login.
  A launch under `immediate`, or under `pause` without a terminal, leaves it pending and names
  `--egress-login` and the launcher action. A later launch under `immediate` that declares the
  pending identity approves it.
- A revoke while a refresh holds the lock leaves no login afterwards. A refresh exchange past its
  time bound leaves the old token in the store and is not retried.
- A launcher action while a proxy on the volume runs is refused and leaves the login; after the
  proxy exits, the same action drops it.
- A first launch on a fresh volume starts, and two concurrent first launches on one name share a
  volume and its store.
- `--reset` during a delayed refresh exchange removes the proxy (`podman rm --force`) and the
  volume with its store.
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
- Under `--egress-login=codex:EMAIL`, a foreign key at `chatgpt.com` is refused before any sign-in,
  and a session without a sign-in leaves the store unchanged. A sign-in to the declared address
  binds without a prompt, its placeholder passes, and the store then holds what a sign-in without
  the option and its approval at a later launch leave. A sign-in to another address, or one whose
  `email_verified` is false, is refused, names both identities and stores nothing, and a relaunch
  with the corrected declaration binds at its sign-in.
- A later launch without the option keeps a binding that a declared sign-in wrote, and the launcher
  action drops it. A declaration that names a pending binding's identity approves it, and one that
  names the approved binding's changes nothing; one that names another identity, pending or
  approved, refuses the launch and names both identities. Of two launches that declare different
  identities and sign in, the first sign-in binds, and the other is refused and names both. The
  other launch's API requests that carry the binding's placeholder are refused too, before its own
  sign-in and after it, and the refusal names both identities.
- A launch that declares a pending binding's identity for one login, and for the other a
  conflicting identity or a login with brokering off, is refused and approves nothing, in either
  order. A paused launch that declares a saved pending binding's identity asks nothing about that
  binding at its prompt and approves it.
- No workspace file declares a login. A declaration for a login whose entry names no email field,
  or cites no evidence that the provider verifies the address, is refused. So is one for a login
  whose provider verifies the address but whose entry cites no evidence that it keeps the address
  on one account, a declaration that names a pending binding's identity included.
- A command-line `--egress-login` replaces the options file's entry for its login, and its empty
  value drops the file's entries. A launch that names one login twice is refused. With brokering
  off for a login on the volume, a launch that declares that login is refused and names the action
  that turns brokering on.
- On a volume with an unbound login, the banner names `--egress-login` and says that a sign-in
  there runs unprotected until a later launch approves it; with a preset credential selected at
  the login's host, it says that the sign-in's placeholder is refused there until then.
- While brokering is on for a login, a proxy refuses a tunnel to its login host or an API host and
  names the launcher action. The action, in either direction, is refused while any proxy on the
  volume runs, a paused launch's included.
- An action and a proxy's start, in both orders and from launchers with different state roots,
  leave every proxy with the setting that the store holds while it runs.
- A volume with brokering off, removed with `podman volume rm` or by `--reset` and created again
  under its name, starts with brokering on; so does a volume whose store is missing. A proxy whose
  store exists but cannot be read refuses to start and leaves the store.
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
- A refresh whose real token differs in length from its placeholder reaches the provider with a
  matching `Content-Length`, and a chunked one arrives with a `Content-Length`. A token request
  over the bound is refused before any byte reaches the provider. A request with
  `Expect: 100-continue` gets the proxy's `100` and completes without waiting for the client's
  own timer.
- A token or revoke request that repeats `grant_type`, `client_id` or `expires_in`, in JSON or in a
  form body, or that repeats a name only in its encoding, such as `client%5Fid`, is refused before
  it is forwarded. A response that repeats `access_token`, or a name in a nested object, is refused
  and stores nothing; so is one with `"access_token"` and `"\u0061ccess_token"`, and one with an
  undeclared token field whose name is spelled with escapes.
- A token response whose rewrite changes its length reaches the client with a matching
  `Content-Length`, whether the provider framed it by length, chunked it or ended it by closing
  the connection. A `204` at a checked path reaches the client without `Content-Length` or
  `Transfer-Encoding`, even when the provider sent one, and a response to `HEAD` keeps its
  `Content-Length`. A `103` before a final response reaches the client without either header, and
  the final response is reframed.
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
  binding that another launch dropped and replaced with another identity is refused, and the next
  prompt shows the replacement; a replacement of the same identity is approved. After one prompt
  approves a binding, a drop from a second prompt that showed it is refused. A binding whose proxy
  died before reporting it appears at a later prompt.
- `--reset-all` keeps a user-named volume and its login.
- A revoke request that a workspace rule refuses leaves the login until the launcher action
  drops it. Codex's revoke of an access token, which carries no `client_id`, retires the login.
- Once a login is bound, no real token of it reaches the sandbox's environment or persistent
  volume (`ProxyContainerTest`).
- Removing the volume removes its store, and a placeholder copied out of the session authenticates
  nothing elsewhere.
- In the production image, Claude Code, the Codex TUI and `codex exec` each sign in, refresh and
  complete a turn with brokering on, Codex once by its device sign-in and once by its browser
  sign-in.
