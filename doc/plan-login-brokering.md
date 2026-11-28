# Plan: brokering the agents' own logins

## Outcome

An agent signs in inside the sandbox as it does today, but the persistent volume holds placeholders
instead of the tokens that the catalog declares. The proxy rewrites the tokens in each sign-in and
refresh response to the volume's placeholders, and puts the real token back at the declared API
hosts and in the refresh request. The real tokens live in a store on the host side, one per
persistent volume.

- Today any process in the session reads an agent's refresh token from the persistent volume
  (SECURITY.md, "Agents' own provider logins"). The process can send the token out in an allowed
  request (SECURITY.md, "Exfiltration through allowed network traffic"), and the token then works
  from anywhere until its owner revokes it. A brokered login works only through this volume's
  proxies, at the catalog's hosts.
  - That holds once a sign-in has completed. While one runs, the session holds what completes it:
    the authorization code and its verifier, which Codex's device poll returns
    (`codex-rs/login/src/device_code_auth.rs`, `CodeSuccessResp`). A process that sends both out
    before the client exchanges them lets their receiver take the tokens elsewhere.
- In a launch that declares the login's account ("Declaring the account"), the session's own
  credential is the volume's placeholder. So the refusal of `plan-preset-credential-proxy.md`
  covers a signed-in session too, not only a static token.
- A process in the session still uses the login through the proxy while the session runs. The
  proxy cannot tell the agent's request from another process's: the launched command is not a
  security principal (SECURITY.md, "What the persistent volume holds"), and the log's `client=` is
  the request's `User-Agent`. The placeholder works at the catalog's hosts alone, and the proxy
  refuses the known requests that would answer with a new credential ("The rewrite").

This plan reverses these recorded decisions, and delivery step 5 rewrites each where it stands:

- `design.md`, "Credential brokering at the egress proxy": "Brokering the agents' own logins" and
  "Storing a credential on the host across runs", both under "Left out"; and the rule that a
  rewrite is "never in a body or a response", with "Response and body rewriting" under "Left out".
- `design.md`, the same section, "Copilot CLI's `copilot login`" under "Left out", once that
  login's measurement lands (Delivery order, step 6).
- `design.md`, "Model hosts inspected by default": "Refusing paths on a model host" under "Not
  done", and "A host's treatment is chosen in the ruleset alone".
- `agent-measurement.md`, "Rules", 2: a login host grants every `method=` word at the root.
- `TODO.md`, "Server tools that connect where a request says", says that a refusal by body "needs
  a decision of its own". This plan makes that decision for the token and revoke endpoints alone.

## Why the earlier reasons no longer hold

- "The proxy would mirror that lifecycle per release": the client keeps its own sign-in, expiry and
  refresh. The proxy follows each release's token endpoint paths and token field names, as the
  presets already follow each release's hosts (`agent-measurement.md`). A moved endpoint fails
  closed, within the limits that "The rewrite" states.
- "A host-side OAuth flow needs a public-client registration": the client signs in and refreshes
  under its own client identity, and the proxy only rewrites what passes.
- "Hiding the model token does not pay", since a stolen model token is "a nuisance to the account
  holder": a token copied out of the volume works from anywhere until its owner revokes it, and
  some logins grant more than model access (SECURITY.md, "The web reached through the model
  provider"). The refusal needs the session's own token as well, which a brokered login gives a
  signed-in session.
- "Storing a credential on the host across runs" ("Left out"): the tokens already outlive the run,
  in a volume that the sandbox reads. The store moves them where the sandbox cannot read them, in
  the same volume, so they need no cleanup of their own. One placeholder per token kind keeps the
  store to one entry set per login, with no generations of placeholders to track (One placeholder
  per token kind); the store still needs the lock that "The store" describes.
- "Never in a body or a response", since "broader rewriters recurrently fail by breaking
  applications that carry tokens of their own": the proxy rewrites only a declared field, in a
  request to a declared token or revoke endpoint and in that request's response. Every other body
  and response passes as sent.
- "Such a refusal is a per-release contract with each CLI" ("Refusing paths on a model host"): the
  plan accepts that contract for the few known writes that answer with a new credential ("The
  rewrite"). A release that moves one of them returns its credential unrewritten until the
  catalog follows. Each release's measurement already compares the paths that the client calls
  with the records (`agent-measurement.md`, "The measurement suite").
- "A host's treatment is chosen in the ruleset alone": while brokering is on for a login, a
  setting in the volume's store decides whether the proxy opens a workspace's tunnel to that
  login's hosts ("The rewrite"). A tunnel there would bring a sign-in's real tokens into the
  volume.

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
- the path prefixes whose writes the check below reads: `/v1/oauth/` on `platform.claude.com` and
  on `api.anthropic.com`, and `/oauth/` and `/api/accounts/deviceauth/` on `auth.openai.com`.
  - The presets grant the login hosts, `platform.claude.com` and `auth.openai.com`, no write
    outside these prefixes (Delivery order, step 3). So the ruleset refuses a token endpoint that
    a release moves elsewhere on a login host, unless a workspace's rule grants a write there. A
    sign-in at a path that such a rule grants brings real tokens into the volume.
  - `api.anthropic.com` keeps its writes at the root, where it serves model traffic;
- the revoke endpoints: those that the measured sign-outs called, Claude Code's
  `platform.claude.com` `/v1/oauth/token/revoke` and Codex's `auth.openai.com` `/oauth/revoke`;
  and `api.anthropic.com` `/v1/oauth/token/revoke`, where `ant auth logout` revokes the profile's
  refresh token and then its access token (anthropic-cli `pkg/cmd/cmd_auth_revoke.go`);
- the client's OAuth client IDs, which a public client sends in each token request's body. The
  proxy brokers only token requests that carry one: a refresh token is bound to the client that it
  was issued to (RFC 6749, section 6), so another client's grant must not share the login's
  placeholders. Another client's sign-in passes unbrokered, and its real tokens are refused as
  foreign where a launch's refusal applies ("Selection and the refusal").
  - Claude Code's entry names two: its `CLIENT_ID`, which its subscription sign-in sends, and the
    Anthropic profile client, which its Console sign-in sends and writes into the profile
    (2.1.326's binary). `ant auth login` uses the profile client too (anthropic-cli
    `pkg/cmd/cmd_auth.go`, `oauthClientIDProd`), so the proxy brokers it as the Console sign-in
    (below).
  - The `client_id` selects the catalog rule and proves nothing: a client identifier is no secret
    (RFC 6749, section 2.2). A launch's declaration says which account it trusts ("Declaring the
    account").
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
- the known writes that answer with a new credential, which the proxy refuses whatever credential
  they carry. Claude Code's legacy Console sign-in, "Create an API key", sends `POST`
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
    account, which a sign-in brings in.
  - Claude Code's Remote Control registers with `POST` `api.anthropic.com`
    `/v1/environments/bridge` under the access token, and reads `environment_secret` from the
    response, the credential of its later polls (2.1.326's binary, `anthropic-evidence.md`). The
    entry refuses it until the proxy captures that secret (Open questions), so Remote Control fails
    at its start.
  - A route that creates a credential and that the catalog does not list returns it unrewritten,
    as a response that echoes a credential does (SECURITY.md). Each release's measurement reports
    a path that no record lists (`agent-measurement.md`, "The measurement suite"); a new write at
    an API host is then read for what its response holds, and joins these routes when it holds a
    credential.
  - Not chosen: a list of the writes at which a placeholder resolves, with every other write
    refused, for a login or for a preset credential. Such a list fails each time a release adds or
    moves an endpoint, and in every mode that no measurement ran: the image installs each client's
    latest release unmeasured (`agent-measurement.md`, "Rules"). It would also refuse a workspace's
    own programs, which may use a selected key at other paths.

Claude Code's keyless Console sign-in belongs to Claude Code's login, as its subscription sign-in
does: a volume holds one login per client ("The login's account"). Claude Code keeps
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

- reads each response to a write under the catalog's checked prefixes whole, with any status,
  before it stores or forwards any part of it:
  - the body is at most 64 KiB, enforced while the proxy reads a declared length, a chunked body
    or a body that the connection's close ends; a longer one is refused before any byte reaches
    the client. Open: the bound, until step 3's rewrite logs the largest response to each checked
    write that the measurements list, since the bound applies to every one of them;
  - a read's response passes as it arrives, under a checked prefix too. `platform.claude.com` also
    serves Anthropic's documentation, whose pages no bound for a token response admits. Measured
    on 2026-11-24 with `Accept-Encoding: identity`: `/docs/en/build-with-claude/files` is
    1,064,757 bytes, and `/llms.txt` 108,297;
  - the proxy asks for the body uncompressed (`Accept-Encoding: identity`) and refuses a compressed
    one, so that it reads what the client would;
  - the proxy forwards the body, rewritten or not, with a `Content-Length` of its own length and no
    `Transfer-Encoding`, as it forwards a token request. A `204` goes without either header, which
    HTTP forbids on it (RFC 9110, section 8.6). An interim head, such as `103 Early Hints`,
    reaches the client before the final head, as the relay forwards it today, but without either
    header, which HTTP forbids on every `1xx`;
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
- refuses a token or revoke request, or a checked response, whose body repeats a field name, in a
  JSON object at any depth or in a form body, even with equal values:
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
- stores the declared tokens of a successful (`2xx`) refresh response before the checks that
  decide only whether to forward it. The provider has replaced the refresh token by then, and
  Claude Code's provider refused the old one 17 seconds later ("The store"). So a refresh response
  that the proxy refuses to forward leaves the client's placeholders on the new tokens.
  - A refresh must not let a placeholder do more than its sign-in permits. So the proxy stores
    nothing from a refresh response that names another user, organization or workspace than the
    login's, or a scope that the login's sign-in did not grant, and refuses to forward it. A
    response that names fewer scopes is stored as any other.
  - A response over the bound, or one that does not parse, stores nothing either.
  - A response that stores nothing ends a login whose provider no longer accepts the old refresh
    token: the next refresh fails, and the user signs in again.
- refuses to forward a checked response that holds a field named like a token (`access_token`,
  `refresh_token`, `id_token` or another `*_token`) that the entry does not declare for that path,
  a declared field beside it included. nono checks its capture hosts' unmatched paths and error
  responses for such fields (`docs/cli/features/sandboxed-oauth-logins.mdx`, "token_endpoints");
  - the check fails closed for an error response, for a new token field and for a token endpoint
    that a release moves within a checked prefix, but not for a token under a name it does not
    recognize;
  - nor for a token response that a release moves out of `/v1/oauth/` on `api.anthropic.com`. A
    refresh moved there still fails, since the proxy resolves the refresh placeholder only at a
    token endpoint. A sign-in's exchange moved there brings real tokens into the volume until a
    measurement lists its path;
  - a provider can add a token field without a client release, which no release's measurement
    sees. Until the catalog declares the field, each refresh stays in the store while the client
    reads it as failed, and each sign-in is refused. Turning brokering off is the way back
    (below);
- refuses a response with an error status that holds any token field, declared or not, and stores
  nothing from it, so a failed exchange never replaces a working credential;
- otherwise, for a successful (`2xx`) response, replaces each declared token in a token endpoint's
  response with the volume's placeholder for that field, after it stores the real token. A
  refresh reaches the provider only with the volume's refresh placeholder, so only a sign-in
  changes whose account the login is ("The login's account");
- puts the real refresh token in place of its placeholder in a token request, and the real access
  token in place of its placeholder at the API hosts.

A login host that a workspace made a tunnel gets no brokering, as a tunnel host gets no
substitution (`plan-preset-credential-proxy.md`, "Selection"). So while brokering is on for a
login on the volume, the proxy refuses a tunnel to that login's login host or an API host, and the
refusal names the rule and the launcher action below. A tunnel at the login host would let a
sign-in's real tokens into the volume, and one at an API host would pass foreign credentials beside
the refusal, as the preset plan refuses a tunnel at an entry's host.

- A launcher action turns brokering off for a login on the volume, and drops its login in the same
  write; from then on a proxy opens a tunnel to those hosts, except in a launch that declares
  the login ("Declaring the account"). This keeps the way back that `design.md`, "Model hosts
  inspected by default", leaves for a client release that fails under inspection, and it is the
  way back from a token response that the catalog does not yet read. A
  launch that declares the login is refused meanwhile ("Declaring the account").
- The setting lives in the store, so it follows the store's volume, and every launch on the volume
  reads the same one whatever its launcher's state root. A new store starts with brokering on. A
  proxy whose store exists but cannot be read refuses to start, names the store, and leaves it for
  recovery, since it could enforce neither the setting nor a declaration.
- A proxy reads the setting under the store's shared lock at each decision that depends on it: a
  tunnel's `CONNECT` to a login's host, a token request and a placeholder's resolution ("The
  store"). The action writes it under the exclusive lock. So a change applies to the next decision
  in every proxy on the volume, and the action needs no session stopped.
  - A tunnel opened while brokering was off runs on to its end after brokering is turned on, as a
    WebSocket opened before a change does ("The store").
- The store is in the persistent volume, so a volume removed and created again starts with a new
  store, brokering on, and podman removes no volume that a running proxy uses
  (`plan-preset-credential-proxy.md`, "The volume's store").
- A proxy reports at its start each tunnel of its ruleset that the setting refuses, before the
  sandbox's container starts, and the banner shows the setting from the launcher's saved report
  ("The store"). Tunnels at those hosts serve a client release that fails under inspection, so
  this is rare.
- Either change takes a sign-in. Off leaves the client's credentials holding placeholders that
  resolve nothing; on refuses the client's refresh of its real tokens ("The login's account").

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

## The login's account

A sign-in inside the sandbox could bring an attacker's account: a process could exchange an
authorization code that the attacker obtained for their own account, and the provider answers with
real tokens. That account then stands behind the volume's placeholder. The store accepts any
sign-in all the same. A launch that declares the login's account refuses the placeholder while
the store's login is another account's, and refuses other credentials ("Declaring the account").
An undeclared launch does neither ("What an undeclared launch leaves open").

- A sign-in replaces the volume's login for its client: the store holds the new tokens behind new
  placeholders, and records the account that the response names. So changing the account, or
  switching between Claude Code's subscription and Console sign-ins, takes a sign-in and nothing
  else.
  - A volume thus holds one login per client. Claude Code's keyless sign-in itself signs out of
    the claude.ai login (https://code.claude.com/docs/en/authentication, "Sign in without an API
    key").
- The proxy replaces the login under the store's exclusive lock, in one write. So of two launches
  that sign in at once, the later write is the volume's login, whole.
  - Each client saves its own response afterwards, in either order. Where the earlier sign-in's
    client saves last, the shared credentials file holds retired placeholders, which authenticate
    nothing, and the user signs in again.
- The store records, where the sign-in response names them, the user, the organization, the
  workspace, the granted scopes, the email address and the organization's and workspace's names.
  Claude Code 2.1.330 reads `account.uuid`, `account.email_address`, `organization.uuid`,
  `workspace.id` and `scope` from its token response (the binary's `formatTokens`); Codex's ID
  token names `sub`, `email` and `chatgpt_account_id` (`openai-evidence.md`). Step 3's first run
  confirms the fields in the token responses.
  - The store records the address only where the sign-in satisfies the entry's verification
    rule, such as Codex's `email_verified`. A login without a recorded address matches no
    declaration, whichever launch took its sign-in, so no declared launch runs on an address that
    the provider did not verify.
  - A declaration compares the address ("Declaring the account"), a refresh the user, the
    organization, the workspace and the scopes ("The rewrite"), and the banner shows the address
    and the names.
  - The store keeps the provider's stable user identifier beside the address, since OpenID Connect
    lets a provider move an address to another subject (Core, section 5.7).
  - A sign-in whose token has other scopes replaces the login as any sign-in does. The placeholder
    then permits what those scopes permit at the provider, which can be more than before. Two
    Anthropic profiles of one user and organization can differ in workspace and scopes, such as a
    profile with `org:admin`
    (https://platform.claude.com/docs/en/cli-sdks-libraries/cli/authentication, "Admin access").
  - The user grants a sign-in's scopes in the host's browser. The proxy never sees the authorize
    request, so it cannot hold a sign-in to the scopes that the client itself asks for.
- While brokering is on, the proxy refuses a token request that sends back a token other than the
  volume's placeholder, such as a real refresh token. So a login from before brokering brings no
  real token into the volume: its next refresh fails, and the refusal says to sign in again, which
  brokers the login. A real access token works until it expires.
- On the host, a launcher action drops the volume's login, to sign out when the agent's own
  sign-out sent no revoke request. It writes under the store's exclusive lock, so it needs no
  session stopped ("The store").

## Declaring the account

`--egress-login=LOGIN:IDENTITY`, such as `--egress-login=codex:me@example.com`, names the account
that the launch trusts for a login. The refusal covers a login only in a launch that declares it
("Selection and the refusal"). The option is not required: a required declaration would ask every
user for each client's exact identity before the client first starts.

- `LOGIN` names a catalog login, `claude` or `codex`, and `IDENTITY` the user's email address at
  its provider. Each entry declares the response field or claim that carries the address, and
  cites the provider's evidence that it verifies the address and keeps it on one account. The
  launch refuses a declaration for a login whose entry lacks either.
  - Codex's ID token has the claims `email`, `email_verified` and `sub` (`openai-evidence.md`),
    and the store records the address only when `email_verified` is true ("The login's account").
  - Claude Code 2.1.330 reads `account.email_address` from its token response ("The login's
    account"). Step 3's first run confirms that each sign-in response holds it.
- The option comes from the command line or the options file, never from a repository file, as
  `--egress-preset-cred` does: a workspace's declaration would name the attacker's account.
  - In the options file, one declaration reaches every volume at its next launch, in every
    workspace and after `--reset`. The README recommends it there.
  - It merges as `--egress-cred` does: a command-line `--egress-login` replaces the file's entry
    for its login, and an empty value drops the file's entries. So a workspace with another
    account declares that account on its command line.
  - A launch that names one login twice, after the options file and the command line merge, is
    refused.
- A declaration writes nothing to the store. The proxy keeps the launch's declarations in memory,
  and in that launch:
  - it refuses other credentials at each declared login's API hosts from the session's first
    request ("Selection and the refusal");
  - it accepts the login's access placeholder only while the store's login names the declared
    address. Another launch on the volume can sign in to another account meanwhile; the refusal
    then names both addresses, so this session never runs on an account that it did not declare;
  - it refuses a sign-in response that names another address, or none, stores nothing from it, and
    names both addresses. So a mistyped declaration costs one relaunch. An attacker cannot sign in
    as the declared address while the provider verifies it and keeps it on one account;
  - a sign-in to the declared address replaces the login, as any sign-in does;
  - a session without a sign-in leaves the store unchanged.
- A launch that declares another address than the store's login names starts. Its refusal names
  both addresses, and a sign-in to the declared address in that launch replaces the login.
- A launch that declares a login whose brokering is off on the volume is refused when its proxy
  starts, and the refusal names the launcher action that turns brokering on: with brokering off,
  the session's own token is a real one, which the proxy cannot tell from a foreign one.
- A launch that declares a login refuses a tunnel to that login's hosts for as long as it runs,
  whatever the setting. So an action that turns brokering off while the launch runs opens no
  tunnel there, through which a foreign credential would pass the refusal. The action drops the
  login, so its placeholder resolves nothing in that launch from then on. The launch's preset
  entries and bindings at those hosts keep passing, and every other credential stays refused.

## What an undeclared launch leaves open

A launch that declares no account for a login still hides that login's tokens. It leaves these
risks, which SECURITY.md records (Delivery order, step 5):

- A foreign key passes at the login's hosts, as today, unless the launch selects a preset
  credential there ("Selection and the refusal").
- A process can sign in to its own account, which replaces the volume's login. The client then
  works under that account, and what it uploads goes there.
  - The user learns of it from the client's account display, such as `/status`, or from a later
    launch's banner, which names the login's address as last reported ("The store").
  - A launch that declares the user's address refuses that login's placeholder and names both
    addresses.

A declaration closes both for its login, in its launch. For each login on the volume that the
launch does not declare, the banner names the login's address and the `--egress-login` option that
declares it, and says that the launch refuses no other credential at that login's hosts; at a host
where the launch selected a preset credential, it says instead that the proxy refuses the signed-in
client's requests there.

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
- Every decision that depends on the store reads it under the shared lock: the token behind a
  placeholder, the account that the login names, and the brokering setting. So a sign-in, a
  dropped login or a changed setting applies to the next request in every proxy, and no proxy
  decides from a copy it read earlier.
  - A change governs later requests and WebSocket handshakes. A WebSocket opened before it runs
    on, since the proxy relays an upgraded stream without further decisions
    (`AgentEgressProxy.scala`).
- A sign-in, a revoke and a launcher action take the lock exclusively too, so an in-flight refresh
  cannot bring a retired login back: a refresh that holds the lock finishes before the retire, and
  one that starts after it finds no login.
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
  - A launcher action runs a short-lived container of the proxy image that mounts the store,
    takes the lock, writes the change and exits, whether or not a session runs on the volume.
  - A proxy reports the volume's logins at its start and after each sign-in: each client, its
    address and names, and its brokering setting. The launcher saves the report, and each launch's
    banner prints the saved one, as it prints the BPF reconcile's saved notes: the proxy starts
    beside the prompt, so the banner cannot wait for it (`design.md`, "What may move across the
    start prompt").
  - The saved report decides nothing: every decision reads the store. The banner says that it
    shows the logins as last reported: a sign-in whose proxy died before reporting it appears
    once a later proxy's report has arrived, which can be after the next launch's banner.
- A proxy can read every login in its volume's store, those of agents that its session never runs
  included, where a proxy today holds only the credentials sent through it (SECURITY.md, "Who
  holds a brokered value").
- At rest the store is a plaintext file in the persistent volume, where the real tokens are kept
  today; the sandbox only loses its read.
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
- The refusal is decided per launch. At each refusing host, it accepts one set: the placeholders
  of the launch's preset entries and `--egress-cred` bindings there
  (`plan-preset-credential-proxy.md`, "Refusing another credential"), and the access placeholder
  of each login that the launch declares, while the store's login names the declared address. It
  applies once the set holds a preset entry, or once the launch declares a login with an API host
  there; until then the host keeps today's behavior ("What an undeclared launch leaves open").
  - Every value in the set is one that the user selected or declared at launch, so a foreign key
    stays refused. The placeholder of a login that the launch does not declare, which may stand
    for an attacker's account, is refused where the refusal applies; the refusal names
    `--egress-login`.
  - Nothing that another launch does changes the set. Which account the store's login names can
    change at any sign-in on the volume, so the proxy reads it with the token at each resolution
    ("The store").
- A volume whose client already holds real tokens has no login in the store until the client's
  next sign-in, which its refused refresh asks for ("The login's account"). The banner names no
  login for that client.
  - Capturing the login at a refresh is not chosen: it would rest on a refresh response that names
    the account, and the forced sign-in brokers the login at the first refresh as well.
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
     an identifier's value. A login whose email address that run finds nowhere, or whose
     provider's evidence does not show the address verified and kept on one account, cannot be
     declared ("Declaring the account").
   - The proxy's log records no body field. The token fields come from Codex's source (a JSON
     refresh request with `client_id`, `grant_type` and `refresh_token`,
     `codex-rs/login/src/auth/manager.rs`) and, for Claude Code, from nono's and Docker's
     declarations. Step 3's first run confirms them, as the item above records.
   - Record the result in the preset's evidence file.
2. The store and its lock come with `plan-preset-credential-proxy.md`, step 2, which measures the
   lock.
3. Add the catalog, the store and the rewrite, without the refusal. Narrow the `anthropic` and
   `openai` presets' write grants at `platform.claude.com` and `auth.openai.com` to the checked
   prefixes.
   Remote Control ships unsupported from this step, which refuses its registration, and the README
   says so, unless the proxy captures its tokens first (Open questions).
4. Let the refusal of `plan-preset-credential-proxy.md` use the access placeholder of each login
   that the launch declares, and add `--egress-login`.
5. Rewrite the documents that record what this plan reverses, and delete each plan fact once they
   record it:
   - `design.md`, "Credential brokering at the egress proxy" and "Model hosts inspected by
     default", in the items that "Outcome" lists;
   - SECURITY.md: "Agents' own provider logins", "Exfiltration through allowed network traffic"
     and "What the persistent volume holds"; in "Who holds a brokered value", that a proxy can
     read every login in its volume's store; what an undeclared launch leaves open and what a
     declaration closes; that a placeholder permits what its latest sign-in's scopes permit; that
     a session holds a sign-in's code and verifier while the sign-in runs; and, beside echoed
     credentials, a credential-creating route that the catalog does not list;
   - `egress-proxy.md`, "Where the value goes", which says that no response is rewritten;
   - `agent-measurement.md`: rule 2, for the login hosts' narrowed grants, and a reading of each
     write that a release adds at an API host, for a credential in its response;
   - `TODO.md`, "Server tools that connect where a request says", which then cites the decision on
     refusing by body;
   - the README and the launcher help: `--egress-login`, recommended in the options file; that
     Console users choose "Sign in with your Console account"; and that "Create an API key
     (legacy)" fails in the sandbox.
6. Broker the other agents' logins, each after a measurement as in step 1, in this order. A forge
   token rates above a model token (`design.md`, "Credential brokering at the egress proxy"):
   - Copilot CLI's `copilot login`, whose OAuth token has the `repo` scope and is kept in
     plaintext under `~/.copilot` (SECURITY.md, "The web reached through the model provider").
     - The device sign-in polls `github.com` `/login/oauth/access_token`, and the token goes to
       `api.github.com` and the plan's host (`github-evidence.md`).
     - The `github` preset grants `GET` `api.github.com` `/copilot_internal/v2/token` as a read,
       and its response carries a Copilot token. A read's response passes as it arrives, so the
       entry refuses or brokers that exchange before this login is brokered.
     - Open: whether the token expires or refreshes, the token response's format and fields,
       which field names the account, and whether Copilot's local token check accepts a
       placeholder (github/copilot-cli #2431). `/logout` fails in the sandbox before any request
       (`github-evidence.md`), so the launcher action is this login's sign-out.
   - agy's Google sign-in, which exchanges its code and refreshes at `oauth2.googleapis.com`
     `/token` and keeps the token in `~/.gemini/antigravity-cli/antigravity-oauth-token`
     (`google-evidence.md`).
     - Other Google clients in a session, such as gcloud, exchange their tokens at the same
       endpoint, so the entry's client IDs tell agy's requests apart. agy's sign-out sent no
       request.
   - kiro-cli's sign-in, which refreshes at `/refreshToken` and signs out at `/logout`
     (`aws-evidence.md`).
     - A refresh forced 50 minutes early was answered 401, and kiro-cli deleted the token. Open:
       its Builder ID, Identity Center and GitHub sign-ins, which are unmeasured.

## Verification

- Two launches sharing one volume both keep working through a sign-in and a refresh in either, in
  both orders. After one proxy is killed between a test provider's refresh answer and the store's
  write, the next refresh sends the old refresh token once: the login continues where the test
  provider accepts it, and ends with a refused refresh where it does not.
- A sign-in replaces the volume's login for its client, whatever account, sign-in kind or scopes
  the stored login has, and gives the client new placeholders. Two launches that sign in at once
  to different accounts leave one login whole in the store, the later write's. Where the other
  sign-in's client saves its credentials last, its requests fail, and the next sign-in works.
- After a sign-out, a sign-in to another account replaces the login. A keyless Console sign-in on
  a volume that holds Claude Code's subscription login replaces it.
- A revoke while a refresh holds the lock leaves no login afterwards. A refresh exchange past its
  time bound leaves the old token in the store and is not retried.
- A launcher action that drops a login while a proxy on the volume runs applies to that proxy's
  next request: the login's placeholders then authenticate nothing. The action changes the store
  through its short-lived container, with or without a session on the volume, and leaves no
  container behind.
- A first launch on a fresh volume starts, and two concurrent first launches on one name share a
  volume and its store.
- `--reset` during a delayed refresh exchange removes the proxy (`podman rm --force`) and the
  volume with its store.
- A proxy killed at each point of a store write leaves the old state or the new one, whole.
- After the agent deletes its credentials without a revoke request, its placeholders keep working
  until the launcher action drops the login, and authenticate nothing afterwards.
- While brokering is on, a refresh request with a real refresh token is refused, and the refusal
  says to sign in again. A volume whose client holds real tokens is brokered at the sign-in that
  its refused refresh asks for.
- Codex's token exchange for an API key and `claude setup-token`'s exchange are refused before
  they are forwarded. Codex's browser sign-in completes without a key, and the `setup-token`
  refusal says to run it outside the sandbox. Codex's authorization-code exchange and its
  refreshes pass and change only their own store entries.
- Codex's device poll answers pass unchanged, and store nothing.
- Codex's workspace switch at `/backend-api/accounts/switch-workspace-token` is refused before it
  is forwarded, and no token of another workspace reaches the volume.
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
- An `ant auth login` replaces the volume's Claude Code login, as a Console sign-in does; Claude
  Code then uses that profile, and a refresh by either client changes only that login's store
  entries.
- A response to a write under `/v1/oauth/` on `api.anthropic.com` with an undeclared token field is
  refused, and a `/v1/messages` stream passes as it arrives. A documentation page of 1 MiB at
  `platform.claude.com` passes as it arrives, and so does a read under `/v1/oauth/`. Under the
  presets alone, the ruleset refuses a write outside the checked prefixes at
  `platform.claude.com` and `auth.openai.com`. Where a workspace's rule grants such a write, a
  token response there passes unchecked.
- A refresh response with an undeclared token field is refused to the client, and the store holds
  its declared tokens: the next request under the same placeholders reaches the provider with the
  new access token. A refresh response that names another user, organization or workspace, or a
  scope beyond the sign-in's, stores nothing; scopes in another order, or fewer, are no change.
- A token request with another `client_id` passes unbrokered, and its response changes nothing in
  the store.
- A sign-in or a dropped login in one proxy applies to the next request in another running proxy.
- Under `--egress-login=codex:EMAIL`, a foreign key at `chatgpt.com` is refused before any sign-in,
  and a session without a sign-in leaves the store unchanged. A sign-in to the declared address
  replaces the login, and its placeholder passes. A sign-in to another address, one whose response
  names no address, or one whose `email_verified` is false, is refused, names both identities and
  stores nothing, and a relaunch with the corrected declaration takes its sign-in. In a launch
  that declares no login, the same sign-ins replace the login. After such a sign-in whose
  `email_verified` is false, the store records no address, and a launch that declares that
  address refuses the login's placeholder.
- A later launch without the option resolves the login's placeholder and refuses no foreign key
  at its hosts. A launch that declares another address than the store's login names starts,
  refuses the placeholder and names both addresses; a sign-in to its declared address then
  replaces the login. Of two running launches that declare different addresses, each refuses the
  placeholder while the store's login names the other's address.
- A running session's refusal does not change when another launch on the volume declares a login
  or selects a preset credential.
- With a preset entry and a declared login at one host, each placeholder passes, and a foreign
  token is refused. In a launch that selects the preset entry and declares no login, the login's
  placeholder is refused there and the refusal names `--egress-login`, and a sign-in in that
  launch replaces the login as in any other.
- A launch that declares a login and binds a refusing host with `--egress-cred` starts, and the
  binding's placeholder passes there as the login's does; a foreign token is refused.
- No workspace file declares a login. A declaration for a login whose entry names no email field,
  or cites no evidence that the provider verifies the address, is refused. So is one for a login
  whose provider verifies the address but whose entry cites no evidence that it keeps the address
  on one account.
- A command-line `--egress-login` replaces the options file's entry for its login, and its empty
  value drops the file's entries. A launch that names one login twice is refused. With brokering
  off for a login on the volume, a launch that declares that login is refused and names the action
  that turns brokering on.
- For a login that the launch does not declare, the banner names the login's address and
  `--egress-login`, and says that the launch refuses no other credential at the login's hosts;
  with a preset credential selected at the login's host, it says that the login's placeholder is
  refused there. The launch after a sign-in names the new address. After a sign-in whose proxy
  died before reporting it, the next launch's banner names the new address where that launch's
  proxy reported before the banner printed, and the old one where it had not; the launch after
  names the new one in both orders.
- While brokering is on for a login, a proxy refuses a tunnel to its login host or an API host and
  names the launcher action. The action, in either direction, applies to the next decision in
  every running proxy on the volume, and a tunnel opened before it runs on. A running launch that
  declares the login still refuses the tunnel after the action turns brokering off. At the
  login's API hosts it then refuses the login's placeholder and a foreign token, and a preset
  entry's placeholder that it selected there still passes.
- An action and a proxy's start, in both orders and from launchers with different state roots,
  leave every proxy deciding by the setting that the store holds.
- A volume with brokering off, removed with `podman volume rm` or by `--reset` and created again
  under its name, starts with brokering on; so does a volume whose store is missing. A proxy whose
  store exists but cannot be read refuses to start and leaves the store.
- A brokered login, turned off, then a tunneled launch and a sign-in, completes a request; turned
  back on, its refresh is refused, and a sign-in brokers it again.
- A response to a checked write with a token-like field at an undeclared path, with an error
  status, or beside a declared field at a token endpoint is refused, as is a body over the bound,
  whether its length is declared, chunked or ended by the connection's close. An error response
  that holds only declared token fields is refused and changes nothing in the store.
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
  the connection. A `204` to a checked write reaches the client without `Content-Length` or
  `Transfer-Encoding`, even when the provider sent one. A `103` before a final response reaches
  the client without either header, and the final response is reframed.
- One client that sends two refreshes a second apart keeps working, and both responses carry the
  same placeholders.
- A refresh that changes a claim Codex reads, such as the plan type, reaches Codex's stored ID
  token. Codex refreshes before the access token's `exp` without a 401, and an older access
  placeholder still resolves.
- `--reset-all` keeps a user-named volume and its login.
- A revoke request that a workspace rule refuses leaves the login until the launcher action
  drops it. Codex's revoke of an access token, which carries no `client_id`, retires the login.
- Once a sign-in is brokered, no real token of it reaches the sandbox's environment or persistent
  volume (`ProxyContainerTest`).
- Removing the volume removes its store, and a placeholder copied out of the session authenticates
  nothing elsewhere.
- In the production image, Claude Code, the Codex TUI and `codex exec` each sign in, refresh and
  complete a turn with brokering on, Codex once by its device sign-in and once by its browser
  sign-in.
