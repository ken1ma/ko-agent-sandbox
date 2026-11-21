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
  `platform.claude.com` `/v1/oauth/token`; Codex's `auth.openai.com` `/oauth/token` and
  `/api/accounts/deviceauth/token` (`anthropic-evidence.md`, `openai-evidence.md`), and every
  path on those login hosts for the check below;
- the revoke endpoints, which the measured sign-outs called: Claude Code's `platform.claude.com`
  `/v1/oauth/token/revoke` and Codex's `auth.openai.com` `/oauth/revoke`;
- the response fields that carry tokens, and the request fields where the client sends a token
  back, to refresh or to revoke it;
- the API hosts where the access placeholder resolves, in the places that
  `plan-preset-credential-proxy.md`'s catalog declares.

The proxy:

- reads each response from a login host whole, at any path and with any status, before it
  stores or forwards any part of it, since the presets grant `POST` at the roots of
  `platform.claude.com` and `auth.openai.com`:
  - the body is at most 64 KiB, enforced while the proxy reads a declared length, a chunked body
    or a body that the connection's close ends; a longer one is refused before any byte reaches
    the client. Open: the bound, until step 3's rewrite logs the largest token response;
  - the proxy asks for the body uncompressed (`Accept-Encoding: identity`) and refuses a compressed
    one, so that it reads what the client would;
- refuses the whole response when it holds a field named like a token (`access_token`,
  `refresh_token`, `id_token` or another `*_token`) that the entry does not declare for that path,
  a declared field beside it included. nono checks its capture hosts' unmatched paths and error
  responses for such fields (`docs/cli/features/sandboxed-oauth-logins.mdx`, "token_endpoints");
  - the check fails closed for a moved endpoint, an error response and a new token field, but not
    for a token under a name it does not recognize;
- refuses a response with an error status that holds any token field, declared or not, and stores
  nothing from it, so a failed exchange never replaces a working credential;
- otherwise, for a successful (`2xx`) response, replaces each declared token in a token endpoint's
  response with the volume's placeholder for that field, after it stores the real token;
- puts the real refresh token in place of its placeholder in a token request, and the real access
  token in place of its placeholder at the API hosts.

A login host that a workspace made a tunnel gets no brokering, as a tunnel host gets no
substitution (`plan-preset-credential-proxy.md`, "Selection"). Where a login host refuses other
credentials, its sign-in, refresh and revoke requests, which carry their codes and tokens in bodies
with no credential header, are among the writes that its entry lists as sent without one
(`plan-preset-credential-proxy.md`, "Refusing another credential").

## One placeholder per token kind

Each volume's store holds, per login, one placeholder per token kind (access, refresh and, for
Codex, the ID token) and the current real token behind each. This is Docker's fixed sentinel,
scoped to the volume, and OpenShell's stable handle.

- A refresh replaces the real tokens behind the same placeholders, so the client's credentials file
  keeps the placeholders it has.
- No proxy meets a placeholder that another launch minted and it cannot resolve, which is nono's
  #2087.
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
- Codex's ID token placeholder keeps the current real token's header and claims, and puts the
  volume's random placeholder in the signature's place. So the claims follow each refresh, and the
  signature part stays stable and identifies the placeholder.
  - Codex parses the token locally, reads claims such as the plan type from a refreshed one, and
    its device sign-in checks the account claim against a workspace restriction before it stores
    the token (`codex-rs/login/src/token_data.rs`, `device_code_auth.rs`).
  - `codex exec` 0.169.0 completed turns with a stored ID token whose signature was replaced, and
    with one whose claims were empty, without a refresh (`openai-evidence.md`). The TUI, which may
    read more claims, was not measured.
  - Any ID token placeholder with the volume's signature part resolves to the current real ID
    token, so a client that kept an older one is not stranded.
  - The signature part is not the provider's, so a provider that verifies the signature rejects
    the placeholder. Verification checks that the provider rejects it.
- Codex's browser sign-in also sends the ID token back, as `subject_token` in a token exchange at
  `/oauth/token`, and receives an API key (`codex-rs/login/src/server.rs`, `obtain_api_key`). So
  the entry resolves the ID token placeholder in that field, and the returned key is a token kind
  of its own.

## Which account the store accepts

A sign-in inside the sandbox could bring an attacker's account: a process could exchange an
authorization code that the attacker obtained for their own account, and the provider answers with
real tokens. Captured blindly, that account would stand behind the volume's placeholder, and the
refusal would pass uploads to it.

- The store binds a login to the account of its first brokered sign-in in the volume, and the
  banner names that account at every launch.
- A refresh keeps the placeholders. A token response for another account is refused, and nothing
  is stored.
- The user changes the account on the host, with a launcher action that drops the volume's
  binding and login; the next sign-in then binds anew and gets new placeholders.
- Each client keeps the account in its credentials, and step 3's rewrite confirms the field in
  the token response: Claude Code's credentials file holds `claudeAiOauth.accountUuid` and
  `organizationUuid`; Codex's `auth.json` holds `tokens.account_id`, and its ID token names the
  account by `sub` and `chatgpt_account_id` (`anthropic-evidence.md`, `openai-evidence.md`).
- Open: the first sign-in in a volume is trusted. A host-side confirmation of that account would
  close the case where an attacker's sign-in comes first.

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
- A proxy holds the store's lock exclusively from reading the real refresh token until it writes
  the new tokens. So refreshes serialize, and each one resolves the refresh placeholder to the
  newest real token.
  - One client can refresh twice in quick succession: one `claude -p` run of 2.1.326 sent two
    token requests a second apart, each followed by a new token (`anthropic-evidence.md`).
- A request that resolves a placeholder takes the lock shared, so it waits only while a refresh
  runs, and then gets the new token.
- The lock cannot make the provider's rotation and the store's write one step. A proxy that dies
  after the provider answers and before the store holds the new tokens leaves the old refresh token
  in the store.
  - The next refresh sends the old token. By an OpenAI engineer's account, Codex's provider
    accepts it for a while (Open questions), so the login continues.
  - A provider that rejects the old token ends the login, and the agent signs in again. The proxy
    retries no exchange whose outcome it does not know, as OpenShell does.
- A revoke request retires the login's tokens and placeholders once the proxy has resolved the
  request's placeholder, whatever the provider answers, so those placeholders authenticate nothing
  afterwards.
  - A revoke request that the proxy's rules refuse retires the login too, since the client deletes
    its credentials then as well: the proxy reads the body of a refused request to a declared revoke
    endpoint, up to the 64 KiB bound of login-host bodies, before it answers.
  - The volume keeps its bound account and its refusal: a later sign-in to the same account gets
    new placeholders, and one to another account is refused until the host-side action drops the
    binding ("Which account the store accepts").
  - Both clients delete their local credentials when the revoke request fails, so the store
    follows the request, not the answer: claude 2.1.326 warns that the login may still work, and
    codex 0.169.0 reports a successful logout (`anthropic-evidence.md`, `openai-evidence.md`).
  - A sign-out that sends no request leaves the login in the store until the next sign-in
    replaces it or the volume goes. claude 2.1.326's `/logout` called the revoke endpoint; a user
    reported in March 2026 that `claude logout` revoked nothing (anthropics/claude-code #34198).
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
  reopens this.
- The refusal applies at a refusing host once the volume has bound an account there, signed out or
  not. Until then the host keeps today's behavior, and a launch governed by a binding keeps it
  throughout.
- Each proxy fixes at its start what governs each refusing host: a preset credential, a binding, or
  the volume's brokered login. Another launch's sign-in during its run changes the tokens behind
  a brokered login, not what governs the host.
  - A launch governed by a preset credential or a binding refuses the token responses of that
    host's login, so a sign-in there neither binds the volume nor brings real tokens in. Its
    refusal stays its own credential's for its whole run.
  - Any other launch is governed by the volume's brokered login, bound or not. Its refusal starts
    when the volume binds an account, by this launch's sign-in or another's. Once the volume binds
    an account, the proxy refuses requests carrying an `--env` key at that host, which the
    launch's note says.
- A volume that already holds real tokens: the first brokered sign-in replaces them, and from then
  on the refusal rejects any real token, as a foreign credential.
- A launch whose `--egress-cred` binding names a refusing host where the volume has bound an
  account is refused, as two entries that name one refusing host are. A launch whose `--env` names
  a catalog variable for a refusing host gets a note that the refusal rejects that value once the
  volume binds an account there.
- One refusing host takes one session credential: a launch selects either a preset credential or
  a brokered login there, as two entries that name one refusing host are refused
  (`plan-preset-credential-proxy.md`, "Selection").

## Open questions

- Whether Claude Code's refresh returns a new refresh token and invalidates the old one, and after
  how long. The serialized store makes rotation safe, but rotation decides what a failed exchange
  costs.
  - Codex's refresh returns a new pair, and the old refresh token keeps working "on the order of an
    hour", by an OpenAI engineer's account (openai/codex #10332).
- Whether the Codex TUI accepts the ID token placeholder that `codex exec` accepted.
- Copilot's device-flow token and agy's and kiro-cli's logins: whether each refreshes, and through
  which endpoint.

## Delivery order

1. Measure each login's sign-in, refresh and sign-out, each sign-out with its revoke request
   succeeding and failing, with its hosts inspected: the endpoints, the headers at the API hosts,
   the account that each sign-in names, and whether the client accepts each placeholder. Claude
   Code's and Codex's logins were measured on 2026-11-21.
   - The proxy's log records no body field. The token fields come from Codex's source (a JSON
     refresh request with `client_id`, `grant_type` and `refresh_token`,
     `codex-rs/login/src/auth/manager.rs`) and, for Claude Code, from nono's and Docker's
     declarations. Step 3's rewrite logs the names of the fields it rewrote, never their values,
     and its first run confirms them.
   - Record the result in the preset's evidence file.
2. Measure the store's lock across two proxy containers on one named volume, on macOS, Windows
   and Linux, including a proxy killed while it holds the lock.
   - macOS, podman 6.1.4, 2026-11-21: a second container's `flock -n` exited 1 while the holder
     held the lock and 0 after the holder was killed.
   - Windows, podman 6.2.0, 2026-11-22: the same results. Linux remains.
3. Add the catalog, the store and the rewrite, without the refusal.
4. Let the refusal of `plan-preset-credential-proxy.md` use the volume's access placeholder.
5. Rewrite `design.md`'s section and SECURITY.md ("Agents' own provider logins", "Exfiltration
   through allowed network traffic"), and delete each plan fact once they record it.

## Verification

- Two launches sharing one volume both keep working through a sign-in and a refresh in either, in
  both orders. After one proxy is killed mid-refresh, the login continues where the provider
  accepts the old refresh token, and ends with a refused refresh where it does not.
- A token response for an account other than the volume's is refused, and the store keeps the
  volume's login.
- A response with a token-like field at an undeclared path, with an error status, or beside a
  declared field at a token endpoint is refused, as is a body over the bound, whether its length is
  declared, chunked or ended by the connection's close. An error response that holds only declared
  token fields is refused and changes nothing in the store.
- After a sign-out, a sign-in to another account is refused until the host-side action drops the
  binding.
- A static-credential launch keeps its credential while another launch on the same volume signs
  in, and refuses a sign-in of its own at that host. An `--env` session's real key is refused from
  the moment another launch binds the volume's account.
- One client that sends two refreshes a second apart keeps working, and both responses carry the
  same placeholders.
- A refresh that changes a claim Codex reads, such as the plan type, reaches Codex's stored ID
  token, and an older ID token placeholder still resolves.
- `auth.openai.com` rejects an ID token placeholder sent unresolved, as `subject_token` in the
  token exchange for an API key.
- `--reset-all` keeps a user-named volume's store and removes the stores of removed and missing
  volumes.
- A store whose volume was removed with `podman volume rm`, or created again, is discarded.
- A `--persistent-volume` that names a store is refused. A volume at a store's name without the
  store's label is not mounted into a proxy, and `--reset-all` leaves it in place.
- A revoke request that a workspace rule refuses retires the login: its old placeholders
  authenticate nothing afterwards, and the volume keeps its bound account.
- No real token reaches the sandbox's environment or persistent volume (`ProxyContainerTest`).
- Removing the volume removes its store, and a placeholder copied out of the session authenticates
  nothing elsewhere.
