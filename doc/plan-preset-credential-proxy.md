# Plan: preset credentials at the egress proxy

## Outcome

A launch selects a credential by the environment variable that a client reads and by a preset, a
named set of default rules in the proxy image (`egress-proxy.md`, "Choosing an egress profile").
The proxy substitutes the value at every host that the preset's catalog entry names for that
variable. On some of those hosts, the entry's refusing hosts, the proxy also refuses a request
that carries any other credential.

At the refusing hosts, the refusal stops one attack in SECURITY.md, "Exfiltration through allowed
network traffic", for keys in the forms that the catalog declares: an injected instruction supplies
an attacker's API key, and a process uploads workspace files under that key to storage the attacker
retrieves later. The section's other channels, such as data in an allowed URL, header or body, stay
open.

Anthropic closed the same attack in Cowork with a proxy that "only passes requests carrying the
VM's own provisioned session token; an attacker-embedded key is rejected by the proxy"
(https://www.anthropic.com/research/how-we-contain-claude).

`--egress-cred` stays the specification of what this plan reuses (`egress-proxy.md`, "Brokered
credentials"): the placeholder, the value grammar, exact-token substitution, the audit field and
how the value reaches the proxy. `design.md`, "Credential brokering at the egress proxy", records
what neither covers: stored credentials, refresh, OAuth flows and brokering at a tunnel host.

## Why a binding is not enough

An `--egress-cred=NAME@HOST` binding lacks three things that the refusal and a forge token need:

- A binding forwards a token that is not its placeholder, so that an application's own credential
  reaches its host (docker/sbx-releases #8). On a model host, that token can be the attacker's
  key.
- A binding names one header, and a provider accepts several. Anthropic accepts an API key as
  `Authorization: Bearer` and as `x-api-key`, so a check of one header misses a key in the other
  (https://platform.claude.com/docs/en/manage-claude/authentication).
- A binding names one host. Copilot 1.0.111 sends one credential to its plan host and to
  `api.github.com` (`ko-agent-egress-proxy/doc/preset/github-evidence.md`). The GitHub measurement
  in `egress-proxy.md`, "Brokered credentials", needed two names, `GH_TOKEN@api.github.com` and
  `GIT_TOKEN@github.com`, for one token.

The forms and hosts are knowledge about each service, so they belong in a catalog that the proxy
image ships, not in an option that each user writes.

## Selection

```text
--egress-preset-cred=NAME@PRESET
```

- `NAME` is the variable that the client reads, such as `ANTHROPIC_API_KEY` or `GH_TOKEN`.
  `PRESET` names the catalog entry's preset, so the command line shows where the value may go.
- The value comes from the launcher's environment, as an `--egress-cred` value does, and the
  sandbox and the `--run-on-host` commands see `NAME` set to the placeholder.
- The placeholder lasts as long as the persistent volume: each volume gets one random placeholder
  per `NAME@PRESET`, which the launcher keeps in its state under the volume's name and creation
  time. The first launch creates it atomically, so launches that start together agree.
  - Clients keep the value: interactive Claude Code asks to approve each new `ANTHROPIC_API_KEY`,
    with "No (recommended)" preselected (`anthropic-evidence.md`), and Codex's TUI uses the key
    that `codex login --with-api-key` stored. A changed placeholder breaks each kept copy, as
    revisioned handles broke the MCP headers that NemoClaw stores (NVIDIA/NemoClaw #12594).
  - A rotated value keeps the placeholder, and so does a value of another account: each launch's
    proxy holds the value that its own launch supplied, so a copy kept from an earlier session
    gains nothing that the session's own variable lacks. A volume created again under the same
    name gets a new one. `--reset` and `--reset-all` remove the records of the volumes that they
    remove and of volumes that are gone.
  - Launchers with different state roots (`LauncherState.stateRoot`) keep separate records, so
    they give one volume different placeholders. A copy kept in the volume then works only under
    the state root that recorded it; each proxy still refuses every value but its own.
  - A string written before the volume existed equals the placeholder only by chance. A
    placeholder that a session writes into the workspace is still substituted in later sessions on
    that volume, at the entry's hosts and places.
  - Claude Code records a declined key and does not ask again, so a decline holds for the volume;
    `/config`'s "Use custom API key" toggle undoes it (anthropics/claude-code #74858).
  - An `--egress-cred` binding keeps a new placeholder per launch (`egress-proxy.md`, "Where the
    value goes").
- The option is separate from `--egress-cred`. The binding grammar admits a dotless host, so
  `NAME@github` would be ambiguous there, and a binding forwards a foreign token that a preset
  credential refuses.
- The option repeats, and comes from the command line or the options file, never from a repository
  file. In the options file the option behaves as `--egress-cred` does.
- The launch refuses each of these, and names what to change:
  - a `NAME@PRESET` that the catalog lacks;
  - an entry with a host that the session's resolved ruleset does not inspect, such as a host that
    a workspace made a tunnel or a profile does not admit. A tunnel at a refusing host would pass
    the foreign key that the entry refuses, and `design.md` says why brokering never terminates a
    tunnel host. A credential never adds a host, and selecting one does not select its preset;
  - a `NAME` that `--env`, an `--egress-cred` binding or another `--egress-preset-cred` also
    names, after the options file and the command line merge. `--env=NAME` would forward the real
    value that the selection keeps out.
- Nothing else selects a credential: not the agent command, the selected presets or the variable's
  presence in the environment. Docker Sandboxes let unrelated service state change the selected
  mechanism (docker/sbx-releases #344).
- The banner, `--egress-effective` and the agent instructions name each selected `NAME@PRESET`
  with its hosts and places, and name its refusing hosts. None shows the value.

## The catalog

The catalog is a closed image resource beside the presets
(`ko-agent-egress-proxy/app/src/main/resources/defaults/preset/`). Each entry holds:

- the preset and the variable name;
- its targets: an exact host and one place that `--egress-cred`'s grammar admits, with the
  binding's meaning (`egress-proxy.md`, "Where the value goes"). The default place is the token of
  `Authorization` under `Bearer` or `token`, or the password of `Basic`, so one target covers both
  `gh` and Git. An entry may name one host in several targets, one per place;
- every authentication form that the service accepts at each of its hosts, since any of them
  refuses other credentials when the session's rules grant writes there ("Refusing another
  credential");
- the preset's sign-in requests by method and path, as the measurements list them, whose grants
  make no host refusing;
- at each host, the writes, by method and path, that the client sends without a credential, which
  a refusing host forwards without one ("Refusing another credential").

The catalog's parser and tests require:

- every host in the entry's preset or in the inspected catalog (`defaults/host`);
- a host in an entry only when the service documents the host as a recipient of that credential,
  or a measurement shows the client sending that credential there. Convenience is not evidence.

The first entries. The preset evidence files hold their measurements of 2026-11-21, unless an
entry says otherwise:

- `ANTHROPIC_API_KEY@anthropic` at `api.anthropic.com`, in `x-api-key` and in `Authorization`.
  - Claude Code 2.1.326 sends the key in `x-api-key`, as its documentation says
    (https://code.claude.com/docs/en/authentication).
  - The API documents `Authorization: Bearer` first and `x-api-key` as its "legacy fallback". The
    migration guide for API version 2026-10-21 says that Anthropic's SDK and CLI send the key as
    `Bearer` (https://platform.claude.com/docs/en/api/migration-2026-10-21). Both targets keep the
    entry working if Claude Code follows.
  - The entry lists `POST /api/event_logging/v2/batch` as a write without a credential. Claude Code
    sent it before a launch's first request with the key.
    - Claude Code 2.1.326's event exporter builds the request from `Content-Type`, `User-Agent`,
      `x-service-name`, `Accept` and, when compressed, `Content-Encoding`. It adds its credential
      only once workspace trust is established and while its OAuth token is unexpired, and resends
      a batch without one after a 401.
- `CLAUDE_CODE_OAUTH_TOKEN@anthropic` at `api.anthropic.com`, in `Authorization`, with the same
  write without a credential. The variable holds the one-year token that `claude setup-token`
  prints (https://code.claude.com/docs/en/authentication, "Generate a long-lived token").
  - Claude Code 2.1.326 sends the token in `Authorization`, and accepts a placeholder without the
    token's `sk-ant-oat01-` prefix.
  - Claude Code 2.1.330 refused to start Remote Control under this token, which it calls
    inference-only, on a volume without a sign-in. A `/login` token beside it would be foreign to
    the refusal, so Remote Control does not run under this entry.
- `CODEX_API_KEY@openai` at `api.openai.com` and `chatgpt.com`, where Codex fetches its model list
  with the key. Codex 0.169.0 sends the key in `Authorization` to `api.openai.com`, and the same
  value to `chatgpt.com`.
  - `codex exec` sends `CODEX_API_KEY` as its credential, and the TUI does not: it uses the key
    that `codex login --with-api-key` stored (`codex-rs/login/src/auth/manager.rs`, `load_auth` and
    its callers' `enable_codex_api_key_env`).
  - With the built-in OpenAI provider's default settings, Codex sends `OPENAI_API_KEY` as a
    credential only as its realtime conversation's fallback key
    (`codex-rs/core/src/realtime_conversation.rs`). A custom provider can send it through
    `env_key` or `env_http_headers`. Codex's sign-in screen fills in the key from the variable,
    and its telemetry and `codex doctor` report whether the variable is set.
  - An `OPENAI_API_KEY@openai` entry for another client, such as pi or OpenCode, waits for that
    client's measurement.
- `CODEX_ACCESS_TOKEN@openai` at `chatgpt.com` and `auth.openai.com`, for a ChatGPT workspace
  user without an API key.
  - The entry is delivered from Codex's source and documentation, without a measurement:
    `TODO.md` has its measurement, which needs a Business or Enterprise workspace.
  - The variable holds a Codex access token, which only ChatGPT Business and Enterprise workspaces
    issue, at https://chatgpt.com/admin/access-tokens. A token lasts the 1 to 90 days that its
    creator chose under the workspace owner's limit, and an older dialog offers no expiry
    (https://learn.chatgpt.com/codex/enterprise/access-tokens).
  - `load_auth` reads the variable whether or not the mode reads `CODEX_API_KEY`, the TUI
    included, ahead of a stored sign-in. The token's auth holds no refresh: Codex sends the token
    as `Bearer` to `auth.openai.com`'s `/api/accounts/v1/user-auth-credential/whoami` at start,
    then as the bearer of its ChatGPT requests (`codex-rs/login/src/auth/manager.rs`, `load_auth`;
    `codex-rs/login/src/auth/personal_access_token.rs`).
  - Codex reads a value without the `at-` prefix as an agent identity JWT, and checks nothing
    else of the value (`codex-rs/login/src/auth/access_token.rs`,
    `classify_codex_access_token`). So the placeholder is `at-` followed by 22 random letters and
    digits, whatever the token's length. `EgressCredentials` gives no placeholder a fixed prefix
    yet.
  - `auth.openai.com` refuses other credentials, since the `openai` preset grants writes at its
    root. Codex's whoami `GET` carries the placeholder. The measured sign-in requests there carry
    their codes and tokens in bodies, with no credential header (`openai-evidence.md`), so the
    entry lists them as writes without a credential.
- `COPILOT_GITHUB_TOKEN@github` at the four `githubcopilot.com` hosts and `api.github.com`.
  - The variable holds a fine-grained personal access token with the "Copilot Requests" permission
    (https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli).
  - Copilot CLI checks the token locally and sends nothing when the check fails. It refused
    `github_pat_` followed by a placeholder of another length and other characters
    (github/copilot-cli #2431, closed without a stated fix).
  - Copilot 1.0.113 accepted the format-kept placeholder, which keeps the length and each
    character's class, and sent it to `api.github.com` and its plan host.
- `GH_TOKEN@github` at `api.github.com` and `github.com`, both in the default place, so that `gh`
  and a Git credential helper returning `$GH_TOKEN` share one placeholder. Under the defaults the
  entry has no refusing host: the defaults grant neither host a write beyond `github.com`'s
  device-sign-in `POST`s, and a Git fetch of a public repository sends no credential.
- agy has no entry: its sign-in is OAuth with a refresh exchange, and a `GEMINI_API_KEY` session may
  send the key in the query (`ko-agent-egress-proxy/doc/preset/google-evidence.md`).
  kiro-cli has none either: its sign-in token is refreshed at expiry
  (`ko-agent-egress-proxy/doc/preset/aws-evidence.md`).

A workspace or a third-party kit cannot add an entry. A host-owned format for custom entries needs
its own design for provenance and approval, and waits for a service that the reviewed catalog
cannot take.

## Refusing another credential

An entry's refusing hosts are its hosts where the proxy's resolved rules grant a write: a
`method=` or an `upgrade=websocket` grant, whichever file gave it. A host whose only write grants
are the sign-in requests that the catalog lists, by method and path, is not refusing, such as
`github.com` with its device-sign-in `POST`s. Any other write grant at a sign-in path makes it
refusing.

- The rule decides by what the rules grant, not by what the service stores, and rests on two
  assumptions that the proxy does not check:
  - a `GET` or `HEAD` stores no request data that the credential's owner can retrieve later;
  - a measured sign-in request carries its codes and tokens in its body, not in a credential
    header (`github-evidence.md`, `openai-evidence.md`).
- `git-fetch` grants a `POST` to `git-upload-pack` for fetching alone, and is no write grant here.
- Under the defaults, the first entries' refusing hosts are `api.anthropic.com`,
  `api.openai.com`, `chatgpt.com`, `auth.openai.com` and the four `githubcopilot.com` hosts.
- `api.github.com`, where the defaults grant reads alone, gets substitution only, so `gh`'s own
  token and a forge binding still reach it.
- A workspace rule that grants writes at an entry's host makes that host refusing. Otherwise an
  attacker's GitHub token could create a gist of workspace files on an `api.github.com` that the
  workspace opened to `POST`. A session that needs its own token there selects it as an entry's
  credential or binds it with `--egress-cred`; `gh` with a token of its own stops working at that
  host.
- Selected entries that share a refusing host share one refusal there, which accepts each
  entry's placeholder and the placeholder of each `--egress-cred` binding to that host. Every
  accepted value is one that the user selected, so a foreign key stays refused.
  - A Copilot user with private organization repositories needs two tokens: the organization's
    for the repositories and a personal one for Copilot (docker/sbx-releases #886). Under a
    workspace that grants writes at `api.github.com`, `GH_TOKEN@github` and
    `COPILOT_GITHUB_TOKEN@github` both work there.
  - A refusal per entry would refuse the other entry's placeholder, and the user would have to
    drop one of the two clients.

- A foreign key reaches storage that its owner reads back at two of the refusing hosts:
  - `api.anthropic.com`: uploads under a foreign key are a reported attack (SECURITY.md). An
    uploaded file serves later requests by `file_id`, and code execution can produce a file that the
    account downloads (https://platform.claude.com/docs/en/build-with-claude/files).
  - `api.openai.com`: the Files API returns a file's content
    (https://developers.openai.com/api/reference/resources/files/methods/content).
- At `chatgpt.com` and the `githubcopilot.com` hosts, no such storage is known. Refusing there is
  a precaution. It costs every other credential sent there in that session: a workspace's own key,
  unless the launch binds it with `--egress-cred`, and another client's own sign-in, such as
  OpenCode's at `chatgpt.com`.

The rule:

- The proxy forwards a request to a refusing host when the request carries no credential in any
  declared form, or exactly one, which is the placeholder of an entry selected at that host or of
  a binding to that host, in a place that the entry or binding substitutes. The proxy counts each
  occurrence of a repeated header or parameter, and checks before it substitutes.
  - A selected binding's place counts as a declared form at its host, so a binding in a header that
    the catalog does not declare can write there, and a foreign value in that header is refused.
  - `--egress-cred` rewrites each occurrence that holds the placeholder and forwards the others
    (`CredentialTest`). So a foreign key in a second field would otherwise pass beside the
    placeholder.
  - Anthropic's SDKs send two keys when code adds `X-Api-Key` to a client that holds one ("both
    keys go out"), and the API "expects one credential for each request" (the migration guide
    above). The guide does not say which key the API reads.
  - iron-proxy's `replace.require` shows the weaker check: it rejects a request where nothing was
    substituted, and forwards a foreign key beside the placeholder
    (paradigmxyz/iron-proxy, `internal/transform/secrets/secrets.go`).
- A read without a credential in a declared form is forwarded at any path: a `GET` or `HEAD`
  that opens no WebSocket, or a `git-fetch` request. By the first assumption above, a read stores
  nothing for the key's owner to retrieve.
  - Claude Code sends such requests to `api.anthropic.com`, among them WebFetch's domain check
    `/api/web/domain_info` (`ko-agent-egress-proxy/doc/preset/anthropic-evidence.md`, "Requests
    without a credential").
  - Git's first ref discovery for a private repository sends no credential (`egress-proxy.md`,
    "Brokered credentials"), and a public clone none at all, so both pass at a `github.com` that a
    workspace's write grant made refusing.
- A write without a credential in a declared form is forwarded only at a method and path that the
  entry lists.
  - A route qualifies when its audit line has no `cred=` and the client's source or documentation
    shows the request carrying no cookie, query parameter or header that the service accepts as a
    credential: `cred=` counts only the headers that `RequestAudit` knows.
  - A write elsewhere that seems to carry no credential may carry a key in a form that the catalog
    does not declare. Refusing it keeps an incomplete list of forms from reopening the attack at
    the routes that store data.
  - A client release that adds a write without a credential meets a `deny` line until its
    measurement adds the route. Delivery step 4 adds that comparison to each release's
    measurement (`agent-measurement.md`).
- The proxy refuses every other request at every path, with a fixed reason and a `deny` audit line.
- The entry declares every form that the service accepts, not only the one that the client sends:
  a request without the client's header is not thereby unauthenticated.
  - The tests send a foreign key in each declared form, alone and beside the placeholder, and in a
    second occurrence of the placeholder's own header, in both orders.
  - A form that the service accepts and the catalog does not declare reopens the attack in a write
    until the catalog declares it: alone at a route that the entry lists as written without a
    credential, and beside the placeholder at any route, since the proxy cannot tell which
    credential the provider reads.
  - `chatgpt.com` and the `githubcopilot.com` hosts document no complete list. Their declared forms
    are what clients and GitHub's firewall send: `Authorization` with `Bearer`, and also `token`
    at Copilot's hosts (github/gh-aw-firewall, `containers/api-proxy/providers/copilot-auth.js`).
  - Open: whether a ChatGPT session cookie authenticates a request at `chatgpt.com`. If it does,
    the declared form is that cookie by name, not `Cookie` as a whole: Codex sends Cloudflare's
    cookies and its routing cookie `__oailb` there, and its cookie store keeps no account or session
    cookie (`codex-rs/http-client/src/chatgpt_cloudflare_cookies.rs`).
- A workspace that tests against the service with its own key binds it with `--egress-cred`,
  selects no credential for that entry, or accepts the refusal. Every other host in an entry
  forwards a token that is not a placeholder.

## Run-on-host proxies

A host command sees the placeholder too (`egress-proxy.md`, "Brokered credentials"), so its
proxy substitutes the value. That proxy has no refusing host: each program's rules grant `read`
alone (`RunOnHostPrereqs.egressRuleText`).

- The launcher sends a record to a host proxy only when the entry names a host that the
  program's rules allow, as it sends a binding only to the proxy that inspects its host
  (`RunOnHostSandbox.credentialsFor`). The launcher's jar carries the catalog, as it carries the
  presets.
- That proxy expands the entry to those hosts alone, all of which it inspects
  (`RunOnHostSandbox.credentialHosts`).

## What stays open after delivery

- A session that signs in interactively gets no refusal: `claude` under `/login`, Codex under a
  ChatGPT login, `copilot login` and agy. The proxy knows no placeholder of the session's own
  (`design.md`, "Credential brokering at the egress proxy", "Brokering the agents' own logins").
  - A ChatGPT Plus or Pro user has no static token to select instead: only Business and
    Enterprise workspaces issue Codex access tokens.
  - `plan-login-brokering.md` brokers such logins, and gives the refusal the session's own token.
- A request that makes the provider connect to a server the request names carries the session's own
  credential, so the refusal does not stop it (`TODO.md`, "Server tools that connect where a
  request says").
- A path refusal on the model host does not replace the credential refusal (`design.md`, "Model
  hosts inspected by default", "Not done").

## Delivery order

1. Measure each first entry with its hosts inspected at the root (`agent-measurement.md`,
   "Measurement"), and record the result in the preset's evidence file: the header and format that
   carry the credential, every host that receives it, every write sent without one, and whether
   the client accepts the placeholder's format. The first entries were measured on 2026-11-21;
   `CODEX_ACCESS_TOKEN@openai` waits for a workspace that issues the token, after step 2
   (`TODO.md`).
2. Add the catalog, `--egress-preset-cred`, the placeholder per volume and substitution at each
   entry's hosts, without the refusal. Reuse `CredentialGrammar` and `EgressCredentials`.
   - The launcher sends each proxy that has a recipient one record per selected `NAME@PRESET`,
     with its placeholder and value, and the proxy expands the entry's targets from its own
     catalog ("Run-on-host proxies"). Expanding in the launcher would send one name and
     placeholder several times, which the record parser refuses (`CredentialGrammar.checkDistinct`),
     and would copy the host table out of the image.
   - The record is a line kind of its own, not a binding line: the binding grammar would read
     `NAME@PRESET` as a binding to a dotless host. Names and placeholders stay distinct across both
     kinds.
3. Add the refusal.
4. Update SECURITY.md ("Exfiltration through allowed network traffic", "Who holds a brokered
   value"), the README, the launcher help, the agent instructions and the `--egress-effective`
   reference. Delete each plan fact once the code or those documents record it.
   - The README says that `/config`'s "Use custom API key" toggle undoes a declined
     `ANTHROPIC_API_KEY`.
   - Add to `agent-measurement.md`'s manual items a turn under each entry, which fails when a
     release moves the entry's header or rejects its placeholder.
   - Add to `agent-measurement.md`'s checks every write without `cred=` at a refusing host,
     compared with the routes that the entry lists. A new route is a lead for the source reading
     that "Refusing another credential" requires, not evidence that the request carries no
     credential.

## Verification

- Catalog: every entry's hosts are in its preset or the inspected catalog, and its places pass the
  binding grammar.
- Selection: the launch refuses an absent or unknown `NAME@PRESET`, a `NAME` given twice, an
  uninspected host, and a collision with `--env` or `--egress-cred`, including one between the
  options file and the command line. Selecting a credential leaves the selected presets unchanged.
  No workspace file selects a credential.
- The record pipe: one entry with two hosts reaches the proxy as one record and substitutes at
  both hosts. A record and a binding with the same name are refused. A host proxy receives the
  entry's hosts that its program allows, and no other.
- Substitution: `CredentialTest` runs for each entry's places. Each `NAME`'s placeholder differs
  from every binding's and every other `NAME`'s.
- Placeholder per volume: two launches on one volume, one with a rotated value, get the same
  placeholder for an entry. A volume created again under the same name gets a new one, and
  `--reset` removes the record. A launch that selects no entry at a host forwards another entry's
  placeholder there unchanged. A launch that selects only `CLAUDE_CODE_OAUTH_TOKEN@anthropic`
  refuses `ANTHROPIC_API_KEY@anthropic`'s placeholder in a declared form, as a foreign credential.
- Refusal: at several paths, the proxy refuses a foreign key in each declared form, alone and
  beside the placeholder, and the placeholder in two declared forms at once.
  - It forwards a read without a declared credential at any path, and a write without one only at
    a listed route. A placeholder in an undeclared header that no selected binding names counts as
    no declared credential and passes unchanged.
  - With a workspace grant of `POST` at `github.com`, a private clone's first ref discovery and a
    public clone still pass.
  - With `GH_TOKEN@github` and `COPILOT_GITHUB_TOKEN@github` selected and a workspace grant of
    `POST` at `api.github.com`, each placeholder passes there and gets its own value; a foreign
    token, and the two placeholders in one request, are refused. With `GH_TOKEN@github` and an
    `--egress-cred=FORGE@api.github.com` binding, the binding's placeholder passes there too. A
    binding in an undeclared header writes there, and a foreign value in that header is refused.
  - An entry's host that does not refuse forwards a foreign token.
  - A workspace rule that grants `POST` at `api.github.com` makes it refuse a foreign token, and so
    does an `upgrade=websocket` grant there; the banner names it as refusing.
  - Under the defaults, `github.com` does not refuse, and `auth.openai.com` does. A `DELETE` or
    an `upgrade=websocket` grant at `github.com`'s device-sign-in path makes `github.com` refuse.
- `ProxyContainerTest` finds no selected value in the sandbox's environment or persistent volume
  after a session.
- In the production image, each entry's client completes a request with its credential selected:
  a turn for each agent, and `gh api user` and a private `git clone` for `GH_TOKEN@github`.
