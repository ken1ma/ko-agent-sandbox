# Plan: preset credentials at the egress proxy

## Outcome

A launch selects a credential by the environment variable that a client reads and by a preset, a
named set of default rules in the proxy image (`egress-proxy.md`, "Choosing an egress profile").
The proxy substitutes the value at every host that the preset's catalog entry names for that
variable. On the hosts that the entry marks, the proxy refuses a request that carries any other
credential.

At the marked hosts, the refusal closes one attack in SECURITY.md, "Exfiltration through allowed
network traffic": an injected instruction supplies an attacker's API key, and a process uploads
workspace files under that key to storage the attacker retrieves later. The section's other
channels, such as data in an allowed URL, header or body, stay open.

`--egress-cred` stays the specification of what this plan reuses (`egress-proxy.md`, "Brokered
credentials"): the placeholder, the value grammar, exact-token substitution, the audit field and
how the value reaches the proxy. `design.md`, "Credential brokering at the egress proxy", records
what neither covers: stored credentials, refresh, OAuth flows and brokering at a tunnel host.

## Why a binding is not enough

An `--egress-cred=NAME@HOST` binding lacks three things that the refusal and a forge token need:

- A binding forwards a token that is not its placeholder, so that an application's own credential
  reaches its host (docker/sbx-releases #8). On a model host, that token is the attacker's key.
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
  sandbox sees `NAME` set to the placeholder.
- The option is separate from `--egress-cred`. The binding grammar admits a dotless host, so
  `NAME@github` would be ambiguous there, and a binding forwards a foreign token that a preset
  credential refuses.
- The option repeats, and comes from the command line or the options file, never from a repository
  file. In the options file the option behaves as `--egress-cred` does.
- The launch refuses each of these, and names what to change:
  - a `NAME@PRESET` that the catalog lacks;
  - an entry with a host that the resolved ruleset does not inspect, such as a host that a
    workspace made a tunnel or a profile does not admit. `design.md` says why brokering never
    terminates a tunnel host. A credential never adds a host, and selecting one does not select its
    preset;
  - a `NAME` that `--env`, an `--egress-cred` binding or another `--egress-preset-cred` also
    names, after the options file and the command line merge. `--env=NAME` would forward the real
    value that the selection keeps out;
  - two selected entries that mark the same host. Each entry has its own placeholder, so each
    entry's refusal would refuse the other's requests. Claude Code sends one of
    `ANTHROPIC_API_KEY` and `CLAUDE_CODE_OAUTH_TOKEN` by its precedence
    (https://code.claude.com/docs/en/authentication#authentication-precedence), so a launch
    selects the one that the session uses.
- Nothing else selects a credential: not the agent command, the selected presets or the variable's
  presence in the environment. Docker Sandboxes let unrelated service state change the selected
  mechanism (docker/sbx-releases #344).
- The banner, `--egress-effective` and the agent instructions name each selected `NAME@PRESET`
  with its hosts and places, and mark the hosts that refuse other credentials. None shows the
  value.

## The catalog

The catalog is a closed image resource beside the presets
(`ko-agent-egress-proxy/app/src/main/resources/defaults/preset/`). Each entry holds:

- the preset and the variable name;
- its targets: an exact host and one place that `--egress-cred`'s grammar admits, with the
  binding's meaning (`egress-proxy.md`, "Where the value goes"). The default place is the token of
  `Authorization` under `Bearer` or `token`, or the password of `Basic`, so one target covers both
  `gh` and Git;
- the hosts that refuse other credentials, each with every authentication form that the service
  accepts there.

The catalog's parser and tests require:

- every host in the entry's preset or in the inspected catalog (`defaults/host`);
- a host in an entry only when the service documents the host as a recipient of that credential,
  or a measurement shows the client sending that credential there. Convenience is not evidence.

The first entries, each to be measured (delivery step 1):

- `ANTHROPIC_API_KEY@anthropic` at `api.anthropic.com`, where Claude Code sends the key in
  `x-api-key`.
- `CLAUDE_CODE_OAUTH_TOKEN@anthropic` at `api.anthropic.com`, in a header that the documentation
  does not name. The variable holds the one-year subscription token that `claude setup-token`
  prints, which makes model requests only (https://code.claude.com/docs/en/authentication).
- `OPENAI_API_KEY@openai` at `api.openai.com` and `chatgpt.com`, where Codex fetches its model list
  with the key.
- `COPILOT_GITHUB_TOKEN@github` at the four `githubcopilot.com` hosts and `api.github.com`.
  - The variable holds a fine-grained personal access token with the "Copilot Requests" permission
    (https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli).
  - The two-host measurement ran under `copilot login`, not with such a token.
- `GH_TOKEN@github` at `api.github.com` and `github.com`, both in the default place, so that `gh`
  and a Git credential helper returning `$GH_TOKEN` share one placeholder. The entry marks no host:
  neither host stores data under the defaults, whose only writes there are the `github` preset's
  device-login `POST`s, and a Git fetch of a public repository sends no credential.
- agy has no entry: its sign-in is OAuth with a refresh exchange, and a `GEMINI_API_KEY` session may
  send the key in the query (`ko-agent-egress-proxy/doc/preset/google-evidence.md`).
  kiro-cli has none either: its sign-in token is refreshed at expiry
  (`ko-agent-egress-proxy/doc/preset/aws-evidence.md`).

A workspace or a third-party kit cannot add an entry. A host-owned format for custom entries needs
its own design for provenance and approval, and waits for a service that the reviewed catalog
cannot take.

## Refusing another credential

An entry marks a host where a foreign credential reaches storage that the credential's owner can
retrieve: each model host where the preset's rules grant writes. The first entries mark
`api.anthropic.com`, `api.openai.com`, `chatgpt.com` and the four `githubcopilot.com` hosts.
`api.github.com`, where the defaults grant reads alone, gets substitution only, so `gh`'s own token
and a forge binding still reach it.

- The proxy forwards a request to a marked host only when the request carries exactly one
  credential across the declared authentication forms, counting each occurrence of a repeated
  header or parameter, and that credential is this run's placeholder in a place that the entry
  substitutes. The proxy checks before it substitutes.
  - `--egress-cred` rewrites each occurrence that holds the placeholder and forwards the others
    (`CredentialTest`). So a foreign key in a second `Authorization` field would otherwise pass
    beside the placeholder.
- The proxy refuses every other request at every path, with a fixed reason and a `deny` audit line.
- The entry declares every form that the service accepts, not only the one that the client sends:
  a request without the client's header is not thereby unauthenticated.
  - The tests send a foreign key in each declared form, alone and beside the placeholder, and in a
    second occurrence of the placeholder's own header, in both orders.
  - A form that the service adds later reopens the attack until the catalog declares the form.
- A workspace that tests against the service with its own key selects no credential for that
  entry, or accepts the refusal. Every unmarked host forwards a token that is not a placeholder.
- Open: whether a client sends a request without credentials to a marked host. The measurement
  decides between an exempt literal path in the entry and the refusal.

What stays open after delivery:

- A session that signs in interactively gets no refusal: `claude` under `/login`, Codex under a
  ChatGPT login, `copilot login` and agy. The proxy knows no placeholder of the session's own
  (`design.md`, "Credential brokering at the egress proxy", "Brokering the agents' own logins").
- A path refusal on the model host does not replace the credential refusal (`design.md`, "Model
  hosts inspected by default", "Not done").

## Delivery order

1. Measure each first entry with its hosts inspected at the root (`agent-measurement.md`,
   "Measurement"), and record the result in the preset's evidence file:
   - the header and format that carry the credential;
   - every host that receives the credential, and every request sent without one;
   - whether the client accepts the placeholder's format (`TODO.md`, "Credential brokering", the
     item on values without a recognized prefix).
2. Add the catalog, `--egress-preset-cred` and substitution at each entry's hosts, without the
   refusal. Reuse `CredentialGrammar` and `EgressCredentials`.
   - The launcher sends the proxy one record per selected `NAME@PRESET`, with its placeholder and
     value, and the proxy expands the entry's targets from its own catalog. Expanding in the
     launcher would send one name and placeholder several times, which the record parser refuses
     (`CredentialGrammar.checkDistinct`), and would copy the host table out of the image.
3. Add the refusal.
4. Update SECURITY.md ("Exfiltration through allowed network traffic", "Who holds a brokered
   value"), the README, the launcher help, the agent instructions and the `--egress-effective`
   reference. Delete each plan fact once the code or those documents record it.

## Verification

- Catalog: every entry's hosts are in its preset or the inspected catalog, and its places pass the
  binding grammar.
- Selection: the launch refuses an absent or unknown `NAME@PRESET`, a `NAME` given twice, an
  uninspected host, two entries marking one host, and a collision with `--env` or `--egress-cred`,
  including one between the options file and the command line. Selecting a credential leaves the
  selected presets unchanged. No workspace file selects a credential.
- The record pipe: one entry with two hosts reaches the proxy as one record and substitutes at
  both hosts.
- Substitution: `CredentialTest` runs for each entry's places. Each `NAME`'s placeholder differs
  from every binding's and every other `NAME`'s.
- Refusal: the proxy refuses a foreign key in each declared form, alone and beside the placeholder,
  a request without credentials, and the placeholder in an undeclared header, at several paths. An
  unmarked host forwards a foreign token.
- `ProxyContainerTest` finds no selected value in the sandbox's environment or persistent volume
  after a session.
- In the production image, each entry's client completes a request with its credential selected:
  a turn for each agent, and `gh api user` and a private `git clone` for `GH_TOKEN@github`.
