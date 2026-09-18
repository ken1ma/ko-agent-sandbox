# Plan: credential brokering at the egress proxy

## Outcome

A secret the session needs is never inside the sandbox. The sandbox holds a placeholder of the
same format; the proxy holds the value and substitutes it into one header or one query parameter
of requests to the one inspected host the secret is bound to. Everywhere else the placeholder goes
out as it is and authenticates nothing.

One secret qualifies here: a value forwarded with `--env`, bound to a host —
`--env=GH_TOKEN@api.github.com`. Copilot CLI's forge-credential sign-in (SECURITY.md, "The web
reached through the model provider") is a provider instance of
`plan-provider-credential-proxy.md`, which reuses the rewrite below ("Copilot").

## Evidence and target

The credential gaps SECURITY.md concedes are the target.

- A forwarded `--env` value "is in its environment — tolerated rather than provided for, and
  reaching whatever this project's egress rules allow". A `GET` carries its URL, and a URL is
  a message, so a forwarded token leaves through any inspected host, or inside the opaque model
  tunnel as part of a prompt. Brokered, the sandbox holds nothing worth carrying.
- Copilot's OAuth token, `repo` scope, plaintext under `~/.copilot`, readable by every program in
  the sandbox and by anything that captures the environment or the volume — the class Codex hit
  when shell snapshots persisted secret variables (openai/codex #30971).

Every comparable project that holds a credential converged on the same design: Claude Code on the
web (real GitHub token in a proxy outside the VM), Codex CLI (`credential_broker.rs`: dummy of the
same prefix and length in the child's environment, swapped only for the bound GitHub hosts),
Docker Sandboxes (`proxy-managed` sentinel, value in the OS keychain), greywall
(`greyproxy:credential:v1:…`, headers and query only), clampdown (auth-proxy container, `sk-proxy`
inside). This plan keeps the recurring rules: sentinel inside, one host per secret, a rewrite in
a declared header or one named parameter, never a body or a response.

What brokering does not change: the bound host still receives authenticated requests, within the
method grants the inspected path already enforces (`GET`/`HEAD`, `git-upload-pack` on the
`git-fetch` hosts). It answers "the token leaks", not "the agent spends the token on
an unauthorized repository"; repository scoping is a later increment ("Deliberate exclusions").
One property it relies on already holds: the rewrite is the one route by which a host-held
credential enters a request, since no other host channel that authenticates — an SSH agent's
socket, a key — is mounted (SECURITY.md, "Credential theft"; `SessionBoundaryTest`'s mount
population). What the sandbox holds of its own toward the same host — an agent's login, an
unbrokered forward, a file in the project — is priced in SECURITY.md and unchanged by this. That
socket is the route of docker/sbx-releases #121.

## Guarantees

1. The value reaches the proxy container only, never the sandbox's environment, the persistent
   volume, the project, the launch banner, or the audit log.
1. An explicit `--env` binding names exactly one host, which must be inspected in the
   resolved profile. A `tunnel` host is opaque, where no substitution can
   happen; a denied or absent host is a binding to nothing. Both refuse the launch with the
   reason. A service instance (`plan-provider-credential-proxy.md`) spends on its finite
   target list instead, under the same rewrite.
1. Substitution happens in one declared place only — `Authorization`, the header a binding
   names, or the query parameter a binding names — and only when the whole credential token
   equals the placeholder. Never in the request path, another header or parameter, a body, or a
   response. A placeholder that appears anywhere else is forwarded verbatim, which is harmless:
   it authenticates nothing.
1. A value, a header name and a parameter name reach the request bytes only through one grammar,
   checked where each is produced and again where the proxy loads the file. A value is 1–4096
   bytes of visible ASCII (`0x21`–`0x7E`): no space, tab, control byte, CR, LF, or byte above
   `0x7E`, so it cannot end a field, start another, or alter framing. A header name is one of a
   closed set — `Authorization`, `x-api-key`, `PRIVATE-TOKEN` — never a free token: `Host`,
   `Content-Length`, `Transfer-Encoding`, `Connection` and their kin route or frame, and a
   closed set is the one form that needs no list of them. A parameter name is free: a parameter
   frames nothing, and the one the proxy reads for policy — `service` in Git discovery
   (`GitHelper`) — is read after the rewrite, since authorization runs on the rewritten head
   ("Substitution"), so no binding passes a check with the placeholder and reaches the origin
   with the value. Into a query the value is written percent-encoded (RFC 3986), since
   the grammar admits `&`, `=`, `#` and `%`, which raw would split or re-parse the query. The
   rewrite replaces the token inside a header or parameter the client sent; it never adds one.
1. The placeholder is unpredictable to the project: fresh random bytes per launch, in the format
   of the value it stands for (prefix and length preserved for a recognizable prefix such as
   `ghp_`, `gho_`, `github_pat_`; otherwise the same length of base64url). Programs that validate
   token syntax before sending keep working; nothing can be derived from it.
1. The placeholder, its name and its bound host are printed at launch beside the forwarded
   names, and shown by `--egress-effective`; the rules have one home and one display.
1. A request that spent a credential is marked in the audit line, so `--proxy-log` shows every
   authenticated request the session made and to where.

## Command-line contract

```text
--env=NAME@HOST            forward NAME, brokered: the sandbox sees a placeholder, the proxy
                           substitutes the host value into Authorization for HOST only
--env=NAME=VALUE@HOST      the same with an explicit value
--env=NAME@HOST:HEADER     substitute into HEADER instead of Authorization
                           (x-api-key, PRIVATE-TOKEN)
--env=NAME@HOST?PARAM      substitute where the whole value of query parameter PARAM equals the
                           placeholder, instead of a header (an Azure SAS `sig`, a Google API
                           `key`)
--env=NAME@HOST/PREFIX/    substitute only for requests whose path is under /PREFIX/; combines
                           with the two above as NAME@HOST/PREFIX/:HEADER or /PREFIX/?PARAM
```

The value of `NAME` is the parameter's value alone. An Azure SAS token is composed around it
inside the sandbox: `"sv=…&sp=rl&sig=$AZURE_SAS_SIG"`.

The prefix form takes the ruleset's own matcher: the canonical-form rule for `PREFIX` and the
literal comparison are the proxy's rule-path ones (doc/egress-proxy.md, "The rule file";
SECURITY.md, "Adding hosts, not patterns"), and the ruleset's own path, if the host's line
has one, applies first. Where requests may go and where a credential may be spent are two facts
and stay two lines; the comparison is one function.

`EnvironmentName` accepts no `@`, so a bound forward cannot be mistaken for a plain one. `--env`
stays command-line-only; a repository file cannot bind a host. `KO_AGENT_SANDBOX_*` stays refused.

Refusals, each fatal at launch and naming the fix:

- `HOST` is not in the resolved profile: "add `allow https://HOST/ read` to
  `.ko-agent-sandbox/egress/rule`".
- `HOST` is a tunnel: "an opaque tunnel cannot substitute; bind to an inspected host or
  forward unbrokered with `--env=NAME`".
- `HOST` is denied: the denial wins, as for every other entry.
- two bindings for one `NAME`: refused; one name, one host.
- the value outside the grammar (guarantee 4): "value of `NAME` contains a byte a header cannot
  carry" — the byte's offset, never the value; an empty value is "`NAME` is empty".
- `HEADER` outside the set: "header must be one of `Authorization`, `x-api-key`, `PRIVATE-TOKEN`".
- `PARAM` empty or containing `&`, `=`, `#` or a byte outside the value grammar: "parameter name
  cannot be carried in a query".
- both `:HEADER` and `?PARAM`: refused; one binding, one place.

## Custody

The value takes the CA leaf's route ("Who holds the CA key"): written by the launcher to a
per-run file under the project's state directory, owner-only, bind-mounted read-only into the
proxy container, removed with the run. Not an environment variable on the proxy container:
`KO_AGENT_SANDBOX_EGRESS_RULESET` is public by design and `podman inspect` shows environment;
a secret does not belong beside it.

The proxy reads the file once at start and refuses to start if a value or header fails the
grammar (guarantee 4) or a binding names a host outside its own resolved inspected set — the
same in-both-directions check the leaf certificate gets, for the same reason: a binding the
proxy cannot honour would appear as a 401 inside the sandbox with nothing in the log to
explain it. The refusal reaches the user through `AgentSandboxLauncher.awaitProxyReady`: the launch
fails with the message.

"Removed with the run" is the run directory's lifetime, which `SandboxLifecycle` ("Removing
what the run created") defines, open edges included: where those edges leave a lingering proxy
and two networks, a binding leaves a lingering value too — owner-only on the host, gone with
`--reset` — at the same price and for the reason that comment gives. A lingering value is never
reused: the next run has its own directory and placeholder.

## Substitution

In the inspected relay, after the request head is parsed and before `authorizeInspectedRequest`,
so that authorization and the origin see the same head:

1. Take the header the binding names. `Authorization` is parsed by scheme:
    - `Bearer <token>`, `token <token>`: the whole `<token>` must equal a placeholder.
    - `Basic <base64>`: decode; the password half must equal a placeholder; re-encode with the
      value. This is what git sends for `https://` remotes with a credential helper, and what
      `gh` sends for API calls under `GH_TOKEN`.
    - any other scheme, or a token that is not a placeholder: forwarded unchanged.
1. Another header named by a binding (`x-api-key`, `PRIVATE-TOKEN`): the whole value must equal
   a placeholder.
1. A query parameter named by a binding: it must occur once, and its percent-decoded value must
   equal a placeholder; the value is written percent-encoded. A parameter that occurs twice is
   forwarded unchanged, as is a placeholder in the path, a header or a parameter no binding
   names.
1. Only bindings whose host is the tunnel's `CONNECT` host are consulted. A placeholder bound to
   `api.github.com` inside a request to `gitlab.com` stays a placeholder.
1. The substituted head is what goes to the origin; the client never sees the value in any response.
   Response bodies are not rewritten — a server echoing a credential is out of scope, as it is
   without brokering.

The `allow` line, printed once the origin leg connects, gains one field, `inject=NAME`, when the
head it forwards had a header or parameter substituted; absent otherwise. A request denied after
substitution spent nothing and its `deny` line carries no `inject`. The value and the placeholder
never appear in the log, on either line: the target is recorded whole, query included
(SECURITY.md, "The audit line grammar"), so a bound parameter's value prints as the binding's
name — `?sig=AZURE_SAS_SIG`.

A credential sent any other way — `https://user:token@host/` in a URL (git puts that into
`Authorization: Basic`, so the URL form is rewritten too; curl likewise), a parameter no binding
names, a multipart field — reaches the origin as the placeholder and fails with the origin's 401.
The proxy cannot tell that case from a wrong token, so the launch banner says it once: "brokered
values are substituted in the bound header or parameter only".

The header form reaches more than forge tokens. Google Cloud and Azure access tokens are bearer
tokens in `Authorization`, so a binding covers them unchanged once a project inspects the API
host — with the `method=POST` grants cloud APIs need and the cloud's CLI or SDK trusting the
launch CA. A Bedrock API key (`AWS_BEARER_TOKEN_BEDROCK`) is a bearer token too, at a host no
default names ("Claude Code and Codex logins: excluded" has why it stays a tunnel).

## Credentials in the query

Two kinds of credential travel in the query, and the rewrite holds one:

- A whole token in one parameter: an Azure storage SAS token's `sig` — an HMAC over the SAS's own
  fields (permissions, expiry, resource), not over the request, so whoever holds it reuses it —
  or a Google API key in `key`. These are bearer credentials in the query, and the `?PARAM`
  binding is for them.
- A request-bound signature: an S3 presigned URL's `X-Amz-Signature`, a Cloud Storage V4 signed
  URL's `X-Goog-Signature`. The signature covers that one request, so the URL is itself a
  one-object, time-bounded credential. Consuming one the sandbox received needs nothing here.
  Generating one computes the signature locally from the signing secret, and no request passes
  the proxy while it happens, so nothing here can hold the secret. Cloud Storage can sign through
  the IAM Credentials `signBlob` API instead: the request carries a bearer token the header form
  covers once the host is inspected, and the response is the signature, so the key stays with
  Google. Azure's `getUserDelegationKey` runs under a bearer token too, but its response is the
  delegation key itself, forwarded unchanged (guarantee 3), so the sandbox then holds a signing
  credential for the account until the expiry the request asked for, at most seven days
  (https://learn.microsoft.com/en-us/rest/api/storageservices/get-user-delegation-key); a
  session that must not hold one obtains the key and signs on the host. AWS has no signing API,
  so a presigned URL is the SigV4 case ("Deliberate exclusions").

This is not the query rewriting "Deliberate exclusions" refuses. That is rewriting every
occurrence of a token, the form that broke applications' own tokens (docker/sbx-releases #8); one
named parameter under whole-value equality is greywall's headers-and-query rule.

## Copilot

Not brokered by this plan. Its production design — a host-side OAuth mechanism or a `gh`
executable source, the token exchanged at `api.github.com/copilot_internal/v2/token` and
substituted by the rewrite above — is `plan-provider-credential-proxy.md`, "OAuth mechanisms",
with the one measurement that design must settle first.

## Claude Code and Codex logins: excluded

Not brokered, for reasons that hold independently of effort:

- The Codex CLI is a statically linked binary with compiled-in roots ("Who holds the CA key").
  It cannot be shown the project CA, so nothing between it and `chatgpt.com` /
  `api.openai.com` can be inspected, and there is no substitution point.
- Claude Code is a Node program and could be inspected, but its endpoints are tunnels by
  design: model traffic has to write, and there are no rules to apply inside it beyond the swap.
  Its login is an OAuth pair with local expiry bookkeeping and a refresh exchange on the
  provider's hosts; the proxy would have to mirror that lifecycle per release, at every refresh,
  for a token that "can only spend model quota". A stolen model token is a nuisance to the
  account holder; a stolen forge token is every private repository. The gain does not pay for
  a per-release contract with the CLI.
- `--env=ANTHROPIC_API_KEY@api.anthropic.com` is the one Claude case the mechanism would fit —
  API-key mode, a fixed header, no lifecycle — and it is refused by guarantee 2 because the host
  is a tunnel. `AWS_BEARER_TOKEN_BEDROCK` at a project's `bedrock-runtime.<region>.amazonaws.com`
  line is the same case: a model endpoint, so a tunnel. If the model endpoints are ever inspected
  for another reason, the binding works unchanged; nothing in this plan is built for it.

## Security model

Additions to SECURITY.md, each at its binding site:

- "Exfiltration through allowed network traffic": a brokered `--env` value is not in the sandbox;
  the gap narrows to unbrokered forwards and credentials in the project directory.
- "Who holds the CA key" gains a sibling, "Who holds a brokered value": launcher state, proxy
  container, nowhere else; the proxy was already the ruleset's single point of trust and becomes
  a holder of what the ruleset allows spending. Compromising it compromises both ruleset and
  credential — one boundary. What a lost reaper leaves, and that `--reset` is what removes it
  ("Custody").
- "The audit line grammar": the `inject` field, and the one exception to "query string
  included": a bound parameter's value prints as the binding's name.

Gaps that stay, stated: the credential is still spent by the agent on the bound host within
the allowed methods; the placeholder tells a hostile project that a `GH_TOKEN` exists and
where it is honoured (harmless); an origin echoing a credential in a response is not rewritten.

## Implementation sites

### `src/main/scala/AgentSandboxLauncher.scala`

- `EnvForward` gains `binding: Option[Binding]` — the host, the place (a header from the closed
  set, or a query parameter name) and the optional prefix; `forwardedEnvironment` returns the
  sandbox `--env` list with placeholders and, separately, the proxy's secret-file contents.
- Binding validation against the resolved profile, reusing the inspected hosts read from the
  allow lines of
  `--print-ruleset` (what the leaf certificate's names are derived from, so no second host list).
- `CredentialGrammar`: the value, header-name and parameter-name checks of guarantee 4, one
  object in the proxy's main sources, which `build.sbt` compiles into the launcher jar for
  `--serve-proxy-on-host`, so both sides run the same check. Not the proxy dry run, the
  launcher's authority for rule arithmetic: the gate must fire in
  `plan-provider-credential-proxy.md`'s management actions before any run exists, and the dry run
  mounts nothing by design — a secret file in it would be one more custody site. The
  executable-source result there passes through the same object.
- Placeholder generation: `SecureRandom`, format rules from guarantee 5.
- Secret file: created 0600 under the run's state directory beside the leaf, mounted read-only
  into the proxy, removed in `SandboxLifecycle` with the leaf.
- Banner and `--egress-effective`: `NAME → HOST (Authorization)` or `NAME → HOST (?sig)` per
  binding.

### `container/ko-agent-egress-proxy/app`

- Start-up: load bindings, re-check each through `CredentialGrammar`, check hosts against the
  resolved inspected set both ways, refuse otherwise with the mismatch named.
- `HTTPHelper`: `HttpRequestHead.withCredential(bindings)` — the scheme-aware rewrite of one
  header, or the percent-aware rewrite of one query parameter; pure, so it is unit-testable on
  heads alone. The same object yields the target as the audit line prints it.
- `AgentEgressProxy`: apply it on the inspected path before forwarding; emit `inject=NAME` and
  the printed target.

### Tests

- Launcher: grammar (`NAME@HOST`, `NAME=VALUE@HOST`, `:HEADER`, `?PARAM`, each with `/PREFIX/`),
  every refusal with its message;
  `CredentialGrammar` over the population of bytes a header cannot carry — CR, LF, NUL, tab,
  space, `0x7F`, a byte above `0x7E`, an empty value, 4097 bytes — each refused from the
  environment and from `=VALUE` alike, and each header name outside the set, `Host` and
  `Transfer-Encoding` among them;
  placeholder format per prefix, secret file mode and lifetime, banner content, no value in any
  `--env` argument the sandbox receives (`AgentSandboxLauncherTest` already checks the forwarded
  list — extend the same test).
- Proxy unit: `Bearer`, `token`, `Basic` (password half only, user half untouched), other
  header, wrong host, placeholder in the path or an unbound parameter left alone, non-placeholder
  token untouched under every scheme, `Bearer` or a `Basic` password — an application's own
  credential for the bound host (docker/sbx-releases #8), two placeholders in one request (one
  bound to another host); a bound parameter substituted and percent-encoded, a value containing
  `&` and `%` decoding intact at the origin, the parameter twice untouched, the printed target
  naming the binding; a `service` binding on a Git host — the value `git-receive-pack` refused at
  ref discovery, its `deny` line printing `?service=NAME` and no `inject`; `git-upload-pack`
  allowed as a fetch, its `allow` line with `inject` — so authorization reads the rewritten head
  in both Git discovery cases; a secret file with a value, header or parameter outside the grammar
  refuses start-up; `HostileInputTest` gains the substituted head re-parsed as exactly one request
  with the same header count and the same parameter count.
- Proxy end-to-end (`AgentEgressProxyTest` style, local TLS origin): a `GET` with the
  placeholder arrives at the origin with the value; the same to an unbound inspected host
  arrives with the placeholder; audit line shows `inject` exactly once; an application's own
  `Bearer` and `Basic` credential to the bound host arrives at the origin unchanged, audit line
  without `inject` — #8 over the whole relay path.
- Lifecycle (`RunTopologyTest`'s lost-reaper case, and a launcher killed between creating the
  run directory and the handover): the value file is either gone with the run or still
  owner-only under its own run directory and gone after `--reset`; never under another run's
  directory.
- Session boundary (`SessionBoundaryTest`): after a session that forwarded a brokered value,
  the persistent volume and the project contain neither the value nor the placeholder-to-value
  mapping — the openai/codex #30971 check, population-level over every agent's state directory.

### Documentation

- README `--env` entry.
- SECURITY.md sites above.
- Agent instructions: one line — "a brokered credential works only in its bound header or
  parameter on its host; a 401 elsewhere is the placeholder, not a wrong token".
- The proxy's 403/401-adjacent guidance is unchanged: the origin answers 401, the proxy does
  not intervene.

## Acceptance checklist

- [ ] `--env=GH_TOKEN@api.github.com` launches; `env` inside the sandbox shows a placeholder in
      GitHub token format; `gh api user` succeeds; the same token sent to `gitlab.com` arrives
      there as the placeholder (audit line without `inject`).
- [ ] `github.com` is another host, so the same value bound under a second name,
      `--env=GIT_TOKEN@github.com`, gets a placeholder of its own; a private
      `git clone https://github.com/...` with a credential helper returning that placeholder
      succeeds, and returning the `api.github.com` one fails with the origin's 401; `git push`
      is still refused at ref discovery. One credential at both hosts under one name is
      `plan-provider-credential-proxy.md`'s first use case.
- [ ] `--env=SAS_SIG@<account>.blob.core.windows.net?sig`, or any `?PARAM` binding, against the
      end-to-end test's local TLS origin, there being no real host to exercise yet: the origin
      receives the value, percent-encoded, in that parameter alone; `--proxy-log` prints
      `?sig=SAS_SIG` and `inject=SAS_SIG`.
- [ ] Every refusal in "Command-line contract" fires with its message.
- [ ] `--proxy-log` shows `inject=GH_TOKEN` and `inject=GIT_TOKEN` on exactly the authenticated
      requests, each at its own host.
- [ ] `SessionBoundaryTest` finds no value in the volume after exit.
- [ ] `sbt testWithPodman` green on Linux, macOS and Windows podman machines.

## Deliberate exclusions

- Repository scoping (Claude Code cloud's "attached repositories" 403): needs path knowledge
  per forge API; a separate increment on top of this one.
- Response rewriting, body rewriting, and rewriting every occurrence of a token in a query: the
  recurring failure of broader rewriters is breaking applications with tokens of their own
  (docker/sbx-releases #8); a declared header or one named parameter is the durable form.
- Brokering for tunnel hosts, hence the Claude/Codex logins ("Claude Code and Codex
  logins: excluded").
- AWS SigV4 re-signing (sandbox-runtime does it): no AWS host is in the catalog; a signed
  request is a body-dependent signature, which is body inspection by another name. Every AWS
  login — `aws login`, `aws sso login`, a static key — ends in an access key the client signs
  with and never sends, so no header carries a placeholder to replace: with the hosts as the
  Pulumi example's `tunnel` lines, guarantee 2 refuses the binding at launch, and with them
  inspected the origin answers `SignatureDoesNotMatch`, not a 401. What a session forwards
  instead, and what bounds it, is `doc/cloud-credentials.md`.
- A keychain or secret-manager resolver on the host (Docker's `gh auth token`, 1Password):
  `--env=NAME` already reads the host environment; a resolver is a shell pipeline in front of
  it.
- Rotation or revocation on exit: `--reset` and the host's own revocation cover it; an
  automatic revoke needs a provider API call the launcher does not make.

## References

- openai/codex `codex-rs/network-proxy/src/credential_broker.rs`, providers `github.rs`,
  `openai.rs`
- anthropic-experimental/sandbox-runtime README, "credential masking" (`injectHosts`)
- docs.docker.com/ai/sandboxes — secrets and the `proxy-managed` sentinel;
  docker/sbx-releases #8 (header rewriting broke an application's own bearer tokens),
  #121 (a forwarded SSH agent reached a private repository under a public-reads ruleset)
- GreyhavenHQ/greywall — placeholder format, headers-and-query-only rule
- 89luca89/clampdown — auth-proxy container holding the real key
- openai/codex #30971, #32327 — shell snapshots persisted secret environment variables
- code.claude.com/docs/en/cloud-environments — GitHub proxy, branch-scoped push,
  repository-scoped API
