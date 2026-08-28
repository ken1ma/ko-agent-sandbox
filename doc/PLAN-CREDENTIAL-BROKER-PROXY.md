# Plan: credential brokering at the egress proxy

## Outcome

A secret the session needs is never inside the sandbox. The sandbox holds a placeholder of the
same shape; the proxy holds the value and substitutes it into one header of requests to the one
inspected host the secret is bound to. Everywhere else the placeholder goes out as it is and
authenticates nothing.

Two secrets qualify:

1. A value forwarded with `--env`, bound to a host: `--env=GH_TOKEN@api.github.com`.
1. Copilot CLI's sign-in — the one agent login that is a forge credential (SECURITY.md,
   "Exfiltration through an allowed host"). The proxy intercepts the device flow's token
   response and hands Copilot a placeholder, so `~/.copilot` in the persistent volume never
   holds the `repo`-scope token.

Delivered in that order; the first is a contained change to the launcher and the inspected
relay, and the second is the same substitution applied at one more site plus a decision about
`api.githubcopilot.com` ("Copilot", below).

## Evidence and target

Two residues SECURITY.md concedes are the target.

- A forwarded `--env` value "is in its environment — tolerated rather than provided for, and
  reaching whatever this project's egress policy admits". A `GET` carries its URL, and a URL is
  a message, so a forwarded token leaves through any restricted host, or inside the opaque model
  tunnel as part of a prompt. Brokered, the sandbox holds nothing worth carrying.
- Copilot's OAuth token, `repo` scope, plaintext under `~/.copilot`, readable by every tool in
  the sandbox and by anything that captures the environment or the volume — the class Codex hit
  when shell snapshots persisted secret variables (openai/codex #30971).

Every comparable project that holds a credential converged on the same shape: Claude Code on the
web (real GitHub token in a proxy outside the VM), Codex CLI (`credential_broker.rs`: dummy of the
same prefix and length in the child's environment, swapped only for the bound GitHub hosts),
Docker Sandboxes (`proxy-managed` sentinel, value in the OS keychain), greywall
(`greyproxy:credential:v1:…`, headers and query only), clampdown (auth-proxy container, `sk-proxy`
inside). Three rules recur and this plan keeps them: sentinel inside, one host per secret,
header-only rewrite.

What brokering does not change: the bound host still receives authenticated requests, within the
method policy the inspected path already enforces (`GET`/`HEAD`, `git-upload-pack` on the
`allow=git-fetch` hosts). It answers "the token leaks", not "the agent spends the token on
something it should not"; repository scoping is a later increment ("Deliberate exclusions").

## Invariants

1. The value reaches the proxy container only, never the sandbox's environment, the persistent
   volume, `/workspace`, the launch banner, or the audit log.
1. A secret binds to exactly one host, which must be `restricted` in the resolved profile. An
   `unrestricted` host is an opaque tunnel where no substitution can happen; a denied or absent
   host is a binding to nothing. Both refuse the launch with the reason.
1. Substitution happens in a declared header only — `Authorization`, or the header a binding
   names — and only when the whole credential token equals the placeholder. Never in the
   request target, the query, a body, or a response. A placeholder that appears anywhere else is
   forwarded verbatim, which is harmless: it authenticates nothing.
1. A value and a header name reach the request bytes only through one grammar, checked where
   each is produced and again where the proxy loads the file. A value is 1–4096 bytes of
   visible ASCII (`0x21`–`0x7E`): no space, tab, control byte, CR, LF, or byte above `0x7E`,
   so it cannot end a field, start another, or alter framing. A header name is one of a closed
   set — `Authorization`, `x-api-key`, `PRIVATE-TOKEN` — never a free token: `Host`,
   `Content-Length`, `Transfer-Encoding`, `Connection` and their kin route or frame, and a
   set is the one shape that needs no list of them. The rewrite replaces the token inside a
   header the client sent; it never adds a header.
1. The placeholder is unpredictable to the checkout: fresh random bytes per launch, in the shape
   of the value it stands for (prefix and length preserved for a recognizable prefix such as
   `ghp_`, `gho_`, `github_pat_`; otherwise the same length of base64url). Tools that validate
   token syntax before sending keep working; nothing can be derived from it.
1. The placeholder, its name and its bound host are printed at launch beside the forwarded
   names, and shown by `--egress-effective`; the policy has one home and one display.
1. A request that spent a credential is marked in the audit line, so `--proxy-log` shows every
   authenticated request the session made and to where.

## Command-line contract

```text
--env=NAME@HOST            forward NAME, brokered: the sandbox sees a placeholder, the proxy
                           substitutes the host value into Authorization for HOST only
--env=NAME=VALUE@HOST      the same with an explicit value
--env=NAME@HOST:HEADER     substitute into HEADER instead of Authorization
                           (x-api-key, PRIVATE-TOKEN)
```

`EnvironmentName` admits no `@`, so a bound forward cannot be mistaken for a plain one. `--env`
stays command-line-only; a repository file cannot bind a host. `KO_AGENT_SANDBOX_*` stays refused.

Refusals, each fatal at launch and naming the fix:

- `HOST` is not in the resolved profile: "add `+host HOST` to `.ko-agent-sandbox/egress/allowed`".
- `HOST` is unrestricted: "an opaque tunnel cannot substitute; bind to a restricted host or
  forward unbrokered with `--env=NAME`".
- `HOST` is denied: the denial wins, as for every other entry.
- two bindings for one `NAME`: refused; one name, one host.
- the value outside the grammar (invariant 4): "value of `NAME` contains a byte a header cannot
  carry" — the byte's offset, never the value; an empty value is "`NAME` is empty".
- `HEADER` outside the set: "header must be one of `Authorization`, `x-api-key`, `PRIVATE-TOKEN`".

## Custody

The value takes the CA leaf's route ("Who holds the CA key"): written by the launcher to a
per-run file under the project's state directory, owner-only, bind-mounted read-only into the
proxy container, removed with the run. Not an environment variable on the proxy container:
`KO_AGENT_SANDBOX_EGRESS_POLICY` is public by design and `podman inspect` shows environment;
a secret does not belong beside it.

The proxy reads the file once at start and refuses to start if a value or header fails the
grammar (invariant 4) or a binding names a host outside its own resolved inspected set — the
same in-both-directions check the leaf certificate gets, for the same reason: a binding the
proxy cannot honour would surface as a 401 inside the sandbox with nothing in the log to
explain it.

## Substitution

In the inspected relay, after the request head is parsed and before `toUpstreamBytes`:

1. Take the header the binding names. `Authorization` is parsed by scheme:
    - `Bearer <token>`, `token <token>`: the whole `<token>` must equal a placeholder.
    - `Basic <base64>`: decode; the password half must equal a placeholder; re-encode with the
      value. This is what git sends for `https://` remotes with a credential helper, and what
      `gh` sends for API calls under `GH_TOKEN`.
    - any other scheme, or a token that is not a placeholder: forwarded unchanged.
1. Another header named by a binding (`x-api-key`, `PRIVATE-TOKEN`): the whole value must equal
   a placeholder.
1. Only bindings whose host is the request's authorized host are consulted. A placeholder bound
   to `api.github.com` inside a request to `gitlab.com` stays a placeholder.
1. The substituted head is what goes upstream; the client never sees the value in any response.
   Response bodies are not rewritten — a server echoing a credential is out of scope, as it is
   without brokering.

The audit line gains one field, `inject=NAME`, on a request whose header was substituted; absent
otherwise. The value and the placeholder never appear in the log.

A credential sent any other way — `https://user:token@host/` in a URL (git puts that into
`Authorization: Basic`, so the URL form is rewritten too; curl likewise), a query parameter, a
multipart field — reaches upstream as the placeholder and fails with the origin's 401. The
proxy cannot tell that case from a wrong token, so the launch banner says it once: "brokered
values are substituted in `Authorization` only".

## Copilot

`copilot login` ends with `POST github.com/login/oauth/access_token`, a request the
`allow=github-login-device` allowance already inspects; the token is in the JSON response body
(`access_token`). Brokering Copilot means:

1. On that response, when a session was launched with `--broker-copilot` (name to settle), the
   proxy replaces `access_token` with a placeholder and writes the value to the run's secret
   file — the one write the proxy makes to the launcher's state directory, through a bind mount
   in the log's manner, so the value outlives the run for the next session's proxy to load.
1. Every later session's proxy loads it as a binding: placeholder → value on `github.com` and
   `api.github.com`, `Authorization` only. Copilot's own state under `~/.copilot` holds the
   placeholder.
1. `--reset` removes the file with the volume.

Whether the placeholder can stand in for the token everywhere Copilot presents it turns on one
fact to measure on the installed CLI, from a `--proxy-log` of a `copilot` session: which token
reaches `api.githubcopilot.com`. Copilot clients generally exchange the GitHub OAuth token at
`api.github.com/copilot_internal/v2/token` for a short-lived Copilot session token and present
only that to the model endpoint. Three cases, in order of preference:

- The CLI uses the exchange and the built-in GitHub MCP server also authenticates with the
  session token. The exchange request is on the inspected path, so the placeholder is
  substituted there and nothing else changes: `api.githubcopilot.com` stays an opaque tunnel,
  the sandbox holds a placeholder plus a short-lived Copilot-scoped token, and the residue
  "writes hidden in model traffic" stays as written.
- The CLI uses the exchange but the MCP server sends the OAuth token itself. Brokering then
  breaks the built-in MCP server and nothing else — `--disable-builtin-mcps` is already the
  documented switch for that surface, so this is the first case with one line added to the
  Copilot paragraph.
- The CLI sends the OAuth token straight to `api.githubcopilot.com`. Then an opaque tunnel
  cannot substitute, and the choice is between two ways out:
    - Inspect `api.githubcopilot.com`: move it to `restricted` with an allowance that admits
      its model traffic (`POST` on the chat paths, a body the proxy does not read, streamed
      responses). The proxy relays a conversation it does not police — the trust the opaque
      tunnel already carries — and gains the substitution point plus, as a by-product, the MCP
      writes become visible and refusable by path. Copilot CLI is a Node program and trusts
      `NODE_EXTRA_CA_CERTS`, so inspection is feasible unless it pins. Cost: the inspected relay
      becomes a long-lived streaming path for one host, and the one-request-per-connection
      stance has to hold under a model client's reconnect pattern.
    - Leave Copilot unbrokered: the token stays real in `~/.copilot`, step 2 is the `--env`
      case only, and the document keeps the residue as written.

## Claude Code and Codex logins: excluded

Not brokered, for reasons that hold independently of effort:

- The Codex CLI is a statically linked binary with compiled-in roots ("Who holds the CA key").
  It cannot be shown the project CA, so nothing between it and `chatgpt.com` /
  `api.openai.com` can be inspected, and there is no substitution point.
- Claude Code is a Node program and could be inspected, but its endpoints are unrestricted by
  design: model traffic has to write, and there is no policy to apply inside it beyond the swap.
  Its login is an OAuth pair with local expiry bookkeeping and a refresh exchange on the
  provider's hosts; the proxy would have to mirror that lifecycle per release, at every refresh,
  for a token that "can only spend model quota". A stolen model token is a nuisance to the
  account holder; a stolen forge token is every private repository. The gain does not pay for
  a per-release contract with the CLI.
- `--env=ANTHROPIC_API_KEY@api.anthropic.com` is the one Claude case the mechanism would fit —
  API-key mode, a fixed header, no lifecycle — and it is refused by invariant 2 because the host
  is unrestricted. If the model endpoints are ever inspected for another reason, the binding
  works unchanged; nothing in this plan is built for it.

## Security model

Additions to SECURITY.md, each at its binding site:

- "Exfiltration through an allowed host": a brokered `--env` value is not in the sandbox; the
  residue narrows to unbrokered forwards and credentials in the checkout.
- "Who holds the CA key" gains a sibling, "Who holds a brokered value": launcher state, proxy
  container, nowhere else; the proxy was already the policy's single point of trust and becomes
  a holder of what the policy admits spending. Its compromise was a full policy compromise and
  is now also a credential — one boundary, not two.
- The Copilot paragraph is rewritten for whichever of the two ways is chosen.
- "The audit line grammar": the `inject` field.

Residues that stay, stated: the credential is still spent by the agent on the bound host within
the allowed methods; the placeholder tells a hostile checkout that a `GH_TOKEN` exists and
where it is honoured (harmless); an origin echoing a credential in a response is not rewritten.

## Implementation sites

### `src/main/scala/AgentSandboxLauncher.scala`

- `EnvForward` gains `binding: Option[(host, header)]`; `forwardedEnvironment` returns the
  sandbox `--env` list with placeholders and, separately, the proxy's secret-file contents.
- Binding validation against the resolved profile, reusing the restricted line read from
  `--print-policy` (the leaf certificate's source of truth, so no second host list).
- `CredentialGrammar`: the value and header-name checks of invariant 4, one source file under
  `container/ko-agent-egress-proxy/app/src/shared/scala/`, which that build compiles as an
  ordinary source and the launcher's `build.sbt` adds to `Compile / unmanagedSourceDirectories`
  — one file, two jars, no copy to drift. Not the proxy dry run, the launcher's authority for
  policy arithmetic: the gate must fire in `PLAN-PROVIDER-CREDENTIAL-PROXY.md`'s management
  verbs before any run exists, and the dry run mounts nothing by design — a secret file in it
  would be one more custody site. The executable-source result there passes through the same
  object.
- Placeholder generation: `SecureRandom`, shape rules from invariant 5.
- Secret file: created 0600 under the run's state directory beside the leaf, mounted read-only
  into the proxy, removed in `SandboxLifecycle` with the leaf.
- Banner and `--egress-effective`: `NAME → HOST (Authorization)` per binding.

### `container/ko-agent-egress-proxy/app`

- Start-up: load bindings, re-check each through `CredentialGrammar`, check hosts against the
  resolved inspected set both ways, refuse otherwise with the mismatch named.
- `HTTPHelper`: `HttpRequestHead.withCredential(bindings)` — the scheme-aware rewrite of one
  header; pure, so it is unit-testable on heads alone.
- `AgentEgressProxy`: apply it on the inspected path before forwarding; emit `inject=NAME`.
- Copilot (step 2): a response-body hook on `POST /login/oauth/access_token` only, JSON field
  replacement, write to the mounted file. A captured token outside the grammar is not stored
  and the exchange is answered with a proxy refusal naming it, not passed through: the token
  must not reach the sandbox by failing to be brokered.

### Tests

- Launcher: grammar (`NAME@HOST`, `NAME=VALUE@HOST`, `:HEADER`), every refusal with its message;
  `CredentialGrammar` over the population of bytes a header cannot carry — CR, LF, NUL, tab,
  space, `0x7F`, a byte above `0x7E`, an empty value, 4097 bytes — each refused from the
  environment and from `=VALUE` alike, and each header name outside the set, `Host` and
  `Transfer-Encoding` among them;
  placeholder shape per prefix, secret file mode and lifetime, banner content, no value in any
  `--env` argument the sandbox receives (`AgentSandboxLauncherTest` already checks the forwarded
  list — extend the same test).
- Proxy unit: `Bearer`, `token`, `Basic` (password half only, user half untouched), other
  header, wrong host, placeholder in URL and query left alone, non-placeholder token untouched,
  two placeholders in one request (one bound to another host); a secret file with a value or
  header outside the grammar refuses start-up; `HostileInputTest` gains the substituted head
  re-parsed as exactly one request with the same header count.
- Proxy end-to-end (`AgentEgressProxyTest` style, local TLS origin): a `GET` with the
  placeholder arrives at the origin with the value; the same to an unbound inspected host
  arrives with the placeholder; audit line shows `inject` exactly once.
- Session boundary (`SessionBoundaryTest`): after a session that forwarded a brokered value,
  the persistent volume and `/workspace` contain neither the value nor the placeholder-to-value
  mapping — the openai/codex #30971 check, population-level over every agent's state directory.
- Copilot (step 2): the token-exchange response reaches the client with the placeholder; the
  next run's proxy substitutes it on `api.github.com`; `--reset` leaves no file.

### Documentation

- README `--env` entry and the Copilot login paragraph.
- SECURITY.md sites above.
- Agent instructions: one line — "a brokered credential works only as `Authorization` on its
  host; a 401 elsewhere is the placeholder, not a wrong token".
- The proxy's 403/401-adjacent guidance is unchanged: the origin answers 401, the proxy does
  not intervene.

## Acceptance checklist

- [ ] Before step 2: a `--proxy-log` of a `copilot` session shows which token the CLI presents
      where ("Copilot"); the case found is written into the Copilot paragraph.

- [ ] `--env=GH_TOKEN@api.github.com` launches; `env` inside the sandbox shows a `gh`-shaped
      placeholder; `gh api user` succeeds; the same token sent to `gitlab.com` arrives there as
      the placeholder (audit line without `inject`).
- [ ] Private `git clone https://github.com/...` with a credential helper returning the
      placeholder succeeds; `git push` is still refused at ref discovery.
- [ ] Every refusal in "Command-line contract" fires with its message.
- [ ] `--proxy-log` shows `inject=GH_TOKEN` on exactly the authenticated requests.
- [ ] `SessionBoundaryTest` finds no value in the volume after exit.
- [ ] `sbt testFull` green on Linux, macOS and Windows podman machines.
- [ ] Step 2 only: `copilot login` completes, `~/.copilot` holds a placeholder, `copilot` works
      in the next session, `--reset` removes the stored value.

## Deliberate exclusions

- Repository scoping (Claude Code cloud's "attached repositories" 403): needs path knowledge
  per forge API; a separate increment on top of this one.
- Response rewriting, body rewriting, query rewriting: the recurring failure of broader
  rewriters is breaking applications that carry their own tokens (docker/sbx-releases #8);
  header-only is the durable form.
- Brokering for unrestricted hosts, hence the Claude/Codex logins ("Claude Code and Codex
  logins: excluded").
- AWS SigV4 re-signing (sandbox-runtime does it): no AWS host is in the catalog; a signed
  request is a body-dependent signature, which is body inspection by another name.
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
  #121 (a forwarded SSH agent reached a private repository under a public-reads policy)
- GreyhavenHQ/greywall — placeholder format, headers-and-query-only rule
- 89luca89/clampdown — auth-proxy container holding the real key
- openai/codex #30971, #32327 — shell snapshots persisted secret environment variables
- code.claude.com/docs/en/cloud-environments — GitHub proxy, branch-scoped push,
  repository-scoped API
