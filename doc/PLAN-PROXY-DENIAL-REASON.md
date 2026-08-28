# Plan: refusals that say what to do next

## Outcome

Every refusal the proxy can express reaches the agent as one line naming the refusal and one
sentence naming the sanctioned next step, at the enforcement point, so the agent instructions
shrink to a pointer and no session is spent diagnosing the proxy.

Three deliverables, one behind the other:

1. Inside TLS, the `403` body carries the reason and the advice.
1. At `CONNECT`, the `403` carries the same body, and `sandbox-egress-check <host>` in the image
   reads it — the only way a `CONNECT` refusal's reason reaches the sandbox, since no client
   shows a tunnel failure's body.
1. `AGENTS-SANDBOX.md`, "Network", keeps only what the body cannot deliver.

## Evidence and target

A refusal inside TLS is `ko-agent-egress-proxy: restricted path` — the reason, not the step.
A refusal at `CONNECT` is `403 Forbidden` with an empty body (`respondQuietly`): curl reports
"CONNECT tunnel failed, response 403", git "Received HTTP code 403 from proxy after CONNECT",
Node "Proxy response (403) !== 200 when HTTP Tunneling". The reason exists only in the audit
log on the host, which the sandbox cannot read by design.

The agent instructions cover two cases in prose — GraphQL is a `POST`, read through REST; an
unreachable host is named to the user — and nothing else. The LFS escape (one file at a time
from `media.githubusercontent.com`) lives only in SECURITY.md, which no agent reads. The
sessions this costs are the ones every comparable tracker shows: "why does `npm install` hang",
"why does clone fail" (google-gemini/gemini-cli #23875, openai/codex #22387). The design that
answers it is sandbox-runtime's `deniedDomainReasons` and Codex's proxy decision reasons —
here fixed and launcher-owned, since the policy admits hosts, not patterns.

## Invariants

1. The audit line is unchanged: its `<why>` stays the short reason ("The audit line grammar").
   Advice is for the agent; the log is for the person, who has the whole document.
1. Every `PolicyViolation` carries advice: the constructor takes both, so a new refusal site
   cannot ship without its next step. `BadRequest` does not — a malformed request is the
   client's defect, and its message already names the defect.
1. Advice names a step the agent can take inside the sandbox, or the one thing to tell the
   user. It never names a way around the policy, and never a host the policy does not admit.
1. The body is plain text, one line per part, no control characters, bounded — what the
   parser already guarantees for everything that reaches it.
1. No body ever contains project data or a credential: the reason and the advice are fixed
   strings plus the host, the rule spelling, the port or the path the request itself named.

## The table

One row per refusal site in `AgentEgressProxy.scala`; the reason column is the audit text as it
is, the advice column is new. Sites are listed by the reason they emit so that the table can be
checked against the code for completeness.

| Reason | Advice |
|---|---|
| `host not allowed` | Not in this session's egress policy. Ask the user to add `+host <host>` to `.ko-agent-sandbox/egress/allowed` on the host. |
| `host denied (<rule>)` | Denied by this project's policy, rule `<rule>`. Ask the user; do not look for another route. |
| `port <n>` | Only port 443 is reachable. |
| `IP-literal target` | Connect by hostname; addresses are refused. |
| `git push ref discovery` | Push is refused in the sandbox. Leave the commits; the user pushes on the host. |
| `restricted path`, path `/graphql` | GraphQL is a `POST`. Read through the REST API. |
| `restricted path`, path ending `/info/lfs/objects/batch` | LFS batch is refused. Read one file from `https://media.githubusercontent.com/media/<owner>/<repo>/<ref>/<path>`. |
| `restricted path`, other | This host is read-only here: `GET` and `HEAD`. Do the write on the host. |
| `restricted host` (`PUT`, `PATCH`, `DELETE`, any other method, or a `POST` to a host with no allowance) | Same as the row above. |
| `request body` | A read carries no body. Send the request without one. |
| `HTTP Upgrade is not allowed` | WebSockets and HTTP/2 upgrades are refused. Use a plain request. |
| `only origin-form request targets are allowed` | Send the path, not the absolute URL. |
| `Host header <declared>` | The `Host` header must name the host the tunnel was opened to. |

Two refusal stages have no body and are outside the table, each with its reason:

- The ClientHello stage — no SNI, SNI not matching the `CONNECT` host, Encrypted ClientHello —
  happens after the `200`, so the proxy closes the connection instead of answering (SECURITY.md,
  "Egress proxy", steps 8–11). The agent sees a TLS failure. One sentence in the instructions
  covers it: "a TLS error on an allowed host is a client sending no SNI or ECH; plain
  `curl`/`git` never do".
- A `502` is the world failing, not a refusal; its body stays the origin error.

The path rows for `restricted path` are matched on the request path the proxy already parsed
(`HttpRequestHead.path`), exact for `/graphql` and suffix for the LFS batch endpoint, so the
advice is chosen by the request, not by a body the proxy does not read.

## `CONNECT`-stage body and `sandbox-egress-check`

The `CONNECT` refusal answers `403` with the same body, `Content-Type: text/plain` and a
`Content-Length` — a proxy's failed `CONNECT` may carry a body, and this one does. No client
displays it, so the image ships `sandbox-egress-check`, beside `sandbox-jdk-use-proxy`:

```text
sandbox-egress-check <host>
```

It sends one `CONNECT <host>:443` to `$HTTPS_PROXY`. On `403` it prints the body and exits 1.
On `200` it wraps the same socket in TLS, trusting `$SSL_CERT_FILE`, sends `HEAD /`, prints the
origin's status line and exits 0. Every line it leaves in the audit log is a real event — one
`deny` for a refused host, one `allow` for an admitted one — the same line the agent's own tool
would have caused; a check leaves no `error` line, because the log's value is that every line is
something that happened. Python, since the image has it and its `ssl` module wraps an existing
socket; `openssl s_client` cannot, and curl does not show a failed `CONNECT`'s body.

It is the in-sandbox twin of the launcher's `--egress-check=<host>`: the launcher's answers on
enforcement's resolver path without a session, this one answers the running session's proxy from
inside. The two agree by construction — one policy, one proxy — and the check's output is what
the agent reports to the user in place of "a host will not connect".

## Agent instructions

`AGENTS-SANDBOX.md`, "Network", after the change:

- the two sentences on `git push`/`POST` refusals and on GraphQL become one: "A refused
  request's `403` body says what to do next."
- "If a host will not connect, name it to the user and stop" becomes "If a host will not
  connect, run `sandbox-egress-check <host>` and report its line to the user; do not look for
  another route."
- one sentence for the ClientHello stage, above.
- the DNS, `HTTPS_PROXY` and CA paragraphs are unchanged: those are act-mode already.

The LFS advice and the GraphQL advice then have one home, the table, and README/SECURITY.md keep
their reference-mode explanations of *why* those requests are refused.

## Security model

SECURITY.md changes at two sites:

- "Egress proxy": the refusal "is a `403` inside the tunnel with the reason in it" gains "and
  the sanctioned next step"; the `CONNECT` refusal gains its body.
- "The audit line grammar": unchanged in substance; one sentence that the response body is
  the agent's copy of `<why>` with advice appended, never the other way round.

Nothing in the boundary moves: the same requests are refused, in the same order, with the same
log. What changes is what the refused party is told.

## Implementation sites

### `container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala`

- `case class PolicyViolation(message: String, advice: String)`; every site updated with its
  row; the `restricted path` site selects its row from `head.path`.
- Both `403` responders take `ex.advice`; `respondQuietly(client, 403, …)` at the `CONNECT`
  stage becomes a `respond` with a body.

### `container/ko-agent-egress-proxy/app/src/main/scala/HTTPHelper.scala`

- `respondInsideTls` body becomes `ko-agent-egress-proxy: <reason>\n<advice>\n`.
- A `respondWithBody(client, status, reason, body)` for the plaintext stage, sharing the
  header construction.

### `container/ko-agent-sandbox/sandbox-egress-check`, `Containerfile`

- The script, installed with the other `sandbox-*` helpers.

### `container/ko-agent-sandbox/AGENTS-SANDBOX.md`

- "Network" as above.

### Tests

- Population-level: a test enumerates every `PolicyViolation` construction in the source and
  fails on one without advice — the constructor's second parameter makes this a compile error,
  so the test instead asserts every advice string is non-empty, one line, control-free, under
  the body bound, and mentions no host outside the request's own.
- Per row: `AgentEgressProxyTest` end-to-end cases asserting the body for each reason —
  `/graphql`, an LFS batch path, `git-receive-pack` discovery, a `PUT`, an unallowed host, a
  denied host with its rule spelled, port 8443, an IP literal.
- `CONNECT` stage: the `403` carries `Content-Length` and the body; the audit line is
  unchanged (existing grammar tests).
- `sandbox-egress-check`: in the self-test image (`container/ko-agent-self-test`), an allowed
  host exits 0 and prints the origin's status; a refused host exits 1 and prints the advice;
  the proxy log shows exactly one line per check, `allow` or `deny`, never `error`.
- `HostileInputTest`: a request whose path is chosen to look like `/graphql` with control
  characters or an absolute URL is refused at the parser before any row applies, so no advice
  is chosen for a path the log would refuse to print.

### Documentation

- README, `--egress-check` entry: one clause naming `sandbox-egress-check` as its in-sandbox
  counterpart.
- SECURITY.md sites above.

## Acceptance checklist

- [ ] `curl -X PUT https://api.github.com/x` inside the sandbox prints the read-only advice.
- [ ] `git push` prints the push advice in git's error output.
- [ ] `curl https://api.github.com/graphql -d '{}'` prints the REST advice; an LFS batch `POST`
      prints the `media.githubusercontent.com` advice.
- [ ] `sandbox-egress-check example.com` prints `403` and the `+host` advice, exit 1;
      `sandbox-egress-check api.github.com` prints the origin's status, exit 0; the log gains
      one `deny` and one `allow` line and no `error`.
- [ ] `--proxy-log` lines for all of the above are byte-identical in their heads and `<why>` to
      the lines before the change.
- [ ] `AGENTS-SANDBOX.md` "Network" states nothing the bodies state.
- [ ] `sbt testFull` green.

## Deliberate exclusions

- Reading the audit log from inside the sandbox: the log's point is to sit outside the run and
  outlive it; the body is the run's copy of the one line the agent caused.
- Approve-on-miss prompts (Codex, Gemini "sandbox expansion", Copilot `allowBypass`): a prompt
  is a prompt-injection target and un-auditable afterwards; authority stays launch-only.
- A per-agent violations channel (sandbox-runtime's `<sandbox_violations>` annotation): needs
  integration per CLI release; the body already lands in the tool output every agent reads.
- Advice for the ClientHello stage in-band: the `200` has been sent; nothing HTTP can follow.
- Rewording the audit `<why>`: tooling relies on the head, and the trailing text is stable
  enough that changing it for the agent's sake would be two homes for one fact.

## References

- anthropic-experimental/sandbox-runtime README — `deniedDomainReasons`
- openai/codex `codex-rs/network-proxy` — `codex.network_proxy.policy_decision` reasons;
  openai/codex #22387 (no DNS inside the sandbox surprised users)
- google-gemini/gemini-cli #23875 (network off by default read as "sandbox unusable")
- docs.github.com, Copilot coding agent firewall — a blocked request is reported with the
  address and the command that made it
