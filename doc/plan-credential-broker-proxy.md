# Plan: credential brokering at the egress proxy

## Outcome

The value of a host environment variable named with `--egress-cred` and bound to a host —
`--egress-cred=GH_TOKEN@api.github.com` — is never inside the sandbox or a run-on-host command.
Both see the variable set to a placeholder of the same format; the proxy holds the value and
substitutes it into the `Authorization` header of requests to the one inspected host the value
is bound to, or into the one header or query parameter the option names instead
("Command-line contract"). Everywhere else the placeholder goes out as it is and authenticates
nothing.

This plan keeps no other secret out of the sandbox. `--env=NAME` forwards the value itself into
the sandbox. Copilot CLI's forge-credential sign-in (SECURITY.md, "The web reached through the
model provider") is left to `plan-provider-credential-proxy.md`, which reuses the rewrite below
("Copilot").

## Evidence and target

The credential gaps SECURITY.md concedes are the target.

- A forwarded `--env` value is available in the sandbox's environment, and the egress rules limit
  only where it can be sent (SECURITY.md, "Credential theft"). An allowed `GET` carries its URL,
  and the URL can hold the token, so a forwarded token leaves through any inspected host, or
  inside the opaque model tunnel as part of a prompt. Brokered, the token is not in the sandbox
  to carry out.
- Copilot's OAuth token, `repo` scope, is plaintext under `~/.copilot`, readable by every program
  in the sandbox and by anything that captures the environment or the volume — the class Codex
  hit when shell snapshots persisted secret variables (openai/codex #30971).

Every comparable project that holds a credential converged on the same design:

- Claude Code on the web: the real GitHub token in a proxy outside the VM.
- Codex CLI (`credential_broker.rs`): a dummy of the same prefix and length in the child's
  environment, swapped only for the bound GitHub hosts.
- Docker Sandboxes: a `proxy-managed` sentinel, the value in the OS keychain.
- greywall: `greyproxy:credential:v1:…`, headers and query only.
- clampdown: an auth-proxy container, `sk-proxy` inside.

This plan keeps the recurring rules: placeholder inside, one host per secret, a rewrite in a
declared header or one named parameter, never a body or a response.

What brokering does not change:

- The bound host still receives authenticated requests, within the method grants the inspected
  path already enforces (`GET`/`HEAD`, `git-upload-pack` on the `git-fetch` hosts).
    - Brokering answers "the token leaks", not "the agent uses the token against an unauthorized
      repository"; repository scoping is a later increment ("Deliberate exclusions").
- What the sandbox holds of its own toward the same host — an agent's login, an unbrokered
  forward, a file in the project — is covered in SECURITY.md.

One property brokering relies on already holds: the rewrite is the one route by which a host-held
credential enters a request, since no other host channel that authenticates — an SSH agent's
socket, a key — is mounted (SECURITY.md, "Credential theft"; `SessionBoundaryTest`'s check of
every mount). An SSH agent's socket is the route of docker/sbx-releases #121.

## Guarantees

1. The value reaches the proxies only — the session's proxy container and each run-on-host
   program's proxy ("Run-on-host commands") — never the sandbox's environment, a run-on-host
   command's environment, the persistent volume, the project, the launch banner, or the audit
   log. On its way it is in no file on the host and in no environment or argument of a process
   the launcher starts ("Where the value is held").
1. A binding names exactly one host, which a proxy of the launch must inspect: the session's
   resolved profile, or the rules of a program selected with `--run-on-host` ("Run-on-host
   commands"). A `tunnel` host is opaque, where no substitution can happen; a denied host, or one
   no proxy of the launch allows, is a binding to nothing. Both refuse the launch with the
   reason. For a service instance
   (`plan-provider-credential-proxy.md`), the proxy instead substitutes its credential only in
   requests matching its finite target list, under the same rewrite.
1. Substitution happens in one declared place only — `Authorization`, the header a binding
   names, or the query parameter a binding names — and only when the whole credential token
   equals the placeholder. Never in the request path, another header or parameter, a body, or a
   response. A placeholder that appears anywhere else is forwarded verbatim, which is harmless:
   it authenticates nothing.
1. A value, a header name and a parameter name reach the request bytes only through one grammar,
   checked where each is produced and again where the proxy reads its bindings. A value is 1–4096
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
1. The audit line marks each allowed request forwarded with a substituted credential, so
   `--egress-log` — `--proxy-log`, renamed with this increment into the `--egress-*` family —
   shows every request the session sent a credential with and to where, the run-on-host
   proxies' requests included ("Run-on-host commands").

## Command-line contract

```text
--egress-cred=NAME@HOST          set NAME in the sandbox and in run-on-host commands to a
                                 placeholder; the proxy substitutes the host's value of NAME
                                 into Authorization for HOST only
--egress-cred=NAME@HOST:HEADER   substitute into HEADER instead of Authorization
                                 (x-api-key, PRIVATE-TOKEN)
--egress-cred=NAME@HOST?PARAM    substitute where the whole value of query parameter PARAM
                                 equals the placeholder, instead of a header (an Azure SAS
                                 `sig`, a Google API `key`)
--egress-cred=NAME@HOST/PREFIX/  substitute only for requests whose path is under /PREFIX/;
                                 combines with the two above as NAME@HOST/PREFIX/:HEADER or
                                 /PREFIX/?PARAM
```

The value of `NAME` is the parameter's value alone. An Azure SAS token is composed around it
inside the sandbox: `"sv=…&sp=rl&sig=$AZURE_SAS_SIG"`.

The prefix form takes the ruleset's own matcher: the canonical-form rule for `PREFIX` and the
literal comparison are the proxy's rule-path ones (doc/egress-proxy.md, "The rule file";
SECURITY.md, "Adding hosts, not patterns"), and the ruleset's own path, if the host's line
has one, applies first. Where requests may go and where a credential may be sent are two facts
and stay two lines; the comparison is one function.

`--egress-cred` is an option of its own, not a form of `--env`, so a forgotten `@HOST` is a
refusal, not a forward of the value into the sandbox. `NAME` follows `EnvironmentName`, and
`KO_AGENT_SANDBOX_*` is refused as under `--env`. Like `--env`, it is command-line-only; a
repository file cannot bind a host.

The value comes from the host variable `NAME` alone. There is no `NAME=VALUE@HOST`, though
`--env` takes `NAME=VALUE`:

- `ps` shows a process's arguments to every user of the host, a launcher that stays resident
  keeps them for the whole launch, and a value typed there is in the shell's history file;
- the value grammar (guarantee 4) admits `@`, `:`, `?` and `/`, which are what ends the value
  and starts the host, the header, the parameter and the prefix;
- setting the variable for the launch does the same: `NAME=… <launcher> --egress-cred=NAME@HOST`.

Refusals, each fatal at launch and naming the fix:

- no `@HOST`: "a credential needs a host; to set the value itself in the sandbox, use
  `--env=NAME`".
- `NAME=VALUE@HOST`: "a credential's value is not given on the command line; set `NAME` for
  the launch and pass `NAME@HOST`".
- `HOST` is in no proxy's rules, neither the resolved profile's nor a selected program's: "add
  `allow https://HOST/ read` to `.ko-agent-sandbox/egress/rule` or to
  `.ko-agent-sandbox/run-on-host/<program>/egress/rule`".
- `HOST` is a tunnel: "an opaque tunnel cannot substitute; bind to an inspected host or
  forward the value itself with `--env=NAME`".
- `HOST` is denied: the denial wins, as for every other entry.
- two bindings for one `NAME`: refused; one name, one host.
- `NAME` also given with `--env`: refused; one name, one option.
- the value outside the grammar (guarantee 4): "value of `NAME` contains a byte a header cannot
  carry" — the byte's offset, never the value; an empty value is "`NAME` is empty".
- `HEADER` outside the set: "header must be one of `Authorization`, `x-api-key`, `PRIVATE-TOKEN`".
- `PARAM` empty or containing `&`, `=`, `#` or a byte outside the value grammar: "parameter name
  cannot be carried in a query".
- both `:HEADER` and `?PARAM`: refused; one binding, one place.

## Where the value is held

The value is in memory alone: the launcher's, the runner's, that of a supervisor starting a
proxy, and each proxy's. It is in no file on the host and in no environment or argument of a
process the launcher starts.

- The launcher's own environment holds it, as the user gave it. The handover replaces that
  process with `podman`; a launcher that stays resident (`SandboxLifecycle.handOver`) keeps it
  for the session, and "Run-on-host commands" has what that needs.
- A token works from anywhere until it is revoked. The leaf key ("Who holds the CA key") serves
  only someone between the sandbox and the proxy, so a file is acceptable for the key and not
  for the value: one under the state root reaches backups and outlives a lost reaper.
- An environment is inherited by every helper a process starts, is read by other processes of
  the same user (SECURITY.md, "Run on host"), and on a container is shown by `podman inspect`.
  Arguments are read the same way.

The value travels by pipe, and every proxy takes its bindings on its own standard input: a line
giving their count, then one binding per line, and it reads nothing after them. So the read
neither waits for an end of input nor meets what the writer's ending does to the pipe. A proxy
reads its standard input only with `EGRESS_CREDS=stdin` in its environment, and a launch
without a binding sets neither that variable nor `--interactive`.

- A run-on-host proxy's starter writes them to the process it starts ("Run-on-host commands").
- The session's proxy container is created with `--interactive`, which a start cannot add
  (podman-start(1)), and the launcher starts it with
  `podman start --attach --interactive --sig-proxy=false` in place of `podman start`, writing
  the bindings to that command's standard input: attached, podman pipes it to the contained
  process (podman-create(1), `--interactive`).
  - That `podman start` is a client of the podman machine, which runs the container. It stays
    connected for as long as it is attached, so the launcher ends it once the proxy reports
    ready; `--sig-proxy=false` keeps podman from forwarding that signal to the proxy. The
    remote client leaves the option out of its help and honours it (podman's
    `cmd/podman/containers/start.go`).
  - `src/probe/podman-attach-stdin.sh` measures it: the bytes reach the process, `podman inspect`
    and `podman logs` hold none of them, and the container runs on after the client ends, where
    without the option it stops (macOS, podman 6.1.2 client and 6.1.1 server, 2026-10-04). On
    the Linux and Windows podman machines `ProxyContainerTest` is the first measurement
    ("Tests"); a failure there stops a launch that has a binding or leaves it without egress.
- Not a podman secret, whose default driver keeps it in a file (podman-secret-create(1)). Not a
  `podman exec` writing into the container: the proxy's root is read-only with no tmpfs, its
  audit log its one writable path, and the proxy would take bindings a second way.

Each proxy of the launch — the session's and every run-on-host program's — is given the
bindings whose host its own rules inspect, and no other; a proxy with none is given none. So the
start-up check below holds for every proxy with one rule, and a binding a proxy was not given
is inert there: no request reaches its host, the rules' `deny` line says why, and nothing is
substituted.

The proxy reads its bindings once at start and refuses to start if a value or header fails the
grammar (guarantee 4) or a binding names a host outside its own resolved inspected set — the
same in-both-directions check the leaf certificate gets, for the same reason: a binding the
proxy cannot honour would appear as a 401 inside the sandbox with nothing in the log to
explain it. The refusal reaches the user:

- from the session's proxy, through `AgentSandboxLauncher.awaitProxyReady`: the launch fails with
  the message;
- from a run-on-host proxy, as the refusal of the first command needing it, carrying the proxy's
  first log lines (`RunOnHostSandbox.awaitProxyPort`; doc/run-on-host.md, "Refusals"); the
  launch is up by then.

## Run-on-host commands

A command run on the host (`--run-on-host`) sees `NAME` as the sandbox does: the placeholder, in
the environment the supervisor builds for it (SECURITY.md, "Run on host"). Its requests
pass through its program's proxy, a process from the proxy's codebase (doc/run-on-host.md, "The
command's egress proxy"), which substitutes as the session's proxy does:

- This section is built on the command profile's rule against reading other processes
  (`doc/TODO.md`, "A host command reads other processes' environments"), which comes first.
  Without it a host command reads `NAME` from the launcher's own environment while the launcher
  stays resident, and from any other process of the user that carries it.
- The value reaches each host proxy by pipe ("Where the value is held"):
  - launcher to runner, on the runner's standard input at its start;
  - runner to supervisor, as a frame after the word the runner sends it, on the same pipe;
  - starter to proxy, on the proxy's standard input.
  - The command holds none of these pipes: its standard input is `/dev/null`.
- The frame is not part of the word: the lock holder turns the word's fields into the
  supervisor's arguments (`RunOnHostSession.LockScript`), where another process reads them.
  - The word carries an option saying a frame follows, and no value.
  - The lock holder reads its word a byte at a time, so the frame stays in the pipe across its
    `exec`; the supervisor reads the frame from its standard input, which that pipe remains,
    before it starts its proxy.
- A host proxy's rules are its program's and those of
  `.ko-agent-sandbox/run-on-host/<program>/egress/rule`, not the session's, so a binding whose
  host only those rules allow is honoured by that proxy alone.
  - The proxy's starter — the runner for sbt, `mill` and `gradle`, the supervisor for Maven —
    sends the proxy the bindings those rules allow, as it reads them at the proxy's start.
  - Guarantee 2's tunnel refusal has no case there: a host proxy inspects every host it allows.
- The credential is usable within that proxy's grants, which may differ from the session's; the
  binding widens none of them. A hostile build sees the placeholder, and its route out is that
  proxy's allowed hosts, as without a binding.
- The `inject` field lands in that proxy's audit log, so guarantee 7 needs the host proxy to
  append its audit lines to a `proxy-*.log` file under the project's log directory, as the proxy
  container does:
  - the log's last 64 KiB alone is kept, appended to the launch's `run-on-host-*.log` when the
    runner's session ends or, for Maven's proxy, when the command ends by signal
    (`RunOnHostSandbox.appendSessionLogs`; doc/run-on-host.md, "The channel and the command"), so
    a Maven command that ends normally loses it with its directory;
  - `--proxy-log`, which guarantee 7 renames, prints the `proxy-*.log` files alone
    (`EgressRules.retainedLogs`).
- Each proxy reads its bindings once at start and lives at most the launch, and the placeholder is
  per launch, so a mill or Gradle daemon kept across commands never meets a stale binding.
- Windows has no run-on-host, so nothing applies there.

## Substitution

In `runInspectedConnection`, after the request head is parsed and before
`authorizeInspectedRequest`, so that authorization and the origin see the same head:

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
substitution sent no credential and its `deny` line carries no `inject`. The value and the
placeholder never appear in the log, on either line: the target is recorded whole, query included
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

Not brokered:

- The Codex CLI trusts the CA in `SSL_CERT_FILE` ("Who holds the CA key"). Its built-in
  provider opens a websocket first; the proxy refuses the `Upgrade` on an inspected connection,
  and Codex then falls back to HTTP. Measured with codex-cli 0.155.1 signed in with an API key,
  against a local server that answers the upgrade with an error (2026-09-22): seven
  `GET /v1/responses` with `Upgrade: websocket` over about seven seconds, then
  `POST /v1/responses`. It is not brokered until one turn succeeds over an inspected connection;
  that, and the ChatGPT login, are not measured.
- Claude Code is a Node program and could be inspected, but its endpoints are tunnels by
  design: model traffic has to write. Its login is an OAuth pair with local expiry bookkeeping
  and a refresh exchange on the provider's hosts; the proxy would have to mirror that lifecycle
  per release, at every refresh. A stolen model token is a nuisance to the account holder; a
  stolen forge token is every private repository. The gain from hiding the token does not pay
  for a per-release contract with the CLI.
- Hiding the token is not the only rule an inspected model host could apply: which credential
  may reach the host is another, and a tunnel cannot apply it (SECURITY.md, "Exfiltration
  through allowed network traffic"). `doc/TODO.md`, "Credential brokering", has that item; it
  needs no mirror of the login's lifecycle for an API key.
- `--egress-cred=ANTHROPIC_API_KEY@api.anthropic.com` is the one Claude case the mechanism
  would fit — API-key mode, a fixed header, no lifecycle — and it is refused by guarantee 2
  because the host is a tunnel. `AWS_BEARER_TOKEN_BEDROCK` at a project's
  `bedrock-runtime.<region>.amazonaws.com` line is the same case: a model endpoint, so a tunnel.
  If the model endpoints are ever inspected for another reason, the binding works unchanged;
  nothing in this plan is built for it.

## Security model

Additions to SECURITY.md, each in the section that covers it:

- "Exfiltration through allowed network traffic": an `--egress-cred` value is in neither the
  sandbox nor a run-on-host command; the gap narrows to `--env` forwards and credentials in the
  project directory.
- "Who holds the CA key" gains a sibling, "Who holds a brokered value": the memory of the
  launcher, the runner, a supervisor and each proxy, and the launcher's own environment as
  given; no file, and no environment or argument of a process the launcher starts ("Where the
  value is held"). A proxy was already the ruleset's single point of trust and becomes a holder
  of the credentials sent under it: compromising it compromises both — one boundary.
- "Run on host": the command's environment carries the placeholder, its proxy holds the value,
  the value passes the runner and the supervisor by pipe, and the profile's rule keeps a
  command from reading the launcher's environment ("Run-on-host commands").
- "The audit line grammar": the `inject` field, and the one exception to "query string
  included": a bound parameter's value prints as the binding's name.

Gaps that stay, stated:

- the credential is still used by the agent against the bound host within the allowed methods;
- the placeholder tells a hostile project that a `GH_TOKEN` exists and where it is honoured
  (harmless);
- an origin echoing a credential in a response is not rewritten;
- a token in the environment or arguments of another process of the user — one exported in a
  shell profile, or the launcher's own while it stays resident — is readable by a host command
  while the command profile allows that read (`doc/TODO.md`, "A host command reads other
  processes' environments").

## Implementation sites

### `src/main/scala/AgentSandboxLauncher.scala`

- `--egress-cred` parses to its own case class beside `EnvForward` — the name, the host, the
  place (a header from the closed set, or a query parameter name) and the optional prefix;
  `EnvForward` and `--env` parsing are unchanged. `forwardedEnvironment` returns the sandbox
  `--env` list with the placeholders appended and, separately, the bindings with their values,
  which join no argument list and no environment. The supervisor builds each host command's
  environment from the same placeholder list (`RunOnHostSandbox.commandEnvironment`).
- Binding validation against the resolved profile, reusing the inspected hosts read from the
  allow lines of `--print-ruleset` (what the leaf certificate's names are derived from, so no
  second host list), and against the selected programs' rule files, which the launch already
  reads for its widening report (`runOnHostWideningLines`); the proxy's starter reads them again
  at the proxy's start ("Run-on-host commands"), and the bindings it sends then follow that
  reading.
- `CredentialGrammar`: the value, header-name and parameter-name checks of guarantee 4, one
  object in the proxy's main sources, which `build.sbt` compiles into the launcher jar for
  `--serve-proxy-on-host`, so both sides run the same check. Not the proxy dry run, which
  resolves the ruleset for the launcher: validation must run in
  `plan-provider-credential-proxy.md`'s management actions before any run exists, and the dry run
  mounts nothing by design — a value handed to it would be one more place holding the secret. The
  executable-source result there passes through the same object.
- Placeholder generation: `SecureRandom`, format rules from guarantee 5.
- The values: written to the runner's standard input at its start (`RunOnHostChannel`), and
  `NAME` removed from the environment of every process the launcher starts, `podman` included.
  The proxy container: created with `--interactive` and `EGRESS_CREDS=stdin`, started
  attached, the bindings written, and that podman process ended after the ready line ("Where the
  value is held"); with no binding, created without either and started detached.
- Banner and `--egress-effective`: `NAME → HOST (Authorization)` or `NAME → HOST (?sig)` per
  binding.
- `--proxy-log` becomes `--egress-log` (guarantee 7), the no-argument form printing the host
  proxies' retained logs with the containers'. The supervisor's own `--proxy-log=<file>`
  (`RunOnHostSandbox.ProxyLogOption`) is an internal option, not this action, and keeps its name.

### `src/main/scala/RunOnHostSandbox.scala` and `RunOnHostSession.scala`

- `startProxyUnder`: the bindings whose host the proxy's rules allow ("Where the value is
  held"), written to the proxy's standard input, with `EGRESS_CREDS=stdin` in its closed
  environment. The runner reads the launch's bindings from its own standard input, and sends a
  supervisor its proxy's as a frame after `RunOnHostSession.runWord`, whose arguments name no
  value.
- `RunOnHostSession.LockScript`: the word read with `sysread`, a byte at a time, in place of
  the buffered line read, which would take the frame's bytes and lose them at the `exec`.
- The host proxy's audit log appended to a `proxy-*.log` file under the project's log directory
  ("Run-on-host commands"), so `--egress-log` prints it; `appendSessionLogs` keeps its tail in
  the channel log, which is what is read for a stalled command.

### `container/ko-agent-egress-proxy/app`

- Start-up: with `EGRESS_CREDS=stdin`, read the count line and the bindings from standard
  input before the ready line and nothing from it after, re-check each through
  `CredentialGrammar`, check hosts against the resolved inspected set both ways, refuse
  otherwise with the mismatch named.
- `HTTPHelper`: `HttpRequestHead.withCredential(bindings)` — the scheme-aware rewrite of one
  header, or the percent-aware rewrite of one query parameter; pure, so it is unit-testable on
  heads alone. The same object yields the target as the audit line prints it.
- `AgentEgressProxy`: apply it on the inspected path before forwarding; emit `inject=NAME` and
  the printed target.

### Tests

- Launcher:
  - grammar (`NAME@HOST`, `:HEADER`, `?PARAM`, each with `/PREFIX/`), every refusal with its
    message, `--egress-cred=NAME` without a host and `NAME=VALUE@HOST` among them;
  - a binding whose host only a selected program's rules allow launches, and the session proxy
    is not given it;
  - `CredentialGrammar` over every value a header cannot carry — CR, LF, NUL, tab, space,
    `0x7F`, a byte above `0x7E`, an empty value, 4097 bytes — each refused, and each header name
    outside the set, `Host` and `Transfer-Encoding` among them;
  - placeholder format per prefix, banner content, no value in any file under the state root,
    in any `--env` argument the sandbox receives, in any environment a supervisor builds, or in
    the environment or arguments of `podman`, the runner or a supervisor
    (`AgentSandboxLauncherTest` already checks the forwarded list — extend the same test).
- Proxy unit:
  - `Bearer`, `token`, `Basic` (password half only, user half untouched), other header, wrong
    host, placeholder in the path or an unbound parameter left alone, non-placeholder token
    untouched under every scheme, `Bearer` or a `Basic` password — an application's own
    credential for the bound host (docker/sbx-releases #8), two placeholders in one request
    (one bound to another host);
  - a bound parameter substituted and percent-encoded, a value containing `&` and `%` decoding
    intact at the origin, the parameter twice untouched, the printed target naming the binding;
  - a `service` binding on a Git host — the value `git-receive-pack` refused at ref discovery,
    its `deny` line printing `?service=NAME` and no `inject`; `git-upload-pack` allowed as a
    fetch, its `allow` line with `inject` — so authorization reads the rewritten head in both
    Git discovery cases;
  - bindings with a value, header or parameter outside the grammar refuse start-up;
  - `HostileInputTest` gains the substituted head re-parsed as exactly one request with the
    same header count and the same parameter count.
- Proxy end-to-end (`AgentEgressProxyTest` style, local TLS origin): a `GET` with the
  placeholder arrives at the origin with the value; the same to an unbound inspected host
  arrives with the placeholder; audit line shows `inject` exactly once; an application's own
  `Bearer` and `Basic` credential to the bound host arrives at the origin unchanged, audit line
  without `inject` — #8 over the whole inspected path.
- Proxy container (`ProxyContainerTest`): bindings written to the attached start substitute at
  the test's origin; the container runs on after that podman process ends; `podman inspect` and
  `podman logs` hold no value; without `EGRESS_CREDS` the proxy never reads its standard
  input.
- Lifecycle (`RunTopologyTest`'s lost-reaper case, and a launcher killed between creating the
  run directory and the handover): no file under the state root holds the value in either case.
- Session boundary (`SessionBoundaryTest`): after a session that forwarded a brokered value,
  the persistent volume and the project contain neither the value nor the placeholder-to-value
  mapping — the openai/codex #30971 check, run over every agent's state directory.
- Run on host (`RunOnHostSandboxTest`, macOS):
  - a command's environment holds the placeholder; a request from the command to the bound
    host, allowed by the program's rule file, arrives at the test's local origin with the value
    and its `allow` line carries `inject`;
  - with a binding whose host the program's rules lack, the proxy starts, a request to that
    host gets a `deny` line and no `inject`, and a request to an allowed host is served;
  - no file under the session root holds the value, and neither the runner's nor a
    supervisor's environment or arguments do, read as `src/probe/ProcArgs.java` reads them;
    with the launcher resident, that read of the launcher from a host command is refused;
  - the proxy's audit lines are among what `--egress-log` prints.
- Lock holder (`RunOnHostSessionTest`): bytes the runner writes after the word reach the exec'd
  command's standard input whole, and none of them is among its arguments.

### Documentation

- README: an `--egress-cred` entry after `--env`; `--proxy-log` renamed to `--egress-log` there,
  in SECURITY.md, doc/egress-proxy.md, doc/TODO.md, `plan-provider-credential-proxy.md` and
  `plan-tls-inspect-agents.md`.
- SECURITY.md sites above.
- Agent instructions: one line — "a brokered credential works only in its bound header or
  parameter on its host; a 401 elsewhere is the placeholder, not a wrong token".
- The proxy's 403/401-adjacent guidance is unchanged: the origin answers 401, the proxy does
  not intervene.

## Acceptance checklist

- [ ] `--egress-cred=GH_TOKEN@api.github.com` launches; `env` inside the sandbox shows a
      placeholder in GitHub token format; `gh api user` succeeds; the same token sent to
      `gitlab.com` arrives there as the placeholder (audit line without `inject`).
- [ ] `github.com` is another host, so the same value bound under a second name,
      `--egress-cred=GIT_TOKEN@github.com`, gets a placeholder of its own. One credential at
      both hosts under one name is `plan-provider-credential-proxy.md`'s first use case.
- [ ] A private `git clone https://github.com/...` with a credential helper returning the
      `GIT_TOKEN` placeholder succeeds, and returning the `api.github.com` one fails with the
      origin's 401; `git push` is still refused at ref discovery.
- [ ] `--egress-cred=SAS_SIG@<account>.blob.core.windows.net?sig`, or any `?PARAM` binding,
      against the end-to-end test's local TLS origin, there being no real host to exercise yet:
      the origin receives the value, percent-encoded, in that parameter alone; `--egress-log`
      prints `?sig=SAS_SIG` and `inject=SAS_SIG`.
- [ ] With `--run-on-host=sbt` and `maven.pkg.github.com` allowed in
      `.ko-agent-sandbox/run-on-host/sbt/egress/rule`, `--egress-cred=GH_TOKEN@maven.pkg.github.com`
      resolves a private GitHub Packages artifact from `sbt` on the host; `env` in the command
      shows the placeholder; `--egress-log` shows the sbt proxy's `inject=GH_TOKEN` line.
- [ ] With a binding and `--run-on-host`, no file under the state root or the session root
      holds the value, and `src/probe/ProcArgs.java` reads it from neither `podman`'s, the
      runner's nor a supervisor's environment or arguments.
- [ ] Every refusal in "Command-line contract" fires with its message.
- [ ] `--egress-log` shows `inject=GH_TOKEN` and `inject=GIT_TOKEN` on exactly the authenticated
      requests, each at its own host.
- [ ] `SessionBoundaryTest` finds no brokered value in the volume after exit.
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
  `--egress-cred=NAME@HOST` reads the host environment as `--env=NAME` does; a resolver is a
  shell pipeline in front of it.
- Rotation or revocation on exit: the value is in no file for an exit to leave, and the host's
  own revocation covers a leak; an automatic revoke needs a provider API call the launcher does
  not make.

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
