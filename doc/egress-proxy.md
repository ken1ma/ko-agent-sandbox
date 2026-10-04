# The egress proxy

- Every sandbox session reaches the network through one HTTPS proxy in its own container, on a
  network the session cannot route out of.
- The ruleset specifies the reachable hosts, permitted operations and whether requests are
  inspected.
- The proxy resolves it from its built-in defaults, the profile selected at launch, and the
  project's rule file, and prints it at every start.

This document explains how to write the rule file and read the printout. SECURITY.md, "Egress
proxy", explains the protections and their limits.

A *rule* is a line of the project's file, what is written and reviewed; the *ruleset* is what a
launch enforces: the defaults, the profile and the file resolved together, printed as the ruleset
lines and named by a digest. Two files of different rules may resolve to one ruleset.

## Choosing an egress profile

Every launch selects an `--egress=` profile; `deny-unless-allowed` is the default. An allowed
host has one of two treatments:

- a `tunnel`, whose application traffic stays opaque after the TLS identity check;
- inspected — TLS terminated, each request decided against its resolved scope, and refused where
  no grant allows it ("The rule file" below; SECURITY.md, "Reading without being able to write",
  has what each grant permits, the costs of inspection and what it prevents).

Handshake failures are logged for both treatments; SECURITY.md defines the checks and audit events.

The proxy's default rules, listed in the proxy image's `defaults/host` and
`defaults/model-provider/*` with the reason beside each line:

- for every supported model provider — `anthropic`, `openai`, `google`, `aws` and `github` —
  tunnels to model, authentication and control-plane endpoints; GitHub's rules also permit two
  inspected login `POST`s and one token read, and Google's two inspected reads of the signed-in
  account;
- inspected documentation, package-registry and forge hosts, with `read` on every line and
  `git-fetch` on the three forges.

The profiles:

1. `deny-unless-allowed` (the default) — the defaults, then every line of the project's file.
1. `deny-unless-model` — default rules for the launched agent's provider, then the file's URL
   and model-provider denials. It ignores `allow` and `deny defaults` lines.
   - `claude` selects `anthropic`, `codex` selects `openai`, `agy` selects `google`, `kiro-cli`
     selects `aws`, `copilot` selects `github`; `opencode`, which has no fixed provider, selects
     every provider under `defaults/model-provider/`.
   - Only the basename of the directly launched command is classified; anything else selects no
     provider, allows no host, and says so at startup.
1. `deny-all` — nothing.

## The rule file

One file, `.ko-agent-sandbox/egress/rule` in the project directory. One line per rule, in the
order they apply; `#` starts a comment at the start of a line or after whitespace, and blank
lines are ignored.

```text
deny defaults
allow https://HOST/PREFIX/ GRANT...                       tree
allow https://HOST/PATH    GRANT...                       one path
allow https://HOST/        tunnel                         alone, at the root
allow model-provider NAME
deny  https://HOST/        [GRANT...]                     never a path
deny  https://**.DOMAIN/   [GRANT...]
deny  model-provider NAME

GRANT: read | git-fetch | method=M,... | tunnel           at least one; each once
```

- `HOST` is an exact hostname — IDN mapped, lowercased, one trailing dot removed — never an IP
  literal, a port, userinfo, a query or a fragment.
- `**.` is the deny side's only pattern, the apex and everything under it (`**.foo.com` covers
  `foo.com` and `api.foo.com`, never `barfoo.com`).
- The path is written in canonical form, one spelling for each path (`RulePath.literalPathProblem`):
  - it begins with `/`, in printable ASCII, with no `\`, `;`, `?`, `#`, empty segment, or `.` or
    `..` segment; servlet containers drop a `;` parameter before resolving `..`, so `/a/..;/b` is
    `/b` to Tomcat;
  - `%` only escapes non-ASCII text, in UTF-8, or a space (`%20`): `/docs/%E3%81%82/` is one path,
    and `%41` or `%2e` is refused, since `A` and `.` have a spelling of their own. Hex case is
    compared as written, as letter case is: a request in the other case is not under the line;
  - an escape must decode as strict UTF-8, so no overlong form spells `.` or `/` (`%C0%AE`), and
    its text may not gain `/`, `\`, `.`, `;`, `%`, `?` or `#` under Unicode normalization (NFKC), as
    the fullwidth `／` (`%EF%BC%8F`) and U+037E (`%CD%BE`, `;` under NFC already) do.
- A trailing `/` names the tree under it; none names that one path; `https://HOST/` is the root,
  the whole host. `https://HOST` without its slash is refused, never read as the root.
- Case is the origin's: the proxy folds nothing.

What a line grants is its words, and nothing is implied:

- `read` — `GET` and `HEAD`, without a body or `Content-Length` or `Transfer-Encoding` headers.
  Even `Content-Length: 0` is refused.
- `git-fetch` — a clone's two requests, the ref discovery (`GET .../info/refs?service=
  git-upload-pack`) and the transfer (`POST .../git-upload-pack`). A `git-fetch` line without
  `read` is clonable and not browsable; a `read` line without `git-fetch` is browsable, and a
  clone fails at its first request. `git-fetch` never grants `git push`.
- `method=POST,PUT,...` — the listed methods, from `POST`, `PUT`, `PATCH`, `DELETE`, at that
  path, without granting general `GET` or `HEAD` access. These methods can also retrieve data,
  such as a GraphQL query sent by `POST`. `POST` at a repository also grants `git push`'s ref
  discovery, which uses `GET`.
- `tunnel` — permits traffic without request inspection. It stands alone on its line, and its
  URL ends at `/`.

The selected profile determines the starting rules and which project lines apply. Those lines
apply in file order:

- an `allow` adds its grants under its path;
- a `deny` removes the named grants from every scope on each matching host, or all grants when it
  names none;
- for each grant, the last applicable line decides, regardless of which earlier line supplied it.

`design.md`, "No richer rule format", explains the PF and relayd inspiration.

A denial covers whole hosts, never paths (SECURITY.md, "Adding hosts, not patterns", explains why
path-based denials can fail open). To restrict Git fetches to one owner, deny them on the whole
host before allowing that owner's path:

```text
deny https://codeberg.org/ git-fetch
allow https://codeberg.org/my-org/ git-fetch
```

Reversing these lines also denies Git fetches under `my-org`, because the denial comes last.
Ordinary reads remain allowed. To restrict reads too, use `deny https://codeberg.org/` followed
by `allow https://codeberg.org/my-org/ read git-fetch`.

A request is decided against the resolved scope of its longest literal match: the scope at a path
holds the union of the contributions still in force there once the lines have applied in order,
so a root `git-fetch` line and a narrower `method=POST` line make the narrower scope hold both.
A request matching no line, on a host without a root line, is refused.

Which path spellings a request may carry depends on the matched scope, because the proxy compares
literally and cannot know how the origin decodes:

- Where the longest match is a scope other than the root, the request's path must have a rule
  path's canonical form, on every method: anything else is a spelling the origin might fold onto
  another path. A wrong-case path fails closed on GitHub and GCS alike.
- Under the root, `GET` and `HEAD` may carry any of those spellings, which keeps npm's
  `/@scope%2fname` readable beside a `method=` line. `POST`, `PUT`, `PATCH` and `DELETE` still
  refuse percent-encoding and dot segments there; the canonical form's other checks apply only under
  a scope other than the root.

A line is therefore a boundary as well as a grant: one whose grants its enclosing scope already
holds still changes which path spellings are refused.

The `defaults` and `model-provider` lines:

- Under `deny-unless-allowed`, `deny defaults` removes the built-in rules from the starting
  ruleset. It must be the first line.
- `allow model-provider NAME` expands to the provider's default rules at that position.
- `deny model-provider NAME` expands to a whole-host denial for every host listed in those rules,
  regardless of their paths or grants. It removes all earlier grants on those hosts, including
  grants from the catalog or project rules. A later allow grants only what it names.

For example, `deny model-provider github` also denies repository access on `github.com` and API
access on `api.github.com`; hosts absent from GitHub's model-provider rules, such as
`raw.githubusercontent.com`, are unaffected by that denial.

- To restore repository reads and Git fetches, follow it with
  `allow https://github.com/ read git-fetch`.
- To restore API reads, add `allow https://api.github.com/ read`.

To permit only one provider's default rules under `deny-unless-allowed`:

```text
deny defaults
allow model-provider anthropic
```

A host has one treatment:

- `deny https://api.example/ tunnel` removes it, and an `allow` with `read`, `git-fetch` or
  `method=` then makes the host inspected;
- a `tunnel` line for a host the defaults inspect needs `deny defaults` and the whole ruleset
  after it (SECURITY.md, "Adding hosts, not patterns", has why).

`doc/egress-rule-example/*/rule` holds complete files for common needs — a bucket, a container,
a Pulumi AWS stack, the lockdown, npm's audit `POST` — to copy over `.ko-agent-sandbox/egress/rule`
and trim.

Every ambiguity is a failed launch with the reason and the line printed:

- an unrecognized configuration entry: `egress/` accepts only `rule`, and `.ko-agent-sandbox/`
  accepts `egress`, `file` and `run-on-host`. Dot-prefixed metadata entries are ignored;
- a token outside the grammar, an unknown profile, provider, grant word or method, a `#` inside a
  token, a host that is an IP literal or is not a hostname;
- a path outside canonical form; a `deny` or a `tunnel` with a path; `https://HOST` without its
  slash; an `allow https://` line naming no grant, or a word twice; `tunnel` beside another word;
- a line above `deny defaults`;
- a resolved host holding `tunnel` beside an inspected grant, from the file's lines or the
  defaults'; a `tunnel` line for a host the defaults inspect without `deny defaults`.

Two lines disagreeing about a grant are the ordinary case, not a refusal: the later one decides —
`deny`, `allow`, `deny` removes the exception the `allow` made; `allow`, `deny`, `allow` restores
the grant the `deny` removed.

Three conditions in the file are warned at every launch instead, under every profile, so a
misspelling cannot fail silently:

- a `deny` matching nothing at its position;
- a redundant grant — a line granting nothing its enclosing scope lacks,
  `allow https://github.com/my-org/ git-fetch` under the defaults' root line, which usually means
  a host-wide `deny` before it was intended, though the boundary it opens remains;
- a line every grant of which a later line takes back.

A fourth warning names the hosts of the selected model provider that the resolved ruleset does
not allow.

A line restating a defaults line at its path is silent: that is how a file stays valid as the
image adopts its hosts.

1. Without a rule file, or with one holding only comments and blank lines, the selected profile
   applies without project overrides.
   - An empty ruleset is valid and reported as such — `deny-all` resolves empty by design, as
     does `deny-unless-model` under `bash`.
1. Editing the file takes effect on the next launch; a running session keeps its original ruleset.
1. The sandbox cannot edit it, under either write mode (SECURITY.md, "Why the rules are per
   project, in the project, and read-only").
1. Commit the directory with the project. Review its rules before launching an unfamiliar
   project (SECURITY.md, "A repository that ships wide egress rules").

## The printed ruleset

`--egress-effective` and `--egress-check=<host>` ([README.md](../README.md#reference)) answer
without starting a session; inside one, `ko-sandbox-egress-check <host>` asks the running proxy.
Every start prints, in order:

1. the rule file as written, one line;
1. when the file grants beyond the defaults — a host the defaults lack, a grant the defaults lack
   at the line's path, `deny defaults` — the line `egress rules widen:`, then those rule lines,
   each on its own indented line. A file that only removes grants or narrows them prints neither;
1. the launch banner — the profile and the counts, never a host name.

The ruleset itself is what the proxy prints at its start and `--egress-effective` shows whole, in
the rule grammar, hosts and paths sorted:

1. the profile line;
1. one `allow` line per resolved scope, with the scope's whole grant set.

```text
egress profile: deny-unless-allowed
allow https://api.anthropic.com/ tunnel
allow https://github.com/ read git-fetch
allow https://github.com/login/device/code read git-fetch method=POST
...
```

- Each `allow` line uses the rule grammar so a reader learns one; but the printout is a
  serialization of the ruleset, not a rule file: it has no `deny defaults` header, nothing reads
  it as input, and it is not promised to re-parse to itself.
- Those lines are what the proxy's digest names — one stable log line per run, comparable across
  runs — what the leaf certificate's names are read from, and what
  `KO_AGENT_SANDBOX_EGRESS_RULESET` holds, so two files resolving to one ruleset print one digest
  and the same lines, and the same file under two profiles never does.
- Metadata follows outside the digest: a summary of inspected hosts, tunnel hosts and widening
  lines, then the widening line.
- `--egress-effective` adds each line's sources: an `allow` line's boundary and each of its
  grants, then the hosts the file's lines denied.

The agent instructions include the profile and direct agents to consult
`KO_AGENT_SANDBOX_EGRESS_RULESET` when they need a destination's grants or restrictions. Keeping
the full ruleset there avoids including the host list in every prompt.

## Audit what has been allowed or denied

Run with `--egress-log` from the project directory. Every proxy connection is logged,
and the proxy appends the log to a per-run file on the host, under

    ~/.local/state/ko-agent-sandbox/log/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\log\<project>\     # native Windows

- With no arguments, `--egress-log` prints the retained files oldest first — the newest 20 runs,
  and any older one whose session is still running, since a live proxy is still appending to its
  file.
- A `--run-on-host` program's proxy has its own file there, named after its run as the container
  proxy's is: a hard link to the log in the command's session directory, so it fills as the proxy
  writes (`RunOnHostProxy.linkAuditLog`).
- Startup lines come first; SECURITY.md, "The audit line grammar", lists them.
- Every connection event after them is one line, with an inspected request's full target — query
  string included, which is what makes an exfiltrating `GET` visible.

A refusal reads as

    2026-08-26T11:59:38Z deny github.com POST /owner/repo.git/git-receive-pack POST not granted

SECURITY.md, "The audit line grammar", has every field and reason.

If a log line cannot be written, the proxy refuses every new connection for the rest of the
session, and `ko-sandbox-egress-check <host>` prints
`audit log cannot be written: <the I/O error>`. Make the file on the launch's `egress log` line
writable again — usually by freeing disk space — and relaunch (SECURITY.md, "Egress proxy").

## TLS inspection

The proxy terminates TLS for every inspected host and checks each request against its grants.
Only hosts with the `tunnel` treatment stay opaque:

- under `deny-unless-allowed`, the hosts with model-provider tunnel rules, unless a project
  removes them or adds more;
- under `deny-unless-model`, the selected providers' remaining tunnel hosts;
- under `deny-all`, none.

The per-project CA is stored on the host, under

    ~/.local/state/ko-agent-sandbox/tls/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\tls\<project>\     # native Windows

1. The certificates are created and refreshed automatically for each project (SECURITY.md,
   "Who holds the CA key").
1. Deleting that directory is how you rotate the CA. The next launch recreates it, and every
   launch's proxy starts with the certificates the launch found or issued.

## Brokered credentials

`--egress-cred=NAME@HOST` gives environment variable `NAME` to the proxy that inspects `HOST`. The
sandbox and `--run-on-host` commands see `NAME` set to a placeholder, and that proxy puts the value
in its place in requests to `HOST`.

    GH_TOKEN=$(gh auth token) <launcher> --egress-cred=GH_TOKEN@api.github.com claude

- `HOST` must be inspected by the session's rules or by a `--run-on-host` program's rule file
  (`.ko-agent-sandbox/run-on-host/<program>/egress/rule`). The launch refuses a binding to a host
  no rule allows, naming the `allow` line to add, and one to a tunnel host, naming the alternatives.
- The value comes from the launcher's environment alone: `NAME=VALUE@HOST` is refused (design.md,
  "Credential brokering at the egress proxy", has why).
- The launch prints each binding with its placeholder, `--egress-effective` prints where each would
  go under the ruleset, and the agent instructions name them.
- The audit line of a request that carried a value ends `inject=NAME -> <ip>` (SECURITY.md, "The
  audit line grammar").
- Measured against GitHub (2026-10-04, `gh` 2.102.0 installed in the sandbox), one token bound as
  `GH_TOKEN@api.github.com` and as `GIT_TOKEN@github.com`:
  - each name holds a placeholder of its own in the token's `gho_` format;
  - `gh api user` succeeds, its audit line `inject=GH_TOKEN`;
  - a private `git clone` succeeds with a credential helper returning `$GIT_TOKEN`, its `info/refs`
    and `git-upload-pack` lines `inject=GIT_TOKEN`; git's first `info/refs`, sent without
    credentials, has none;
  - with the helper returning `$GH_TOKEN` instead, GitHub refuses the clone (`Invalid username or
    token`);
  - `GH_TOKEN`'s placeholder sent to `gitlab.com` gets a 401, its line without `inject`;
  - `git push --dry-run` is refused at ref discovery.
- SECURITY.md, "Who holds a brokered value", has where the value is held and what stays open.

### Where the value goes

The binding names one place, and the value goes there only when the whole token in it equals the
placeholder:

- `NAME@HOST`: `Authorization`, the token of `Bearer` or `token`, or the password half of `Basic`.
  `Basic` is what git sends for an `https://` remote with a credential helper, and what git and
  curl make of `https://user:token@host/`, so the URL form is rewritten too.
- `NAME@HOST:HEADER`: the whole value of `HEADER`, such as `x-api-key`. Bind the header the service
  authenticates with: a header the service stores as metadata or echoes back hands the value to the
  sandbox.
- `NAME@HOST?PARAM`: the percent-decoded value of query parameter `PARAM`, the value written
  percent-encoded, since the value grammar admits `&`, `=`, `#` and `%`. The value is the
  parameter's alone: an Azure SAS token is composed around it in
  the sandbox, `"sv=…&sp=rl&sig=$AZURE_SAS_SIG"`.
- `NAME@HOST/PREFIX/` with any of the above: requests whose path is under `/PREFIX/` alone.

A header or parameter sent more than once is rewritten in each occurrence holding the placeholder,
so whichever occurrence the origin reads means what the client sent there.

Everything else is forwarded as sent:

- a request to another host, whatever placeholder it carries;
- a token that is not the placeholder, so an application's own credential for the host reaches it
  unchanged (docker/sbx-releases #8);
- a placeholder anywhere else — the path, a body, an unbound header or parameter — which
  authenticates nothing: a credential sent that way fails with the origin's 401, as the launch's
  note says;
- every response: a response echoing a credential is not rewritten.

The rewrite happens before the request is authorized and framed, so the decision reads what the
origin receives: a bound `service` parameter on a Git host is decided as the value it becomes.

`PREFIX` is written as a rule's path is, in canonical form ("The rule file"), so non-ASCII text is
escaped and anything else spelled two ways is refused at launch. A request under it must have that
form too, or it is not covered: the origin could decode another spelling to a path outside the
prefix. The rules' own paths decide first; a prefix narrows where the value goes, never what may be
requested.

What the binding admits, checked at launch and again where a proxy reads its bindings:

- a value of 1 to 4096 bytes of visible ASCII (`0x21`–`0x7E`), which can end no field and alter no
  framing; a refusal names the offset, never the value;
- a header name that is an HTTP token, other than `Host`, `Content-Length`, `Transfer-Encoding`
  and the hop-by-hop headers, `Connection` and `Upgrade` among them, which the proxy reads or
  removes (`CredentialGrammar.RefusedHeaders`): a value there would never reach the origin as that
  header;
- a parameter name without `&`, `=`, `#`, `+` or a byte outside visible ASCII: `+` is refused
  because a form parser reads it as a space, so the origin would read `a+b` as `a b`.

The placeholder is fresh each launch and keeps the value's format, so a program checking a token's
syntax before it sends one still sends it:

- a prefix programs recognize — `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`, `glpat-` —
  and the length;
- `-`, `.`, `_` and `~` in place, which separate the parts of GitHub's `ghs_APPID_JWT` installation
  tokens;
- a digit for each digit and a letter of the same case for each letter. Other punctuation becomes
  a letter or a digit: `&`, `=`, `#` and `%` would split or re-parse the query a `?PARAM`
  placeholder is composed into.

A value too short for a placeholder with 64 random bits — about 14 letters or 20 digits besides
the prefix and those separators — is refused. The project sees the placeholder once the
session runs; the randomness keeps a string written before it, such as an application's own
token, from equaling it and being replaced.

### Which credentials fit

- Forge tokens, and the bearer tokens of cloud APIs: Google Cloud and Azure access tokens are
  `Authorization: Bearer`, so a binding covers them once the API host is inspected, with the
  `method=POST` grants cloud APIs need and the cloud's CLI or SDK trusting the launch CA.
- A whole token in one query parameter: an Azure storage SAS token's `sig`, an HMAC over the SAS's
  own fields that whoever holds it reuses, and a Google API `key`.
- Not a request-bound signature, an S3 presigned URL's `X-Amz-Signature` or a Cloud Storage V4
  signed URL's `X-Goog-Signature`: consuming one needs nothing here, and generating one computes
  the signature locally, so no request passes the proxy while it happens.
  - Cloud Storage can sign through the IAM Credentials `signBlob` API instead, whose request
    carries a bearer token a binding covers; the key stays with Google.
  - Azure's `getUserDelegationKey` runs under a bearer token too, but its response is the
    delegation key, forwarded unchanged: the sandbox then holds a signing credential for the
    account until the expiry the request asked for, at most seven days
    (https://learn.microsoft.com/en-us/rest/api/storageservices/get-user-delegation-key). A
    session that must not hold one obtains the key and signs on the host.
  - An AWS client signs each request itself and never sends its key (design.md, "Credential
    brokering at the egress proxy").
- Not a model provider's login or API key: their hosts are tunnels, where nothing is substituted
  (the same design.md section has why).

## Through an upstream proxy

`HTTPS_PROXY` in the launcher's environment, `http[s]://[user:password@]host:port`, sends every
origin connection of the session's proxy through that upstream proxy.

- Lowercase `https_proxy` is read when the uppercase is unset or empty; `HTTP_PROXY`, `ALL_PROXY`,
  `NO_PROXY` and OS proxy settings are not read at all.
- The port is explicit because clients disagree on the default: curl assumes 1080, Go, Python and
  Node assume 80.
- A malformed value refuses the launch, naming the part that is wrong and never the value.
- `--build`'s pulls and builds, and `podman machine start`, use the host's variables as podman
  does on its own; of a session's containers only the proxy receives the one selected variable,
  and the sandbox none of them.

What changes is only how an allowed address is reached:

- the ruleset decides every destination, the name is resolved once and every answer
  must be public;
- the upstream proxy is asked for a tunnel to that numeric address — never for the hostname,
  which it would resolve itself, outside the check;
- a failure on that path is an `error` line and a 502, never a direct retry;
  `ko-sandbox-egress-check <host>` prints the stage.

The launch banner and the proxy's startup lines name the endpoint without its userinfo, which
stays in the proxy container's environment (SECURITY.md, "Egress proxy"). `--egress-check=<host>`
reports whether a tunnel to the host's first address could be opened.

Not supported yet, each failing closed with a certificate error:

- an upstream proxy that terminates TLS with its own certificate, whose re-signed origin
  certificates fail validation in the proxy and in the sandbox's clients alike;
- an `https` endpoint under a private CA.

In the proxy container a loopback endpoint is the container's own loopback, not the host's, so a
helper such as cntlm listening on the host's `127.0.0.1` is out of reach; the same variable does
reach it from a `--run-on-host` command's proxy, which runs on the host (`run-on-host.md`, "The
command's egress proxy").
