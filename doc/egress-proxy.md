# The egress proxy

- Every sandbox session reaches the network through one HTTPS proxy in its own container, on a
  network the session cannot route out of.
- The ruleset specifies the reachable hosts, permitted operations and whether requests are
  inspected.
- The proxy resolves the ruleset from its built-in defaults, the profile selected at launch and
  the workspace's rule file. The proxy prints the ruleset at every start.

This document explains how to write the rule file and read the printout. SECURITY.md explains the
protections and their limits (`../SECURITY.md`, "Egress proxy").

- A *rule* is a line of the workspace's file: the text that people write and review.
- The *ruleset* is what a launch enforces: the defaults, the profile and the file resolved
  together. The proxy prints the ruleset as the ruleset lines and names it by a digest.
- Two files of different rules may resolve to one ruleset.

## Choosing an egress profile

Every launch selects an `--egress=` profile; `deny-unless-allowed` is the default. An allowed
host has one of two treatments:

- a `tunnel`, whose application traffic stays opaque after the TLS identity check;
- inspected: the proxy terminates TLS, decides each request against its resolved scope, and
  refuses a request that no grant allows ("The rule file" below). SECURITY.md has what each grant
  permits, the costs of inspection and what inspection prevents (`../SECURITY.md`, "Reading
  without being able to write").

The proxy logs handshake failures under both treatments. SECURITY.md defines the checks and audit
events.

The proxy's default rules are listed in the proxy image's `defaults/host` and
`defaults/model-provider/*`, with the reason beside each line:

- for every supported model provider (`anthropic`, `openai`, `google`, `aws` and `github`),
  tunnels to model, authentication and control-plane endpoints. GitHub's rules also permit two
  inspected login `POST`s and one token read, and Google's rules permit two inspected reads of the
  signed-in account;
- inspected documentation, package-registry and forge hosts, with `read` on every line and
  `git-fetch` on the three forges.

A launch selects the model providers whose default rules it admits:

- The command's first word selects one provider: `claude` selects `anthropic`, `codex` selects
  `openai`, `agy` selects `google`, `kiro-cli` selects `aws`, and `copilot` selects `github`.
- Each `--model-provider=<names>`, in the options file or on the command line, adds the providers
  it names, separated by commas, from those under `defaults/model-provider/`.
  - The launch refuses the option under `deny-all`, where nothing is admitted.
  - `opencode` has no fixed provider, and the launch refuses an `opencode` launch without the
    option.
- Only the basename of the directly launched command is classified. Any other command selects no
  provider of its own, and a launch that selects none says so at startup.

The profiles:

1. `deny-unless-allowed` (the default) — the inspected catalog and the selected providers' rules,
   then every line of the workspace's file.
1. `deny-unless-model` — the selected providers' rules, then the file's URL and model-provider
   denials. This profile ignores `allow` and `deny defaults` lines. With no provider selected, it
   allows no host.
1. `deny-all` — nothing.

## The rule file

The rule file is `.ko-agent-sandbox/egress/rule` in the workspace root. The file holds one rule
per line, in the order the rules apply. `#` starts a comment at the start of a line or after
whitespace, and blank lines are ignored.

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
- `**.` is the deny side's only pattern, and matches the apex and everything under it
  (`**.foo.com` covers `foo.com` and `api.foo.com`, never `barfoo.com`).
- The path is written in canonical form, one spelling for each path (`RulePath.literalPathProblem`):
  - The path begins with `/` and is printable ASCII, with no `\`, `;`, `?`, `#`, empty segment, or
    `.` or `..` segment. Servlet containers drop a `;` parameter before resolving `..`, so Tomcat
    reads `/a/..;/b` as `/b`.
  - `%` only escapes non-ASCII text, in UTF-8, or a space (`%20`). `/docs/%E3%81%82/` is one path,
    and `%41` or `%2e` is refused, since `A` and `.` have a spelling of their own.
  - The proxy compares hex case as written, as it compares letter case: a request in the other
    case is not under the line.
  - An escape must decode as strict UTF-8, so no overlong form spells `.` or `/` (`%C0%AE`). The
    escaped text may not gain `/`, `\`, `.`, `;`, `%`, `?` or `#` under Unicode normalization
    (NFKC), as the fullwidth `／` (`%EF%BC%8F`) and U+037E (`%CD%BE`, `;` under NFC already) do.
- A trailing `/` names the tree under the path, and a path without one names that one path.
  `https://HOST/` is the root: the whole host. `https://HOST` without its slash is refused, never
  read as the root.
- Case is the origin's: the proxy folds nothing.

What a line grants is its words, and nothing is implied:

- `read` — `GET` and `HEAD`, without a body or `Content-Length` or `Transfer-Encoding` headers.
  Even `Content-Length: 0` is refused.
- `git-fetch` — a clone's two requests, the ref discovery
  (`GET .../info/refs?service=git-upload-pack`) and the transfer (`POST .../git-upload-pack`). A
  `git-fetch` line without `read` is clonable and not browsable; a `read` line without `git-fetch`
  is browsable, and a clone fails at its first request. `git-fetch` never grants `git push`.
- `method=POST,PUT,...` — the listed methods, from `POST`, `PUT`, `PATCH`, `DELETE`, at that
  path, without granting general `GET` or `HEAD` access. These methods can also retrieve data,
  such as a GraphQL query sent by `POST`. `POST` at a repository also grants `git push`'s ref
  discovery, which uses `GET`.
- `tunnel` — permits traffic without request inspection. A `tunnel` stands alone on its line, and
  its URL ends at `/`.

The selected profile determines the starting rules and which of the file's lines apply. Those lines
apply in file order:

- an `allow` adds its grants under its path;
- a `deny` removes the named grants from every scope on each matching host, or all grants when it
  names none;
- for each grant, the last applicable line decides, regardless of which earlier line supplied it.

`design.md`, "No richer rule format", explains the PF and relayd inspiration.

A denial covers whole hosts, never paths. SECURITY.md explains why path-based denials can fail
open (`../SECURITY.md`, "Adding hosts, not patterns"). To restrict Git fetches to one owner, deny
them on the whole host before allowing that owner's path:

```text
deny https://codeberg.org/ git-fetch
allow https://codeberg.org/my-org/ git-fetch
```

Reversing these lines also denies Git fetches under `my-org`, because the denial comes last.
Ordinary reads remain allowed. To restrict reads too, use `deny https://codeberg.org/` followed
by `allow https://codeberg.org/my-org/ read git-fetch`.

A `git lfs pull` sends two kinds of request that no grant names:

- the batch `POST` at the repository's `info/lfs/`;
- the `GET`s of the objects, on the host that the batch answer names. A failed pull prints that
  host.

For GitHub, the objects come from `github-cloud.githubusercontent.com` (measured 2026-10-24):

```text
allow https://github.com/<owner>/<repo>.git/info/lfs/ method=POST
allow https://github-cloud.githubusercontent.com/ read
```

The proxy decides a request against the resolved scope of the request's longest literal match:

- The scope at a path holds the union of the contributions still in force there, once the lines
  have applied in order. So a root `git-fetch` line and a narrower `method=POST` line make the
  narrower scope hold both grants.
- A request that matches no line, on a host without a root line, is refused.

Which path spellings a request may carry depends on the matched scope, because the proxy compares
literally and cannot know how the origin decodes:

- Where the longest match is a scope other than the root, the request's path must have a rule
  path's canonical form, on every method. Any other spelling is one that the origin might fold onto
  another path. A wrong-case path fails closed on GitHub and GCS alike.
- Under the root, `GET` and `HEAD` may carry any of those spellings, which keeps npm's
  `/@scope%2fname` readable beside a `method=` line.
  - The proxy still refuses percent-encoding and dot segments in a `POST`, `PUT`, `PATCH` or
    `DELETE` path there.
  - The canonical form's other checks apply only under a scope other than the root.

So a line is a boundary as well as a grant: a line whose grants its enclosing scope already holds
still changes which path spellings are refused.

The `defaults` and `model-provider` lines:

- Under `deny-unless-allowed`, `deny defaults` removes the built-in rules from the starting
  ruleset. It must be the first line.
- `allow model-provider NAME` expands to the provider's default rules at that position.
- `deny model-provider NAME` expands to a whole-host denial for every host listed in those rules,
  regardless of their paths or grants. The denial removes all earlier grants on those hosts,
  including grants from the catalog or the workspace's rules. A later allow grants only what it
  names.

For example, `deny model-provider github` also denies repository access on `github.com` and API
access on `api.github.com`. Hosts absent from GitHub's model-provider rules, such as
`raw.githubusercontent.com`, are unaffected by that denial.

- To restore repository reads and Git fetches, follow the denial with
  `allow https://github.com/ read git-fetch`.
- To restore API reads, add `allow https://api.github.com/ read`.

To permit only one provider's default rules under `deny-unless-allowed`:

```text
deny defaults
allow model-provider anthropic
```

A host has one treatment:

- `deny https://api.example/ tunnel` removes the tunnel, and an `allow` with `read`, `git-fetch`
  or `method=` then makes the host inspected;
- a `tunnel` line for a host that the defaults inspect needs `deny defaults`, with the whole
  ruleset written after it. SECURITY.md says why (`../SECURITY.md`, "Adding hosts, not patterns").

`doc/egress-rule-example/*/rule` holds complete files for common needs, to copy over
`.ko-agent-sandbox/egress/rule` and trim: a bucket, a container, a Pulumi stack on an S3 or a
Pulumi Cloud backend, the lockdown, and npm's audit `POST`.

- An example puts the lines a reader must edit first, under a comment that says so.
- An example groups the other lines under a comment each, with a blank line between groups, and
  aligns its columns.

The launch fails on every ambiguity, and prints the reason and the line:

- an unrecognized configuration entry. `egress/` accepts only `rule`, and `.ko-agent-sandbox/`
  accepts `egress`, `file` and `run-on-host`. Dot-prefixed metadata entries are ignored;
- a token outside the grammar, an unknown profile, provider, grant word or method, a `#` inside a
  token, a host that is an IP literal or is not a hostname;
- a path outside canonical form; a `deny` or a `tunnel` with a path; `https://HOST` without its
  slash; an `allow https://` line naming no grant, or a word twice; `tunnel` beside another word;
- a line above `deny defaults`;
- a resolved host holding `tunnel` beside an inspected grant, from the file's lines or the
  defaults'; a `tunnel` line for a host the defaults inspect without `deny defaults`.

Two lines that disagree about a grant are the ordinary case, not a refusal: the later line
decides. `deny`, `allow`, `deny` removes the exception that the `allow` made. `allow`, `deny`,
`allow` restores the grant that the `deny` removed.

The launch warns about three conditions in the file instead, at every launch and under every
profile, so a misspelling cannot fail silently:

- a `deny` that matches nothing at its position;
- a redundant grant: a line that grants nothing its enclosing scope lacks, such as
  `allow https://github.com/my-org/ git-fetch` under the defaults' root line. Such a line usually
  means that a host-wide `deny` before it was intended. The boundary that the line opens remains;
- a line whose every grant a later line takes back.

A fourth warning names the hosts of the selected model provider that the resolved ruleset does
not allow.

A line that restates a defaults line at its path draws no warning. That is how a file stays valid
as the image adopts its hosts.

1. Without a rule file, or with one holding only comments and blank lines, the selected profile
   applies without workspace overrides.
   - An empty ruleset is valid, and the launch reports it as empty. `deny-all` resolves empty by
     design, and so does `deny-unless-model` under `bash`.
1. An edit of the file takes effect on the next launch. A running session keeps its original
   ruleset.
1. The sandbox cannot edit the file, under either workspace mode (`../SECURITY.md`, "Why the rules
   are per workspace, in the workspace, and read-only").
1. Commit the directory to the repository. Review a repository's rules before launching in an
   unfamiliar repository (`../SECURITY.md`, "A repository that ships wide egress rules").

## The printed ruleset

`--egress-effective` and `--egress-check=<host>` ([README.md](../README.md#reference)) answer
without starting a session. Inside a session, `ko-sandbox-egress-check <host>` asks the running
proxy. Every start prints, in order:

1. the line `.ko-agent-sandbox/egress/rule: <count> widening lines`, then those rule lines
   indented, when the file grants beyond the launch's defaults:
   - A line widens when it grants a host the defaults lack, a grant the defaults lack at the
     line's path, or a provider the launch did not select, or when it is `deny defaults`.
   - The rule lines print one per line, except that `allow https://<host>/ <words>` lines that
     share their words join into `allow <words>: <host>, <host>`.
   - A file that only removes grants or narrows them prints neither.
1. the file's other lines, on one line, so each line of the file prints once;
1. the launch banner: the profile and the counts, never a host name.

The proxy prints the ruleset itself at its start, and `--egress-effective` shows the ruleset whole.
Both use the rule grammar, with hosts and paths sorted:

1. the profile line, naming the selected providers under the two profiles that admit any;
1. one `allow` line per resolved scope, with the scope's whole grant set.

```text
egress profile: deny-unless-allowed; model provider: anthropic
allow https://api.anthropic.com/ tunnel
allow https://github.com/ read git-fetch
allow https://github.com/login/device/code read git-fetch method=POST
...
```

- Each `allow` line uses the rule grammar, so a reader learns one grammar. But the printout is a
  serialization of the ruleset, not a rule file: it has no `deny defaults` header, nothing reads
  it as input, and it is not promised to re-parse to itself.
- Three things come from those lines:
  - the proxy's digest, one stable log line per run, comparable across runs;
  - the leaf certificate's names;
  - the value of `KO_AGENT_SANDBOX_EGRESS_RULESET`.

  So two files that resolve to one ruleset print one digest and the same lines. The same file under
  two profiles never does.
- Metadata follows outside the digest: a summary of inspected hosts, tunnel hosts and widening
  lines, then the widening line.
- `--egress-effective` adds each line's sources: an `allow` line's boundary and each of its
  grants, then the hosts the file's lines denied.

The agent instructions include the profile and direct agents to consult
`KO_AGENT_SANDBOX_EGRESS_RULESET` when they need a destination's grants or restrictions. Keeping
the full ruleset there avoids including the host list in every prompt.

## Audit what has been allowed or denied

Run with `--egress-log` from the workspace root. The proxy logs every connection and appends the
log to a file in the run's directory on the host. The launch's `log dir` line names that
directory:

    ~/.local/state/ko-agent-sandbox/log/<workspace>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\log\<workspace>\     # native Windows
      run-<start>-<run>/           <start> in UTC, as 20261017T022446Z; <run> its containers' suffix
        proxy.log                  the container proxy's audit log
        run-on-host.log            the host command runner's log; only with --run-on-host
        mic.log                    the relay's log; only with --audio=mic
        ko-agent-bpf.log           the BPF backend's launch steps and their times; only under bpf
        <proxy log>-<session>.log  a host program proxy's audit log

- With no arguments, `--egress-log` prints each run's proxy audit logs, oldest run first and
  `proxy.log` first within a run.
- A launch keeps the newest 20 run directories. A launch also keeps an older run directory while
  either container of that run exists, running or not, since the run's proxy, runner or relay may
  still append to its files.
- A `--run-on-host` program's proxy has its own file there, named after its session's log
  (`proxy-sbt-<hash>-r123.log`).
  - When the runtime's proxy starts again in the run, the name gets `-2`, `-3` and so on before
    `.log`.
  - That proxy writes the file itself, so the file fills during the run and stays when the proxy's
    session directory is removed (`RunOnHostProxy.keepAuditLog`).
- A host command is refused when its proxy's file cannot be created there. The message names the
  directory to make writable.
- Startup lines come first. SECURITY.md lists them (`../SECURITY.md`, "The audit line grammar").
- Every connection event after the startup lines is one line, and a chunked request body adds a
  `chunked-end` line with its size when it ends. The line of an inspected request holds the
  request's full target, query string included, which makes an exfiltrating `GET` visible.

A refusal reads as

    2026-08-26T11:59:38Z deny github.com POST /owner/repo.git/git-receive-pack POST not granted

SECURITY.md lists every field and reason (`../SECURITY.md`, "The audit line grammar").

If a log line cannot be written, the proxy refuses every new connection for the rest of the
session, and `ko-sandbox-egress-check <host>` prints
`audit log cannot be written: <the I/O error>`. Make `proxy.log` in the directory on the launch's
`log dir` line writable again, usually by freeing disk space, and relaunch (`../SECURITY.md`,
"Egress proxy").

## TLS inspection

The proxy terminates TLS for every inspected host and checks each request against its grants.
Only hosts with the `tunnel` treatment stay opaque:

- under `deny-unless-allowed`, the selected providers' tunnel hosts, unless the workspace's file
  removes them or adds more;
- under `deny-unless-model`, the selected providers' remaining tunnel hosts;
- under `deny-all`, none.

The per-workspace CA is stored on the host, under

    ~/.local/state/ko-agent-sandbox/tls/<workspace>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\tls\<workspace>\     # native Windows

1. The certificates are created and refreshed automatically for each workspace (`../SECURITY.md`,
   "Who holds the CA key").
1. To rotate the CA, delete that directory. The next launch recreates the directory, and every
   launch's proxy starts with the certificates the launch found or issued.

## Brokered credentials

`--egress-cred=NAME@HOST` gives environment variable `NAME` to the proxy that inspects `HOST`. The
sandbox and `--run-on-host` commands see `NAME` set to a placeholder, and that proxy puts the value
in its place in requests to `HOST`.

    GH_TOKEN=$(gh auth token) <launcher> --egress-cred=GH_TOKEN@api.github.com claude

- `HOST` must be inspected by the session's rules or by a `--run-on-host` program's rule file
  (`.ko-agent-sandbox/run-on-host/<program>/egress/rule`).
  - The launch refuses a binding to a host that no rule allows, and names the `allow` line to add.
  - The launch refuses a binding to a tunnel host, and names the alternatives.
- The value comes from the launcher's environment alone: `NAME=VALUE@HOST` is refused. design.md
  says why (`design.md`, "Credential brokering at the egress proxy").
- The launch prints each binding with its placeholder. `--egress-effective` prints where each
  binding's value would go under the ruleset, and the agent instructions name the bindings.
- The audit line of a request that carried a value holds `inject=NAME` (`../SECURITY.md`, "The
  audit line grammar").
- Measured against GitHub (2026-10-04, `gh` 2.102.0 installed in the sandbox), one token bound as
  `GH_TOKEN@api.github.com` and as `GIT_TOKEN@github.com`:
  - each name holds a placeholder of its own in the token's `gho_` format;
  - `gh api user` succeeds, and its audit line carries `inject=GH_TOKEN`;
  - a private `git clone` succeeds with a credential helper that returns `$GIT_TOKEN`. The clone's
    `info/refs` and `git-upload-pack` lines carry `inject=GIT_TOKEN`. git's first `info/refs`, sent
    without credentials, carries none;
  - with the helper returning `$GH_TOKEN` instead, GitHub refuses the clone (`Invalid username or
    token`);
  - `GH_TOKEN`'s placeholder sent to `gitlab.com` gets a 401, and its line carries no `inject`;
  - `git push --dry-run` is refused at ref discovery.
- SECURITY.md says where the value is held and what stays open (`../SECURITY.md`, "Who holds a
  brokered value").

### Where the value goes

The binding names one place, and the value goes there only when the whole token in it equals the
placeholder:

- `NAME@HOST`: `Authorization`, the token of `Bearer` or `token`, or the password half of `Basic`.
  Git sends `Basic` for an `https://` remote with a credential helper, and git and curl turn
  `https://user:token@host/` into `Basic` too. So the proxy rewrites the URL form as well.
- `NAME@HOST:HEADER`: the whole value of `HEADER`, such as `x-api-key`. Bind the header the service
  authenticates with: a header the service stores as metadata or echoes back hands the value to the
  sandbox.
- `NAME@HOST?PARAM`: the percent-decoded value of query parameter `PARAM`. The proxy writes the
  value percent-encoded, since the value grammar admits `&`, `=`, `#` and `%`. The value fills the
  parameter alone: the sandbox composes an Azure SAS token around it, as in
  `"sv=…&sp=rl&sig=$AZURE_SAS_SIG"`.
- `NAME@HOST/PREFIX/` with any of the above: only requests whose path is under `/PREFIX/`.

A header or parameter sent more than once is rewritten in each occurrence holding the placeholder,
so whichever occurrence the origin reads means what the client sent there.

Everything else is forwarded as sent:

- a request to another host, whatever placeholder it carries;
- a token that is not the placeholder, so an application's own credential for the host reaches
  the host unchanged (docker/sbx-releases #8);
- a placeholder anywhere else, such as the path, a body, or an unbound header or parameter. Such a
  placeholder authenticates nothing: a credential sent that way fails with the origin's 401, as
  the launch's note says;
- every response: a response that echoes a credential is not rewritten.

The proxy rewrites a request before it authorizes and frames the request, so the decision reads
what the origin receives. For example, the proxy decides a bound `service` parameter on a Git host
as the value the parameter becomes.

- `PREFIX` is written in canonical form, as a rule's path is ("The rule file"). So non-ASCII text
  is escaped, and the launch refuses anything else spelled two ways.
- A request under `PREFIX` must have that form too, or the binding does not cover the request: the
  origin could decode another spelling to a path outside the prefix.
- The rules' own paths decide first. A prefix narrows where the value goes, never what may be
  requested.

What a binding admits; the launch checks this, and a proxy checks it again where it reads its
bindings:

- a value of 1 to 16384 bytes of visible ASCII (`0x21`–`0x7E`), which can end no field and alter
  no framing; a refusal names the offset, never the value;
- a binding of at most 16384 bytes, counted with the host normalized and the place named,
  `:Authorization` when the binding names none;
- at most 256 bindings in a launch (`CredentialGrammar.MaxBindings`);
- a header name that is an HTTP token, other than `Host`, `Content-Length`, `Transfer-Encoding`
  and the hop-by-hop headers such as `Connection` and `Upgrade`. The proxy reads or removes these
  headers, so a value there would never reach the origin as that header
  (`CredentialGrammar.RefusedHeaders`);
- a parameter name without `&`, `=`, `#`, `+` or a byte outside visible ASCII: `+` is refused
  because a form parser reads it as a space, so the origin would read `a+b` as `a b`.

The proxy reads a request head of at most 16384 bytes (`AgentEgressProxy.MaxHttpHeaderBytes`). A
request's head holds the value, and the host, the prefix and the header or parameter name of a
binding that applies to the request:

- a JWT with many group or role claims is longer than 4 KiB, so the value's bound is well above
  4 KiB;
- a longer value is refused at the origin by an AWS Application Load Balancer, whose limit for
  one header is 16 K, and by a Node.js server, whose default for a message's headers is 16 KiB:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html
  - https://nodejs.org/docs/latest-v24.x/api/cli.html#--max-http-header-sizesize

Each launch makes a new, random placeholder. Workspace files can hold the placeholder once the
session runs. The randomness keeps a string written before the launch, such as an application's
own token, from equaling the placeholder and being replaced.

A value that starts with a prefix programs recognize (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
`github_pat_`, `glpat-`) gets a placeholder in the value's format. So a program that checks a
token's syntax before sending the token still sends the placeholder. The placeholder keeps:

- the prefix and the length;
- `-`, `.`, `_` and `~` in place, which separate the parts of GitHub's `ghs_APPID_JWT` installation
  tokens;
- a digit for each digit and a letter of the same case for each letter. Other punctuation becomes
  a letter or a digit: `&`, `=`, `#` and `%` would split or re-parse the query that a `?PARAM`
  placeholder is composed into.

Any other value gets a placeholder of 22 random letters and digits, the fewest that hold 128 bits.
No format limits that placeholder's length (`EgressCredentials.placeholderFor`):

- The other values are a value without such a prefix, and a prefixed value whose format leaves
  fewer than 64 random bits: about 14 letters or 20 digits besides the prefix and those
  separators.
- The random placeholder shows the sandbox nothing of the value. A placeholder in the value's
  format would show the value's length, where its separators are and each other character's
  class. That narrows the guesses for a password a person chose.
- A program that checks such a value's syntax before sending it may refuse the placeholder
  (`TODO.md`, "Credential brokering").

### Which credentials fit

- Forge tokens, and the bearer tokens of cloud APIs. Google Cloud and Azure access tokens travel as
  `Authorization: Bearer`, so a binding covers them under three conditions: the API host is
  inspected, the rules hold the `method=POST` grants that cloud APIs need, and the cloud's CLI or
  SDK trusts the launch CA.
- A whole token in one query parameter: an Azure storage SAS token's `sig`, which is an HMAC over
  the SAS's own fields that anyone who holds it can reuse; and a Google API `key`.
- Not a request-bound signature, such as an S3 presigned URL's `X-Amz-Signature` or a Cloud
  Storage V4 signed URL's `X-Goog-Signature`. Consuming such a signature needs nothing here.
  Generating one computes the signature locally, so no request passes the proxy meanwhile.
  - Cloud Storage can sign through the IAM Credentials `signBlob` API instead. That API's request
    carries a bearer token that a binding covers, and the key stays with Google.
  - Azure's `getUserDelegationKey` runs under a bearer token too, but its response is the
    delegation key, which the proxy forwards unchanged. The sandbox then holds a signing
    credential for the account until the expiry the request asked for, at most seven days
    (https://learn.microsoft.com/en-us/rest/api/storageservices/get-user-delegation-key). A
    session that must not hold such a credential obtains the key and signs on the host.
  - An AWS client signs each request itself and never sends its key (`design.md`, "Credential
    brokering at the egress proxy").
- Not a model provider's login or API key: model providers' hosts are tunnels, where nothing is
  substituted. The same design.md section says why.

## Through an upstream proxy

`HTTPS_PROXY` in the launcher's environment, `http[s]://[user:password@]host:port`, sends every
origin connection of the session's proxy through that upstream proxy.

- Lowercase `https_proxy` is read when the uppercase is unset or empty; `HTTP_PROXY`, `ALL_PROXY`,
  `NO_PROXY` and OS proxy settings are not read at all.
- The port is explicit because clients disagree on the default: curl assumes 1080, Go, Python and
  Node assume 80.
- A malformed value refuses the launch, naming the part that is wrong and never the value.
- `--build`'s pulls and builds, and `podman machine start`, use the host's variables, as podman
  does on its own.
- Of a session's containers, only the proxy receives the one selected variable. The sandbox
  receives none of the variables.
- An upstream proxy running on a Windows host is `host.containers.internal` in `HTTPS_PROXY`. The
  upstream proxy needs an inbound firewall rule for its port on the WSL interface
  (`-InterfaceAlias 'vEthernet (WSL*)'`):
  - The firewall drops connections from the podman machine to a host listener that no rule allows,
    and every origin connection then fails with `Connect timed out`.
  - A rule that names the program let no connection through (`development.md`, "On Windows x64").

The upstream proxy changes only how the session's proxy reaches an allowed address:

- the ruleset decides every destination, the proxy resolves the name once, and every answer must
  be public;
- the proxy asks the upstream proxy for a tunnel to that numeric address, never to the hostname,
  which the upstream proxy would resolve itself, outside the check;
- a failure on that path is an `error` line and a 502, never a direct retry.
  `ko-sandbox-egress-check <host>` prints the stage.

The launch banner and the proxy's startup lines name the endpoint without its userinfo. The
userinfo stays in the proxy container's environment (`../SECURITY.md`, "Egress proxy").
`--egress-check=<host>` reports whether a tunnel to the host's first address could be opened.

Not supported yet, each failing closed with a certificate error:

- an upstream proxy that terminates TLS with its own certificate, whose re-signed origin
  certificates fail validation in the proxy and in the sandbox's clients alike;
- an `https` endpoint under a private CA.

In the proxy container, a loopback endpoint is the container's own loopback, not the host's. So a
helper such as cntlm that listens on the host's `127.0.0.1` is out of reach. The same variable does
reach the helper from a `--run-on-host` command's proxy, which runs on the host
(`run-on-host-internals.md`, "The command's egress proxy").
