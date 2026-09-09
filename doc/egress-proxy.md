# The egress proxy

Every sandbox session reaches the network through one HTTPS proxy in its own container, on a
network the session cannot route out of. The ruleset specifies the reachable hosts, permitted
operations and whether requests are inspected. The proxy resolves it from its built-in
defaults, the profile selected at launch, and the project's rule file, and prints it at every
start. This document explains how to write the rule file and read the printout. SECURITY.md,
"Egress proxy", explains the protections and their limits.

A *rule* is a line of the project's file, what is written and reviewed; the *ruleset* is what a
launch enforces: the defaults, the profile and the file resolved together, printed as the ruleset
lines and named by a digest. Two files of different rules may resolve to one ruleset.

## Choosing an egress profile

Every launch selects an `--egress=` profile; `deny-unless-allowed` is the default. An admitted
host has one of two treatments: a `tunnel`, opaque, nothing seen or logged past the `CONNECT`;
or inspected — TLS terminated, each request decided against the grants of its resolved scope,
and refused where no grant admits it ("The rule file" below; SECURITY.md, "Reading without being
able to write", has what each grant opens and what inspection costs and buys).

The proxy supplies default rules for every supported model provider: `anthropic`, `openai`,
`google`, `aws` and `github`. These permit tunnels to model, authentication and control-plane
endpoints. GitHub's rules also permit two inspected login `POST`s and one token read. The defaults
include inspected documentation, package-registry and forge hosts, with `read` on every line and
`git-fetch` on the three forges. The proxy image lists these rules in `defaults/host` and
`defaults/model-provider/*`, with the reason beside each line.

1. `deny-unless-allowed` (the default) — the defaults, then every line of the project's file.
1. `deny-unless-model` — default rules for the launched agent's provider, then the file's URL
   and model-provider denials. It ignores `allow` and `deny defaults` lines.
   `claude` selects `anthropic`, `codex` selects `openai`, `agy` selects `google`,
   `kiro-cli` selects `aws`, `copilot` selects `github`; `opencode`, which has no fixed
   provider, selects every provider under `defaults/model-provider/`.
   Only the basename of the directly launched command is classified; anything else selects no
   provider, admits no host, and says so at startup.
1. `allow-unless-denied` — `deny-unless-allowed`'s ruleset, and every public hostname on port
   443 it leaves out admitted as an inspected `read`: `GET` and `HEAD`, logged, all other methods
   refused. A whole-host or `read` deny refuses such a host outright — an unlisted host holds
   `read` and nothing else, so a `tunnel` deny takes nothing from it. Choose it for work whose
   hosts cannot be listed in advance, such as web browsing or dependency downloads. Public hosts
   remain readable unless a rule restricts them, and a permitted read carries its URL
   (SECURITY.md, "Exfiltration through allowed network traffic"). An `allow` line narrows one such
   host to its grants or, with `tunnel`, makes it opaque; `deny https://**.domain/` refuses a domain
   and every host under it; a clone from an unlisted forge fails at its first request until a
   `git-fetch` line names the forge.
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

`HOST` is an exact hostname — IDN mapped, lowercased, one trailing dot removed — never an IP
literal, a port, userinfo, a query or a fragment; `**.` is the deny side's only pattern, the apex
and everything under it (`**.foo.com` covers `foo.com` and `api.foo.com`, never `barfoo.com`).
The path is written unencoded, in printable ASCII, in canonical form: it begins with `/`, and
has no `%`, `\`, empty, `.` or `..` segment, and no `?`. A trailing `/` names the tree under it;
none names that one path; `https://HOST/` is the root, the whole host. Case is the origin's: the
proxy folds nothing. `https://HOST` without its slash is refused, never read as the root.

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
- `tunnel` — the opaque treatment. It stands alone on its line, and its URL ends at `/`.

The selected profile determines the starting rules and which project lines apply. Those lines
apply in file order: an `allow` adds its grants under its path; a `deny` removes the named grants
from every scope on each matching host, or all grants when it names none. For each grant, the
last applicable line decides, regardless of which earlier line supplied it. `design.md`, "No
richer rule format", explains the PF and relayd inspiration.

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
A request matching no line, on a host without a root line, is refused; under `allow-unless-denied`
that is a host some line narrowed, since one no line names has `read` at the root (the profiles,
above). Where the longest match is
a scope other than the root, the request is first refused, on every method, for a spelling the
origin might fold onto another path — `%`, a dot segment, a backslash, an empty segment — because
the proxy compares literally and cannot know how the origin decodes; a wrong-case path fails
closed on GitHub and GCS alike.
Under the root, `GET` and `HEAD` may carry any of those spellings, which keeps npm's
`/@scope%2fname` readable beside a `method=` line. `POST`, `PUT`, `PATCH` and `DELETE` still refuse
percent-encoding and dot segments there; backslashes and empty segments are refused only under a
scope other than the root. A line is therefore a boundary as well as a grant: one whose grants its
enclosing scope already holds still changes which path spellings are refused.

Under `deny-unless-allowed` and `allow-unless-denied`, `deny defaults` removes the built-in
rules from the starting ruleset. It must be the first line. The public-read fallback under
`allow-unless-denied` still applies. `allow model-provider NAME` expands to the
provider's default rules at that position. `deny model-provider NAME` expands to a whole-host
denial for every host listed in those rules, regardless of their paths or grants. It removes all
earlier grants on those hosts, including grants from the catalog or project rules. A later allow
grants only what it names.

For example, `deny model-provider github` also denies repository access on `github.com` and API
access on `api.github.com`. To restore repository reads and Git fetches, follow it with
`allow https://github.com/ read git-fetch`; to restore API reads, add
`allow https://api.github.com/ read`. Hosts absent from GitHub's model-provider rules, such as
`raw.githubusercontent.com`, are unaffected by that denial.

To permit only one provider's default rules under `deny-unless-allowed`:

```text
deny defaults
allow model-provider anthropic
```

A host has one treatment. `deny https://api.example/ tunnel` takes the treatment, and an `allow`
with `read`, `git-fetch` or `method=` then makes the host inspected; a `tunnel` line for a host
the defaults inspect needs `deny defaults` and the whole ruleset after it (SECURITY.md, "Adding
hosts, not patterns", has why).

`doc/egress-rule-example/*/rule` holds complete files for common needs — a bucket, a container,
a Pulumi AWS stack, the lockdown, npm's audit `POST` — to copy over `.ko-agent-sandbox/egress/rule`
and trim.

Every ambiguity is a failed launch with the reason and the line printed:

- an unrecognized configuration entry: `egress/` accepts only `rule`, and `.ko-agent-sandbox/`
  accepts `egress`, `agent` and `host-command`. Dot-prefixed metadata entries are ignored;
- a token outside the grammar, an unknown profile, provider, grant word or method, a `#` inside a
  token, a host that is an IP literal or is not a hostname;
- a path outside canonical form; a `deny` or a `tunnel` with a path; `https://HOST` without its
  slash; an `allow https://` line naming no grant, or a word twice; `tunnel` beside another word;
- a line above `deny defaults`;
- a resolved host holding `tunnel` beside an inspected grant, from the file's lines or the
  defaults'; a `tunnel` line for a host the defaults inspect without `deny defaults`.

Two lines disagreeing about a grant are the ordinary case, not a refusal: the later one decides,
and a repeated line is the last word on its grants — `deny`, `allow`, `deny` takes an exception
back; `allow`, `deny`, `allow` restores what the deny took.
Three conditions are warned at every launch instead, under every profile, so a misspelling cannot
fail silently: a `deny` matching nothing at its position; a redundant grant — a line granting
nothing its enclosing scope lacks, `allow https://github.com/my-org/ git-fetch` under the
defaults' root line, which usually means a host-wide `deny` before it was intended, though the
boundary it opens remains; and a line every grant of which a later line takes back. A line
restating a defaults line at its path is silent: that is how a file stays valid as the image
adopts its hosts.

1. An absent directory or rule file contributes no rules; the profile still starts from what it
   starts from. `KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` may create an empty `.ko-agent-sandbox`
   directory in the project (SECURITY.md, "Silent changes to what you own"). An empty
   ruleset is valid and reported as such — `deny-all` resolves empty by design, as does
   `deny-unless-model` under `bash`.
1. Editing the file takes effect on the next launch; a running session keeps its original ruleset.
1. The sandbox cannot edit it, under either write mode (SECURITY.md, "Why the rules are per
   project, in the project, and read-only").
1. The directory is meant to be committed, and read before an unfamiliar project is launched
   (SECURITY.md, "A repository that ships wide egress rules").

## The printed ruleset

`--egress-effective` and `--egress-check=<host>` (README, Reference) answer without starting a
session; inside one, `sandbox-egress-check <host>` asks the running proxy. Every start prints the
rule file as written, one line; then the launch banner — the profile and the counts, never a
host name; then, when the file grants beyond the defaults for a host — a host the defaults lack,
`tunnel`, `method=` or `git-fetch` where they lack it, `deny defaults` — those lines once more on
a line of their own, `egress rules widen:`, so a file that only takes or narrows prints nothing
extra.

The ruleset itself is what the proxy prints at its start and `--egress-effective` shows whole: the
profile line, then — under `allow-unless-denied` — one `deny` line per host or subtree the public
default does not reach, then one `allow` line per resolved scope, in the rule grammar, with the
scope's whole grant set, hosts and paths sorted:

```text
egress profile: deny-unless-allowed
allow https://api.anthropic.com/ tunnel
allow https://github.com/ read git-fetch
allow https://github.com/login/device/code read git-fetch method=POST
...
```

Each `allow` and `deny` line uses the rule grammar so a reader learns one; but the printout is a
serialization of the ruleset, not a rule file: it has no `deny defaults` header, nothing reads it
as input, and it is not promised to re-parse to itself. Those lines are what the proxy's digest
names — one stable log line per run, comparable across runs — what the leaf certificate's names
are read from, and what the agent's "What this session may do" section and
`KO_AGENT_SANDBOX_EGRESS_RULESET` give, so two files resolving to one ruleset print one digest and
the same lines, and the same file under two profiles never does. After them, outside the digest,
the metadata: one summary line — the counts of inspected and opaque hosts, denial patterns and
widening lines — and the widening line.
`--egress-effective` adds each line's sources: an `allow` line's boundary and each of its grants,
a `deny` line's pattern, and under the finite profiles the hosts the file's lines denied.

## Audit what has been allowed or denied

Run with `--proxy-log` from the project directory. Every proxy connection is logged,
and the proxy appends the log to a per-run file on the host, under

    ~/.local/state/ko-agent-sandbox/log/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\log\<project>\     # native Windows

With no arguments, `--proxy-log` prints the retained files oldest first — the newest 20 runs, and
any older one whose session is still running, since a live proxy is still appending to its file.
The startup lines are the ruleset, its digest, the metadata and whether inspection is
active; every connection event after them is one line, with an inspected request's full target —
query string included, which is what makes an exfiltrating `GET` visible. A refusal reads as

    2026-08-26T11:59:38Z deny github.com POST /owner/repo.git/git-receive-pack POST not granted

SECURITY.md, "The audit line grammar", has every field and reason.

## TLS inspection

The proxy terminates TLS for every inspected host and checks each request against its grants.
Only hosts with the `tunnel` treatment stay opaque — under `deny-unless-allowed` and
`allow-unless-denied` the hosts with model-provider tunnel rules, unless a project removes them or
adds more; under `deny-unless-model` the selected providers' remaining tunnel hosts; under
`deny-all` none.

The per-project CA is stored on the host, under

    ~/.local/state/ko-agent-sandbox/tls/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\tls\<project>\     # native Windows

1. The certificates are created and refreshed automatically for each project (SECURITY.md,
   "Who holds the CA key").
1. Deleting that directory is how you rotate the CA. The next launch recreates it, and every
   launch's proxy starts with the certificates the launch found or issued.
1. Under `allow-unless-denied` a launch creates a CA for the run instead, as
   `run-<suffix>/agent-egress-proxy/allow-unless-denied/ca.crt` and `ca.key` under that
   directory, and removes it with the run; the proxy issues each host's certificate from it at the
   host's first connection. Nothing is rotated: no session trusts another's.

## Through an upstream proxy

`HTTPS_PROXY` in the launcher's environment, `http[s]://[user:password@]host:port`, sends every
origin connection of the session's proxy through that upstream proxy; lowercase `https_proxy` is
read when the uppercase is unset or empty, and `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` and OS proxy
settings are not read at all. The port is explicit because clients disagree on the default: curl
assumes 1080, Go, Python and Node assume 80. A malformed value refuses the launch, naming the part
that is wrong and never the value. `--build`'s pulls and builds, and `podman machine start`, use
the host's variables as podman does on its own; of a session's containers only the proxy receives
the one selected variable, and the sandbox none of them.

What changes is only how an admitted address is reached: the ruleset decides every destination as
before, the name is resolved once and every answer must be public, and the upstream proxy is
asked for a tunnel to that numeric address — never for the hostname, which it would resolve
itself, outside the check. A failure on that path is an `error` line and a 502, never a direct
retry; `sandbox-egress-check <host>` prints the stage.

The launch banner and the proxy's startup lines name the endpoint without its userinfo, which
stays in the proxy container's environment (SECURITY.md, "Egress proxy"). `--egress-check=<host>`
reports whether a tunnel to the host's first address could be opened.

Not supported yet: an upstream proxy that terminates TLS with its own certificate, whose re-signed
origin certificates fail validation in the proxy and in the sandbox's clients alike, and an
`https` endpoint under a private CA. Both fail closed with a certificate error. In the proxy
container a loopback endpoint is the container's own loopback, not the host's, so a helper such as
cntlm listening on the host's `127.0.0.1` is out of reach; the same variable does reach it from a
`--run-on-host` command's proxy, which runs on the host (`run-on-host.md`, "The command's egress
proxy").
