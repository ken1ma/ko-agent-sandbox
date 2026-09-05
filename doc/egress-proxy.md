# The egress proxy

Every sandbox session reaches the network through one HTTPS proxy in its own container, on a
network the session cannot route out of. Which hosts a session reaches, and with what treatment,
is a ruleset: the launcher-owned defaults, the profile selected at launch, and the project's rule
file, resolved together by the proxy itself and printed at every start. This document is the
reference for writing that file and reading that printout. SECURITY.md, "Egress proxy", is the
security model — what the proxy defends and what it costs — and every "why" below points there.

A *rule* is a line of the project's file, what is written and reviewed; the *ruleset* is what a
launch enforces: the defaults, the profile and the file resolved together, printed as the ruleset
lines and named by a digest. Two files of different rules may resolve to one ruleset.

## Choosing an egress profile

Every launch selects an `--egress=` profile; `deny-unless-allowed` is the default. An admitted
host has one of two treatments: a `tunnel`, opaque, nothing seen or logged past the `CONNECT`;
or inspected — TLS terminated, each request decided against the grants of its resolved scope,
and refused where no grant admits it ("The rule file" below; SECURITY.md, "Reading without being
able to write", has what each grant opens and what inspection costs and buys).

The launcher-owned defaults are every model-provider group — `anthropic`, `openai`, `google`,
`github`, each that provider's model, authentication and control-plane endpoints as tunnels; the
`github` group's forge lines are two login `POST`s and one token read, inspected — plus a curated
catalog of inspected documentation, package-registry and forge hosts, every line a `read`, the
three forges `read git-fetch`. The proxy image's `defaults/host` and `defaults/model-provider/*`
files are the membership, with the reason beside each line.

1. `deny-unless-allowed` (the default) — the defaults, then every line of the project's file.
1. `deny-unless-model` — only the launched agent's own provider group, then the file's `deny`
   lines: `claude` selects `anthropic`, `codex` selects `openai`, `agy` selects `google`,
   `copilot` selects `github`. Only the basename of the directly launched command is classified;
   anything else — `bash`, a wrapper script — selects no provider, admits no host, and says so at
   startup.
1. `allow-unless-denied` — `deny-unless-allowed`'s ruleset, and every public hostname on port
   443 it leaves out admitted as an inspected `read`: `GET` and `HEAD`, logged, every write
   refused. A whole-host or `read` deny refuses such a host outright — an unlisted host holds
   `read` and nothing else, so a `tunnel` deny takes nothing from it. Choose it for work whose
   hosts cannot be listed ahead of it — the open web, an unbounded dependency tree — and expect
   its price: every public host is reachable for reading, and a permitted read carries its URL
   (SECURITY.md, "Exfiltration through an allowed host"). An `allow` line narrows one such host
   to its grants or, with `tunnel`, makes it opaque; `deny https://**.domain/` refuses a domain
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

- `read` — `GET` and `HEAD`, without a body.
- `git-fetch` — a clone's two requests, the ref discovery (`GET .../info/refs?service=
  git-upload-pack`) and the transfer (`POST .../git-upload-pack`). A `git-fetch` line without
  `read` is clonable and not browsable; a `read` line without `git-fetch` is browsable, and a
  clone fails at its first request. `git-fetch` never grants `git push`.
- `method=POST,PUT,...` — the listed methods, from `POST`, `PUT`, `PATCH`, `DELETE`, at that
  path. A `method=` line alone is write-only. `git push`'s ref discovery is refused except where
  `POST` is granted at the repository.
- `tunnel` — the opaque treatment. It stands alone on its line, and its URL ends at `/`.

The lines apply in the order written, over the defaults — the PF and relayd model, whose lineage
and limits design.md records under "No richer rule format": an `allow` adds its grants
under its path, a `deny` takes the named grants from every scope on each host it matches, or
every grant when it names none, and for each grant the last applicable line decides. A `deny`
names a host or a subtree whole, never a path (SECURITY.md, "Adding hosts, not patterns", has
why a denial by path fails open). So the restrictive shape is a host-wide `deny` with the
narrower `allow` beneath it, and the broad denial comes first:

```text
allow https://www.rfc-editor.org/ read                 # reads under the host
deny https://codeberg.org/ git-fetch                   # the defaults' grant, taken back host-wide
allow https://codeberg.org/my-org/ git-fetch           # re-granted under one owner only
allow https://github.com/login/device/code method=POST # one method at one path, no read
allow https://storage.googleapis.com/my-bucket/ read   # reads under one tree only
allow https://api.example/ tunnel                      # an opaque tunnel: the widest word
deny https://telemetry.example/                        # this host, whole
deny https://**.googleapis.com/                        # the apex and everything under it
deny https://github.com/ git-fetch                     # takes back a grant, keeps the reads
deny model-provider google                             # the group's own lines
```

The same two lines the other way round deny the owner too, the deny being the last word. `deny
https://github.com/` then `allow https://github.com/my-org/ read` reads one owner and nothing
else on the forge; a clone there is refused at its first request.

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
Under the root a read may carry any of those, which is what keeps npm's `/@scope%2fname` reading
beside a `method=` line; a write keeps that refusal everywhere. A line is therefore a boundary as
well as a grant: one whose grants its enclosing scope already holds still changes what a request
under it is refused for.

`deny defaults`, the first line if present, means the defaults contribute nothing and the file is
the whole ruleset. Any line above it is refused. `allow model-provider NAME` expands, at its
position, to the group's lines; `deny model-provider NAME` removes the group's contributions in
force at its position and no other line's — the catalog's `read` on `api.github.com` outlives
the `github` group's token line — and a later `allow model-provider NAME` contributes them again.
A lockdown is two lines:

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

- a filename in `egress/` other than `rule` — the retired `allowed` and `denied` are named as
  such, with the pointer here — and in `.ko-agent-sandbox/` itself, an entry other than `egress`,
  `agent` or `host-command`;
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
Three things are warned at every launch instead, under every profile, so a misspelling cannot
fail silently: a `deny` matching nothing at its position; a redundant grant — a line granting
nothing its enclosing scope lacks, `allow https://github.com/my-org/ git-fetch` under the
defaults' root line, which usually means a host-wide `deny` before it was intended, though the
boundary it opens stands; and a line every grant of which a later line takes back. A line
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
are read from, and what the agent's authority section and `KO_AGENT_SANDBOX_EGRESS_RULESET` give,
so two files resolving to one ruleset print one digest and the same lines, and the same file under
two profiles never does. After them, outside the digest, the metadata: one summary line — the
counts of inspected and opaque hosts, denial patterns and widening lines — and the widening line.
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

The proxy terminates the TLS of every inspected host so that reading can be allowed and writing
refused. Only hosts with the `tunnel` treatment stay opaque — under `deny-unless-allowed` and
`allow-unless-denied` the model providers, unless a project adds more; under `deny-unless-model`
the selected group's tunnel lines; under `deny-all` none.

The per-project CA lives on the host, under

    ~/.local/state/ko-agent-sandbox/tls/<project>/     # Linux / macOS / WSL
    %LOCALAPPDATA%\ko-agent-sandbox\tls\<project>\     # native Windows

1. The certificates are created and refreshed automatically for each project (SECURITY.md,
   "Who holds the CA key").
1. Deleting that directory is how you rotate the CA. The next launch recreates it, and every
   launch's proxy starts with the certificates the launch found or minted.
1. Under `allow-unless-denied` a launch mints a CA for the run instead, as
   `run-<suffix>/agent-egress-proxy/allow-unless-denied/ca.crt` and `ca.key` under that
   directory, and removes it with the run; the proxy mints each host's certificate from it at the
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
`--run-on-host` build's proxy, which runs on the host (`run-on-host.md`, "The build's egress
proxy").
