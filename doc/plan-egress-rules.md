# Plan: one `rule` file, entries as URLs

## Outcome

The project's egress policy is one file, `.ko-agent-sandbox/egress/rule`, whose lines say
`allow` or `deny` and name what they mean as a URL:

```text
allow https://www.rfc-editor.org/ read                 # reads under the prefix
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

A lockdown is two lines, `deny defaults` first and `allow model-provider anthropic` after it.

Two words, kept apart throughout: a *rule* is a line of that file, and the file is the
project's rules — what is written and reviewed, in the rule grammar; a *policy* is what a
launch enforces — the defaults, the profile and the file resolved together, printed as the
policy lines and named by the digest. Rules are written; a policy is resolved, and two files of
different rules may resolve to one policy.

`allowed` and `denied`, `+host`, `-host`, `-**`, `allow=`, `path=` and the tags `npm-audit` and
`github-login-device` are gone. What a line grants is its words — `read`, `git-fetch`,
`method=`, `tunnel` — and every `allow https://` line carries at least one; nothing is implied.
The file's order is its meaning, as a PF or relayd ruleset's is: the lines apply in order over
the launcher-owned defaults, an `allow` adding its grants under its path on top of every
wider line for the host, a `deny` taking the grants it names from every scope on the host, and
for each grant the last applicable line decides. So the broad denial comes first and its
exception after it, the shape every example above has.

## Evidence and target

The grammar this replaces spells one fact three ways — an addition's word, an allowance's tag and
a prefix's attribute — and keeps the measured path of an allowance in a Scala constant where a
policy reader cannot see it. A URL is the form every comparable project's operator already
writes (Copilot's coding-agent firewall accepts one beside a domain; coder/boundary spells
`domain= method= path=`), and it reads without knowledge of this proxy's vocabulary. The other
reason is a decision reached while narrowing entries by path: restricting the grammar buys no
security about what a reviewed project may open — `unrestricted` is right there — and real
security about the file meaning exactly what it reads. The second is what this grammar keeps:
one parser of the proxy's own, one resolver the launcher's dry run executes, exact hosts so
that a grant is enumerable and the leaf certificate can name it, `deny` with no path to get
wrong, every ambiguity a refused launch. The first it stops pretending to buy. The evaluation
model is OpenBSD's: PF and relayd evaluate rules in order and let the last matching one decide,
the restrictive pattern being a broad block followed by its exceptions, and relayd applies
that to HTTP requests by method, path and host — the nearest established grammar to this one,
and one that reached this shape by replacing its own earlier one: relayd's HTTP filtering was
per-header protocol directives, matched by name, until 2014, when reyk replaced them with
last-matching rules "inspired by pf" (the commit in References).
What is not borrowed from it is under "Deliberate exclusions". doas is the same house's
smaller instance — `permit`/`deny`, last match wins, no match denies — and the precedent for
keeping the vocabulary this small.

## Invariants

1. A line grants exactly the words it carries, under the path it names, and nothing else on the
   host: `read` is GET and HEAD, bodyless; `git-fetch` is a clone's two requests, the ref
   discovery and the upload-pack POST, so a `git-fetch` line without `read` is clonable and not
   browsable; `method=` is its list; `tunnel` is the opaque treatment, alone. A line with no
   word is refused, never read as `read`, and a line with `method=` alone is write-only — the
   github group's github.com is two such lines and readable nowhere. Resolution folds a host's lines
   into cumulative scopes: the scope at a path is the union of every line whose path contains it,
   after the denies of invariant 3 have had their say in order, so a root `git-fetch` line and a
   narrower `method=POST` line make the narrower scope carry both. A request is authorized
   against the resolved scope of its longest literal match — never against the one line alone —
   and a request matching no line, on a host without a root line, is refused. The longest match
   selects the resolved state for a location and the boundary invariant 5 enforces there; it is
   no precedence among lines. Textual order decides authority, and a later root `deny` beats
   an earlier `/api/` allow of the same grant however specific the path: `allow
   https://example.com/api/ read` then `deny https://example.com/ read` leaves `/api/x` refused,
   where a most-specific-wins rule would admit it, and a specificity-then-order hybrid is the
   precedence model this grammar refuses.
1. `deny` names a host, a subtree or a group, never a path: its URL's path is `/`, as a `tunnel`
   line's is. A grant list on it takes back those grants from every line of the defaults and the
   groups on the host, at every path; without one it takes the host whole. No path, because a grant
   by path needs one spelling that works while a denial by path needs every spelling that reaches
   the tenant, and the proxy, comparing literally, cannot know them. With the defaults granting
   `git-fetch` on github.com and a hypothetical `deny https://github.com/secret-org/`:
   `/%73ecret-org/repo.git/…` misses the deny, lands in the root, is admitted with `git-fetch`, and
   GitHub decodes `%73` to `s`; `/Secret-Org/…` likewise, GitHub folding case; an origin that strips
   a segment's trailing dot or a `;parameter` folds `/secret-org./` and `/secret-org;v=1/` the same
   way; and `/orgs/secret-org`, or a search page with `org:secret-org`, reach the organisation under
   paths the deny never named. Each escape gains access: a denial by path fails open. Under
   invariant 3's shape, a host-wide `deny` with a narrower `allow` beneath it, every spelling that
   misses the narrower allow stays governed by the host-wide deny, so an escape loses access. A
   case-folding keyword would close one of these on one origin and none of the others, so it is not
   a way in.
1. The lines apply in the order written, over the defaults, and for each grant on a host the
   last applicable line decides: an `allow` adds its grants at its path, a `deny` clears the
   grants it names from every scope on the host, a later line of either kind overriding an
   earlier one for the grants it names and no other. So `deny https://codeberg.org/ git-fetch`
   then `allow https://codeberg.org/my-org/ git-fetch` clones one owner on a forge the defaults
   make clonable whole; `deny https://github.com/` then `allow https://github.com/my-org/ read`
   reads one owner; the same two lines the other way round deny the owner too, the deny being
   the last word; and a third line repeating the deny takes the exception back, as it reads.
   Fail-closed for the reason a denial by path is not: a deny is host-wide, so the exception
   beneath it is the narrower scope, and a spelling the proxy cannot place in the narrower one
   lands where the deny holds. A `deny` matching nothing at its position is a launch warning,
   under every profile; so is a line whose every grant a later line takes back, since the file
   says something it then unsays. Denies subtract host-wide from the defaults' lines and the
   file's earlier lines alike; nothing survives beneath a deny except what a later line grants.
1. A rule's path is written unencoded, in printable ASCII, in canonical form: begins with `/`, no
   `%`, `\`, empty, `.` or `..` segment, `?`. A trailing `/` names the tree under it; none names
   that one path. Case is the origin's; the proxy folds nothing. A path a request can only spell
   encoded — a space, a non-ASCII name — cannot be narrowed at all; it stays readable under a
   root line, which is the stated cost.
1. A request is compared literally. Where its longest literal match is a line other than the host's
   root line, the request is first refused for `%`, a dot segment, a backslash and an empty segment,
   on every method: under such a line the path decides grants the root does not give, and `POST
   /uploads/%2e%2e/admin` would otherwise carry a POST to `/admin`. Under the root the request has
   the host's least grants and gains nothing by any decoding, so a read there may carry `%` —
   which is what keeps npm's `/@scope%2fname` reading on a host that also has a `method=` line. A
   write method keeps today's rule under the root as everywhere: `%` and a dot segment refused
   (`requireUnambiguousPath`), so a `method=` grant at the root opens no spelling the origin
   decodes. A line is therefore a boundary as well as a grant: the scope it opens is where this
   refusal begins, so a line whose grants its enclosing scope already holds still changes what
   a request under it is refused for, and stays in the resolved policy and its printed form.
1. What is authorized is what is forwarded, in two strengths. The method and the request-target
   the decision read are the bytes the origin receives: nothing after the decision rewrites,
   normalizes or re-encodes them, and the decision reads no other spelling of them
   (HTTPHelper.toUpstreamBytes). The Host header is held to its meaning, not its bytes: the
   origin receives the client's spelling with the optional whitespace, SP and HTAB, stripped,
   as HTTP defines the value, and the decision compares that value's normalized form — case
   folded, one trailing dot and `:443` removed — to the CONNECT host (normalizeHostHeader),
   every spelling it folds naming the one host the tunnel was opened to. Envoy's
   authorization-then-mutation ordering and nginx's `proxy_pass` choosing between the original
   and a re-encoded URI are the recorded failures of this class; here no stage transforms the
   method or the target, and invariant 5's refusal of ambiguous spellings completes the rule on
   the origin's side.
1. A line that adds nothing to its enclosing scope is a launch warning, printed at every launch
   and naming the deny-then-re-grant pair as the step — `allow https://github.com/my-org/
   git-fetch` under the defaults' root, where narrowing is what the line was written for. A
   warning, never a refusal, because the check reads the defaults: refused, a file that launches
   today would fail under a later image whose defaults grew to cover it, and a policy file must
   not stop parsing because of a change it did not make. Silent, the restatement that is how a
   file stays valid as the image adopts its hosts: a line at a path where the defaults have a
   line, granting nothing the defaults do not already grant there — `allow https://github.com/
   read` over the defaults' `read git-fetch` root line, the github group's login line restated.
   Refused, a line the file itself already carries, the same path and the same words: that one
   is the file's own doing. The check reads the defaults and the file alone, never the profile:
   a file valid under one profile is valid under every one, and a line a profile does not
   consult it ignores.
1. A host has one treatment, and `tunnel` is a grant word on both verbs. A resolved host holding
   `tunnel` beside `read`, `git-fetch` or `method=` is a refused launch, the file's lines and the
   defaults' alike — `tunnel` composes with no other word on its own line, and `allow
   https://api.example/safe/ read` under a defaults tunnel still standing is that refusal.
   Narrowing is local: `deny https://api.example/ tunnel` takes the treatment, and `allow
   https://api.example/ read`, or a narrower line, then makes the host inspected — invariant 3's
   re-grant, the deny no longer holding what the allow grants — so one host's decision costs one
   host. Widening is global: a `tunnel` line for a host the defaults inspect needs `deny
   defaults`, whatever `deny` precedes it — the rule reads the defaults, not the file's state —
   because an opaque tunnel ends inspection and the audit record for a host every project has,
   and a project deciding that states its whole policy.
1. `method=` names methods from the closed list `POST`, `PUT`, `PATCH`, `DELETE`, comma separated,
   under the line's path; a body on GET and HEAD stays refused. `git push`'s ref discovery stays
   refused except where a line grants `POST` at the discovered repository — there the push is the
   project's own grant, visible as such. `git fetch`'s ref discovery, `GET …/info/refs?service=
   git-upload-pack`, is `git-fetch`'s own request, not `read`'s: refused where the scope lacks
   `git-fetch`, so a clone that could not transfer fails at its first request rather than its
   second — the rule push already has.
1. Provider groups are lines. `allow model-provider NAME` expands, at its position in the file,
   to the group's lines, which apply like any others; `deny model-provider NAME` strikes those
   lines, wherever they stand, as though never written — a grant another line also gives stays,
   which is why it is not a host-wide deny of the group's grants: the catalog's `read` on
   api.github.com outlives the group's token line. So the two verbs' provider forms are not the
   URL forms with a different target: a URL `deny` takes authority from a host, a provider
   `deny` takes one named source's contributions and no other's — PF's anchor, a sub-ruleset
   handled by name, is the analogue, not its address lists — and the resolver keeps them two
   operations, so that no later simplification folds them into one and changes what the
   provider form removes. The
   github group is precise — the two login paths as `method=POST` lines, the token exchange as one
   exact `read`, four `tunnel` lines — and grants no read of the forges, so denying the group
   leaves the catalog's repositories readable.
1. `deny defaults`, first line if present, means the defaults contribute nothing and the file is the
   whole policy. Any line above it is refused: the file reads in the order the words imply, and a
   `deny` above it would clear what the next line clears whole.
   It takes nothing after it: narrowing a host the defaults admit is invariant 3's
   deny-then-re-grant, and a line that adds nothing to what the defaults grant is warned naming
   that pair as the step. Under `allow-unless-denied` the pair holds as it does elsewhere: the
   defaults keep the host in the narrowing set, the `deny` subtracts at its root and the narrower
   `allow` re-grants beneath it, so the host stays inspected and narrowed.
1. A `#` starts a comment at the start of a line or after whitespace only; inside a token it is a
   refused line, so `https://host/a#b` is never silently `https://host/a`.
1. Which lines count under which profile: `allow` lines under `deny-unless-allowed`, and the
   inspected ones as the narrowing set under `allow-unless-denied`; `deny` lines under every
   profile; `deny defaults` under `deny-unless-allowed` alone.
1. The leaf certificate names the hosts of the resolved `allow https://` lines, read off the proxy's
   own `--print-policy`; a `tunnel` host is never among them. Unchanged in substance.

## Grammar

```text
deny defaults
allow https://HOST/PREFIX/ GRANT...                       tree
allow https://HOST/PATH    GRANT...                       one path
allow https://HOST/        tunnel                         alone, at the root
allow model-provider NAME
deny  https://HOST/        [GRANT...]                     never a path: invariant 2
deny  https://**.DOMAIN/   [GRANT...]
deny  model-provider NAME

GRANT: read | git-fetch | method=M,... | tunnel           at least one; each once
```

`HOST` is an exact hostname through the existing normalizer — IDN mapped, lowercased, one
trailing dot removed — never an IP literal, a port, userinfo, a query or a fragment; `**.` is
the deny side's only pattern. The parser is the proxy's own: the literal `https://`, the host,
the path — `https://HOST` without its `/` is refused naming the slash, never read as the root —
each refusal named; no `java.net.URI`. The order of the words after the URL is free; `tunnel`
takes no companion on an `allow`, and on a `deny` takes the treatment away (invariant 8). A
`deny` takes any grant word, `read` included: `deny https://github.com/ read` leaves the
defaults' forge clonable and not browsable in one line, where `deny https://github.com/` then
`allow https://github.com/ git-fetch` says the same in two.

The proxy reads the file from one variable, `EGRESS_RULE`. A set `EGRESS_ALLOWED` or
`EGRESS_DENIED` is a refused start naming the new variable: a wrapper or a hand-run image
composing the old grammar must fail, not start on the defaults alone.

Refusals at launch, each naming the line: a filename other than `rule` in `egress/` —
`allowed` and `denied` named as the old ones, with the pointer; a token outside the grammar;
a path outside invariant 4; an `allow https://` line naming no grant, or a word twice; `deny` or
`tunnel` with a path; `tunnel` beside another word on an `allow`; a method outside the list; a
line the file already carries; a resolved host holding `tunnel` beside an inspected grant; a
`tunnel` line for a host the defaults inspect without `deny defaults`; a line above `deny
defaults`; an unknown provider name; `#` inside a token; the old variables set. No
contradiction refusal: two lines disagreeing about a grant are the ordinary case, and the later
one decides (invariant 3). Warnings, printed at every launch: a `deny` matching nothing at its
position; a line adding nothing to its enclosing scope at its position (invariant 7); a line
whose every grant a later line takes back.

## Resolution and enforcement

`resolvePolicy` keeps its profile equations over a new shape: a host's policy is a set of
scopes, each `(path, grants)` — the path a boundary as much as an address (invariant 5), the
grants the words, `read`, `git-fetch`, the methods, or `tunnel`. The defaults are read through
the same parser, and the lines a profile consults apply in file order over what the profile
starts from — the defaults, the selected group, the narrowing set — each as a step on a state:
an `allow` line adds a contribution at its path, or a group's lines at its position; a `deny`
line clears the grants it names from every contribution on the hosts it matches, a whole-host
deny clearing them all; `deny model-provider` strikes the group's contributions; and the scopes
are the contributions folded, a scope's grants the union of every contribution whose path
contains it — one table per host of resolved states by path, which is what a request's longest
match looks up, precedence having been settled by the order before the fold. A host left with
no grant in any scope is denied whole: it leaves the host map, its
CONNECT refused as denied, its name off the leaf — a grant list that empties a host and a
whole-host line are one denial, so the grammar never has to spell an inspected host that grants
nothing, and under `allow-unless-denied` an emptied narrowing-set host is refused, never
ambient. A scope left with no grant while its host keeps some is dropped: scopes are cumulative,
so its enclosing scope is empty too, and every request under it is refused with or without
the boundary. The one-treatment check runs at each line: an inspected grant added to a host
holding `tunnel`, or `tunnel` to a host holding an inspected grant, is the refusal, naming the
`deny` that would clear the way. Provenance is kept beside the structure, not in it, and per
grant rather than per line: a resolved scope has one set of sources for its boundary and, for
each grant it holds, the set of contributions currently supplying it — the defaults' root
`read` and a project line's `POST` meet at `/api/`, and a group and the catalog may supply one
grant together — never one "source" for the line, which a folded scope does not have; PF's
optimizer, which merges rules and thereby changes what per-rule counters mean, is the warning.
An ambient-denial pattern carries a source set the same way: every line that fed it — the
group a `deny model-provider` expanded from, the exact lines a subtree absorbed, the whole-host
and `tunnel` forms that met on one host, the grant lines that emptied a host — so a printed
`deny` line and a `host denied (<line>)` refusal both name lines that exist. Provenance also
marks the project lines that grant beyond the defaults' for their host — a host the
defaults lack, whatever the line grants there; `tunnel`, `method=` and `git-fetch` where
the defaults lack them; `deny defaults` — as widening, one computation for the summary
line's count and `--egress-effective`'s listing. The widening line is delta metadata, printed
after the resolved policy and outside the digest, which names the policy enforced and nothing
about how the file arrived at it. The launcher's own classification goes.

`authorizeInspectedRequest` stays the one gate an inspected request passes, and takes the shape
relayd's 2014 rewrite gave its filter after the earlier design had grown one hook per case:
the request is classified once, into what it is — a read, fetch discovery, upload-pack, push
discovery, another write, each with its path already vetted for the boundary it lands in
(invariant 5) — and that classification is decided once against the resolved scope of the
longest literal match: GET and HEAD under `read`, fetch discovery and upload-pack under
`git-fetch` (GitHelper.isUploadPack, unchanged), push discovery under a `POST` grant
(invariant 9), another write under its method. No second entry point decides anything; the
refusal-site count the advice test keeps holds it to that. The `RefusalAdvice` steps name the
new spelling: a host not allowed is `allow https://HOST/ read` in `egress/rule`, and a defaults
host refused under the default profile is refused by a `deny`
line or by `deny defaults`, the advice naming which. `--check-host` and provenance spell a host's
treatment as its resolved lines, one per scope.

`authorizeRequest` reads the structure in its own precedence, the host map first: a host in the
map gets its treatment, whatever pattern covers it, since an inspected host surviving beneath
a denied subtree is exactly what the map records; a host not in the map is admitted as an
ambient tunnel under `allow-unless-denied` when no denial pattern matches it, and refused
otherwise. Today's order — the denials before the map — inverts that and goes. The refusal's
reason stays presentation: `host denied (<line>)` where a file line matched the host, from
provenance, and `host not allowed` otherwise, under the finite profiles included, where the
structure keeps no denial at all.

Output. The proxy resolves to one structure, `ResolvedPolicy`: the profile, the ambient flag,
and the selected provider under `deny-unless-model` alone, absent under every other profile,
where it changes no authority and must change no identity — the same file under two profiles
confers different authority and must never share one — the host map, each host its scopes as
`(path, grants)` or `tunnel`; and, under `allow-unless-denied` alone, the ambient denials: the
set of patterns, exact hosts and subtrees, under which no ambient tunnel is admitted — a
whole-host `deny` and a `deny … tunnel` alike, since an ambient host holds nothing but its
tunnel, and every
emptied narrowing-set host as an exact pattern — a group expanded to its hosts, a pattern a
subtree covers dropped, sorted. That is the whole of what a denial leaves that the host map
does not already say: a grant taken from an inspected host is a smaller scope in the map, and
an inspected host surviving under a denied subtree is in the map with its scopes, so `deny
https://**.example.com/` and `deny https://**.example.com/ tunnel` over an inspected
docs.example.com are two structures, the first without that host and the second with it.
Under the finite profiles the host map embodies every denial and none is kept. Equality of
that structure is what "one policy" means, its deterministic serialization is what the digest
names, and the printed policy lines are that serialization — so two files resolving to one
policy print one digest and the same lines, and the same file under two profiles never does.
The lines: first the profile line as
today — `egress profile: <profile>`, with the selected provider under `deny-unless-model` and the
public-HTTPS default under `allow-unless-denied`, since the grammar lines alone cannot say "any
public host" or "this provider's group only" — then, under `allow-unless-denied`, the ambient
denials as whole-host `deny` lines, before the `allow` lines so that a host surviving beneath
one reads as the exception the grammar's order makes it — then one `allow` line per resolved
scope in the rule grammar, carrying the scope's whole grant set, a scope a deny has left adding
nothing to its enclosing one included (invariant 5's boundary: dropped, `GET /api/%2e%2e/x`
under a defaults `/api/ method=POST` line denied its `POST` would read as a request under the
root), hosts and paths sorted. Each line uses the rule syntax, so a reader learns one grammar;
but the output is a serialization
of the resolved structure, not a rule file — it carries no `deny defaults` header, is not
promised to re-parse to itself, and nothing reads it as input: the launcher reads hosts and
counts off it, the agent reads it. The policy lines are what the digest names, what the leaf's
hosts are read from, and what the agent's authority section and `KO_AGENT_SANDBOX_EGRESS_POLICY`
carry, so two profiles giving different access never share a digest or an authority text. The
metadata
lines follow them and are outside the digest: one summary line — the counts of inspected and
opaque hosts and ambient denials, and the count of widening lines — and the widening line
itself.
`--print-policy` prints the policy lines, then the metadata; `--provenance` follows each grammar
line with its sources — an `allow` line's boundary and each of its grants, a `deny` line's
pattern; the log's startup lines are the policy
lines, the digest, then the
metadata, in that order. The launcher's terminal banner is the profile line's mode with the
summary line's counts, and the widening line; the full text is `--egress-effective`'s and the
log's, so what prints at every start stays two lines a reader keeps reading. The agent's
authority section and the variable carry the policy lines alone, the launcher splitting the dry
run's text at the first metadata line (`policyLinesOf`), which now read in the rule grammar.

## Defaults

`default/host` and `default/model-provider/*` — the resource directory renamed after the
grammar's word, in the singular design.md's "Naming" gives a directory's role, `BaselineHosts`
and its kin becoming `DefaultHosts` — rewritten in the grammar, each line
keeping its reason. The github group: `allow https://github.com/login/device/code method=POST`,
`allow https://github.com/login/oauth/access_token method=POST` — the device flow Copilot CLI
drives, bodies that are fixed forms naming a client id — and
`allow https://api.github.com/copilot_internal/v2/token read`, plus the four `tunnel` lines. The
catalog's forge lines are `allow https://github.com/ read git-fetch` and the two others, every
other catalog line `read`. The npm audit line
lives in `doc/egress-rule-example/npm-audit/rule` alone, with its price; the defaults no
longer mentions it. `NpmAuditPath`, `GithubLoginDevicePaths`, `AllowancePaths` and `KnownTags`
go; the measured paths are defaults and example data.

Measurements before the group is called precise: what Copilot CLI requests on api.github.com
after sign-in, and that `copilot login` and a session under `deny-unless-model` complete
under the precise group; what npm requests during an install with scoped packages, with the
audit line on, to confirm invariant 5's root exemption is what keeps `%2f` reads working.

## Security model

SECURITY.md sites:

- "Reading without being able to write": re-scoped to the defaults — no bulk write channel is
  in the default — and rewritten in the grammar; the audit and login allowances become the
  lines above; a `method=` line is the project's write channel, inspected and logged.
- "Adding hosts, not patterns": the URL form, the deny-by-host rule and why a deny by path
  fails open, invariants 4 and 5 with the root exemption, and the two stated costs: a
  `method=` prefix on a forge is one line that opens `git-receive-pack` under a tree, surfaced
  by the summary count and `--egress-effective`; a path only spellable encoded cannot be
  narrowed. Its paragraph refusing a removal that matches nothing goes: a `deny` matching
  nothing is a warning under every profile (invariant 3), the cost being a typo'd deny that
  narrows nothing, which the warning names at every launch.
- "Run on host": the build's allowlist sentence, in the new file's name and grammar.
- "Why the policy is per project, in the project, and read-only": `rule`, one file, singular
  as `default/host` is (design.md, "Naming").
- "The audit line grammar": the `<why>` set, and the startup lines' new form — the policy
  lines, the digest naming them, then the metadata.
- "Exfiltration through an allowed host", "Why the policy is not a capability system": the
  sentences naming `path=` and the tags, re-spelled.

design.md, "No richer egress-policy format": the grammar named, its evaluation model as PF's
and relayd's with the borrowings it refuses ("Deliberate exclusions"), and the decision it rests on
— syntax buys the file's meaning, not the project's choices — recorded there with the prior
art moved from the retired path-prefix plan.

## Implementation sites

### `container/ko-agent-egress-proxy/app`

- `PolicyHelper.scala`: the parser (URL, `tunnel`, `model-provider`, `deny defaults`,
  comments), `Scope` as `(path, grants)`, group expansion, additive merge, `deny` subtraction,
  the launch refusals; `policyLines` — the profile line, then the grammar lines — and
  `metadataLines` — the summary and the widening line — after them; `ResolvedPolicy`, the
  structure equality and the digest are over, with the denials' normal form, and its
  serialization, which `policyLines` is; provenance per boundary, per grant and per
  ambient-denial pattern, with widening;
  `authorizeInspectedRequest` over the longest match.
- `Refusals.scala`: the advice spellings.
- `HTTPHelper.scala`: named because invariant 6 is its property — the request line as parsed,
  header values with their optional whitespace stripped, nothing else rewritten — with one
  correction: `parseHeaders` trims a value before it checks for controls, and Java's `trim`
  removes every character up to SP, so a leading or trailing NUL, VT or FF is dropped where
  it should refuse the head, on requests and responses alike; the value is checked raw, then
  stripped of SP and HTAB only.
- `GitHelper.scala`: push discovery refused unless `POST` is granted at the repository, fetch
  discovery refused unless `git-fetch` is.
- `AgentEgressProxy.scala`: `configuredPolicy` reads `EGRESS_RULE` and refuses the old
  variables; `--check-host` prints the resolved lines.
- `src/main/resources/default/*`: rewritten, the directory renamed; with it every naming of the
  path — `build.sbt`'s comment, `doc/run-on-host.md`'s "beside their `/baseline` resources",
  and the README's native-image command, whose `-H:IncludeResources` pattern embeds
  `baseline/.*` and would otherwise ship an image without its defaults. The word goes with the
  directory wherever it names the launcher-owned set: README, SECURITY.md, AGENTS-SANDBOX.md,
  the proxy's comments and tests, `Refusals`, the launcher and its tests, `IntegrationSession`'s
  comment. It stays where it means something else — the staged workspace's per-path
  baselines, `plan-coursier.md`'s measurement, `build-profile-iterate.sh`'s builds. The build
  proxy's `BuildBaselineHosts` is neither: its host is allowed by the build's own line after
  `deny defaults`, so it is named by what it is, `MavenCentralHost`, and `run-on-host.md`'s
  "baseline repository allowlist" with it.

### `src/main/scala`

- `EgressProxyPolicy.scala`: `PolicyFiles` is `rule` alone, the old names refused with the
  pointer; `inspectedHostsOf` reads hosts off the `allow https://` lines; `egressBanner` reads
  the mode off the profile line and the counts off the summary line, `wideningEntries` the
  widening line;
  `policyLinesOf` is the split the authority section and the variable get.
- `AgentSandboxLauncher.scala`: the preflight prints the file as written and the summary; the
  authority section's egress paragraph in the new words.

### The host-build proxy

The build's own proxy (`RunOnHostSandbox`, `doc/run-on-host.md` "The build's egress proxy") is
the second composer of the old grammar: `RunOnHostPolicy.egressAllowedText` hands it `-**` and
`+host` lines in `EGRESS_ALLOWED`, which the renamed proxy would ignore and start on the
defaults — the fail-open direction, which the old-variable refusal above closes. It becomes
`egressRuleText`: `deny defaults`, `allow https://repo1.maven.org/ read`, then the file's lines,
in `EGRESS_RULE`. The build's own file moves with it — `host-command/<tool>/egress/rule`, the
old name refused as `egress/allowed` is — and keeps its subset: `allow https://HOST/ read` lines and
comments, nothing else, refused by the launcher (`buildAllowlist`) before pass-through, for the
reason `run-on-host.md` "Configuration" gives. The refusal wording, the wrapper's "add a line"
advice, `SECURITY.md` "Run on host" and the two `run-on-host.md` sections follow. The probes
`src/probe/session-recovery.sh` and `src/probe/jvm-proxy-rule.sh` start the proxy by hand with
the old variable and are re-spelled.

### Tests

- Grammar: every launch refusal above with its message; the canonical-path table; `deny`
  with a path; `https://HOST` without its slash; an `allow` naming no grant, a word twice, and
  `tunnel` beside another; the method list; a duplicate line; a resolved host holding `tunnel`
  beside an inspected grant, a line under a standing defaults tunnel included; a `tunnel` line
  for an inspected defaults host without `deny defaults`; `#` in a token; a line of either verb
  above `deny defaults`; old filenames; the old variables. The warnings: a `deny` matching
  nothing; a line adding nothing, naming the pair, beside the silent restatement of a defaults
  line and of a defaults scope; a line a later line takes back whole.
- Resolution: additive merge over the defaults; `deny` by host, by subtree, by grant — `read`
  among them, leaving a forge clonable and not browsable — by group, striking the group's
  lines and no other's; the order — the re-grant after its deny, the same pair reversed
  denying, the three-line case denying, a group allowed after a deny re-granting and denied
  after an allow struck — under `deny-unless-allowed` and `allow-unless-denied` alike;
  the empty sibling scope dropped while the host stays;
  `tunnel` taken by `deny` and the host re-granted inspected, at the root and beneath a path;
  the host-emptying transition — a defaults read-only host denied `read` leaves the host map
  and the leaf's names, stays denied under `allow-unless-denied` rather than becoming ambient,
  digests and prints as the whole-host denial does, and is re-granted beneath a narrower path;
  `deny defaults`; each profile's consultation; provenance and the widening marks; the
  identity — two files resolving to one policy yield an equal `ResolvedPolicy`, one digest and
  the same lines, under every profile: a group denial against its exact lines under
  `deny-unless-model`, a grant subtree against its exact lines, a whole-host subtree against
  its `tunnel` form over ambient hosts and apart from it over an inspected one, and a deny list
  against its reordering where no grant depends on the order, under `allow-unless-denied`, a
  grant list emptying a host against a whole-host line, the provenance of those same pairs —
  the group's lines behind an expanded pattern, the absorbed exact line behind its subtree,
  the two forms behind one host, the grant lines behind an emptied host — in the printed
  annotation and in the refusal's reason, and one file with the provider selected and
  unselected under every profile but `deny-unless-model`;
  and one file under `deny-unless-allowed`, `allow-unless-denied` and `deny-unless-model` with
  a provider yields three digests and three authority texts, the profile line being the
  difference.
- Forwarding: a recording origin on a loopback pair behind `relayInspected`, receiving the
  method and request-target byte for byte as the client sent them, for `%2f`, `%2e`, a
  repeated slash, a backslash and a dot segment on a host whose scope admits them, and the
  Host value intact under optional whitespace, `:443`, letter case and a trailing dot as the
  client spelled it — the pipeline, not the authorizer, is what this proves (invariant 6); and
  a header value
  edged with NUL, VT, FF, CR or LF refused, on a request and on a response head, where one
  edged with SP or HTAB is stripped to its value.
- Enforcement: the CONNECT precedence — an inspected host beneath a denied subtree admitted and
  inspected, its ambient siblings refused, under `allow-unless-denied`; longest match, and no
  match on a host without a root line; invariant 5 under a
  prefixed scope and the root exemption, `/@scope%2fname` included, a root `POST` with `%`
  refused; `method=` under a prefix with the confusion spellings refused, and write-only where
  the enclosing scope has no `read`; `git-fetch` under a prefix, and alone, clonable and not
  browsable; push discovery refused, and admitted only under a `POST` grant; fetch discovery
  refused where `git-fetch` is absent.
- Host build: `RunOnHostPolicyTest`'s composition and grammar tables over the new lines;
  `RunOnHostSandboxTest`'s file reading under the new name.
- `HostileInputTest`: the URL corpus — ports, userinfo, query, fragment, IP literals, `**`
  on the allow side, `\`, `%` in host and path, uppercase scheme — reaching nothing; the
  randomized delta over the new lines admitting no unnamed host or grant; and the reference
  evaluator — a deliberately plain one kept in the test code, applying the file's lines in
  order to one request, last applicable line per grant, sharing no code with the fold —
  property-tested against the resolved policy's authorization, PF's own discipline for its
  skip steps: the simple order is the specification, and the fold must be invisible to it.
  The drawn domain names every equation, or the hardest stay untested: each profile, the
  provider selected and not, files with `deny defaults` and without, provider groups allowed
  and struck, `tunnel` taken and re-granted, hosts the defaults lack and hosts they tunnel,
  and requests to ambient hosts, to inspected ones under a denied subtree, and at both sides
  of a boundary.
- Launcher: `EgressProxyPolicyTest` over the banner's two sources — the profile line for the
  mode and the provider, the summary line for the counts, each alone insufficient — the leaf
  hosts and the split, and
  `AgentSandboxLauncherTest` that the authority section carries no metadata line;
  `AgentSandboxLauncherTest`'s authority-text scrape over the new vocabulary;
  `EgressPolicyTest` end to end: a narrowed forge, the npm audit line beside a scoped-package
  install, and Copilot's login under the precise group.

### Documentation

- README "Modifying the egress policy": the grammar block above and the refusal list; the
  Reference block's mentions.
- SECURITY.md and design.md as under "Security model".
- `doc/egress-rule-example/*/rule`: the directory renamed with the file, singular as design.md's
  "Naming" gives a directory's role, and the six examples re-spelled; the launcher test that
  scans the directory, the README, SECURITY.md and `default/host` follow.
- `container/ko-agent-sandbox/AGENTS-SANDBOX.md`: the sentence naming `+host`.
- The fixtures modelling the policy path: `fuse/ko-agent-fs/tests/mounted_mutate.rs` and
  `fuse/ko-agent-fs/src/policy.rs`, `src/probe/build-profile-gate.sh` — the guard freezes
  `.ko-agent-sandbox` at any depth, so they prove nothing about the name, and they model the
  file that exists.
- `doc/plan-credential-broker-proxy.md`: its three mentions of the old spellings.
- `doc/run-on-host.md` and SECURITY.md "Run on host", as under "The host-build proxy".

## Acceptance checklist

- [ ] Every launch refusal fires with its message, `egress/allowed` and `egress/denied` among
      them, naming `rule`.
- [ ] `deny https://github.com/ git-fetch` alone, over the defaults' `git-fetch` line, reads
      github.com and refuses `git clone` at ref discovery, with a `deny` line naming the reason;
      `allow https://github.com/ git-fetch` after it restores the clone and before it is warned
      as taken back.
- [ ] `allow https://registry.npmjs.org/-/npm/v1/security/advisories/bulk method=POST` from the
      example admits npm's audit POST and an install with a scoped package, both measured.
- [ ] Under `deny-unless-model`, `copilot login` and a session complete with the precise group.
      Under `deny-unless-allowed`, `deny model-provider github` leaves
      `https://github.com/octocat/Hello-World` readable and the device-flow POST refused.
- [ ] The example's codeberg pair clones under `/my-org/` and is refused at ref discovery
      elsewhere, and a clone spelled `/My-Org/` is refused; the `allow` line alone is warned
      at launch naming the pair.
- [ ] The terminal prints one summary line per launch, its widening count matching the lines
      `--egress-effective` marks; two files resolving to one policy print one digest and the
      same lines, a grant list emptying a host against a whole-host line among the pairs.
- [ ] A host build under `--run-on-host` resolves from Maven Central and from a host its
      `rule` file names; the proxy started with `EGRESS_ALLOWED` set refuses to start,
      naming `EGRESS_RULE`.
- [ ] `sbt testFull` green in both builds.

## Deliberate exclusions

- A `deny` with a path: a denial by path fails open against the origin's canonicalization
  (invariant 2); PF's `block` on a network is safe where this is not, the kernel being the one
  authority on what an address means.
- PF's `quick`, and IAM's deny-overrides: a second precedence, and a denial no later line can
  undo, each a further way to make a line ineffective; the profile is the ceiling no file
  undoes, and within the file the last word is the rule. First-match evaluation, Squid's and
  nginx's, reads exception before rule, the wrong way round for a reader who should see the
  restriction first.
- The printed policy as input: each line uses the rule syntax for the reader's sake, and the
  output is a serialization of the resolved structure with no promise to re-parse to itself —
  the promise would cost a canonical re-parse for every profile's every case and buy a use
  nothing has.
- A fatal no-op: a line adding nothing is a warning (invariant 7), because the check reads the
  defaults, and a file must not stop parsing because a later image's defaults grew.
- A wildcard or pattern on the allow side; `**.` stays a taking-away form.
- A removal verb, and a per-host `deny defaults`: a project's difference from the defaults is
  `--egress-effective`'s to show; a host-wide `deny` with a narrower `allow` beneath it is
  every take-back the grammar needs.
- Quoting, and non-ASCII paths: the wire is ASCII and every client encodes; a quoted or
  normalized form is a token kind for later, hosts being IDN-mapped already.
- `/**` as the spelling of a tree: a trailing `/` says it, and the noise buys nothing.
- A query rule: the query is the message channel, not a destination.
- An exact-path-only `method=`: invariant 5 leaves a method prefix nothing to confuse, and the
  cost of one line opening push under a tree is stated rather than forbidden.
- A tunnel with a path, or beside another word: a tunnel has no path and no method to grant, so
  its URL ends at `/` as a `deny`'s does and the word stands alone.
- A bare `allow https://` line meaning `read`: the safe reading, and still a rule a reader must
  know; one word per line costs less than a second way to say it.
- An IP literal as `HOST`: the address vetting refuses every private answer at the dial, so a
  LAN site named by address fails where one named by a private zone does, and admitting the
  literal admits nothing until private address space is — which a committed file must never
  do, since it would name a host on whoever clones the repository (SECURITY.md, the lifecycle's
  step 6; `resolvePolicy`'s note that the internal-network denials are no host rule). A literal
  is also never inspected under this lifecycle (its step 10). LAN reach, if ever wanted, is a
  launcher-side authority typed at launch; TODO.md has its shape.

## References

- SECURITY.md, "Adding hosts, not patterns"; "Reading without being able to write"
- design.md, "No richer egress-policy format", with its prior art
- https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall
- https://github.com/coder/boundary
- OpenBSD doas.conf(5) and doas(1): the smallest ordered `permit`/`deny` file, and `-C`
- OpenBSD pf.conf(5) and relayd.conf(5): ordered rules, last match decides; relayd's move to
  them: https://github.com/openbsd/src/commit/cb8b0e5645
