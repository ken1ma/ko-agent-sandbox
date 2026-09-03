# Plan: one `rules` file, entries as URLs

## Outcome

The project's egress policy is one file, `.ko-agent-sandbox/egress/rules`, whose lines say
`allow` or `deny` and name what they mean as a URL:

```text
allow https://www.rfc-editor.org/                      # reads under the prefix
deny https://codeberg.org/ git-fetch                   # the defaults' grant, taken back host-wide
allow https://codeberg.org/my-org/ git-fetch           # re-granted under one owner only
allow https://github.com/login/device/code method=POST # one method at one path
allow https://storage.googleapis.com/my-bucket/        # reads under one tree only
allow tunnel https://api.example/                      # an opaque tunnel: the one loud form
deny https://telemetry.example/                        # this host, whole
deny https://**.googleapis.com/                        # the apex and everything under it
deny https://github.com/ git-fetch                     # takes back a grant, keeps the reads
deny model-provider google                             # the group's own lines
```

A lockdown is two lines, `deny defaults` first and `allow model-provider anthropic` after it.

`allowed` and `denied`, `+host`, `-host`, `-**`, `allow=`, `path=` and the tags `npm-audit` and
`github-login-device` are gone. `git-fetch` stays, the one grant that is not a path. Lines are
additive: a line adds its grants under its path, on top of every wider line for the host, the
launcher-owned defaults' included; `deny` takes grants away at the host, and an `allow`
under a path re-grants beneath it.

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
that a grant is enumerable and the leaf certificate can name it, `deny` last with no path to
get wrong, every ambiguity a refused launch. The first it stops pretending to buy.

## Invariants

1. A line grants exactly what it says, under exactly the path it names, and nothing else on the
   host. Resolution folds a host's lines into cumulative scopes: the scope at a path is the union of
   every line whose path contains it, so a root `git-fetch` line and a narrower `method=POST` line
   make the narrower scope carry both. A request is authorized against the resolved scope of its
   longest literal match, which is that union — never against the one line alone.
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
1. `deny` wins over every `allow` at the host's root, from the file, the defaults or a group alike;
   an `allow` under a path re-grants beneath it, and only there. That is how a host the defaults
   admit is narrowed: `deny https://codeberg.org/ git-fetch` then `allow
   https://codeberg.org/my-org/ git-fetch` clones one owner on a forge the defaults make clonable
   whole, and `deny https://github.com/` then `allow https://github.com/my-org/` reads one owner.
   Fail-closed for the reason a denial by path is not: the deny is always the wider scope, so a
   spelling the proxy cannot place in the narrower one lands where the deny holds. A `deny` matching
   nothing is a launch warning, under every profile.
1. A policy path is written unencoded, in printable ASCII, in canonical form: begins with `/`, no
   `%`, `\`, empty, `.` or `..` segment, `?`. A trailing `/` names the tree under it; none names
   that one path. Case is the origin's; the proxy folds nothing. A path a request can only spell
   encoded — a space, a non-ASCII name — cannot be narrowed at all; it stays readable under a
   root line, which is the stated cost.
1. A request is compared literally. Where its longest literal match is a line other than the host's
   root line, the request is first refused for `%`, a dot segment, a backslash and an empty segment,
   on every method: under such a line the path decides grants the root does not give, and `POST
   /uploads/%2e%2e/admin` would otherwise carry a POST to `/admin`. Under the root the request has
   the host's least grants, gains nothing by any decoding, and may carry `%` — which is what keeps
   npm's `/@scope%2fname` reading on a host that also has a `method=` line.
1. A line that adds nothing to its enclosing scope is refused, a duplicate included; a project line
   restating one of the defaults is the one legal no-op, so a file that names a host defensively
   keeps working when the image adopts it.
1. A host has one treatment: a `tunnel` line and a plain `allow` line for one host are a refused
   launch, and a `tunnel` line for a host the defaults inspect needs `deny defaults` — an opaque
   tunnel ends inspection and the audit record for a host every project has, and a project deciding
   that states its whole policy.
1. `method=` names methods from the closed list `POST`, `PUT`, `PATCH`, `DELETE`, comma separated,
   under the line's path; a body on GET and HEAD stays refused. `git push`'s ref discovery stays
   refused except where a line grants `POST` at the discovered repository — there the push is the
   project's own grant, visible as such.
1. Provider groups are lines. `allow model-provider NAME` expands, after parsing, to the group's
   lines and merges like any others; `deny model-provider NAME` removes exactly those lines. The
   github group is precise — the two login paths as `method=POST` lines, the token exchange as one
   exact read, four tunnels — and grants no read of the forges, so denying the group leaves the
   catalog's repositories readable.
1. `deny defaults`, first line if present, means the defaults contribute nothing and the file is the
   whole policy. An `allow` line above it is refused: the file reads in the order the words imply.
   It takes nothing after it: narrowing a host the defaults admit is invariant 3's
   deny-then-re-grant, and a line that adds nothing to what the defaults grant is refused naming
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
allow https://HOST/PREFIX/ [git-fetch] [method=M,...]     tree
allow https://HOST/PATH    [git-fetch] [method=M,...]     one path
allow tunnel https://HOST/
allow model-provider NAME
deny  https://HOST/       [git-fetch] [method=M,...]     never a path: invariant 2
deny  https://**.DOMAIN/  [git-fetch] [method=M,...]
deny  model-provider NAME
```

`HOST` is an exact hostname through the existing normalizer — IDN mapped, lowercased, one
trailing dot removed — never an IP literal, a port, userinfo, a query or a fragment; `**.` is
the deny side's only pattern. The parser is the proxy's own: the literal `https://`, the host,
the path, each refusal named; no `java.net.URI`. The order of the words after the URL is free.

Refusals at launch, each naming the line: a filename other than `rules` in `egress/` —
`allowed` and `denied` named as the old ones, with the pointer; a token outside the grammar;
a path outside invariant 4; `deny` or `tunnel` with a path; a method outside the list; a line adding
nothing; two treatments for one host; a `tunnel` on a host the defaults inspect without
`deny defaults`; an `allow` above `deny defaults`; a contradiction within the file — a
`deny` beside an `allow` at the same host's root granting what it takes back, the whole host
included — while a `deny` beside a narrower `allow` is invariant 3's re-grant; an unknown
provider name; `#` inside a token.

## Resolution and enforcement

`resolvePolicy` keeps its profile equations over a new shape: a host's policy is a set of
lines, each `(path, grants)`, with `grants` the reads plus `git-fetch` plus methods. The
defaults are read through the same parser, and a host resolves in one fixed order. First the
defaults and the groups the file allows fold into scopes. Then the file's `deny` lines
subtract, host-wide: a denied grant leaves every one of those scopes on the host, a
whole-host deny empties them, so no defaults or group line beneath a deny — the github
group's login path under `deny https://github.com/` — survives it. Last the file's own
`allow` lines add: at the root only what the file's denies do not take back, which the
contradiction refusal has already checked, and beneath a path whatever they say, which is
invariant 3's re-grant — the one thing a deny leaves standing, because it is the project's
explicit line written beside it. Provenance labels each resolved line with its source, and
marks the project lines that grant beyond the defaults' for their host — a host the
defaults lack, whatever the line grants there; `tunnel`, `method=` and `git-fetch` where
the defaults lack them; `deny defaults` — as widening, one computation for the summary
line's count and `--egress-effective`'s listing. A line narrowing one of the defaults' tunnels to
inspected reads is not one. The widening line is delta metadata, printed after the resolved
policy and outside the digest, which names the policy enforced and nothing about how the
file arrived at it. The launcher's own classification goes.

`authorizeInspectedRequest` finds the longest literal match, applies invariant 5, then the
method rule against that scope's grants: GET and HEAD everywhere; `POST` to upload-pack under
a `git-fetch` scope (GitHelper.isUploadPack, unchanged); the scope's `method=` list. The
`RefusalAdvice` steps name the new spelling: a host not allowed is `allow https://HOST/` in
`egress/rules`.

Output, with one boundary. The policy lines are the policy identity: first the profile line as
today — `egress profile: <profile>`, with the selected provider under `deny-unless-model` and the
public-HTTPS default under `allow-unless-denied`, since the grammar lines alone cannot say "any
public host" or "this provider's group only" and the same file means different access under
different profiles — then the resolved policy in the rules grammar, as a complete file: `deny
defaults` first, since a resolved policy is whole and owes nothing to the defaults it came from;
one `allow` line per resolved scope; the `deny` lines in force after. Re-parsed under the profile
the first line names, the grammar lines resolve to the same hosts and print the same lines. The
policy lines are what the digest names, what the leaf's hosts are read from, what the round trip
re-parses, and what the agent's authority section and `KO_AGENT_SANDBOX_EGRESS_POLICY` carry, so
two profiles giving different access never share a digest or an authority text. The metadata
lines follow them and are outside the digest: one summary line — the counts of inspected and
opaque hosts and denied rules, and the count of widening lines — and the widening line itself.
`--print-policy` prints the policy lines, then the metadata; `--provenance` suffixes each grammar
line with its source; the log's startup lines are the policy lines, the digest, then the
metadata, in that order. The launcher's terminal banner is the profile line's mode with the
summary line's counts, and the widening line; the full text is `--egress-effective`'s and the
log's, so what prints at every start stays two lines a reader keeps reading. The agent's
authority section and the variable carry the policy lines alone, the launcher splitting the dry
run's text at the first metadata line (`policyLinesOf`), which now read as the file does under
its profile.

## Defaults

`defaults/host` and `defaults/model-provider/*` — the resource directory renamed with the word
the grammar uses, `BaselineHosts` and its kin with it — rewritten in the grammar, each line
keeping its reason. The github group: `allow https://github.com/login/device/code method=POST`,
`allow https://github.com/login/oauth/access_token method=POST` — the device flow Copilot CLI
drives, bodies that are fixed forms naming a client id — and
`allow https://api.github.com/copilot_internal/v2/token`, plus the four tunnels. The catalog's
forge lines are `allow https://github.com/ git-fetch` and the two others. The npm audit line
lives in `doc/egress-policy-examples/npm-audit/rules` alone, with its price; the defaults no
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
  narrowed.
- "Why the policy is per project, in the project, and read-only": `rules`, one file.
- "The audit line grammar": the `<why>` set, and the startup lines' new form — the policy
  lines, the digest naming them, then the metadata.
- "Exfiltration through an allowed host", "Why the policy is not a capability system": the
  sentences naming `path=` and the tags, re-spelled.

design.md, "No richer egress-policy format": the grammar named, and the decision it rests on
— syntax buys the file's meaning, not the project's choices — recorded there with the prior
art moved from the retired path-prefix plan.

## Implementation sites

### `container/ko-agent-egress-proxy/app`

- `PolicyHelper.scala`: the parser (URL, `tunnel`, `model-provider`, `deny defaults`,
  comments), `Scope` as `(path, grants)`, group expansion, additive merge, `deny` subtraction,
  the launch refusals; `policyLines` — the profile line, then the grammar lines — and
  `metadataLines` — the summary and the widening line — after them; `profileOf`, which reads
  the profile and provider back off the first line and is what the round trip resolves under,
  the proxy's own reader of its own header; provenance with widening;
  `authorizeInspectedRequest` over the longest match.
- `Refusals.scala`: the advice spellings.
- `GitHelper.scala`: the discovery refusal conditioned on a `POST` grant at the repository.
- `src/main/resources/defaults/*`: rewritten, the directory renamed.

### `src/main/scala`

- `EgressProxyPolicy.scala`: `PolicyFiles` is `rules` alone, the old names refused with the
  pointer; `inspectedHostsOf` reads hosts off the `allow https://` lines; `egressBanner` reads
  the mode off the profile line and the counts off the summary line, `wideningEntries` the
  widening line;
  `policyLinesOf` is the split the authority section and the variable get.
- `AgentSandboxLauncher.scala`: the preflight prints the file as written and the summary; the
  authority section's egress paragraph in the new words.

### Tests

- Grammar: every launch refusal above with its message; the canonical-path table; `deny`
  with a path; the method list; the no-op line; both treatments; `#` in a token; an `allow`
  above `deny defaults`; old filenames.
- Resolution: additive merge over the defaults; `deny` by host, by subtree, by grant, by
  group; the re-grant under a host-wide `deny`, for a grant and for reads, under
  `deny-unless-allowed` and `allow-unless-denied` alike, and the root-level contradiction;
  `deny defaults`; each profile's consultation; provenance and the widening marks;
  the round trip — the policy lines of `--print-policy` re-parse, under the profile their first
  line names, to the same policy and print the same policy lines, whatever the metadata; and
  the identity — one file under `deny-unless-allowed`, `allow-unless-denied` and
  `deny-unless-model` with a provider yields three digests and three authority texts, the
  profile line being the difference.
- Enforcement: longest match; invariant 5 under a prefixed scope and the root exemption,
  `/@scope%2fname` included; `method=` under a prefix with the confusion spellings refused;
  `git-fetch` under a prefix; push discovery refused, and admitted only under a `POST` grant.
- `HostileInputTest`: the URL corpus — ports, userinfo, query, fragment, IP literals, `**`
  on the allow side, `\`, `%` in host and path, uppercase scheme — reaching nothing; the
  randomized delta over the new lines admitting no unnamed host or grant.
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
- `doc/egress-policy-examples/*/rules`: the six examples re-spelled.
- `container/ko-agent-sandbox/AGENTS-SANDBOX.md`: the sentence naming `+host`.

## Acceptance checklist

- [ ] Every launch refusal fires with its message, `egress/allowed` and `egress/denied` among
      them, naming `rules`.
- [ ] `deny https://github.com/ git-fetch` alone, over the defaults' `git-fetch` line, reads
      github.com and refuses `git clone` at ref discovery, with a `deny` line naming the reason;
      `allow https://github.com/ git-fetch` beside it in one file is a refused contradiction.
- [ ] `allow https://registry.npmjs.org/-/npm/v1/security/advisories/bulk method=POST` from the
      example admits npm's audit POST and an install with a scoped package, both measured.
- [ ] Under `deny-unless-model`, `copilot login` and a session complete with the precise group.
      Under `deny-unless-allowed`, `deny model-provider github` leaves
      `https://github.com/octocat/Hello-World` readable and the device-flow POST refused.
- [ ] The example's codeberg pair clones under `/my-org/` and is refused at ref discovery
      elsewhere, and a clone spelled `/My-Org/` is refused; the `allow` line alone is refused
      at launch naming the pair.
- [ ] The terminal prints one summary line per launch, its widening count matching the lines
      `--egress-effective` marks; the policy lines of `--print-policy` re-parse to the same
      policy, and two files resolving to one policy print one digest.
- [ ] `sbt testFull` green in both builds.

## Deliberate exclusions

- A `deny` with a path: a denial by path fails open against the origin's canonicalization
  (invariant 2).
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
- A tunnel with a path: a tunnel has none, so its URL ends at `/` as a `deny`'s does, and the
  word keeps the loud form distinct.

## References

- SECURITY.md, "Adding hosts, not patterns"; "Reading without being able to write"
- design.md, "No richer egress-policy format", with its prior art
- https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall
- https://github.com/coder/boundary
