# Plan: path-prefix narrowing of a restricted host

## Outcome

A restricted entry may carry a path prefix, and the proxy refuses every request on that host
whose path is outside it:

```text
+host storage.googleapis.com path=/my-bucket/     # a project's own bucket
+host raw.githubusercontent.com path=/my-org/      # one organisation's raw content
```

Only narrowing: an entry without `path=` is unchanged, `path=` on an unrestricted host is
refused, `denied` stays whole-host. The credential broker (`PLAN-CREDENTIAL-BROKER-PROXY.md`)
reuses the same matcher to bound where a brokered value may be spent — two rules, one comparison.

## Evidence and target

Multi-tenant hosts are the wide entries of every allowlist, and every comparable project has
been asked for this: anthropic-experimental/sandbox-runtime #468 (open) on
`storage.googleapis.com` and `raw.githubusercontent.com` — "every tenant"; GitHub's Copilot
coding-agent firewall accepts a URL entry, `https://host/path/`, beside a domain; coder/boundary
and clawker carry path rules. The use case here is a host a project adds for one tenant's
content — its own bucket, one organisation on a raw-content host — where the prefix is the
reviewer's whole intent.

What a prefix bounds is *which tenant can be reached*, on that host. It does not bound the
channel: a `GET` inside the prefix still carries its suffix and query ("Exfiltration through an
allowed host"). It does not attenuate a credential either — that is the broker's job — and it
does not make reading narrow by default: the catalog forges stay whole, since discovering and
reading public repositories is what the agents are for ("Why the policy is not a capability
system"). It is an instrument for the entry whose reviewer meant one tenant.

## Invariants

1. A prefix only narrows. Adding `path=` to an entry removes reach and adds none; a request
   outside the prefix is refused with the reason and logged as `deny`.
1. A prefix binds to a restricted entry. `unrestricted` has no path; the combination is a
   failed launch. A `denied` entry names a host whole; there is no `denied` path.
1. A prefix is in canonical form or the launch fails: begins and ends with `/`, no
   percent-encoding, no `\`, no empty segment (`//`), no `.` or `..` segment, no query, no
   fragment, no control character. What is compared is what was reviewed.
1. With a prefix in force, the request path is compared literally, after being refused for
   anything the origin might canonicalize differently: a `%`, a `\`, a `.` or `..` segment
   anywhere in the path is a refusal, on every method. The proxy does not know the origin's
   decoding, so the proxy accepts only paths that need none. A path the origin would have
   accepted and this rule refuses is the fail-closed cost, stated in the document.
1. Case is the origin's. `/MyOrg/` and `/myorg/` are one owner on GitHub and two buckets on
   GCS; the proxy folds nothing, so a prefix in the wrong case fails closed on GitHub and
   closed on GCS alike — never open.
1. Every fixed allowance path on the entry lies under its prefix, or the launch fails:
   `allow=github-login-device` needs `/login/device/code` and `/login/oauth/access_token`,
   `allow=npm-audit` its one path; `allow=git-fetch` composes (upload-pack under `/owner/…`).
   A prefix that silently disables an allowance is the failure this rule exists to refuse.
1. Several prefixes for one host are several entries, each with its own `path=`; their reach
   unions, their allowances do not: an allowance stays with the prefix it was written on, so
   `path=/public/` beside `path=/repos/ allow=git-fetch` serves `git fetch` under `/repos/`
   only. Prefixes on one host are disjoint or the launch fails: one containing the other
   (`/org/` and `/org/private/`, or an entry without `path=` — the prefix `/` — beside one
   with it) would make the scope of a request a matter of selection order or of pooling, and
   either is reach a reviewer did not write. A request therefore matches at most one scope.
1. The leaf certificate is unchanged: it names hosts. `--print-policy`, `--egress-effective`
   and the startup lines carry the prefix beside the host, so the one format the launcher,
   the proxy log and the dry run read stays one format.

## Grammar

```text
+host HOST path=/PREFIX/                       restricted, reads under PREFIX only
+host HOST path=/PREFIX/ allow=git-fetch       clone and fetch under PREFIX only
+host HOST path=/A/
+host HOST path=/B/                            two prefixes, one host
```

`path=` is an attribute in the position `allow=` already occupies; order between the two is
free. The README's "Modifying the egress policy" gains the lines above and one sentence:
"`path=` narrows an entry to one tree; a request outside it is refused like a write".

Refusals at launch, each naming the entry: prefix not canonical (invariant 3); `path=` with
`unrestricted`; `path=` in `denied`; an allowance path outside the prefix (invariant 6); two
prefixes on one host where one contains the other, an unprefixed entry included (invariant 7).

## Enforcement

In `authorizeInspectedRequest`, before the method rule and after the `Host` header check: if
the entry carries prefixes, `requireLiteralPath(head.path)` (invariant 4) and then the scope
whose prefix `head.path` starts with — at most one, by invariant 7; a miss is
`PolicyViolation("path outside allowance")` with the advice "this host is admitted under
`<prefixes>` only" — its row in `PLAN-PROXY-DENIAL-REASON.md`'s table. The method rule that
follows sees that scope's tags alone (invariant 7).

`requireUnambiguousPath` refuses `%` and dot segments on `POST` only, because only the
allowance paths are compared. `requireLiteralPath` is the same check plus `\` and `//`, applied
to every method on a prefixed entry; the two share one implementation with the `POST` rule
keeping its current scope on unprefixed entries, so a `GET` to an unprefixed host with a
percent-encoded object name keeps working.

Redirects are the client's: a same-host redirect out of the prefix is a fresh request, refused
and logged; nothing is followed by the proxy.

## Baseline

No baseline entry needs a prefix. The catalog admits `storage.googleapis.com` as "gcr blobs",
and SECURITY.md calls it the one unauthenticated write surface the built-in list has. Measured
2026-08-28: `gcr.io` serves blobs itself. A blob request answers
`302 Location: /artifacts-downloads/namespaces/distroless/repositories/gcr.io/downloads/<id>`
on `gcr.io` (`X-Gcr-Using-Artifact-Registry: true`) and the second hop is a `200` on `gcr.io`;
`storage.googleapis.com` is not contacted, for `distroless/static` and for the 60 MB layers of
`gcr.io/distroless/java25-debian13`. The entry names a redirect `gcr.io` does not make, and the
change it calls for is removal — a smaller inspected set and the write-surface caveat gone —
which is independent of this plan and belongs in its own change, confirmed by the self-test's
nested pull under the baseline without the entry.

## Credential broker

The broker's binding takes the same matcher: `--env=NAME@HOST/PREFIX/` substitutes only when
the request is on `HOST` and its path is under `/PREFIX/`; the policy's own prefix, if any,
applies first. The two are different facts — where requests may go, and where a credential may
be spent — and stay different lines; the comparison and the canonical-form rule are one
function. `PLAN-CREDENTIAL-BROKER-PROXY.md` gains the binding form and a pointer here for the
rules; nothing in that plan waits on this one.

## Security model

SECURITY.md sites:

- "Adding hosts, not patterns": a paragraph that a prefix is on the narrowing side, like a
  removal — its worst case is over-blocking — and that the matcher is literal by rule
  (invariants 3–5), because the origin's canonicalization is the one thing a proxy cannot
  know; the `%`/`\`/dot-segment refusal is the cost, and a wrong-case prefix is fail-closed.
- "Exfiltration through an allowed host": one clause — a prefix narrows the recipient, not
  the message.
- "Why the policy is not a capability system": unchanged in substance; one sentence that a
  path prefix names a destination more precisely and still grants no operation.
- "The audit line grammar": the new `<why>`.

## Implementation sites

### `container/ko-agent-egress-proxy/app/src/main/scala/AgentEgressProxy.scala`

- `Treatment.Restricted(scopes: Set[Scope])` with `Scope(prefix: Option[String], tags)`, so
  a tag cannot exist apart from its prefix; a host's entries merge as a union of scopes, and
  the existing tag merge applies only within one scope. Entry parser for `path=`;
  the launch refusals; `spelled` and the `--print-policy` lines emit one line per scope.
- `authorizeInspectedRequest`: the prefix check; `requireLiteralPath` in `GitHelper` beside
  `requireUnambiguousPath`, one implementation.
- Baseline merge: an addition with `path=` overrides the baseline entry as any addition does.

### `src/main/scala/EgressProxyPolicy.scala`, `AgentSandboxLauncher.scala`

- The launcher reads only hosts from the restricted line for the leaf, and prints the
  prefixes in `--egress-effective` and the banner.

### Tests

- Grammar: every launch refusal above, with its message; canonical-form table (each forbidden
  shape once); an allowance path outside the prefix for each allowance; `/org/` beside
  `/org/private/`, and beside an unprefixed entry, each refused in both orders.
- Enforcement, end-to-end against the local TLS origin: under-prefix `GET` allowed;
  sibling path refused; `/prefix/../other` refused; `/prefix/%2e%2e/other` refused;
  `/prefix\..\other` refused; `//prefix/` refused; wrong-case prefix refused; two prefixes
  union for `GET` while `allow=git-fetch` on one of them leaves upload-pack under the other
  refused; `git clone` under `/owner/` works with `allow=git-fetch` and is refused outside it;
  an unprefixed host still accepts a percent-encoded `GET`.
- `HostileInputTest`: the population of path spellings that differ from the prefix only by
  an encoding or a separator the origin might fold, each refused before the prefix compare.
- Policy round trip: `--print-policy` output re-parses to the same entries, prefixes
  included, and the leaf names are unchanged by any prefix.

### Documentation

- README "Modifying the egress policy": grammar and the one sentence.
- SECURITY.md sites above.
- `doc/egress-policy-examples/`: one example narrowing a project bucket.
- `PLAN-PROXY-DENIAL-REASON.md` table: the row.

## Acceptance checklist

- [ ] `+host example.test path=/x/` admits `GET /x/y` and refuses `GET /z/y`,
      `GET /x/../z/y`, `GET /x/%2e%2e/z/y`, each with a `deny` line naming the reason.
- [ ] Every launch refusal fires with its message; `--egress-effective` shows the prefix.
- [ ] `+host github.com path=/owner/ allow=git-fetch,github-login-device` refuses the launch
      (invariant 6: the login paths are not under `/owner/`), naming the allowance and prefix.
- [ ] Under `+host github.com path=/owner/ allow=git-fetch` beside `+host github.com
      path=/login/ allow=github-login-device`, `git clone https://github.com/owner/repo` works,
      a clone of `other/repo` is refused, and `copilot login` still completes.
- [ ] `sbt testFull` green.

## Deliberate exclusions

- Nested prefixes on one host with most-specific-wins or pooled allowances: a launch
  refusal is the only reading with no selection rule to get wrong.
- Wildcards or globs inside a prefix, and suffix or regex matching: a prefix is the one shape
  whose worst case is over-blocking; a pattern reintroduces reach a reviewer did not enumerate.
- Path rules on `denied`: denial is whole-host so that "denial wins" stays one rule.
- Query-string rules: the query is the message channel and is not a destination.
- Folding case or decoding on the proxy's side to "help" a prefix match: guessing the origin's
  canonicalization is the bypass class; literal-or-refuse is the only durable form.
- Prefixes on the catalog forges by default: reading public repositories is designed broad;
  a project that wants `/my-org/` writes it.

## References

- anthropic-experimental/sandbox-runtime #468 — path prefixes for multi-tenant hosts
- docs.github.com, Copilot coding agent firewall — domain and URL (path-prefix) entries
- coder/boundary — `domain= method= path=` rules
- SECURITY.md, "Adding hosts, not patterns"; "Reading without being able to write"
