# Next plan: workspace authority and egress

This increment makes both ways a sandbox can affect the host explicit: writes to the project
directory and network destinations. The safe defaults are a read-only project directory and access
only to the model provider needed by the selected agent.

## Command line

```text
ko-agent-sandbox [launcher-options] [--] [command [arguments...]]
```

Outside a management verb's documented operands, the first non-option is the command and ends
launcher parsing; everything after it is passed verbatim. `--` is an optional escape when the
command could look like a launcher option. No launcher option is parsed after the command.

The independent authority options are:

```text
--write=reject|staged|live
--egress=deny-all|deny-unless-model|deny-unless-allowed|allow-unless-denied
```

`reject` and `deny-unless-model` are the defaults. Authority is selected on every launch and is
never persisted by a stage or an agent resume.

This pre-release change has no compatibility aliases. A present
`KO_AGENT_SANDBOX_WORKSPACE_GUARD` refuses launch with a direct migration message: `fuse` becomes
`--write=live`; the weaker `none` mode has no equivalent. The old `--proxy-effective` spelling and
`.ko-agent-sandbox/egress-hosts` layout likewise refuse with the exact replacement to use. Stale
authority configuration is never silently ignored or translated into broader access.

## Workspace authority

### Reject

`--write=reject` bind-mounts the host project directory read-only; it does not start `ko-agent-fs`
or create a FUSE mount.
Writes outside `/workspace`, including persistent agent state, are unchanged. The mode does not
claim to prevent reading, interpreting or executing project files.

Launch itself creates no path in the project directory. An absent `.ko-agent-sandbox` means empty
policy; when an empty mount source is needed it comes from launcher-owned state. Existing policy is
read on the host, and the read-only workspace prevents the session from changing it.

### Staged

`--write=staged` creates or resumes the project's persistent stage. A stage is a persistent
copy-on-write view:

```text
live host project directory, read-only ---+
                                  +--- staged /workspace
persistent writable upper layers-+
```

Untouched paths read the current host project directory, so host changes appear during the session.
The first staged mutation records the lower state; the upper entry then shadows that path, and a
later host change becomes an apply conflict. Deletions use whiteouts. Nothing is copied back
automatically.

The sharing unit is the project. Sessions attached to its stage share the merged view, locks, cache,
upper layers and failure domain. `.ko-agent-sandbox` remains unmodifiable. Git metadata may exist
privately in a stage but is never applied to the host.

One workload can add latency for every attached session, and a `ko-agent-fs` failure makes the
merged view fail closed for all of them until they restart. This shared cost is accepted to keep
locks and caches coherent across 20–30 collaborating sessions. One process and mount serve the
project's attached staged sessions, rather than one per session.

Implement the merged view in `ko-agent-fs`. Kernel OverlayFS is not a candidate: changing a mounted
lower tree is outside its defined contract, while live host changes are a requirement. A Podman
volume may hold upper data, but raw upper layers, whiteouts, baselines, manifests, journals and
control sockets are never mounted into the sandbox. Only the merged FUSE view is reachable.

Before exposing staged mode, prove the engine on native Linux and in the macOS and Windows Podman
machines. The contract covers resume, live lower changes, copy-up, whiteouts, symlinks, hardlink
identity, advisory and POSIX locks, rename and exchange, open-unlinked files, writable handles and
shared mmap across a generation switch. Failure aborts staged launch; there is no detached-copy or
live-write fallback.

Every stage starts with a host-only manifest carrying a representation version. A launcher that
does not understand that version preserves the stage and refuses attachment with recovery
instructions. Future migrations are separate work.

### Stage management and visibility

```text
--stage list
--stage status
--stage apply [-- <paths>...]
--stage discard
```

The current project identifies the stage for every verb except `list`. There is no bulk discard
command in this increment. `--reset` and `--reset-all` remove runtime resources but preserve every
stage. Discard refuses an attached stage and confirms the project directory, pending path count and
size plus any sealed, partially applied or recovery-needed state; non-interactive use additionally
requires `--yes`.

`--stage list` lists every stored stage by project; the other verbs address the current project.
Attachment and list output show the representation version, pending path count and logical size,
physical stored size, backing volume, attached-session count, lower path and last-use time. No
pending stage is pruned automatically. Status also exposes `quiescing`, `sealed`, `applying` and
`recovery-needed` states, with the controlling host process and start time. Stage storage has a
distinct reserved resource name shape that neither reset command matches; tests bind the
preservation rule. Reset takes the same project lifecycle lock and refuses while an apply or
recovery transition is active; it never tears down a stage underneath its control process.

### Apply while sessions run

Apply uses a host-only control channel that is not mounted into the sandbox. A stage has one active
generation and at most one sealed plan. Before review, apply quiesces the stage, seals and rotates
the active generation. If a sealed plan already exists, apply reuses it and reports newer unplanned
changes rather than sealing another. Canceling review leaves that plan sealed for the next apply.

Sealing is one per-stage serialized operation:

1. Briefly pause every container attached to the stage and drain filesystem requests.
2. Flush dirty FUSE pages, mappings and metadata, then drain the daemon again.
3. Advance the generation barrier and create a new writable generation above the sealed one.
4. Rebind every open logical object so a later write, truncate or shared-mmap write copy-ups into
   the new generation; a backing descriptor from the old generation is never write authority.
5. Resume every container before review.

Failure to flush, drain or rebind any writable handle, mapping or open directory aborts before the
barrier advances. New agent changes during review stay in the new generation. Before pausing, the
command reports the project directory and number of attached sessions it will quiesce.

Apply holds the stage's control lock for its whole state transition. The sealed plan is a durable
ordered set of operation groups: a rename, hardlink relationship or other indivisible change is
selected and applied as one group. For each group, trusted code:

1. Revalidates its lower baseline and every host path through open directory descriptors.
2. Persists and fsyncs an intent containing the baseline and desired result hashes.
3. Performs atomic replacement where the host supports it, then fsyncs the object and parent.
4. Persists completion and stops the sealed entry from shadowing the live lower.

After interruption, a baseline match is safe to retry, a desired-result match completes the intent,
and any third state is a conflict. Applied entries fall through to the host lower, so later host
changes remain visible; unapplied entries stay in the residual sealed view. Interactive review can
explicitly keep the host version and drop a whole staged operation group, including a baseline
conflict found before intent, without changing the host or newer active-generation work. A group
with a persisted intent must first recover to its baseline or desired result; it cannot be dropped
from an ambiguous partial state. The sealed plan is retired only when every operation is applied or
explicitly dropped. A successful partial apply or drop atomically rewrites the residual plan before
review continues or control returns. This is crash-resumable but not a portable multi-file
transaction; rollback is deferred.

Review is deterministic, safely quoted and Git-like:

```text
M  src/main/Example.scala
A  src/test/ExampleTest.scala
D  old-script.sh
R  old.conf -> new.conf
M  scripts/run.sh  [mode 0644 -> 0755]
```

A directory with more than 100 changed descendants collapses into an indexed summary. The summary
shows exact counts by operation class. A collapsed group containing a rename, hardlink, symlink,
type change, executable-bit addition or deletion must be expanded before it can be approved. The
prompt can expand one group or all groups, page or search the expansion, show diffs, keep the host
version, cancel, or explicitly apply a low-risk collapsed group. Plain `y` is available only when
every selected path is displayed.

Trusted fixed code performs apply without project Git, hooks, filters, pagers or executables. It
recursively resolves current host gitdirs, commondirs, configuration includes and hook locations,
then refuses every path host Git treats as control state. It applies the existing conservative
raw-byte name rules to `.git` and `.ko-agent-sandbox` at every depth and also refuses a resulting
bare Git layout, host-incompatible paths, symlink escapes and path-replacement races. The same
classification is rerun immediately before each affected mutation because host Git state can
change during review.

Only regular files, directories, safe symlinks and hardlinks are eligible for apply. Planning
refuses FIFOs, sockets and device nodes rather than reproducing special files in the project
directory.

### Live

All `--write=live` sessions for one project retain the existing topology: one FUSE mount, daemon,
kernel filesystem view, page cache and writable backing tree.

This preserves shared Git and POSIX locks and avoids multiplying daemon and cache costs. It also
means sessions race on files and build output, one workload can add latency, and a daemon failure
interrupts every live session for the project. Staged mode, not live mode, provides writable
isolation from the host.

### Live mutation journal

The live daemon writes a host-only, sandbox-unmodifiable journal. It records semantic mutations:
first writable open or create, truncate, mode or type change, rename or exchange, link, symlink,
unlink and directory removal. Repeated writes to one path are coalesced and contents are not
recorded. Each journal has fixed byte, exact-path and aggregate-directory ceilings. After either
entry table fills, new keys fold into fixed total counters, and the journal records the loss of
detail. Journals rotate and retain within fixed file-count and total-byte budgets across daemon
lifetimes. The daemon durably reserves a journal slot before authorizing a mutation. A reservation
failure denies that mutation; a completion failure marks the journal damaged and makes later
mutations fail closed.

The first mutation of each recorded key requires one durable reservation before the backing
mutation, while coalesced writes require no further journal sync. Benchmark that latency and
representative `sbt` builds on every platform before enabling the journal. Runtime storage or I/O
failure remains fail-closed; the deferred disk-exhaustion work is for staged upper layers, apply,
rollback bundles and staged control journals.

### Git residue closure

Live mode recursively validates nested repositories before mounting without following symlinks.
It validates `.git` directories and pointer files, detects bare layouts in ordinary directories,
and gates create, write, rename, exchange, hardlink and symlink operations that could complete one.
Complete full-tree validation is a launch-time cost; benchmark it on build-output-heavy projects on
every platform. An acceleration must still validate the current complete tree; a skipped directory
or stale result would reopen the residue.

The bare-layout rule uses Git's valid-`HEAD` plus `objects/` plus `refs/` discovery shape. Gitdirs
reached from an existing worktree's `.git` metadata are classified separately. Elsewhere, only a
mutation affecting an entry whose basename is one of those three candidates performs sibling
lookups and, when necessary, validates `HEAD`; ordinary filesystem operations and tree walks pay no
extra checks. Benchmark the candidate path against the standing FUSE performance measurements.

This rule cannot distinguish a bare repository from a project fixture containing the same valid
triple. Live mode deliberately refuses completing either one, and recursive preflight refuses an
existing one; staged mode may hold the fixture privately, but apply refuses to reproduce it on the
host. This narrower completion rule supersedes the current per-name infeasibility conclusion in
`fuse/ko-agent-fs/doc/git-metadata.md` ("Consequences").

Initialized submodules and ordinary Git commands continue working. Initializing a missing
submodule remains blocked in live mode and works inside a stage; its private Git metadata cannot be
applied.

## Egress authority

### Profiles

```text
--egress=deny-all
--egress=deny-unless-model       # default
--egress=deny-unless-allowed
--egress=allow-unless-denied
```

Configuration lives in host-read policy files that the sandbox cannot modify:

```text
.ko-agent-sandbox/egress/allowed
.ko-agent-sandbox/egress/denied
```

The launcher never creates this directory. In live and staged modes the FUSE reserved-name rule
prevents creating or changing `.ko-agent-sandbox` at any depth; reject mode makes the whole project
directory read-only. A missing directory is empty policy input, not a directory to materialize.

Let `M` be the selected agent's launcher-owned map of host to treatment and `B` the launcher-owned
baseline containing all model-provider maps plus the curated restricted-host catalog. Applying the
`allowed` delta to `B` produces a host map `A`. Let `N` contain `B`'s restricted entries plus
restricted exact-host additions from `allowed`; removals, `.defaults` and unrestricted additions
cannot subtract from `N`. Let `D` be the exact-host, subtree and provider rules expanded from
`denied`, and `H` immutable internal-network denials. `U` is the implicit map from every public
hostname on port 443 to `unrestricted`:

```text
deny-all              = empty
deny-unless-model     = M - D - H
deny-unless-allowed   = A - D - H
allow-unless-denied   = narrow(U, N) - D - H
```

The `allowed` delta controls admission only in `deny-unless-allowed`; its restricted projection `N`
also narrows treatment in `allow-unless-denied`. Thus an `allowed` removal narrows the curated
profile without blocking a model endpoint selected by `deny-unless-model` or widening an ambient
restricted host. Only `denied` removes ambient access, and it applies to every profile. Denial wins
over either treatment, and order in a file has no effect. Duplicate exact-host additions with
different treatments are refused as contradictory. A group expansion can be narrowed by an exact
`allowed` rule but never silently widened. The proxy resolves the policy once per run; a host edit
affects the next launch, never a live session.

With no project policy files, `--egress=deny-unless-allowed` resolves to `B`: all model-provider
maps plus the curated restricted-host catalog. This is the migration profile closest to the current
default.

An empty effective map is valid. This reverses the proxy's current refusal of an empty allowlist
and its tests: `deny-all` intentionally resolves empty, as can `deny-unless-model` when no model
provider is selected or `deny-unless-allowed` after `.defaults` with no additions. Empty policy is
reported as such, not treated as broken configuration.

### Model-provider groups

The policy names the party trusted to receive data:

```text
model-provider openai
model-provider anthropic
model-provider google
```

Each group expands only to launcher-maintained model, authentication and control-plane endpoints
operated by that provider, with the treatment each endpoint requires. It does not mean every domain
the provider owns. Both policy files accept groups, so a denied provider stays denied when its
concrete endpoints change.

The baseline includes every model-provider group. `allowed` is project-wide and does not condition
entries on the launched command: a project may remove providers it never uses, but every provider
left in `A` is reachable in each `deny-unless-allowed` session. `deny-unless-model` selects only the
current provider but admits no project extras; `allow-unless-denied` admits every non-denied public
host. This increment adds no selected-provider-plus-extras variant.

For `deny-unless-model`, a recognized command selects one group:

```text
codex  -> openai
claude -> anthropic
agy    -> google
```

Only the basename of the directly launched command is classified; the launcher does not inspect a
wrapper's arguments or guess what it may later execute. An unknown command selects no provider and
produces a startup warning under `deny-unless-model`; a directly launched `bash` therefore has no
egress under the default profile. Under every profile, a recognized agent whose model endpoints are
absent or denied also warns but does not prevent the requested session from starting; the profile
remains the user's authority decision.

### Host rules and treatment

The file grammar is explicit and extensible:

```text
# allowed: delta over launcher-owned defaults
-model-provider google
+host repo.maven.apache.org restricted
-host github.com
-host **.example.com
# .defaults clears the launcher-owned baseline; additions still apply

# denied: always applied
model-provider google
host telemetry.example.com
host **.example.com
```

`restricted` means inspected HTTPS limited to the existing closed set of read and fetch operations.
`unrestricted` means opaque application traffic to that exact host. These replace the current
`read-only` and `read-write` tier names. Under `allow-unless-denied`, entries in `N` stay restricted
and every other non-denied public host is unrestricted.

`allowed` accepts `+model-provider`, `-model-provider`, exact `+host` additions with treatment and
tags, exact or `**.example.com` `-host` removals, and `.defaults`. The last form removes the whole
launcher-owned baseline before additions are applied. A removal must match the baseline or an
addition, and contradictory add/remove or differently treated exact additions are refused. Grants
remain exact: no `+host` wildcard exists.

Per-host treatment widening deliberately has no delta spelling. Removing a baseline host and
re-adding it as `unrestricted` is a contradiction; a project that needs this must use `.defaults`
and state its complete replacement policy.

`denied` accepts concrete provider groups and exact or `**.example.com` hosts without `+` or `-`.
The subtree matcher denies the apex and every subdomain. Every subtree operation is removal-only and
therefore cannot widen authority. Irrespective of profile, the proxy rejects loopback, link-local,
multicast and private addresses, Podman gateways, proxy and sandbox control services, and any
hostname resolving to them. It validates resolved addresses at connection time. Direct networking
is never restored.

An `allowed` removal that matches neither the baseline nor an addition remains an error. A valid
`denied` entry is not refused merely because it matches no host admitted by the selected finite
profile: it can still apply under another profile or a future provider expansion. Except under
`deny-all`, startup warns once about such idle denials and preflight marks each one; under
`allow-unless-denied`, every syntactically valid host or subtree matches `U`. Unknown provider
groups and malformed entries remain errors. This replaces exact no-match refusal for denials,
because a typo cannot be distinguished from a proactive denial against the ambient host universe.

### Preflight, provenance and presentation

Rename `--proxy-effective` to `--egress-effective`; it uses the accompanying `--egress` profile.
Add `--egress-check=<host>` with the same rule. Model-dependent preflight accepts the command it is
evaluating without launching it:

```text
--egress-effective [--] [command [arguments...]]
--egress-check=<host> [--] [command [arguments...]]
```

Without a command, no model provider is selected and preflight says so. Finite profiles report every
effective host, treatment and source: built-in provider or curated baseline, `allowed` addition or
removal, `denied`, or an immutable denial. `allow-unless-denied` instead reports its public-HTTPS
default, restricted exceptions and finite denied rules; it never invents a host count. A removal or
deny that overrides an allow is shown rather than silently discarded, and an idle denial is marked.

`--egress-check` resolves through a one-shot proxy container with the same Podman network
configuration and resolver path as enforcement, never through the launcher's host resolver. It
reports that current evidence separately from the policy decision because a connection resolves
and validates the destination again when it is made.

Startup reports both authorities and their relevant state:

```text
Workspace: STAGED; 17 paths, 42 KiB; 3 attached sessions
Egress: DENY-UNLESS-ALLOWED; 18 effective hosts
Egress: ALLOW-UNLESS-DENIED; public HTTPS; 2 restricted, 4 denied
Egress: DENY-UNLESS-MODEL; no provider selected; 0 effective hosts
```

The proxy records the resolved-policy digest in its audit log. Egress elevation is per run and is
not inherited when an agent or stage resumes. `deny-unless-model` limits destinations but cannot
prevent project data from being sent to the selected model provider.

The launcher-appended agent instructions report the workspace mode and its writable locations, the
egress profile and effective destinations, and whether package installation or cloning needs a
host policy change and relaunch under `deny-unless-allowed` or a broader explicit profile. Static
`SANDBOX.md` describes only mode-independent container facts; agents must not have to infer a
read-only workspace or model-only registry refusal from a failed command.

## Delivery order

1. Add the option parser, optional `--`, authority enums, banners and pure parser tests. Continue
   honoring `KO_AGENT_SANDBOX_WORKSPACE_GUARD` until step 7.
2. Refuse the legacy egress layout, then implement egress profiles, the built-in baseline,
   `allowed` deltas, always-applied `denied`, intentional empty policy, provenance and
   enforcement-side preflight.
3. Implement `reject`, retain the shared live topology behind `--write=live`, and stop creating
   policy paths in the project directory. Keep the existing writable default until staged mode is
   complete; no distributable build may make ordinary launches read-only before the staged workflow
   is usable.
4. Close nested Git and bare-layout residues and add the live mutation journal.
5. Implement and prove the staged `ko-agent-fs` engine, versioned storage, and shared per-project
   lifecycle and visibility.
6. Implement handle-safe generation sealing, deterministic review, recursive Git classification,
   the durable apply state machine and conflict detection. Do not expose staged mode as complete
   until status, apply, recovery and discard are available.
7. Make `reject` the default only after step 6. Remove the workspace pin mode and make any present
   `KO_AGENT_SANDBOX_WORKSPACE_GUARD` refuse launch with its migration message. Remove the other
   superseded surfaces listed below, and update their binding code, tests and documents in the same
   change. Remove completed TODO rows rather than retaining a change history.

## Verification

- Unit-test option termination and management operands, every profile equation and presentation,
  allowed additions, removals and `.defaults`, denied subtrees, intentional empty policy,
  profile-scoped removals, ambient narrowing that cannot be widened by a removal or baseline reset,
  treatment collisions, provider expansion, command classification, idle-denial warnings,
  provenance, conflicting entries and legacy refusals.
- Test private-address and DNS-rebinding refusal, restricted HTTP and fetch operations, unrestricted
  tunnels, enforcement-side DNS preflight, fixed-per-run policy, and audit output.
- Test stage resume, representation refusal, shared locks, live lower changes, whiteouts, hardlinks,
  open-unlinked objects, shadow conflicts and applied-layer retirement.
- Test writable handles, open directories and shared mmap across sealing; inject interruption after
  every durable apply boundary; test partial apply, retry, operation dropping, third-state conflicts
  and concurrent seal/apply/discard.
- Test nested repositories, initialized and absent submodules, split Git directories, relocated
  hooks and includes, folded reserved names, every mutation route to a bare layout, the accepted
  fixture false positive, absence of sibling checks on unrelated operations, and launch-time walk
  cost on a build-output-heavy project.
- Test malicious filenames, indivisible operation selection, collapsed large build trees and the
  expansion requirement for security-significant entries.
- Test refusal of FIFOs, sockets and device nodes during apply planning.
- Test journal bounds with high path and directory cardinality, rotation, retention and append
  failure; benchmark first-key durability and representative builds with and without the journal.
- Test that an absent policy directory stays absent and both reset commands preserve all stage
  resources, refuse an active apply and never expose raw stage storage inside the sandbox.
- Exercise 32 concurrent sessions and smoke-test 64, including Git locks, append, rename, mmap,
  host-side writes, daemon failure and journal ordering.
- Test the launcher-appended instructions in every workspace and egress mode, including a direct
  `bash`, unavailable package registries and the writable output locations.
- Run the complete behavior on native Linux and in macOS and Windows Podman machines.

## Removed surfaces, deliberate exclusions and deferred work

The general-purpose built-in restricted-host catalog remains as baseline `B`, but the default
`deny-unless-model` profile does not admit it. The current per-treatment files become one `allowed`
delta whose entries carry their treatment; `+`, `-`, deny-only `**.example.com`, defensive
restatement and `.defaults` baseline replacement remain. The current `blocked` host and subtree
rules become `denied` and apply under every profile; `.defaults` belongs to the `allowed` delta
because it is a baseline reset, not a hostname matcher. Update the binding policy descriptions in
`README.md`, including its per-host treatment-override examples, `SECURITY.md` ("Reading without
being able to write" and "Adding hosts, not patterns") and `doc/DESIGN.md`, plus `resolveTiers` and
its launcher, proxy and integration tests.

The `KO_AGENT_SANDBOX_WORKSPACE_GUARD=none` pin mode has no replacement. Remove its launcher branch,
Git pin construction and `WorkspaceGuardOffTest`; retain launcher-owned empty mount sources only
where another mount still needs one, and update SECURITY.md's pin entry. The dynamic bare-layout
gate also replaces the residue and blocked-operation conclusions in
`fuse/ko-agent-fs/doc/git-metadata.md`, `guard.rs` and their tests.

Read-only-by-default supersedes `doc/DESIGN.md`'s writable-workspace principle. Creating no project
path supersedes SECURITY.md's two launcher-created mountpoint exceptions. Persistent stages narrow
the meaning of reset: `--reset` and `--reset-all` remove runtime state but no longer mean that the
project was never opened; launcher comments, help, README and SECURITY must point to explicit stage
discard. Static `container/ko-agent-sandbox/SANDBOX.md` becomes mode-independent, with the
actionable workspace and egress state supplied by the launcher-appended per-session section.

There is no detached full-copy stage, named parallel stage, automatic apply, per-session live mount,
bulk stage discard, host-wide command broker, executable-bit enforcement, or implicit fallback
between write modes. Project-controlled commands remain a workflow concern rather than a claimed
host-wide boundary.

Deferred staged work lives in `doc/TODO.md`: project-directory replacement detection, apply
rollback bundles, disk-exhaustion preflight and recovery, persistent-format migration,
shared-workspace session attribution, non-interactive plan/apply, and named parallel stages. The
optional no-symlink profile and the settled executable-bit decision live in
`fuse/ko-agent-fs/doc/TODO.md`.
