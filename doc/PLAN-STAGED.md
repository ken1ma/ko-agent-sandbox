# Plan: staged workspace, live-mode closure, and the default flip

The remaining increments of the workspace-authority work. No distributable build may make
ordinary launches read-only before the staged workflow is usable.

## Staged mode

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
machines ("Proving the engine per platform" below carries the contract and where each item is
settled). Failure aborts staged launch; there is no detached-copy or live-write fallback.

Every stage starts with a host-only manifest carrying a representation version. A launcher that
does not understand that version preserves the stage and refuses attachment with recovery
instructions. Future migrations are separate work.

## Proving the engine per platform

The axes a venue varies on are `DESIGN.md`, and `../fuse/ko-agent-fs/doc/testing.md` has the venues
themselves. What follows is only which one settles which part of the staged contract.

| contract item                                      | settled by                  |
| -------------------------------------------------- | --------------------------- |
| resume, representation refusal, whiteouts, copy-up | dev rig, any host           |
| advisory and POSIX locks                           | in situ, in each machine    |
| shared mmap across a generation switch             | in situ, in each machine    |
| open-unlinked files and writable handles           | in situ, in each machine    |
| live lower changes, and copy-up from the share     | in situ, on each share      |
| baseline revalidation and apply write-back         | in situ, on each share      |
| hardlink identity                                  | the filter's inode model    |
| rename and exchange on the lower                   | in situ, on each share      |
| symlinks: creation, and refusal of an escape       | in situ, on each share      |
| upper and lower names differing only by case       | in situ, APFS and NTFS      |
| upper durability and reflink behaviour             | in situ, each Linux backing |

A successful `--self-test` stamps the filter's source id and the venue it proved — podman version,
machine identity, kernel and the lower's filesystem. Staged launch refuses on an absent or
non-matching stamp, which is what makes "failure aborts staged launch" above a mechanism rather than
an intention, and what turns "re-run after a podman or macOS upgrade" from a row someone remembers
into a refused launch until `--self-test` runs again. The stamp records that a venue was proved
once; that the filter can still mount here now is the filter's own `--self-test`'s job, before every
session.

Windows carries one measured hazard to settle before the apply state machine is built rather than
during it: a host write to a file a live session holds open is refused with a sharing violation
(SECURITY.md, "The project checkout"; `../fuse/ko-agent-fs/doc/verification-log.md` has the
measurement). Apply writes to the host while sessions are
attached, and sealing rebinds write authority without necessarily closing the lower descriptor, so
apply's atomic replacement can be refused on exactly the paths it is applying.

## Stage management and visibility

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

The startup banner gains the stage's state, in the shape the implemented authorities already use:

```text
workspace: STAGED; 17 paths, 42 KiB; 3 attached sessions
```

## Apply while sessions run

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
selected and applied as one group. A link relationship cannot be recovered from what a session
observed — the filter mints an inode per `(parent, name)`, so two names for one object are two
inodes there (`../fuse/ko-agent-fs/doc/verification-log.md`) — so the stage records it at copy-up,
from the backing object's identity, and the plan carries it. The lower keeps the relationship;
only the view through the filter does not. For each group, trusted code:

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
transaction; rollback is deferred (`TODO.md`).

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

## Live mutation journal

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
rollback bundles and staged control journals (`TODO.md`).

## Git residue closure

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
`../fuse/ko-agent-fs/doc/git-metadata.md` ("Consequences"), whose text — with `guard.rs` and its
tests — changes in the same increment.

Initialized submodules and ordinary Git commands continue working. Initializing a missing
submodule remains blocked in live mode and works inside a stage; its private Git metadata cannot be
applied.

## Delivery order

1. Characterize the three lowers, before the stage representation is fixed. Hardlink identity,
   rename and exchange, symlink creation, case folding between upper and lower and the reach of an
   open-file hold each decide a representation choice, and none can be reasoned to a conclusion
   (`../fuse/ko-agent-fs/doc/TODO.md`, "P1"). Their answers are cheapest to act on now.
2. Close nested Git and bare-layout residues and add the live mutation journal.
3. Implement and prove the staged `ko-agent-fs` engine, versioned storage, and shared per-project
   lifecycle and visibility, with the in-situ suite, the launcher verb and the stamp that gates
   staged launch.
4. Implement handle-safe generation sealing, deterministic review, recursive Git classification,
   the durable apply state machine and conflict detection. Do not expose staged mode as complete
   until status, apply, recovery and discard are available.
5. Make `reject` the default only after step 4. Remove the workspace pin mode and make any present
   `KO_AGENT_SANDBOX_WORKSPACE_GUARD` refuse launch with a direct migration message: `fuse` needs
   no replacement — the filter is `--write=live`'s only mechanism then — and the weaker `none`
   mode has no equivalent. Remove the pin mode's launcher branch, Git pin construction,
   `WorkspaceGuardOffTest` and its policy mount-back; retain launcher-owned empty mount sources
   only where another mount still needs one; and update the surfaces that document the pin mode
   and the writable default — README, SECURITY.md ("Silent changes to what you own", "The `.git`
   pins of `WORKSPACE_GUARD=none`"), `doc/DESIGN.md` — in the same change. Persistent stages
   narrow the meaning of reset: `--reset` and `--reset-all` no longer mean the project was never
   opened; launcher comments, help, README and SECURITY must point to explicit stage discard. Remove
   completed TODO rows rather than retaining a change history.

## Verification

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
- Test that both reset commands preserve all stage resources, refuse an active apply and never
  expose raw stage storage inside the sandbox.
- Exercise 32 concurrent sessions and smoke-test 64, including Git locks, append, rename, mmap,
  host-side writes, daemon failure and journal ordering.
- Run every row of the table above on native Linux and in the macOS and Windows Podman machines,
  and record each run with its venue.

## Deliberate exclusions

There is no detached full-copy stage, named parallel stage, automatic apply, per-session live mount,
bulk stage discard, host-wide command broker, executable-bit enforcement, or implicit fallback
between write modes. Project-controlled commands remain a workflow concern rather than a claimed
host-wide boundary.

Deferred staged work is `TODO.md` ("staged-workspace extensions and hardening"); the optional
no-symlink profile and the executable-bit decision are `../fuse/ko-agent-fs/doc/TODO.md`.
