# Plan: staged workspace, live-mode closure, and the default flip

This plan holds the remaining increments of the workspace-mode work. No distributable build may
make a launch without a `--workspace` option read-only before the staged workflow is usable.

## Staged mode

`--workspace=staged` creates or resumes the workspace's persistent stage. A stage is a persistent
copy-on-write view:

```text
live host workspace, read-only ---+
                                  +--- staged workspace mount
persistent writable upper layers--+
```

- An untouched path reads the current host workspace, so host changes appear during the session.
- The first staged mutation of a path records the lower state. The upper entry then shadows that
  path, and a later host change to the path becomes an apply conflict.
- Deletions use whiteouts.
- Nothing is copied back automatically.

The workspace is the unit of sharing.

- Sessions attached to the workspace's stage share the merged view, the locks, the cache, the
  upper layers and the failure domain.
- `.ko-agent-sandbox` stays unmodifiable.
- Git metadata may exist privately in a stage, but is never applied to the host.

The shared failure domain has a cost, accepted to keep locks and caches coherent across 20–30
collaborating sessions:

- One workload can add latency for every attached session.
- A `ko-agent-fs` failure makes the merged view fail closed for all attached sessions until they
  restart.

One process and one mount serve the workspace's attached staged sessions, rather than one per
session.

Implement the merged view in `ko-agent-fs`.

- Kernel OverlayFS is not a candidate. Changing a mounted lower tree is outside OverlayFS's defined
  contract, and live host changes are a requirement.
- A podman volume may hold upper data.
- Raw upper layers, whiteouts, baselines, manifests, journals and control sockets are never mounted
  into the sandbox. Only the merged FUSE view is reachable.

Before staged mode is exposed, prove the engine on native Linux and in the macOS and Windows podman
machines. "Proving the engine per platform" below lists the contract and where each item is
settled. A failure aborts the staged launch, and no detached-copy or live-write fallback exists.

Every stage starts with a host-only manifest that names a representation version. A launcher that
does not understand that version preserves the stage, and refuses attachment with recovery
instructions. Future migrations are separate work.

## Proving the engine per platform

`design.md` lists the properties that vary between machines, and `../ko-agent-fs/doc/testing.md`
lists the places to run the suites. This section says only which place settles which part of the
staged contract.

| contract item                                      | settled by                  |
| -------------------------------------------------- | --------------------------- |
| resume, representation refusal, whiteouts, copy-up | dev rig, any host           |
| advisory and POSIX locks                           | in situ, in each machine    |
| shared mmap across a generation switch             | in situ, in each machine    |
| open-unlinked files and writable handles           | in situ, in each machine    |
| live lower changes, and copy-up from the share     | in situ, on each share      |
| baseline revalidation and apply write-back         | in situ, on each share      |
| hard-link identity                                 | the filter's inode model    |
| rename and exchange on the lower                   | in situ, on each share      |
| symlinks: creation, and refusal of an escape       | in situ, on each share      |
| upper and lower names differing only by case       | in situ, APFS and NTFS      |
| upper durability and reflink behavior              | in situ, each Linux backing |

A successful `--self-test` stamps the filter's source id and the machine it proved: the podman
version, the machine identity, the kernel and the lower's filesystem.

- A staged launch refuses when the stamp is absent or does not match.
- That refusal makes "failure aborts staged launch" above a mechanism rather than an intention.
- The refusal also turns "rerun after a podman or macOS upgrade" from a row someone must remember
  into a refused launch, until `--self-test` runs again.
- The stamp records that a machine was proved once. Whether the filter can still mount on this
  machine now is the job of the filter's own `--self-test`, before every session.

Windows has one measured hazard, to settle before the apply state machine is built rather than
during it:

- A file that a live session holds open refuses some host writers with a sharing violation,
  PowerShell's `Set-Content` among them (SECURITY.md, "The workspace").
  `../ko-agent-fs/fuse/doc/verification-log.md` has the measurement.
- Apply writes to the host while sessions are attached.
- Sealing rebinds write authority without necessarily closing the lower descriptor.
- So the host can refuse apply's atomic replacement on exactly the paths that apply is applying.

## Stage management and visibility

```text
--stage list
--stage status
--stage apply [-- <paths>...]
--stage discard
```

- The current workspace identifies the stage for every action except `list`. `--stage list` lists
  every stored stage by workspace.
- This increment has no bulk discard action.
- `--reset` and `--reset-all` remove runtime resources, but preserve every stage.
- Discard refuses an attached stage.
  - Discard confirms the workspace root, the pending path count and size, and any sealed, partially
    applied or recovery-needed state.
  - Non-interactive use also requires `--yes`.
- Attachment output and list output show the representation version, the pending path count and
  logical size, the physical stored size, the backing volume, the attached-session count, the lower
  path and the last-use time.
- No pending stage is pruned automatically.
- Status also shows the `quiescing`, `sealed`, `applying` and `recovery-needed` states, with the
  controlling host process and its start time.
- Stage storage has a distinct reserved resource-name pattern that neither reset action matches.
  Tests verify the preservation rule.
- Reset takes the same workspace lifecycle lock, and refuses while an apply or recovery transition
  is active. Reset never tears down a stage underneath the stage's control process.

The startup banner gains the stage's state, in the format that the workspace mode and the egress
profile already use:

```text
workspace: STAGED; 17 paths, 42K; 3 attached sessions
```

## Apply while sessions run

- Apply uses a host-only control channel, which is not mounted into the sandbox.
- A stage has one active generation and at most one sealed plan.
- Before review, apply quiesces the stage, then seals and rotates the active generation.
- If a sealed plan already exists, apply reuses that plan and reports newer unplanned changes,
  rather than sealing another plan.
- Canceling review leaves the plan sealed for the next apply.

Sealing is one per-stage serialized operation:

1. Briefly pause every container attached to the stage, and drain filesystem requests.
2. Flush dirty FUSE pages, mappings and metadata, then drain the daemon again.
3. Advance the generation barrier, and create a new writable generation above the sealed one.
4. Rebind every open logical object, so that a later write, truncate or shared-mmap write copies
   the object up into the new generation. A backing descriptor from the old generation is never
   write authority.
5. Resume every container before review.

- If flushing, draining or rebinding any writable handle, mapping or open directory fails, sealing
  aborts before the barrier advances.
- Agent changes made during review stay in the new generation.
- Before pausing, the command reports the workspace root and the number of attached sessions it
  will quiesce.

Apply holds the stage's control lock for its whole state transition. The sealed plan is a durable,
ordered set of operation groups. A rename, a hard-link relationship or another indivisible change
is selected and applied as one group.

A link relationship cannot be recovered from what a session observed:

- The filter assigns an inode per `(parent, name)`, so two names for one object are two inodes in
  the filter (`../ko-agent-fs/fuse/doc/verification-log.md`).
- So the stage records the relationship at copy-up, from the backing object's identity, and the
  plan records it too.
- The lower keeps the relationship; only the view through the filter loses it.

For each group, trusted code:

1. Revalidates the group's lower baseline and every host path, through open directory descriptors.
2. Persists and fsyncs an intent that contains the baseline and desired result hashes.
3. Performs atomic replacement where the host supports it, then fsyncs the object and its parent.
4. Persists completion, and stops the sealed entry from shadowing the live lower.

After an interruption, a baseline match is safe to retry, a desired-result match completes the
intent, and any third state is a conflict.

- Applied entries fall through to the host lower, so later host changes stay visible. Unapplied
  entries stay in the remaining sealed view.
- Interactive review can explicitly keep the host version and drop a whole staged operation group,
  including a baseline conflict found before the intent. The drop changes neither the host nor
  newer work in the active generation.
- A group with a persisted intent must first recover to its baseline or its desired result. Such a
  group cannot be dropped from an ambiguous partial state.
- The sealed plan is retired only when every operation is applied or explicitly dropped.
- A successful partial apply or drop atomically rewrites the remaining plan, before review
  continues or control returns.

Apply is crash-resumable, but it is not a portable multi-file transaction. Rollback is deferred
(`TODO.md`).

Review is deterministic, safely quoted and Git-like:

```text
M  src/main/Example.scala
A  src/test/ExampleTest.scala
D  old-script.sh
R  old.conf -> new.conf
M  scripts/run.sh  [mode 0644 -> 0755]
```

- A directory with more than 100 changed descendants collapses into an indexed summary. The summary
  shows exact counts by operation class.
- A collapsed group that contains a rename, a hard link, a symlink, a type change, an
  executable-bit addition or a deletion must be expanded before it can be approved.
- The prompt can expand one group or all groups, page or search the expansion, show diffs, keep the
  host version, cancel, or explicitly apply a low-risk collapsed group.
- Plain `y` is available only when every selected path is displayed.

Trusted fixed code performs apply, without the workspace's Git, hooks, filters, pagers or
executables. That code:

- recursively resolves the current host gitdirs, commondirs, configuration includes and hook
  locations, then refuses every protected Git path;
- applies the existing conservative raw-byte name rules to `.git` and `.ko-agent-sandbox` at every
  depth;
- also refuses a resulting bare Git layout, host-incompatible paths, symlink escapes and
  path-replacement races;
- reruns the same classification immediately before each affected mutation, because host Git state
  can change during review.

Only regular files, directories, safe symlinks and hard links are eligible for apply. Planning
refuses FIFOs, sockets and device nodes rather than reproducing special files in the workspace.

## Live mutation journal

The live daemon writes a host-only journal that the sandbox cannot modify.

- The journal records semantic mutations: the first writable open or create, truncate, a mode or
  type change, rename or exchange, link, symlink, unlink, and directory removal.
- Repeated writes to one path are coalesced, and contents are not recorded.
- Each journal has fixed limits on bytes, exact paths and aggregate directories. After either entry
  table fills, new keys fold into fixed total counters, and the journal records the loss of detail.
- Journals rotate, and are retained within fixed budgets of file count and total bytes across
  daemon lifetimes.
- The daemon durably reserves a journal slot before it authorizes a mutation.
  - A reservation failure denies that mutation.
  - A completion failure marks the journal damaged, and later mutations fail closed.

The reservation costs latency:

- The first mutation of each recorded key requires one durable reservation before the backing
  mutation. Coalesced writes require no further journal sync.
- Benchmark that latency, and representative `sbt` builds, on every platform before enabling the
  journal.
- A runtime storage or I/O failure stays fail-closed. The deferred disk-exhaustion work covers
  staged upper layers, apply, rollback bundles and staged control journals (`TODO.md`).

## Closing the git gaps

Before mounting, live mode recursively validates nested repositories, without following symlinks.
Live mode:

- validates `.git` directories and pointer files;
- detects bare layouts outside recognized gitdirs;
- checks the create, write, rename, exchange, hard-link and symlink operations that could complete
  a bare layout.

Full-tree validation is a launch-time cost. Benchmark the validation on build-output-heavy
workspaces on every platform. An acceleration must still validate the current complete tree, since
a skipped directory or a stale result would reopen the gap.

- The bare-layout rule uses Git's discovery layout: a valid `HEAD`, plus `objects/`, plus `refs/`.
- Gitdirs reached from an existing worktree's `.git` metadata are classified separately.
- Elsewhere, only a mutation that affects an entry whose basename is one of those three candidates
  performs sibling lookups, and validates `HEAD` when necessary. Operations on other names, and
  tree walks, pay no extra checks.
- Benchmark the candidate path against the existing FUSE performance measurements.

The rule cannot tell a bare repository from a workspace fixture that contains the same valid
triple.

- Live mode deliberately refuses to complete either one, and the recursive preflight refuses an
  existing one.
- Staged mode may hold the fixture privately, but apply refuses to reproduce it on the host.
- This narrower completion rule replaces a conclusion of
  `../ko-agent-fs/policy/doc/git-metadata.md`: that no rule per name can refuse a bare layout
  ("Consequences: git operations blocked inside the workspace"). That document's text, `guard.rs`
  and its tests change in the same increment.

Submodules and Git commands:

- Initialized submodules, and the permitted Git commands that `AGENTS-SANDBOX.md` names, keep
  working.
- Initializing a missing submodule stays blocked in live mode, and works inside a stage. The
  submodule's private Git metadata cannot be applied.

## Delivery order

1. Characterize the supported lower filesystems before the stage representation is fixed.
   - Five properties each decide a representation choice, and none can be reasoned to a
     conclusion: hard-link identity, rename and exchange, symlink creation, case folding between
     upper and lower, and the reach of an open-file hold (`../ko-agent-fs/fuse/doc/TODO.md`, "What
     the staged lower can do, per share").
   - Settling the five first avoids revising an implemented representation.
2. Close the nested-git and bare-layout gaps, and add the live mutation journal.
3. Implement and prove the staged `ko-agent-fs` engine, versioned storage, and shared per-workspace
   lifecycle and visibility. Include the in-situ suite, the launcher action and the stamp that a
   staged launch requires.
4. Implement handle-safe generation sealing, deterministic review, recursive Git classification,
   the durable apply state machine and conflict detection. Do not expose staged mode as complete
   until status, apply, recovery and discard are available.
5. Make `read-only` the default only after step 4.
   - Update the documents that describe the writable default in the same change: README,
     SECURITY.md and `doc/design.md`.
   - Persistent stages narrow what a reset means. `--reset` and `--reset-all` keep every stage, so
     a reset does not return the workspace to a never-opened state. Launcher comments, help,
     README and SECURITY must point to explicit stage discard.
   - Remove completed TODO rows rather than retaining a change history.

## Verification

- Test stage resume, representation refusal, shared locks, live lower changes, whiteouts, hard
  links, open-unlinked objects, shadow conflicts and applied-layer retirement.
- Test writable handles, open directories and shared mmap across sealing.
- Inject an interruption after every durable apply boundary. Test partial apply, retry, operation
  dropping, third-state conflicts, and concurrent seal, apply and discard.
- Test nested repositories, initialized and absent submodules, split Git directories, relocated
  hooks and includes, folded reserved names, and every mutation route to a bare layout.
  - Also test the accepted fixture false positive, the absence of sibling checks on unrelated
    operations, and the launch-time walk cost on a build-output-heavy workspace.
- Test malicious filenames, indivisible operation selection, collapsed large build trees, and the
  expansion requirement for security-significant entries.
- Test that apply planning refuses FIFOs, sockets and device nodes.
- Test journal bounds with high path and directory cardinality, rotation, retention and append
  failure. Benchmark first-key durability and representative builds with and without the journal.
- Test that both reset commands preserve all stage resources, refuse during an active apply, and
  never expose raw stage storage inside the sandbox.
- Exercise 32 concurrent sessions and smoke-test 64, including Git locks, append, rename, mmap,
  host-side writes, daemon failure and journal ordering.
- Run every row of the table above on native Linux and in the macOS and Windows podman machines,
  and record each run with its machine.

## Deliberate exclusions

The plan has none of these:

- a detached full-copy stage;
- a named parallel stage;
- automatic apply;
- a per-session live mount;
- bulk stage discard;
- a host-wide command runner;
- executable-bit enforcement;
- an implicit fallback between workspace modes.

Workspace-controlled commands stay the user's workflow to manage. The plan claims no host-wide
boundary around them.

`TODO.md` holds the deferred staged work ("Deferred — staged-workspace extensions and hardening").
`../ko-agent-fs/fuse/doc/TODO.md` holds the optional no-symlink profile and the executable-bit
decision.

## Unresolved: a staged workspace under `--run-on-host`

`--run-on-host` runs an agent's build natively against the host workspace (`run-on-host.md`). A
staged session's agent sees the merged mount, so the agent and the build disagree about what the
workspace contains:

- the build compiles the host tree, not what the session staged;
- the build writes its output where no stage records it.

Three answers are possible, and which one holds is undecided:

- refuse the combination;
- stage the build's writes too;
- define the host tree as the build's view, and say so.

The decision belongs with whichever of the two features is implemented second.
