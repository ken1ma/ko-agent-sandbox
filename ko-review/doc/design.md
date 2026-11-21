# Independent review from Claude Code or Codex

`/ko-review` asks a separate Codex or Claude Code session, the reviewer, to review the working
tree. The user chooses the reviewer.

- The coordinator, the session that runs ko-review, sends the author's answer to each finding on
  the same reviewer thread.
- The cycle ends when the reviewer approves every change in the scope, or when the reviewer asks
  for a decision only the user can make.
- The reviewer's suggestions never block approval ("The cycle", step 2).

Each new review has its own reviewer thread, and so audits the scope independently.

Four roles take part in a review. Today the coordinator acts as the author, and no advisor exists.

- The coordinator runs ko-review: it starts and continues the review, decides each step, reports
  to the user and escalates. SKILL.md addresses the coordinator.
- The author answers the reviewer: it fixes the findings it accepts, disputes the others with
  evidence, and adopts or disputes each suggestion. The reviewer prompts address the author, whose
  statements are claims, whoever wrote the change.
- The reviewer reviews the change on its own thread and decides each turn's disposition.
- The advisor would give the coordinator a second opinion on the reviewer's findings, suggestions
  or a dispute before the coordinator answers (`TODO.md`). An advisor decides nothing, and its
  opinion is a claim like the author's.

- Before the skill opens a new review, the skill offers to continue an approved review whose
  approval still covers part of the scope (`approvals`, below).
- `approvals` offers only reviews with the instructions that the argument names, since an approval
  holds for the instructions it was given. The skill makes no offer when the argument names a
  reviewer, model or effort that a continuation would not keep.
- When such a review already approves the current tree, the skill asks whether to stop or to open
  a new review, such as one with a stronger model or a higher effort.

Who starts a review, and how:

- A Claude session that reviews another Claude session's changes has its own thread and none of
  the coordinator's context. The same applies to Codex.
- A review starts only at the user's request: `/ko-review`, `$ko-review` in Codex, or a request in
  words ("ko-review the changes since the last review with Claude"). The sandbox's
  `AGENTS-SANDBOX.md` has the coordinator offer a review after a non-trivial change.
  - The skill has the plugin's name, `ko-review`. Claude Code lists a plugin skill as
    `/ko-review:ko-review`, and also runs it by its bare name, `/ko-review`, which no other command
    has.
    - A skill named `review` would have the bare name `/review`, which is a built-in alias of
      `/code-review`.
    - Codex lists its copy without a plugin prefix, so a Codex user types `$ko-review`.
  - The skill's description tells the coordinator to invoke the skill only on such a request.
    Nothing enforces that rule.
    - Claude Code's `disable-model-invocation` or Codex's `allow_implicit_invocation: false` would
      enforce the rule, but each setting also stops the coordinator from acting on a request in
      words.
- A base commit or branch in the skill's argument becomes `--base` (below).
  - `/ko-review HEAD~1` reviews the last commit and whatever is uncommitted.
  - `/ko-review main` reviews whatever differs from `main`.
- A reviewer of the coordinator's product uses the sign-in of the coordinator's session. A reviewer
  of the other product needs its own sign-in in this workspace's sandbox (`REVIEWER_AUTH_FAILED`,
  below).
- The skill asks the user for the reviewer, the model and the effort, offered from
  `ko-review defaults REVIEWER`, unless the argument names them.
  - Codex has no question tool outside Plan mode, so a Codex coordinator asks in its reply. Codex's
    `default_mode_request_user_input` feature is under development and off in codex-cli 0.162.1.

Where the parts are:

- `ko-review/` at the repository root holds what a repository of the plugin's own would hold:
  - `doc/`: this design and the plugin's `TODO.md`;
  - `plugin/`: the plugin's files, which `plugin/README.md` describes: the skill, the reviewer
    prompts, the result schema, the manifest in `claude-plugin/`, and `bin/ko-review`;
  - `src/`: the helper `ko-review`, the sbt subproject of the same name. The helper is a Scala 3
    program with no dependency on the launcher. Its `start` takes the reviewer's name, so that
    another reviewer can be added under another name.
- Installing takes an assembled plugin, which the subproject's `pluginAssembly` task builds:
  - `claude-plugin/` becomes `.claude-plugin/`, which Claude Code requires and most listings hide;
  - `lib/` holds the helper's jar and its dependencies' jars, and `bin/ko-review` runs
    `java -cp "lib/*"`;
  - `lib/dependencies.txt` lists every module of the helper's runtime classpath at the version sbt
    resolved.
- The launcher jar carries the assembled plugin in the runtime image's build context, without the
  dependencies' jars. The image build fetches the listed modules with `cs fetch --intransitive`,
  which checks each file's checksum, into `lib/`.
  - `--intransitive` names one module, so the command passes it before each listed module. It
    keeps Coursier from resolving the graph again, so `lib/` holds the jars sbt tested with.
  - So the launcher jar grows by the helper's own jar, about 0.5 MiB, not by the Scala library,
    circe, cats and tomlj, about 20 MiB, and no image build compiles anything.
  - sbt writes every jar entry with one fixed timestamp, so the jar's bytes, and the runtime
    image's id, change only with the helper's sources.
  - Once CI publishes the helper's jar, the image build fetches it the same way.
- Outside the image, the subproject's `sbt dist` builds the same assembly with the dependencies'
  jars, which it copies from its own classpath.
- The image loads the plugin from `/etc/claude-code/plugins` through `CLAUDE_CODE_PLUGIN_DIRS`
  (Claude Code 2.1.280 or later).
- Codex reads a copy of the skill from `/etc/codex/skills`, its admin scope, and runs the helper
  through the helper's link in `/usr/local/bin`. The Containerfile explains why.
  - On a host, a copy of the skill directory in `~/.agents/skills` and the plugin's `bin/` on PATH
    do the same.
- The working directory must be inside a Git working tree. Elsewhere, `start` fails with
  `NOT_A_GIT_REPOSITORY` before the reviewer runs.
  - The error message gives the `git init` and the empty `git commit` that make a working tree.
    These commands leave every file uncommitted, and so in the review's scope.


## The cycle

1. The coordinator starts the review with the author's summary of the work.
   - The author first re-reads every changed hunk against `AGENTS.md`, with the unchanged lines
     around it, and fixes what it finds.
     - The reviewer prompt limits findings to material issues. So conformance to the project's
       instructions is the author's to check, and a turn spent on it would cost reviewer quota.
     - Claude Code reads `AGENTS.md` from 2.1.277 on, or through a `CLAUDE.md` import.
   - `ko-review start REVIEWER --message-file FILE` opens a reviewer thread with the reviewer
     prompt and the author's summary. The reviewer reads the repository itself.
   - `--base REF` has the reviewer review the changes since that commit or branch, committed or
     not.
     - The helper records the commit id that the ref resolves to at `start`, so a branch that
       moves during the review does not move the scope.
     - Without `--base`, each turn's prompt names the commit that HEAD points at when the turn
       starts, and the reviewer reviews the working tree against it. Work committed during the
       session is out of scope. Before the first commit, the reviewer reviews every file.
     - The skill passes a base only from its argument, for the reason `SKILL.md` step 1 gives.
     - The reviewer compares the working tree with the base's tree, so commits merged or pulled
       since the base are in scope too.
     - The scope is one diff that ends at the working tree, never a range that ends at an earlier
       commit. A fix is an edit on top of HEAD. For such a range, the reviewer would read the
       finding in one diff and its fix in another, with the commits between them as context it
       did not review.
     - To review commits in the middle of the history, check out the last of them in a clone and
       pass the parent of the first as the base.
   - The helper refuses an empty scope with `NOTHING_TO_REVIEW` before a review exists. The scope
     is empty when the working tree equals the base commit, or HEAD without `--base`, and no file
     is untracked.
     - A dirty checkout whose edits restore the base's content counts as empty.
     - A reviewer turn on nothing would yield an approval that looks like an approval of the
       session's committed work.
   - `--instructions-file FILE` adds the user's own instructions, from the skill's argument, to
     every turn's prompt. The user's instructions follow the reviewer instructions and take
     precedence over them.
   - `--model` and `--effort` choose the reviewer's model and reasoning effort for every turn:
     `codex exec --model` and the `model_reasoning_effort` configuration key, or `claude --model`
     and `--effort` ("Defaults", below).
2. The reviewer answers with a structured result:
   - a `disposition`: `APPROVED`, `CHANGES_REQUESTED` or `USER_DECISION_REQUIRED`;
   - a summary;
   - findings with stable ids, and suggestions with their own ids;
   - for a user decision: the issue, the reviewer's position, why evidence cannot decide it, and
     the decision requested.

   A finding is a material issue, and the findings decide the disposition. A suggestion is an
   opinion beside the findings, with its reason: a design the reviewer prefers, a simpler way, an
   alternative another project took, or a question about a premise.
   - Findings and suggestions are separate because a finding blocks approval, and an opinion must
     not block it. So `APPROVED` may carry suggestions.
3. The author fixes the findings it accepts, disputes the others with evidence, and adopts or
   disputes each suggestion the same way. The author then runs the relevant tests and checks,
   which the reviewer does not run. `ko-review continue REVIEW_ID --message-file FILE` sends all
   of it to the same thread.
   - The user decides an item that depends on what the user owns, the task's scope, ownership of
     the work, a recorded decision (AGENTS.md's boundary rule), a product requirement or a risk
     acceptance, or on a disagreement evidence cannot settle.
     - `USER_DECISION_REQUIRED` and the coordinator's "ask the user to decide" apply that one
       condition.
       The prompt and the skill state the condition in the same words, and the test suite checks
       them, so that neither side escalates what the other side acts on.
   - The author adopts or disputes every other suggestion rather than relaying it to the user.
     - The reviewer already judges a suggestion worth attention before raising it, and the next
       turn reviews what the author adopted.
   - The coordinator's turn report names each adopted suggestion that changes an interface or the
     split into components. So the user learns of a design change made on the reviewer's opinion
     without reading the transcript.
   - `continue --instructions-file FILE` sends instructions that the user gives during a review.
     - The new instructions replace the earlier instructions from that turn on.
     - An approval holds for the instructions it was given, so instructions with a different text
       make it stale until a turn under them ends in a new approval.
4. The review repeats until `APPROVED`, or until the limit of answered turns ends it with
   `LOOP_LIMIT_REACHED`.
   - The default limit is 12; `start REVIEWER --max-answered-turns` sets another. A turn that ends
     in an error does not count.
   - A `continue` that the limit refuses leaves an approval in place.
   - `status` reads `LOOP_LIMIT_REACHED` once the limit is reached without an approval, so the
     coordinator learns that the review is over before sending another response. A request for
     the user's decision stays `USER_PROPOSED`, so that the coordinator can still escalate it.
   - A request for a user decision ends the review only when the coordinator agrees and runs
     `ko-review escalate REVIEW_ID --message-file FILE`. Otherwise the author argues the point on
     the same thread.
5. Before the coordinator reports an approval, `ko-review check-approval REVIEW_ID` confirms that
   the approval covers the current working tree ("Approval binds to the reviewed changes and the
   review's instructions", below).

The coordinator reports each turn's outcome, and when the review ends, a table of every turn and the
command `ko-review transcript REVIEW_ID`.

- The reader of that report needs at most the transcript, whose footer lists the other `inspect`
  lines. `start` deletes a review 30 days after its last update ("Where the state is").
- The table comes from `ko-review transcript`, since the session's context may have been
  summarized by then.

The coordinator's own model and effort are those of the coordinator's session, set with `/model`
or the launch options.


## Commands

Every command prints one JSON object, except `transcript`, which prints Markdown, and `diff`, which
prints git's output. A command exits 1 when its object contains an `error` field.

- Each summary carries the review id, `inspect` and `reviewer`.
- A failure carries the review id and `inspect` when the command had read the review's records
  before failing.

The commands:

- `list`: one short entry per review of this worktree, oldest first, which gives the id that the
  other commands take.
  - A review whose records this helper cannot read is listed with the error's code as its
    `effectiveStatus`, so that `delete` can be given its id.
- `digest`: the content digest of the reviewable files, with HEAD's commit id.
- `show REVIEW_ID`: the review's state, computed from its records.
  - For a turn in progress, `show` adds `activity`: the path of the reviewer's standard output, the
    time elapsed, and the type and time of the last event received.
  - The last event says when the reviewer last wrote, not that the reviewer is still working.
- `transcript REVIEW_ID [--turn N]`: the transcript as Markdown, one section per turn, or the
  named turn's section alone.
- `diff REVIEW_ID [--from N] [--to M] [-- git options]`: the difference between two turns' starts,
  rebuilt from their patches ("The patches", below).
  - Without `--from`, the turn is the approved one, or the last one when none is approved.
  - Without `--to`, the other side is the working tree, untracked files included.
  - The two sides become trees in a scratch repository, so git's options, such as `--stat`, name
    the files as a diff of the worktree does.
  - A path that the patches leave out ("The patches", below) is named on stderr when its hashes in
    the two sides' manifests differ. The rebuilt trees leave such paths out, so their content
    never decides.
- `restore REVIEW_ID --turn N DIR`: rebuilds a turn's start in `DIR`, a new or empty directory,
  without the paths that the patches leave out, and lists those paths in its output.
- `delete REVIEW_ID`: deletes the review's directory, whatever its records hold. The coordinator
  runs `delete` on the user's request only.
- `defaults REVIEWER`: the model and effort that the reviewer's local configuration selects for
  this repository, the models to offer with each model's efforts, and the `recommended` pair
  ("Defaults", below).
- `approvals [--base REF] [--instructions-file FILE]`: the approved reviews whose approval still
  covers part of the scope that a `start` with that base would have, newest approval first.
  - Each entry has `coveredPaths` and `newPaths`, so that the skill can offer to continue a review
    instead of opening a thread.
  - A path is covered when two conditions hold:
    - the path is in the scope that the approved turn recorded;
    - the path's content is the one in that turn's manifest.
  - Content decides, so staging or committing the approved paths keeps them covered.
  - A path that no reviewer was told to look at is not covered, however long its content has been
    the approved one, as when HEAD moves under an untouched file.
  - A candidate has the same base as the new review would have. The instructions of its approval and
    the review's current instructions both equal the new review's, so a continuation keeps them.
    Whitespace around the instructions does not count, as in `check-approval`.

The helper never commits, stages or moves HEAD. The author's fixes during a review are
working-tree edits like any other, and the user commits them when and as they choose.


## What the helper guarantees

- **The same thread.** Every turn of a review runs on the reviewer thread that its first turn
  opened. A resumed turn that names another thread fails with `REVIEWER_RESUME_MISMATCH`.
  - The thread id is the id that the reviewer's first event names. The helper writes the id to the
    turn's `thread.json` the moment the event arrives:
    - Codex: the `thread.started` event's `thread_id`, resumed with `codex exec resume <that id>`;
    - Claude Code: the `system` `init` event's `session_id`, resumed with
      `claude -p --resume <that id>`.
  - The coordinator never chooses a thread, and nothing uses `--last` or `--continue`.
- **Approval binds to the reviewed changes and the review's instructions.** After a file changes,
  an unreviewed path enters the scope, or the instructions change, `check-approval` fails with
  `NOT_APPROVED` and the `effectiveStatus` `STALE_APPROVAL`. The error's `staleReasons` says what
  changed, and `continue` obtains a new approval.
  - The approval is the result of the latest turn the reviewer answered, when that result is
    `APPROVED`. `effectiveStatus` is then `APPROVED` or `STALE_APPROVAL`, and otherwise the latest
    outcome.
  - The content digest covers every reviewable file's raw content ("The digest", below).
  - Staging, committing or moving HEAD keeps the approval, because the reviewer approved the
    files, not the index or HEAD. Content that is staged and then removed from the files can
    therefore reach a commit unreviewed.
  - A path that enters the scope without a content change, as after `git reset --soft`, makes the
    approval stale: no reviewer looked at it. The rule is the one that `approvals` applies.
  - A failed turn keeps the approval, since neither the files nor the instructions changed.
    Approvals of other reviews of the same content, by other reviewers, models or efforts, hold
    alongside it.
  - `staleReasons`, in `show` and in `check-approval`'s error, gives these reasons:
    - "working files changed", with the paths, from the approved turn's manifest;
    - "paths entered the scope since the approval", with the paths;
    - the instructions changed after the approval.
- **Each turn is kept as files written once** ("Where the state is", below), and nothing is
  written to the user's repository, index, HEAD or files.
  - A turn's start can be rebuilt from the patches: the first turn's commit, then each turn's patch
    in order ("The patches", below).
  - A rebuilt turn lacks the paths that the patches leave out. The manifest still hashes them, so
    the approval rules still cover them.
  - A turn cannot be rebuilt once its commit is gone from the repository, as after a rebase and a
    garbage collection.
- **A change to the files during a turn discards the turn's result.** The helper compares the
  content digest before and after the reviewer runs. A difference fails with
  `WORKTREE_CHANGED_DURING_REVIEW`, with the changed paths.
  - Staging, committing or moving HEAD during a turn keeps the result. The prompt names a commit
    id rather than `HEAD`, so a commit does not move what the reviewer reads.
  - The check therefore misses a reviewer that stages or commits without editing a file.
  - Nothing is reverted.
  - The helper does not say who changed the tree: a host editor, another session or the reviewer
    itself may have.
- **Failures are never outcomes.** A failed turn's `outcome.json` holds the error, and the status
  stays the outcome of the latest turn the reviewer answered.
  - A `continue` retries on the same thread once the reviewer has named a thread. When the failure
    came before that, the `continue` opens a thread.
  - The helper writes the thread id the moment the reviewer names it. So the retry resumes that
    thread, whatever ends the turn after that: a timeout, an interrupt or termination signal,
    unparsable later output, or a helper bug (`HELPER_FAILED`).
  - The retry's prompt carries again every author message since the last turn the reviewer
    answered, oldest first and as written. A failed turn may not have left its message in the
    thread.
  - Before any turn has been answered, the retry sends the reviewer prompt again.
  - A turn that ends in an error does not count toward the limit of answered turns, so retries
    after a usage limit do not use up the review.
  - Whatever ends the turn, the reviewer's own exit included, the helper kills the reviewer's
    process group and waits for the reviewer before the helper returns. So neither the reviewer
    nor a process the reviewer left in that group runs on past the lock that serialized the turn.
    - On Linux, the helper also adopts the reviewer's orphaned descendants for the turn
      (`PR_SET_CHILD_SUBREAPER`), and kills and reaps them until none is left. So a process that a
      tool command left in a session of its own does not run on either.
    - On Linux, a process left holding the reviewer's stdout therefore does not hold the turn.
    - On a macOS host, the helper kills only the group, and such a holder holds the turn until the
      holder exits.
  - Every reviewer error's `error` carries `reviewer`, the name that the message uses:
    - `REVIEWER_AUTH_FAILED`: `codex login status` or `claude auth status` reports no sign-in,
      whichever credential store the CLI uses. Sign in to that CLI in this workspace's sandbox.
    - `REVIEWER_EGRESS_DENIED`: the ruleset in `KO_AGENT_SANDBOX_EGRESS_RULESET` allows none of
      the reviewer's hosts, as when the launch admitted the coordinator's preset alone. Relaunch
      with `--egress-preset` naming both agents' presets, such as
      `--egress-preset=anthropic,openai`.
      - Codex's hosts are `api.openai.com` and `chatgpt.com`. Claude's hosts are
        `api.anthropic.com` and `platform.claude.com`.
    - `REVIEWER_FAILED`: any other failure of the reviewer.
      - When the reviewer said why, `message` ends with the reviewer's words, such as a usage
        limit and when it resets. The words come from the reviewer's last failure event, else from
        its last line of stderr.
      - A thread that the reviewer no longer has is also `REVIEWER_FAILED`, and its message says
        to start a new review.
    - `INVALID_RESULT`: the reviewer's final message does not follow the schema exactly. The
      helper validates the message before touching state; the CLI's schema option only asks.
    - `TURN_INTERRUPTED`: a timeout or a signal ended the reviewer. A signal that ended the helper
      itself raises the same code without `reviewer`.
  - The helper never edits the egress rules or a reviewer's configuration.
- **One mutation per review at a time.** `start`, `continue`, `escalate` and `delete` take an
  exclusive lock on the review's `review.lock` before reading the files they act on.
  - A second such command fails at once with `REVIEW_LOCKED`, instead of waiting behind a reviewer
    turn.
  - The lock is a POSIX record lock, which closing any descriptor of the file releases for the
    whole process. So a command that holds the lock never opens the file again, as when it asks
    whether a turn is in progress.
  - Each record is written to a temporary name and linked to its final name. So `show` and
    `list` read without the lock and never see part of a record, and a mistaken second write
    fails instead of replacing a record.


## Where the state is

The state directory:

```text
$HOME/persistent-volume/ko-review/
└── worktrees/<sha256 of the worktree path>/
    ├── worktree.json        the unhashed worktree path
    └── reviews/<review id>/
        ├── start.json       the base, answered-turn limit and turn timeout
        ├── review.lock
        └── turns/
            ├── 001/
            │   ├── request.json
            │   ├── thread.json
            │   ├── outcome.json
            │   ├── escalation.json
            │   ├── manifest.json
            │   ├── start.patch
            │   ├── reviewer.stdout
            │   └── reviewer.stderr
            └── 002/ …
```

A turn's files:

- `request.json`: the reviewer, model, effort, reviewer CLI and plugin versions, the instructions,
  the author's message, the scope's paths, what `start.patch` applies to, and the coordinator
  ("The coordinator's record", below).
- `thread.json`: the reviewer's thread id, only in a turn that opened a thread.
- `outcome.json`: the exit code, and the validated result or the helper's error.
- `escalation.json`: only when the coordinator escalates the turn's request for a decision.
- `manifest.json`: the content hash of every reviewable file at the turn's start.
- `start.patch`: the turn's start, as text changes from what `request.json` names.
- `reviewer.stdout` and `reviewer.stderr`: the reviewer CLI's output, whatever its format.

- Each JSON file and the patch are written once, at the moment their fact exists: the request
  before the reviewer runs, the thread id when the reviewer names it, the outcome when the reviewer
  exits, and an escalation when the coordinator decides. A JSON file also records when it was
  written.
  - The reviewer's output files grow while the reviewer runs, and stay unchanged once
    `outcome.json` exists.
- The helper computes the review's status, its approval, its last error, the count of answered
  turns, the content digest and the binary paths from these files rather than storing them.
  - A turn is in progress while it has a `request.json` and no `outcome.json`, and a command holds
    the review's lock. A turn without an outcome whose lock nobody holds was left by a helper that
    died, and its error reads `HELPER_FAILED`.
  - The content digest is the SHA-256 of the manifest's entries, sorted by path, in one fixed
    encoding. So `manifest.json`'s write time and JSON layout never enter the digest.
  - The binary paths are Git's entries in `start.patch`.
- `request.json`'s `from` names what `start.patch` applies to, by the store that holds it:
  - `{"store": "git", "commit": "…"}` in the first turn: the base, or HEAD at the turn's start.
    Without a `commit`, the start is an empty tree, as under an unborn HEAD.
  - `{"store": "ko-review:turn", "turn": "001"}` in a later turn: that turn's start.
- The classes in the subproject's `ReviewFiles.scala`, one per JSON file, define every field and its
  default. Their header comment states how the files may change, so that a review stays readable
  across helper versions.
- Every JSON file carries `formatVersion`, the semantic version of the format the file follows,
  `0.2.0` for this design. A review's files may come from different helpers, one per turn or
  escalation, so each file names its own.
  - Until 1.0.0, a newer patch version only adds fields that an older helper may ignore.
  - A newer minor version changes what an older helper must not ignore. The older helper then
    refuses to continue the review with `REVIEW_FORMAT_NEWER`, which says to update the plugin.
    Read-only commands still work.
  - A munit test compares one of each file, every field set, with samples checked in under the
    format version. A format change fails the test until samples under a bumped version join them.
- `start` deletes every review under the state root whose latest record is 30 days old or more,
  whichever worktree it belongs to, and names them in its output's `expiredReviews`.
  - The sweep covers every worktree, so that the reviews of a removed linked worktree or a deleted
    checkout expire too. A worktree's directory goes once it holds no review.
  - A review that `start` cannot delete is in `expiryFailures` with the error. The new review
    starts regardless.
  - A review that another command holds stays, silently.
  - For a review whose records the helper cannot read, the start minute in the id counts as the
    latest record.
- A review id is its local start minute, `2026-09-24-1005-`, plus eight hex digits.
  - The state directory groups reviews by start minute, in an arbitrary order within one minute.
  - The id can be typed.
- State is namespaced by worktree path, because a review is about one worktree: Git's main
  worktree or a linked one. A persistent volume can be shared by several workspaces
  (`--persistent-volume`), or by a main worktree and its linked worktrees.
- The reviewers' own session files stay in `~/.codex` and `~/.claude`. Sharing them is safe,
  because every continuation names its thread id.
  - A session file holds each turn's exact prompt, which the helper does not keep. Claude Code
    deletes its transcripts after `cleanupPeriodDays`, 30 days by default, and the 30-day expiry
    above follows that default.
- `--reset` removes the workspace's own volume, and with it the review state and those session
  files.
  - `--reset` keeps a volume named through `--persistent-volume` and, from a linked worktree, the
    main worktree's volume, each with what it holds (`SECURITY.md`, "What the persistent volume
    holds").
- Outside the sandbox, the state root is `$XDG_STATE_HOME/ko-review`, by default
  `~/.local/state/ko-review`. `KO_REVIEW_STATE` overrides either.


## Why it is built this way

### The digest

- The content digest covers every file Git would review, from
  `git ls-files --cached --others --exclude-standard`.
  - Each file contributes its raw content with its executable bit, or its symlink target byte for
    byte, through `readlink`: a JVM path loses bytes that are not UTF-8 and trailing slashes. An
    absent path contributes nothing.
  - The digest reads raw content because `git status` calls a file clean when its content after
    the clean filter matches the index, and so misses a change that a filter strips.
- HEAD, the index and other refs are not part of the digest, because the reviewer reviews the
  files. Each turn records its scope as paths.
- A submodule or nested repository is digested the same way, as a tree of its own, since Git
  lists it as one path. A commit inside it changes no content and leaves the digest alone.
- No `git diff` runs, so no diff or textconv driver shapes the digest.
- The helper reads file names as UTF-8, as the JVM names files. A worktree that holds a name that is
  not UTF-8 fails with `PATH_NOT_UTF8`, since the helper could not tell whether that file changed.
- One scan of the worktree produces HEAD's commit id, the content digest and the manifest. A
  command scans once, and a turn scans twice, before and after the reviewer runs, since those are
  two observations.

### The patches

- A turn's `start.patch` holds only the paths whose content changed since the previous turn's
  start, which the two manifests name. The first turn's patch runs from the commit's bytes to the
  start.
  - The commit's bytes are its blobs as stored, which no later attribute or filter setting
    changes. So a rebuild of a turn writes the same files whenever it runs.
  - The first patch therefore holds every path whose bytes on disk differ from its blob, as when
    a checkout converted line endings, and every path that exists on only one side. The helper
    computes each file's blob id from its bytes, as `git hash-object --no-filters` does, and
    compares it with the commit's tree.
- The helper copies each changed path's earlier and current content into a temporary directory,
  then runs one `git diff --no-index` there.
  - The earlier content comes from the previous turn's rebuilt start, or from the commit's blob,
    with `git cat-file blob`.
  - The current content must match its hash in the turn's manifest, so a file edited after the scan
    cannot enter the patch.
  - Untracked files need no index, and the user's index is never read for it or written.
- The diff and every `git apply` run outside the repository, with no system or global Git
  configuration (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`) beyond the helper's own
  settings ("Git as it is called", below).
  - The diff also takes `--no-ext-diff`, `--no-textconv` and `--no-renames`, and `git apply` takes
    `--whitespace=nowarn`.
  - So no diff driver, textconv, attribute or whitespace setting of the user's changes what a patch
    stores or what a rebuild writes. Outside a repository, `git diff --no-index` reads no
    `.gitattributes`.
- The patches leave out two kinds of path, which the manifest still hashes:
  - a binary file, as Git's content check decides, which appears only as "Binary files … differ".
    A rebuild finds those paths with `git apply --numstat` and excludes them. A later patch that
    holds the file whole, as after the file becomes text, brings it back;
  - a file inside a nested repository or submodule, since the superproject's commit holds only the
    nested repository's commit id, and the superproject lacks that commit's objects. A file that
    becomes, or becomes part of, a nested repository enters the patch as deleted, and one that
    stops being one as added.
- The patches, not Git refs, hold each turn's start. With refs:
  - refs and objects in the user's `.git` would be the helper's only writes to the user's
    repository;
  - a linked worktree, whose Git directory is read-only, could hold none;
  - `delete` would have to remove the refs, and objects would stay until a garbage collection;
  - `--mirror` would copy the refs;
  - the review's storage would depend on Git, which another version control system lacks.

### Git as it is called

- Every `git` call takes the helper's own settings, one list in its code, through
  `GIT_CONFIG_COUNT`. Those settings rank above the repository's configuration, as `git -c` does.
  - The list fixes the settings that shape the output the helper parses, such as `core.quotePath`.
  - A call inside the repository still reads the user's configuration for what the list leaves
    alone, such as `core.excludesFile`, which decides the untracked files that `ls-files` lists.
- An option that no setting replaces, such as `--no-textconv`, stays on the command line.
- The `git` calls sit in one Scala file with no ko-review types, as the calls into the C library
  do ("The helper's language", below). The file can move into a library without the helper.

### The coordinator's record

Each turn's `request.json` records the session that ran its command, from what that session's tool
exports. A fact that the environment does not give stays absent; the helper guesses nothing.

- Claude Code: `CLAUDE_CODE_SESSION_ID`, the version that `$CLAUDE_CODE_EXECPATH --version` prints,
  and `CLAUDE_EFFORT`.
  - `CLAUDE_CODE_EXECPATH` is undocumented, and was measured on the native install alone, where it
    names `claude`. The helper takes the output as the version only when it names Claude Code, so
    another program's version, such as Node's under an npm install, is never recorded. A program
    that does not start leaves the version absent.
  - Measured with Claude Code 2.1.325: `CLAUDE_EFFORT` followed `/effort low` and `/effort high`
    within one session.
- Codex: `CODEX_THREAD_ID` and `CODEX_VERSION`.
  - Measured with codex-cli 0.169.0: Codex exports neither the model nor the effort, and a switch
    with `/model` changed no variable but `CODEX_TOOL_CALL_ID`. `codex --version` on the PATH may
    not be the running Codex, so the helper does not ask it.
- Neither tool exports its model, so the record has none.
- Each turn records its own coordinator, since any session can continue a review by its id.
- The record names the coordinator, not the author: nothing tells the helper who wrote the
  change. In one review of this repository, Codex coordinated a change that Claude Code wrote.

### The helper's language

- The helper is Scala 3, as the rest of this repository is. Its record classes with circe codecs
  define the stored format in code that the compiler checks.
- A JVM's startup costs nothing that matters here: the launcher's `--help` takes 0.27–0.34s, and a
  reviewer turn takes minutes.
- The cost is a build before the plugin runs, which a script would not need. The plugin is meant to
  move to a repository of its own, which builds its jar the same way.
- The calls into the C library sit in one object with no ko-review types: the reviewer's process
  group, `killpg`, Linux's child subreaper and the reaping of adopted orphans. The object can
  move into a library without the helper.
  - The JVM cannot set a child's process group between fork and exec. So the group's leader and
    the reviewer start as `JoinGroup`, a program of that object's, which joins the group and then
    becomes the command.
- A native image would remove the JVM and the wrapper, at one build per platform (`TODO.md`).

### Defaults

`defaults REVIEWER` reports these values:

- `model` and `effort`, as the reviewer's local configuration sets them, each with its `source`;
- a `catalog` of the models to offer, with each model's efforts;
- `recommended`, the pair the reviewer would use.

A value that nothing sets stays null, which stands for the reviewer's built-in default. The skill
leaves that default to the reviewer by passing no option.

- `defaults` marks its output `partial`, because a layer that the reviewer ranks above its files
  is not on disk. So the skill passes each chosen value explicitly, rather than relying on the
  default it displayed.
- The skill recommends no model.
- The skill recommends `high` as the effort when the configuration sets none, ahead of the model's
  own default. That default is `low` for the current Codex models.
  - A configured effort stays first, since the user set it knowing the usage limit it spends.
  - Measured on 2026-10-13: Codex `gpt-6.1-sol` reviewed one tree once per level, with the
    reviewer prompt of 2026-10-13. The tree was the microphone plan as it stood during its review
    of 2026-10-09, in a clone.
    - `low`: 6 commands, 3 web searches, 46s, approved with no finding.
    - `high`: 12 commands, 9 web searches, 210s, two material findings the plan had not
      answered (`doc/mic.md`, "The controller and the writer", records both).
    - Neither level found the PulseAudio option that does not exist, which a review outside the
      sandbox found. The five rounds of 2026-10-09 at `low` ran one to four commands each.

For Codex:

- The helper reads the configuration in Codex's precedence: the project's `.codex/config.toml`
  when the user configuration trusts the project, then the user's, then the image's system layer.
  - The catalog comes from `codex debug models`.
  - The layer not on disk is the cloud-managed one.
  - A linked worktree without its own trust entry takes its main checkout's, as Codex does. The
    exception is Git metadata that Codex refuses: a copy that the registration does not name, a
    symlink, or a metadata file over 64 KiB. Git itself follows all three.
- The catalog holds the models that Codex's `/model` picker offers, those that
  `codex debug models` marks `"visibility": "list"`.
  - The catalog sorts the models by their `priority`, as Codex sorts the list its picker shows and
    takes its default model from.
  - A configured model that the picker omits still gets its efforts in `recommended`.
- `recommended` holds the configured model, else the catalog's first, which Codex takes as its
  default. `recommended.effort` is the configured effort, else that model's default in the
  catalog.
  - With an API key rather than a ChatGPT sign-in, Codex also leaves out the models that are not
    `supported_in_api`, and the catalog keeps them. In the catalog measured with codex-cli 0.156.1,
    every model is supported.
- The skill offers `recommended.model` first, and `recommended.effort` first when the configuration
  set it. The skill labels both values as the picker does: "(current)" when the configuration set
  the value, "(default)" otherwise.
- For a retiring model, `recommended.upgrade` names the model that its catalog `upgrade` field
  recommends. The skill offers that model second.

For Claude:

- The defaults are what the reviewer's session reads, not what the coordinator's session reads. The
  reviewer's session loads no user, project or local settings file ("Claude Code as it is called",
  below), so a model saved with `/model` selects nothing.
  - Model: `ANTHROPIC_MODEL`, else the managed `model`, else `ANTHROPIC_DEFAULT_MODEL`.
  - Effort: `CLAUDE_CODE_EFFORT_LEVEL`, else the managed top-level `effortLevel`.
  - A managed `env` block's value overrides the inherited variable, as Claude Code applies it. An
    empty value unsets the variable.
  - The managed files are `managed-settings.json` and `managed-settings.d/*.json` in
    `/etc/claude-code`, or on macOS in `/Library/Application Support/ClaudeCode`. A drop-in
    overrides the main file, and a later drop-in in alphabetical order overrides an earlier one.
  - Not on disk: server-managed settings and a role's effort cap.
- The helper does not resolve managed `modelSettings`, an effort per model under Claude Code's
  canonical model names. Where a managed file holds them, the effort stays null rather than
  guessed.
- Claude Code has no command that renders its model list. So the catalog is the four aliases that
  its documentation names, with the efforts that its table gives the models they name on the
  Anthropic API (code.claude.com/docs/en/model-config):
  - `low`, `medium`, `high`, `xhigh` and `max` for `fable`, `opus` and `sonnet`;
  - none for `haiku`.
- The catalog states no default effort, which varies by model.
- For a model outside the catalog, such as a full model name, `efforts` is null, which stands for
  unknown.
  - Claude Code lowers a level that the model does not support to the highest level it does
    support. So the review records the requested effort.

### The reviewer prompt

`prompts/reviewer.md` is the default for every review. The prompt does these things:

- asks for skepticism toward the author's claims;
- tells the reviewer not to run tests or builds, but to read the tests and judge what they prove;
- limits findings to material issues, and asks for suggestions beside them ("The cycle", step 2).

Further rules of the review:

- Findings are `F1`, `F2`, …, and suggestions `S1`, `S2`, …. An id stays while its item is
  discussed.
- A suggestion that the reviewer keeps after the author's dispute is no ground for
  `USER_DECISION_REQUIRED`, since the coordinator's report shows the suggestion to the user.
- Every turn after the first names two sets of paths:
  - the paths whose content changed since the turn the reviewer last answered, from the turns'
    manifests;
  - the paths that entered the scope without changing, as when HEAD moves under a file, from the
    scope that turn recorded.
- That turn's prompt says the rest of the tree is as the reviewer read it. So a continued review
  after an approval sends the reviewer to the new work first.
- Each turn records the instructions in force, and the transcript shows a change in the turn it
  takes effect.
- Both reviewers also read the repository's own instructions, AGENTS.md or CLAUDE.md, as any
  session in the repository would.

### Codex as it is called

- Codex runs with the repository root as its working directory. `codex exec resume` has no `-C`,
  and both `exec` forms refuse a working directory outside a trusted Git directory.
- Codex is not sandboxed a second time.
  - Codex's Linux sandbox cannot set up under podman's masked `/proc` (the Containerfile has the
    measurement). So the image sets `danger-full-access`, and the reviewer prompt tells Codex not
    to write.
  - The check after each turn enforces that rule for files, and the container stays the boundary.
- The helper does not use native `codex exec review`. That command starts a fresh reviewer each
  time, so a fix could not be re-reviewed with the earlier debate in context.
  - openai/codex-plugin-cc #375 found the same and fell back to ordinary turns.
- `codex mcp-server` resolves `codex-reply` threads only in the live server's memory
  (openai/codex #24833).
- `codex app-server` would add JSON-RPC lifecycle handling for no gain over `codex exec`.
- A persistent review primitive from Codex would replace the helper's Codex transport alone. The
  content binding, the turn records and the retries serve Claude reviews the same way.
- Measured with codex-cli 0.155.1:
  - `exec` and `exec resume` both accept `--json`, `--output-schema` and `--output-last-message`;
  - the resumed turn emits the persisted id and answers from the earlier turn's context;
  - a made-up id fails with `no rollout found for thread id`, rather than opening a new thread
    (openai/codex #15539, closed).
- Measured with codex-cli 0.156.1 on a real usage limit: `codex exec resume` exits with status 1.
  Two of its events hold Codex's text, "You’ve hit your usage limit. … try again at" and the reset
  time:
  - an `error` event, in its `message`;
  - a `turn.failed` event, in its `error.message`.
- Measured with codex-cli 0.162.1: `codex exec` run with `CODEX_THREAD_ID` in its environment opens
  a thread of its own. A Codex coordinator's shell sets that variable.
  - So a Codex coordinator's Codex reviewer never resumes the coordinator's thread.
  - The helper records the variable as the coordinator's session id only.

### Claude Code as it is called

The reviewer runs as `claude -p --output-format stream-json --verbose --json-schema <the schema>`,
with the prompt on stdin, and resumes with `--resume <session id>`. The result is the `result`
event's `structured_output`. The helper keeps that result in the turn's `outcome.json`, as it keeps
Codex's final message.

- The helper does not pass `--bare`, because `--bare` accepts only an API key, and the sandbox's
  sign-in is a claude.ai login. So the session runs under the managed settings, the image's
  plugins and the project's CLAUDE.md, with these options:
  - `--setting-sources ""`: no user, project or local settings file;
  - `--disable-slash-commands`;
  - `--strict-mcp-config`: no MCP server, so no connector that a `claude.ai` login would otherwise
    load.
- The helper passes `--tools Bash,Read,Grep,Glob,WebFetch,WebSearch` with
  `--permission-prompts none`, which denies every tool call that a permission prompt would gate.
  `--allowedTools` admits the git read commands and the web tools.
  - On a host with the default permission mode, the reviewer can therefore only read.
  - Under the image's managed `bypassPermissions`, nothing prompts, and the check after each turn
    is the enforcement, as for Codex.
- The failure is in the result object, not in the exit status. An API error can end a print-mode
  run with exit status 0, `is_error` true and the error text in `result`
  (anthropics/claude-code #79500).
  - The helper treats a `result` event with `is_error`, or with a `subtype` other than `success`,
    as the turn's failure. The event's `errors` or `result` text become the reviewer's words.
- `CLAUDE_CODE_EFFORT_LEVEL` overrides `--effort` (code.claude.com/docs/en/env-vars). So the
  helper sets the variable to the chosen effort in the reviewer's environment, on `start` and on
  every resumed turn.
  - A managed `env` block would replace the variable. So `start` refuses an effort other than the
    one such a block sets, with `REVIEWER_CHOICE_REFUSED`.
- The reviewer session counts against the usage of this workspace's Claude Code sign-in, as a
  Claude coordinator does.
- The reviewer's transcript is written to `~/.claude/projects/` like any session's, where
  `claude --resume` can open it.
- Measured with Claude Code 2.1.283 in a session of the image, with a claude.ai sign-in:
  - a nested `claude -p` runs from Claude Code's Bash tool;
  - `--resume` of the print-mode session answers from the earlier turn's context and returns the
    same `session_id`;
  - `--resume` of an unknown id exits 1 with `No conversation found with session ID`;
  - `--json-schema` returns the parsed object in `structured_output`;
  - `--bare` fails with `Not logged in · Please run /login` and `is_error` true at exit status 0;
  - `stream-json` without `--verbose` is refused.


## Tests

The subproject's munit suites run the helper's command line in their own JVM, through `Main.run`
with a test's `CommandContext`, against a fake reviewer: a test program installed as both `codex`
and `claude` on `PATH` that imitates each CLI's events. A test that signals the helper, or runs it
beside another command, starts the helper as a process of its own.

- The suites fork a JVM and run one at a time, for the reasons in `../build.sbt`. So they run in a
  session container or on a host outside the run-on-host sandbox, which refuses a forked JVM.
- The tests cover thread continuity and mismatch, every failure class, the digest over each kind
  of change, the base range, the coverage of an earlier approval and the changed paths each turn
  names, the transcript, the lock, the limit of answered turns, escalation, state namespacing,
  the deletion of old reviews at `start`, a linked worktree whose main Git directory is read-only,
  and the coordinator that each turn records.
- `PatchesTest` rebuilds turns: line-ending conversion, the user's Git configuration, a binary
  file that changes, symlinks, executable bits and deletions.
- `ReviewFilesTest` reads the samples of every format version, and fails when the classes change
  without a new format version and its samples.
- Tests that call the helper's code directly cover cases that a fake reviewer cannot force: event
  streaming with a timeout action paused into the cleanup, with an interrupt raised inside it,
  with a failing reader, and with a turn that fails while the reviewer runs; and a child whose
  command name is not UTF-8.
- Claude's own tests cover its command line, the effort variable in its environment, the effort
  that a managed `env` block sets, and the sources of its defaults.
- `PluginTest` runs `claude plugin validate` on the assembled plugin when `claude` is on `PATH`.
  With `codex` on `PATH`, it has `codex debug prompt-input`, which calls no model, list a copy of
  the skill, and fails unless Codex names the skill `ko-review`.
- Inside the image, the launcher's `KoReviewTest` checks that the installed copy is readable, that
  Codex's copy equals the plugin's, that `/usr/local/bin/ko-review` resolves to the helper, and
  that the helper runs with the jars that the image fetched.
- A regression test for a fix counts only after a run against the helper without the fix shows the
  test failing.
  - The fake reviewer exits on its own once the helper exits. So a test for an orphaned reviewer
    passes without the fix, and only that run shows the gap.
- A run against a real reviewer spends model quota, so it is done by hand.
- Measured with Claude Code 2.1.325 as the coordinator and codex-cli 0.169.0 as the reviewer in a
  session of the image (2026-11-15): the skill drove a Codex review of the helper's own rewrite on
  one thread through four turns to approval, with findings fixed between them. The first three
  turns ran the assembled helper, and the fourth the image's installed copy.
- Measured with codex-cli 0.169.0 as the coordinator and Claude Code 2.1.325 as the reviewer in a
  session of the image (2026-11-15): `$ko-review` asked for the reviewer, model and effort in
  replies, then ran a Claude Opus 5.5 review at high effort to approval. Claude Code 2.1.325 then
  coordinated three more turns on the same thread, and each recorded its coordinator.
  - The first two turns predate the coordinator record. Codex's version comes from that session's
    banner and its `CODEX_VERSION`.
