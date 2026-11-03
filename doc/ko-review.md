# Independent review from Claude Code or Codex

`/ko-review` asks a separate Codex or Claude Code session, the reviewer, to review the working
tree. The user chooses the reviewer.

- The author, the session that made the changes, fixes or disputes each finding on the same
  reviewer thread.
- The cycle ends when the reviewer approves the exact tree, or when the reviewer asks for a
  decision only the user can make.
- The reviewer's suggestions never block approval ("The cycle", step 2).

Each new review has its own reviewer thread, and so audits the scope independently.

- Before the skill opens a new review, the skill offers to continue an approved review whose
  approval still covers part of the scope (`approvals`, below).
- The skill makes no such offer when the argument names instructions, or a reviewer, model or
  effort, that a continuation would not keep.
- When such a review already approves the current tree, the skill asks whether to stop or to open
  a new review, such as one with a stronger model or a higher effort.

Who starts a review, and how:

- A Claude session that reviews another Claude session's changes has its own thread and none of
  the author's context. The same applies to Codex.
- A review starts only at the user's request: `/ko-review`, `$ko-review` in Codex, or a request in
  words ("ko-review the changes since the last review with Claude"). The sandbox's
  `AGENTS-SANDBOX.md` has the author offer a review after a non-trivial change.
  - The skill has the plugin's name, `ko-review`. Claude Code lists a plugin skill as
    `/ko-review:ko-review`, and also runs it by its bare name, `/ko-review`, which no other command
    has.
    - A skill named `review` would have the bare name `/review`, which is a built-in alias of
      `/code-review`.
    - Codex lists its copy without a plugin prefix, so a Codex user types `$ko-review`.
  - The skill's description tells the author to invoke the skill only on such a request. Nothing
    enforces that rule.
    - Claude Code's `disable-model-invocation` or Codex's `allow_implicit_invocation: false` would
      enforce the rule, but each setting also stops the author from acting on a request in words.
- A base commit or branch in the skill's argument becomes `--base` (below).
  - `/ko-review HEAD~1` reviews the last commit and whatever is uncommitted.
  - `/ko-review main` reviews whatever differs from `main`.
- A reviewer of the author's product uses the sign-in of the author's session. A reviewer of the
  other product needs its own sign-in in this workspace's sandbox (`REVIEWER_AUTH_FAILED`, below).
- The skill asks the user for the reviewer, the model and the effort, offered from
  `ko-review defaults REVIEWER`, unless the argument names them.
  - Codex has no question tool outside Plan mode, so a Codex author asks in its reply. Codex's
    `default_mode_request_user_input` feature is under development and off in codex-cli 0.162.1.

Where the parts are:

- The plugin `ko-review` (`container/ko-agent-sandbox/claude-code/plugins/ko-review`) holds these
  parts:
  - the skill;
  - the helper `ko-review`, whose `start` takes the reviewer's name, so that another reviewer can
    be added under another name;
  - the reviewer prompts and the result schema.
- The image loads the plugin from `/etc/claude-code/plugins` through `CLAUDE_CODE_PLUGIN_DIRS`
  (Claude Code 2.1.280 or later).
  - The helper needs only the reviewer's CLI, `git` and Python 3, so
    `claude --plugin-dir <the plugin directory>` loads the plugin on a host too.
- Codex reads a copy of the skill from `/etc/codex/skills`, its admin scope, and runs the helper
  through the helper's link in `/usr/local/bin`. The Containerfile explains why.
  - On a host, a copy of the skill directory in `~/.agents/skills` and the plugin's `bin/` on PATH
    do the same.
- The working directory must be inside a Git working tree. Elsewhere, `start` fails with
  `NOT_A_GIT_REPOSITORY` before the reviewer runs.
  - The error message gives the `git init` and the empty `git commit` that make a working tree.
    These commands leave every file uncommitted, and so in the review's scope.


## The cycle

1. The author starts the review with a summary of the work.
   - The author first re-reads every changed hunk against `AGENTS.md`, with the unchanged lines
     around it, and fixes what it finds.
     - The reviewer prompt limits findings to material issues. So conformance to the project's
       instructions is the author's to check, and a round spent on it would cost reviewer quota.
     - Claude Code reads `AGENTS.md` from 2.1.277 on, or through a `CLAUDE.md` import.
   - `ko-review start REVIEWER --message-file FILE` opens a reviewer thread with the reviewer
     prompt and the author's summary. The reviewer reads the repository itself.
   - `--base REF` has the reviewer review the changes since that commit or branch, committed or
     not.
     - The helper records the commit id that the ref resolves to at `start`, so a branch that
       moves during the review does not move the scope.
     - Without `--base`, the reviewer reviews the working tree against HEAD, so work committed
       during the session is out of scope.
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
     every round's prompt. The user's instructions follow the reviewer instructions and take
     precedence over them.
   - `--model` and `--effort` choose the reviewer's model and reasoning effort for every round:
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
     - `USER_DECISION_REQUIRED` and the author's "ask the user to decide" apply that one condition.
       The prompt and the skill state the condition in the same words, and the test suite checks
       them, so that neither side escalates what the other side acts on.
   - The author adopts or disputes every other suggestion rather than relaying it to the user.
     - The reviewer already judges a suggestion worth attention before raising it, and the next
       round reviews what the author adopted.
   - The author's round report names each adopted suggestion that changes an interface or the
     split into components. So the user learns of a design change made on the reviewer's opinion
     without reading the transcript.
   - `continue --instructions-file FILE` sends instructions that the user gives during a review.
     - The new instructions replace the earlier instructions from that round on.
     - The new instructions invalidate the current approval, since the reviewer has not approved
       the tree under them.
4. The review repeats until `APPROVED`, or until `maxRounds` completed rounds end it with
   `LOOP_LIMIT_REACHED`.
   - The default limit is 12; `start REVIEWER --max-rounds` sets another.
   - A request for a user decision ends the review only when the author agrees and runs
     `ko-review escalate REVIEW_ID --message-file FILE`. Otherwise the author argues the point on
     the same thread.
5. Before the author reports an approval, `ko-review check-approval REVIEW_ID` confirms that the
   approval covers the current working tree ("Approval binds to the exact tree", below).

The author reports each round's outcome, and when the review ends, a table of every round and the
command `ko-review transcript REVIEW_ID`.

- The reader of that report needs at most the transcript, whose footer lists the other `inspect`
  lines. `start` deletes a review eight weeks after its last update ("Where the state is").
- The table comes from `ko-review transcript`, since the session's context may have been
  summarized by then.

The author's own model and effort are those of the author's session, set with `/model` or the
launch options.


## Commands

Every command prints one JSON object, except `transcript`, which prints Markdown, and `diff`, which
prints git's output. A command exits 1 when its object contains an `error` field.

- Each summary carries the review id, `snapshots`, `inspect` and `reviewer`.
- A failure carries the review id, `snapshots` and `inspect` when the command had loaded the
  review's state as a JSON object before failing.

The commands:

- `list`: one short entry per review of this checkout, oldest first, which gives the id that the
  other commands take.
  - A review whose state this helper cannot read is listed with the error's code as its
    `effectiveStatus`, so that `delete` can be given its id.
- `digest`: the working-tree digest.
- `show REVIEW_ID`: the review's state.
  - For a round in progress, `show` adds `activity`: the event log's path, the time elapsed, and
    the type and time of the last event received.
  - The event log's path is known as soon as the round starts.
  - The last event says when the reviewer last wrote, not that the reviewer is still working.
- `transcript REVIEW_ID [--round N]`: the transcript as Markdown, one section per round, or the
  named round's section alone.
- `diff REVIEW_ID [--round N] [-- git options]`: the working tree, untracked files included,
  against a round's snapshot. Without `--round`, the round is the approved one, or the last one
  when none is approved.
- `delete REVIEW_ID`: deletes the review's state and its refs, whatever `schemaVersion` its state
  has. The author runs `delete` on the user's request only.
  - Git removes the tag and tree objects that nothing else points to at a later garbage
    collection.
- `defaults REVIEWER`: the model and effort that the reviewer's local configuration selects for
  this repository, the models to offer with each model's efforts, and the `recommended` pair
  ("Defaults", below).
- `approvals [--base REF]`: the approved reviews whose approval still covers part of the scope that
  a `start` with that base would have, newest approval first.
  - Each entry has `coveredPaths` and `newPaths`, so that the skill can offer to continue a review
    instead of opening a thread.
  - A path is covered when two conditions hold:
    - the approved round's reviewer was told to look at the path, by the approved tree against
      the review's base or against the HEAD of that round;
    - the path's content is the one in that round's manifest.
  - Content decides, so staging or committing the approved paths keeps them covered.
  - A path that no reviewer was told to look at is not covered, however long its content has been
    the approved one, as when HEAD moves under an untouched file.
  - A candidate has the same base as the new review would have, and a snapshot tree. An approval
    without a snapshot tree, as in a linked worktree, is never offered.

The helper never commits, stages or moves HEAD. The author's fixes during a review are
working-tree edits like any other, and the user commits them when and as they choose.


## What the helper guarantees

- **The same thread.** Every round of a review runs on the reviewer thread that its first round
  opened. A resumed turn that names another thread fails with `REVIEWER_RESUME_MISMATCH`.
  - The thread id is the id that the reviewer's first event names. The helper persists the id the
    moment the event arrives:
    - Codex: the `thread.started` event's `thread_id`, resumed with `codex exec resume <that id>`;
    - Claude Code: the `system` `init` event's `session_id`, resumed with
      `claude -p --resume <that id>`.
  - The author never chooses a thread, and nothing uses `--last` or `--continue`.
- **Approval binds to the exact tree.** After any change since the approval, `check-approval` fails
  with `NOT_APPROVED` and the `effectiveStatus` `STALE_APPROVAL`. The error's `staleReasons` says
  what changed, and `continue` obtains a new approval.
  - The digest covers HEAD, the index and every file's raw content ("The digest", below).
  - When the approved round has a snapshot, staging or committing the approved changes keeps the
    approval, a staged deletion or rename included.
    - The digest moves, but the content digest recorded with the approval still matches.
    - The index, written as a tree, equals the approved snapshot's tree. Unreviewed staged content
      fails this second check.
    - A changed HEAD alone is then never a reason.
  - Without a snapshot, as in a linked worktree ("Each round's tree and transcript are kept in
    Git", below), a changed HEAD or index makes the approval stale, even when every
    file's content is the approved one.
  - `staleReasons`, in `show` and in `check-approval`'s error, gives these reasons:
    - "working files changed", with the paths, from the manifest of hashes that the round saved
      beside its snapshot;
    - "unreviewed content staged", with the paths;
    - HEAD or the index changed, and the round has no snapshot;
    - the index could not be compared;
    - the instructions changed after the approval.
- **Each round's tree and transcript are kept in Git**, under
  `refs/ko-review/<review id>/round-NNN`, without touching the user's index, HEAD or files.
  - The ref points at a tag object. The tag object's message is the round's transcript: the
    author's message, and the reviewer's result or the error.
  - The tag object points at the tree of the working tree as reviewed.
  - `git for-each-ref --format='%(contents)' <ref>` prints the transcript alone. `git show`
    follows the transcript with a listing of the tree's top level.
  - `git diff` between two rounds' refs shows what the author changed in response to a finding.
  - `ko-review diff` compares the current tree with a round, because `git diff <tree>` alone reads
    the user's index and reports every untracked file as deleted.
  - `git for-each-ref` lists the refs; `git tag`, `git branch` and `git log` do not:

    ```sh
    git for-each-ref --format='%(objecttype) %(objectname:short) %(refname)' refs/ko-review/
    ```

  - A clone or push copies the refs only when it names them, as `--mirror` does.
  - A tree holds a submodule or nested repository as a commit id, not as its working tree. The
    snapshot names those paths in `excludes`, and the digest alone covers their contents.
  - In a linked worktree, whose Git directory is read-only, the round records no snapshot, and the
    digest alone binds the round.
  - When the transcript cannot be written, the tree stays on the ref, and the snapshot's
    `transcriptError` holds the diagnostic.
- **A change to the tree during a turn discards the turn's result.** The helper takes the digest
  before and after the reviewer runs. A difference fails with `WORKTREE_CHANGED_DURING_REVIEW`,
  with the paths.
  - Nothing is reverted.
  - The helper does not say who changed the tree: a host editor, another session or the reviewer
    itself may have.
- **Failures are never outcomes.** A failed turn leaves `status` at the previous outcome, and
  records the failure in `lastError` and the journal.
  - A `continue` retries on the same thread once the reviewer has named a thread. When the failure
    came before that, the `continue` opens a thread.
  - The helper persists the thread id the moment the reviewer names it. So the retry resumes that
    thread, whatever ends the turn after that: a timeout, an interrupt or termination signal,
    unparsable later output, or a helper bug (`HELPER_FAILED`).
  - The retry's prompt carries again every author message since the last round the reviewer
    answered, oldest first and as written. A failed turn may not have left its message in the
    thread.
  - Before any round has completed, the retry sends the reviewer prompt again.
  - A round that ends in an error does not count toward `maxRounds`, so retries after a usage
    limit do not use up the review.
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
      the reviewer's hosts, as when the launch admitted the author's provider alone. Relaunch with
      `--model-provider` naming both providers, such as `--model-provider=anthropic,openai`.
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
- **One mutation per review at a time.** `start`, `continue`, `escalate` and `delete` take `flock`
  on the review's lock file before reading the state they act on.
  - A second such command fails at once with `REVIEW_LOCKED`, instead of waiting behind a reviewer
    turn.
  - The helper replaces `state.json` atomically, so `show` and `list` read it without a lock.


## Where the state is

The state directory:

```text
$HOME/persistent-volume/ko-review/repositories/<sha256 of the checkout path>/
├── repository.json          the unhashed path
└── reviews/<review id>/
    ├── state.json           reviewer, status, round, thread id, reviewed and approved digests
    ├── journal.jsonl        every author message, reviewer result, escalation and error
    ├── review.lock
    └── rounds/NNN-{input.md,manifest.json,<reviewer>.jsonl,<reviewer>.stderr,result.json}
```

The repository's own Git directory holds `refs/ko-review/<review id>/round-NNN` for each round's
transcript and tree. `delete` removes those refs together with the review's directory above.

- `start` deletes the checkout's reviews whose last update, `updatedAt`, is 56 days old or more.
  `start` deletes their state and refs as `delete` does, and names them in its output's
  `expiredReviews`.
  - A review that `start` cannot delete, as under a read-only Git directory, is in
    `expiryFailures` with the error. The new review starts regardless.
  - A review that another command holds stays, silently.
  - For a state that the helper cannot read, the start minute in the id counts as the last update.
- A review id is its local start minute, `2026-09-24-1005-`, plus eight hex digits.
  - The state directory and the refs group reviews by start minute, in an arbitrary order within
    one minute.
  - The id can be typed.
- State is namespaced by checkout path, because a review is about one checkout. A persistent
  volume can be shared by several workspaces (`--persistent-volume`), or by a main worktree and its
  linked worktrees.
- The reviewers' own session files stay in `~/.codex` and `~/.claude`. Sharing them is safe,
  because every continuation names its thread id.
- `--reset` removes the workspace's own volume, and with it the review state and those session
  files.
  - `--reset` keeps a volume named through `--persistent-volume` and, from a linked worktree, the
    main worktree's volume, each with what it holds (`SECURITY.md`, "What the persistent volume
    holds").
- Outside the sandbox, the state root is `$XDG_STATE_HOME/ko-review`, by default
  `~/.local/state/ko-review`. `KO_REVIEW_STATE` overrides either.


## Why it is built this way

### The digest

- The working-tree digest is SHA-256 over three parts:
  - the HEAD id;
  - every record of
    `git status --porcelain=v2 -z --untracked-files=all --no-renames --ignore-submodules=none`,
    sorted by path, which carries the index's and HEAD's object ids and modes;
  - a content digest.
- The content digest covers every file Git would review, from
  `git ls-files --cached --others --exclude-standard`.
  - Each file contributes its raw content with its executable bit, or its symlink target. An absent
    path contributes nothing.
  - The digest reads raw content because `git status` calls a file clean when its content after
    the clean filter matches the index. The status records alone miss a change that a filter
    strips.
- A submodule or nested repository is digested the same way, as a tree of its own, since its
  status record carries dirty flags, not what changed.
- No `git diff` runs, so no diff or textconv driver shapes the digest.
- One scan of the checkout produces the digest, the content digest and the manifest. A command
  scans once, and a turn scans twice, before and after the reviewer runs, since those are two
  observations.

### The snapshot

- The helper writes the tree and its ref before the reviewer runs, so the ref names what the
  reviewer reviewed.
  - When the round ends, with a result or with an error, the transcript's tag object replaces the
    tree on the ref.
- The scratch index starts as a copy of the entries of the user's index. So the tracked paths are
  the checkout's, staged additions and removals included, whatever the ignore rules say of them.
  - `git add -A` then adds untracked files and leaves ignored files out.
- Each `diff` invocation writes its own scratch index, so overlapping invocations do not disturb
  each other.
- The transcript is a tag object rather than a commit:
  - a tag object on a tree contributes nothing to `git log --all`;
  - each round gets a distinct object even when two rounds' trees are equal. Git notes, keyed by
    the tree id, would merge those rounds.
- The tagger is `ko-review`, since neither the user nor the reviewer wrote the whole message.

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
  - Measured on 2026-10-13 (reviews `2026-10-13-1001-7dc56e66` and `2026-10-13-1001-526190d9`):
    Codex `gpt-6.1-sol` reviewed one tree once per level, with the reviewer prompt of 2026-10-13.
    The tree was round 3 of the 2026-10-09 review, the microphone plan, rebuilt from its snapshot
    in a clone.
    - `low`: 6 commands, 3 web searches, 46 s, approved with no finding.
    - `high`: 12 commands, 9 web searches, 210 s, two material findings the plan had not
      answered (`microphone.md`, "The controller and the writer", records both).
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

- The defaults are what the reviewer's session reads, not what the author's session reads. The
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
  `USER_DECISION_REQUIRED`, since the author's report shows the suggestion to the user.
- Every round after the first names two sets of paths:
  - the paths whose content changed since the round the reviewer last answered, from the rounds'
    manifests;
  - the paths that entered the scope without changing, as when HEAD moves under a file, from that
    round's snapshot tree.
- That round's prompt says the rest of the tree is as the reviewer read it. So a continued review
  after an approval sends the reviewer to the new work first.
- The journal records an instruction change in the round it takes effect, and the transcript shows
  the change there.
- Both reviewers also read the repository's own instructions, AGENTS.md or CLAUDE.md, as any
  session in the repository would.

### Codex as it is called

- Codex runs with the repository root as its working directory. `codex exec resume` has no `-C`,
  and both `exec` forms refuse a working directory outside a trusted Git directory.
- Codex is not sandboxed a second time.
  - Codex's Linux sandbox cannot set up under podman's masked `/proc` (the Containerfile has the
    measurement). So the image sets `danger-full-access`, and the reviewer prompt tells Codex not
    to write.
  - The digest check enforces that rule, and the container stays the boundary.
- The helper does not use native `codex exec review`. That command starts a fresh reviewer each
  time, so a fix could not be re-reviewed with the earlier debate in context.
  - openai/codex-plugin-cc #375 found the same and fell back to ordinary turns.
- `codex mcp-server` resolves `codex-reply` threads only in the live server's memory
  (openai/codex #24833).
- `codex app-server` would add JSON-RPC lifecycle handling for no gain over `codex exec`.
- A persistent review primitive from Codex would replace the helper's Codex transport alone. The
  digest binding, the snapshots and the retries serve Claude reviews the same way.
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
  a thread of its own. A Codex author's shell sets that variable.
  - So a Codex author's Codex reviewer never resumes the author's thread.
  - The helper records the variable as `authorSessionId` only.

### Claude Code as it is called

The reviewer runs as `claude -p --output-format stream-json --verbose --json-schema <the schema>`,
with the prompt on stdin, and resumes with `--resume <session id>`. The result is the `result`
event's `structured_output`. The helper keeps that result in the round's `result.json`, as the
helper keeps Codex's final message.

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
  - Under the image's managed `bypassPermissions`, nothing prompts, and the digest check is the
    enforcement, as for Codex.
- The failure is in the result object, not in the exit status. An API error can end a print-mode
  run with exit status 0, `is_error` true and the error text in `result`
  (anthropics/claude-code #79500).
  - The helper treats a `result` event with `is_error`, or with a `subtype` other than `success`,
    as the turn's failure. The event's `errors` or `result` text become the reviewer's words.
- `CLAUDE_CODE_EFFORT_LEVEL` overrides `--effort` (code.claude.com/docs/en/env-vars). So the
  helper sets the variable to the chosen effort in the reviewer's environment, on `start` and on
  every resumed round.
  - A managed `env` block would replace the variable. So `start` refuses an effort other than the
    one such a block sets, with `REVIEWER_CHOICE_REFUSED`.
- The reviewer session counts against the usage of this workspace's Claude Code sign-in, as a
  Claude author does.
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

`src/test/python/ko_review_test.py`, which `KoReviewTest` runs on Linux, drives the helper against
one fake script. The fake is installed as both `codex` and `claude` on `PATH`, and imitates each
CLI's events.

- The tests cover thread continuity and mismatch, every failure class, the digest over each kind
  of change, the snapshot refs and their absence under a read-only Git directory, the base range,
  the coverage of an earlier approval and the changed paths each round names, the transcript, the
  lock, the round limit, escalation, state namespacing, and the deletion of old reviews at `start`.
- The tests marked `both_reviewers` run against each fake. The rest test the helper's own logic,
  and run against the fake Codex only.
- Tests in the test's own process load the helper as a module, for cases that a fake reviewer
  cannot force:
  - `stream_events` with a timeout callback paused into the cleanup, with an interrupt raised
    inside it, and with a failing reader;
  - `children_of` with a child whose command name is not UTF-8.
- Claude's own tests cover its command line, the effort variable in its environment, the effort
  that a managed `env` block sets, and the sources of its defaults.
- `KoReviewTest` also runs `claude plugin validate` on the plugin when `claude` is on `PATH`.
  Inside the image, `KoReviewTest` checks that the installed copy is readable.
- With `codex` on `PATH`, `KoReviewTest` has `codex debug prompt-input`, which calls no model, list
  a copy of the skill. The test fails unless Codex names the skill `ko-review`.
- Inside the image, `KoReviewTest` checks that Codex's copy equals the plugin's, and that
  `/usr/local/bin/ko-review` resolves to the helper.
- A regression test for a fix counts only after a run against the helper without the fix shows the
  test failing.
  - The fake reviewer exits on its own once the helper exits. So a test for an orphaned reviewer
    passes without the fix, and only that run shows the gap.
- A run against a real reviewer spends model quota, so it is done by hand.
- Measured with codex-cli 0.156.1 in a session of the image: the skill in Claude Code drove a Codex
  review to an approval on one thread, through fixes, re-reviews and a retry after a usage limit.
  A second invocation opened a new thread.
- Measured with Codex 0.157.1 as the author and Claude Code 2.1.284 as the reviewer in the
  image: `$ko-review` asked for the reviewer, model and effort in replies, then ran a Claude
  Fable review at high effort to approval. `check-approval` confirmed that the approval covered the
  working tree.
