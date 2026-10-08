# Independent review from Claude Code or Codex

`/ko-review` asks a separate Codex or Claude Code session to review the working tree. The user
chooses the reviewer. The author — the session that made the changes — fixes or disputes each
finding on the same reviewer thread until the reviewer approves the exact tree or asks for a
decision only the user can make.

Each new review has its own reviewer thread. Invoke the skill without an existing review id to
start an independent audit of an approved tree.

- The author and reviewer may use the same product. A Claude session reviewing another Claude
  session's changes has its own thread and none of the author's context; the same applies to Codex.
- A review starts only at the user's request, as `/ko-review`, `$ko-review` in Codex, or in words
  ("ko-review the changes since the last review with Claude"); the sandbox's `AGENTS-SANDBOX.md`
  has the author offer it after a non-trivial change.
  - The skill has the plugin's name, `ko-review`. Claude Code lists a plugin skill as
    `/ko-review:ko-review` and also runs it by its bare name, `/ko-review`, which no other command
    has; named `review`, its bare name would be `/review`, a built-in alias of `/code-review`.
    Codex lists its copy without a plugin prefix, so the skill's name is what a Codex user types,
    `$ko-review`.
  - The skill's description tells the author to invoke it only on such a request. Nothing enforces
    that: Claude Code's `disable-model-invocation` or Codex's `allow_implicit_invocation: false`
    would, but each also stops the author acting on a request in words.
  - Invoked by the author, the skill's argument holds only a reviewer, base, review id, model,
    effort or instructions the user named, and the author first says it invoked the skill, quoting
    the request. Codex passes a skill no argument, so the skill takes the text after `$ko-review`
    in the user's message as one.
- A base commit or branch in the skill's argument becomes `--base` (below): `/ko-review HEAD~1`
  reviews the last commit and whatever is uncommitted, `/ko-review main` whatever differs from
  `main`.
- A reviewer of the author's product uses the sign-in the author's session has; the other
  product's needs its own in this project's sandbox (`REVIEWER_AUTH_FAILED`, below).
- The skill asks three questions before a new review, each skipped when the argument answers it:
  the reviewer, then, from `ko-review defaults REVIEWER`, the model and the effort. Codex has no
  question tool outside Plan mode (its `default_mode_request_user_input` feature is off in
  codex-cli 0.159.0), so a Codex author asks in its reply and waits for the answer.
- The plugin `ko-review` (`container/ko-agent-sandbox/claude-code/plugins/ko-review`) holds the
  skill, the helper `ko-review`, whose `start` takes the reviewer's name so that another reviewer
  can join as another name, the reviewer prompts and the result schema.
- The image loads it from `/etc/claude-code/plugins` through `CLAUDE_CODE_PLUGIN_DIRS` (Claude Code
  2.1.280 or later). The helper needs only the reviewer's CLI, `git` and Python 3, so
  `claude --plugin-dir <the plugin directory>` loads it on a host too.
- Codex reads a copy of the skill from `/etc/codex/skills`, its admin scope, and runs the helper
  through its link in `/usr/local/bin`; the Containerfile has why. On a host, a copy of the skill
  directory in `~/.agents/skills` and the plugin's `bin/` on PATH do the same.
- The project must be a Git working tree. A `start` elsewhere fails with `NOT_A_GIT_REPOSITORY`
  before the reviewer runs; its message gives the `git init` and empty `git commit` that make one
  while leaving every file uncommitted, and so in the review's scope.


## The cycle

1. The author writes a Markdown summary of the task, its changes and its verification, and runs
   `ko-review start REVIEWER --message-file FILE`, REVIEWER being `codex` or `claude`. The helper
   opens a reviewer thread with the reviewer prompt and that summary; the reviewer reads the
   repository itself.
   - `--base REF` has the reviewer review the changes since that commit or branch, committed since
     then or not, by the commit id the ref resolved to at `start`, so a branch that moves during
     the review does not move the scope. Without it the reviewer reviews the working tree against
     HEAD, so work committed during the session is out of scope.
     - The skill passes a base only from its argument, for the reason its scope paragraph gives.
     - The reviewer compares the working tree with the base's tree, so commits merged or pulled
       since the base are in scope too.
   - An empty scope is refused with `NOTHING_TO_REVIEW` before a review exists: the working tree
     equals the base commit, HEAD without `--base`, and no file is untracked. A dirty checkout
     whose edits restore the base's content counts as empty. A reviewer turn on nothing would
     yield an approval that looks like one of the session's committed work.
   - `--instructions-file FILE` adds the user's own instructions, from the skill's argument, to
     every round's prompt after the reviewer instructions, which they take precedence over.
   - `--model` and `--effort` choose the reviewer's model and reasoning effort for every round:
     `codex exec --model` and the `model_reasoning_effort` configuration key, or `claude --model`
     and `--effort`. The skill asks the user before every `start`, offering first what
     `ko-review defaults REVIEWER` reports ("Defaults", below).
2. The reviewer answers with a structured result: `disposition` `APPROVED`, `CHANGES_REQUESTED` or
   `USER_DECISION_REQUIRED`, a summary, findings with stable ids, and for the user's decision the
   issue, the reviewer's position, why evidence cannot decide it and the decision requested.
3. The author fixes the findings it accepts, disputes the others with evidence, runs the tests, and
   sends both with `ko-review continue REVIEW_ID --message-file FILE` to the same thread.
   - To send instructions the user gives during a review, add `--instructions-file FILE` to
     `continue`. They replace the standing instructions from that round on and invalidate the
     current approval, since the reviewer has not approved the tree under those instructions.
4. The review repeats until `APPROVED` or until `maxRounds` completed rounds end it with
   `LOOP_LIMIT_REACHED`. The default is 12; set another limit with `start REVIEWER --max-rounds`.
   - A request for a user decision ends the review only when the author agrees and runs
     `ko-review escalate REVIEW_ID --message-file FILE`; otherwise the author argues the point
     on the same thread.
5. Before reporting that the reviewer approved the changes, the author runs
   `ko-review verify REVIEW_ID`. It succeeds only when the approval covers the current working tree.

The skill has the author report each round's outcome in a line or two, and, when the review ends, a
table of every round and the `inspect` lines: the commands with which the user sees how the review
went, lists the checkout's reviews and deletes this one. The table comes from `ko-review export`,
since the session's context may have been summarized by then. The author's own model and effort
are its session's, set with `/model` or the launch options; the skill runs in that session.


## Commands

Every command but `export`, which prints Markdown, and `diff`, which prints git's output, prints
one JSON object and exits 1 when it contains an `error` field. Each summary, and each failure after
the command has loaded the review's state as a JSON object, carries the review id, `snapshots` and
`inspect`; a summary also carries `reviewer`.

- `list`: one short entry per review of this checkout, oldest first, for the id the other
  commands take. A review whose state this helper cannot read is listed with the error's code as
  its `effectiveStatus`, so that `delete` can be given its id.
- `digest`: the working-tree digest.
- `show REVIEW_ID`: the review's state. For a round in progress, `show` adds
  `activity`: the event log's path, known as soon as the round starts, the time elapsed, and the
  type and time of the last event received, which says when the reviewer last wrote, not that it
  is still working.
- `export REVIEW_ID [--round N]`: the transcript as Markdown, one section per round, or that
  round's alone.
- `diff REVIEW_ID [--round N] [-- git options]`: the working tree, untracked files included,
  against a round's snapshot; the approved round unless one is named, the last round when none is
  approved.
- `delete REVIEW_ID`: the review's state and its refs, on the user's request only, whatever
  `schemaVersion` its state has. The tag and tree objects nothing else points to become eligible
  for a later garbage collection, which by default keeps recent unreachable objects for two weeks.
- `defaults REVIEWER`: the model and effort the reviewer's local configuration selects for this
  repository, the models to offer with each one's efforts, and the `recommended` pair
  ("Defaults", below).

The helper never commits, stages or moves HEAD: the author's fixes during a review are working-tree
edits like any other, and the user commits them when and as they choose.


## What the helper guarantees

- **The same thread.** Every round of a review runs on the reviewer thread its first round
  opened; a resumed turn that names another thread is `REVIEWER_RESUME_MISMATCH`.
  - The thread id is what the reviewer's first event names, persisted the moment it arrives:
    Codex's `thread.started` event's `thread_id`, resumed with `codex exec resume <that id>`;
    Claude Code's `system` `init` event's `session_id`, resumed with `claude -p --resume <that id>`.
    The author never chooses a thread, and nothing uses `--last` or `--continue`.
- **Approval binds to the exact tree.** Any change after approval makes `verify` fail with
  `NOT_APPROVED`, its `effectiveStatus` `STALE_APPROVAL`, and `staleReasons` says what changed;
  `continue` obtains a new approval.
  - The digest covers HEAD, the index and every file's raw content ("The digest", below).
  - Staging or committing the approved changes keeps the approval when the approved round has a
    snapshot, a staged deletion or rename included: the digest moves, but the content digest
    recorded with the approval still matches and the index, written as a tree, equals the
    approved snapshot's tree. Unreviewed staged content fails that second check. A changed HEAD
    alone is then never a reason.
  - Without a snapshot, as in a linked worktree ("Each round's tree and transcript are kept in
    Git", below), a changed HEAD or index makes the approval stale even when every file's
    content is the approved one.
  - `staleReasons`, in `show` and in `verify`'s error, names "working files changed" with the
    paths, from the manifest of hashes the round saved beside its snapshot; "unreviewed content
    staged" with the paths; that HEAD or the index changed and the round has no snapshot; that
    the index could not be compared; or that the instructions changed after the approval.
- **Each round's tree and transcript are kept in Git**, under
  `refs/ko-review/<review id>/round-NNN`, without touching the user's index, HEAD or files.
  - The ref points at a tag object whose message is the round's transcript, the author's message
    and the reviewer's result or the error; the tag object points at the tree of the working tree
    as reviewed.
  - `git for-each-ref --format='%(contents)' <ref>` prints the transcript alone, since `git show`
    follows it with a listing of the tree's top level.
  - `git diff` between two rounds' refs shows what the author changed in response to a finding.
  - `ko-review diff` compares the current tree with a round, because `git diff <tree>` alone reads
    the user's index and reports every untracked file as deleted.
  - `git tag` and `git branch` do not list the refs, since they read only `refs/tags/` and
    `refs/heads/`, and `git log` does not reach them. `git for-each-ref` lists them:

    ```sh
    git for-each-ref --format='%(objecttype) %(objectname:short) %(refname)' refs/ko-review/
    ```

  - A clone or push leaves the refs and their objects behind unless it names them. `--mirror`
    names every ref: `git push --mirror` sends them to the remote, and `git clone --mirror` copies
    them.
  - A tree holds a submodule or nested repository as a commit id, not its working tree; the
    snapshot names those paths in `excludes`, and the digest alone covers their contents.
  - In a linked worktree, whose Git directory is read-only, the round records no snapshot and the
    digest alone binds it. A transcript that cannot be written leaves the tree on the ref and its
    diagnostic in the snapshot's `transcriptError`.
- **A tree that changes during a turn voids the turn.** The digest is taken before and after the
  reviewer runs; a difference is `WORKTREE_CHANGED_DURING_REVIEW`, with the paths, and the result
  is discarded. Nothing is reverted, and the helper does not say who changed the tree: a host
  editor, another session or the reviewer itself may have.
- **Failures are never outcomes.** A failed turn leaves `status` at the previous outcome and
  records the failure in `lastError` and the journal; a `continue` retries on the same thread
  once the reviewer has named one, and opens a thread when the failure came before that.
  - The thread id is persisted the moment the reviewer names it, so whatever ends the turn after
    that, a timeout, an interrupt or termination signal, unparsable later output or a helper bug
    (`HELPER_FAILED`), the retry resumes that thread.
  - The retry's prompt carries again every author message since the last round the reviewer
    answered, oldest first and as written, since a failed turn may not have left its message in
    the thread. Before any round has completed, the retry sends the reviewer prompt again.
  - A round that ends in an error does not count toward `maxRounds`, so retries after a usage
    limit do not use up the review.
  - Whatever ends the turn, the reviewer's own exit included, the helper kills the reviewer's
    process group and waits for the reviewer before it returns, so neither the reviewer nor a
    process it left in that group runs on past the lock that serialized the turn.
    - On Linux the helper also adopts the reviewer's orphaned descendants for the turn
      (`PR_SET_CHILD_SUBREAPER`) and kills and reaps them until none is left, so a process a tool
      command left in a session of its own does not run on either, and one left holding the
      reviewer's stdout does not hold the turn. On a macOS host, the group is all it kills, and
      such a holder holds the turn until it exits.
  - Every reviewer error's `error` carries `reviewer`, the name the message uses:
    - `REVIEWER_AUTH_FAILED`: `codex login status` or `claude auth status` reports no sign-in,
      whichever credential store the CLI uses; sign in to that CLI in this project's sandbox.
    - `REVIEWER_EGRESS_DENIED`: the ruleset in `KO_AGENT_SANDBOX_EGRESS_RULESET` allows none of
      the reviewer's hosts, `api.openai.com` and `chatgpt.com` for Codex, `api.anthropic.com` and
      `platform.claude.com` for Claude, as under `--egress=deny-unless-model` with the other
      agent; relaunch under the default profile.
    - `REVIEWER_FAILED`: any other failure of the reviewer. When it said why, `message` ends with
      its words, such as a usage limit and when it resets, from its last failure event, else its
      last line of stderr. A thread the reviewer no longer has is also `REVIEWER_FAILED`, and its
      message says to start a new review.
    - `INVALID_RESULT`: the reviewer's final message does not follow the schema exactly; the
      helper validates it before touching state, the CLI's schema option only asks.
    - `TURN_INTERRUPTED`, when a timeout or a signal ended the reviewer. A signal that ended the
      helper itself raises the same code without `reviewer`.
  - The helper never edits the egress rules or a reviewer's configuration.
- **One mutation per review at a time.** `start`, `continue`, `escalate` and `delete` take `flock`
  on the review's lock file before reading the state they act on; a second one fails at once with
  `REVIEW_BUSY` instead of waiting behind a reviewer turn. `state.json` is replaced atomically, so
  `show` and `list` read it without a lock.


## Where the state is

```text
$HOME/persistent-volume/ko-review/repositories/<sha256 of the checkout path>/
├── repository.json          the unhashed path
└── reviews/<review id>/
    ├── state.json           reviewer, status, round, thread id, reviewed and approved digests
    ├── journal.jsonl        every author message, reviewer result, escalation and error
    ├── review.lock
    └── rounds/NNN-{input.md,manifest.json,<reviewer>.jsonl,<reviewer>.stderr,result.json}
```

and, in the repository's own Git directory, `refs/ko-review/<review id>/round-NNN` for each round's
transcript and tree, which `delete` removes with the directory above.

- A review id is its local start minute, `2026-09-24-1005-`, plus eight hex digits: the state
  directory and the refs group by start minute, in an arbitrary order within one, and the id can
  be typed.
- State is namespaced by checkout path because a persistent volume can be shared by several
  projects (`KO_AGENT_SANDBOX_PERSISTENT_VOLUME`) or by a main worktree and its linked worktrees,
  and a review is about one checkout. The reviewers' own session files stay in `~/.codex` and
  `~/.claude`; sharing them is safe because every continuation names its thread id.
- `--reset` removes the project's own volume, and the review state and those session files with
  it. It keeps a volume named through `KO_AGENT_SANDBOX_PERSISTENT_VOLUME` and, from a linked
  worktree, the main worktree's volume, each with what it holds (`SECURITY.md`, "What the
  persistent volume holds").
- Outside the sandbox the state root is `$XDG_STATE_HOME/ko-review`, default
  `~/.local/state/ko-review`; `KO_REVIEW_STATE` overrides either.


## Why it is built this way

### The digest

- The working-tree digest is SHA-256 over the HEAD id, every record of
  `git status --porcelain=v2 -z --untracked-files=all --no-renames --ignore-submodules=none` sorted
  by path, which carries the index's and HEAD's object ids and modes, and a content digest.
- The content digest covers every file Git would review, from
  `git ls-files --cached --others --exclude-standard`, by its raw content with its executable bit
  or its symlink target; an absent path contributes nothing. Raw content, because `git status`
  calls a file clean when its content after the clean filter matches the index, so the status
  records alone miss a change a filter strips.
- A submodule or nested repository is digested the same way as a tree of its own, since its
  status record carries dirty flags, not what changed. No `git diff` runs, so no diff or textconv
  driver shapes the digest.
- The digest, the content digest and the manifest come from one scan of the checkout, made once
  per command, and twice per turn, before and after the reviewer runs, since those are two
  observations.

### The snapshot

- The tree and its ref are written before the reviewer runs, so the ref names what it reviewed;
  the transcript's tag object replaces the tree on the ref when the round ends, with a result or
  with an error.
- The scratch index starts as a copy of the entries of the user's index, so the tracked paths are
  the checkout's, staged additions and removals included, whatever the ignore rules say of them;
  `git add -A` then adds untracked files and leaves ignored ones out. Each `diff` invocation
  writes its own scratch index, so overlapping ones do not disturb each other.
- The transcript is a tag object rather than a commit: a tag object on a tree contributes nothing to
  `git log --all`, and each round gets a distinct object even when two rounds' trees are equal,
  which git notes, keyed by the tree id, would merge. The tagger is `ko-review`, since neither the
  user nor the reviewer wrote the whole message.

### Defaults

`defaults REVIEWER` reports `model` and `effort` as the reviewer's local configuration sets them,
with each one's `source`, a `catalog` of the models to offer with each one's efforts, and
`recommended`, the pair the reviewer would use. A value nothing sets stays null: the reviewer's
built-in default, which the skill leaves to it by passing no option.

- `defaults` is marked `partial`: a layer the reviewer ranks above its files is not on disk, so the
  skill passes each chosen value explicitly rather than relying on the default it displayed.
- The skill recommends no model or effort: nothing measured shows which one finds more in a change,
  and a guess toward higher effort spends more of the reviewer's usage limit.

For Codex:

- The configuration is read in Codex's precedence: the project's `.codex/config.toml` when the
  user configuration trusts the project, then the user's, then the image's system layer; the
  catalog comes from `codex debug models`. The layer not on disk is the cloud-managed one.
  - A linked worktree without its own trust entry takes its main checkout's, as Codex does,
    unless Codex refuses its Git metadata: a copy the registration does not name, a symlink, or
    a metadata file over 64 KiB, all of which Git itself follows.
- The catalog holds the models Codex's `/model` picker offers, those `codex debug models` marks
  `"visibility": "list"`, sorted by their `priority`, as Codex sorts the list its picker shows
  and takes its default model from. A configured model the picker omits still gets its efforts in
  `recommended`.
- `recommended` is the configured model, else the catalog's first, which Codex takes as its
  default, and the configured effort, else that model's default in the catalog.
  - With an API key rather than a ChatGPT sign-in, Codex also leaves out the models not
    `supported_in_api`, and the catalog does not. In the catalog measured with codex-cli 0.156.1,
    every model is supported.
- The skill offers `recommended` first, labeled as the picker labels it: "(current)" when the
  configuration set it, "(default)" otherwise.
- For a retiring model, `recommended.upgrade` names the model its catalog `upgrade` field
  recommends, which the skill offers second.

For Claude:

- The defaults are what the reviewer's session reads, not what the author's does: that session
  loads no user, project or local settings file ("Claude Code as it is called", below), so a
  model saved with `/model` selects nothing.
  - Model: `ANTHROPIC_MODEL`, else the managed `model`, else `ANTHROPIC_DEFAULT_MODEL`.
  - Effort: `CLAUDE_CODE_EFFORT_LEVEL`, else the managed top-level `effortLevel`.
  - A managed `env` block's value overrides the inherited variable, as Claude Code applies it; an
    empty one unsets the variable.
  - Managed files are `managed-settings.json` and `managed-settings.d/*.json` in `/etc/claude-code`,
    on macOS `/Library/Application Support/ClaudeCode`; a drop-in overrides the main file, and a
    later one in alphabetical order an earlier one.
  - Not on disk: server-managed settings and a role's effort cap.
- Managed `modelSettings`, an effort per model under Claude Code's canonical model names, are not
  resolved: where a managed file holds them, the effort stays null rather than guessed.
- Claude Code has no command that renders its model list, so the catalog is the four aliases its
  documentation names, with the efforts its table gives the models they name on the Anthropic API
  (code.claude.com/docs/en/model-config): `low`, `medium`, `high`, `xhigh` and `max` for `fable`,
  `opus` and `sonnet`, none for `haiku`. It states no default effort, which varies by model.
  - For a model outside the catalog, such as a full model name, `efforts` is null: unknown.
    Claude Code lowers a level the model does not support to the highest one it does, so the
    review's recorded effort is the one requested.

### The reviewer prompt

`prompts/reviewer.md` is the default for every review: it asks for skepticism toward the author's
claims, tells the reviewer not to run tests or builds but to read the tests and judge what they
prove, and invites questions about the premises, better solutions and sources from other projects.
Instruction changes are journaled in the round they take effect, and the export shows them there.
Both reviewers also read the repository's own instructions, AGENTS.md or CLAUDE.md, as any session
in it would.

### Codex as it is called

- Codex runs with the repository root as its working directory: `codex exec resume` has no `-C`,
  and both `exec` forms refuse a working directory outside a trusted Git directory.
- Codex is not sandboxed a second time. Its Linux sandbox cannot set up under podman's masked
  `/proc` (the Containerfile has the measurement), so the image sets `danger-full-access` and the
  reviewer prompt tells Codex not to write; the digest check is what enforces it, and the
  container stays the boundary.
- Native `codex exec review` is not used: it starts a fresh reviewer each time, so a fix could not
  be re-reviewed with the earlier debate in context (openai/codex-plugin-cc #375 found the same and
  fell back to ordinary turns). `codex mcp-server` resolves `codex-reply` threads only in the live
  server's memory (openai/codex #24833), and `codex app-server` would add JSON-RPC lifecycle
  handling for no gain over `codex exec`.
- Measured with codex-cli 0.155.1: `exec` and `exec resume` both accept `--json`,
  `--output-schema` and `--output-last-message`; the resumed turn emits the persisted id and
  answers from the earlier turn's context; a made-up id fails with `no rollout found for thread id`
  rather than opening a new thread (openai/codex #15539, closed).
- Measured with codex-cli 0.156.1 on a real usage limit: `codex exec resume` emits an `error` event
  whose `message` and a `turn.failed` event whose `error.message` both hold Codex's text, "You’ve
  hit your usage limit. … try again at" and the reset time, and exits with status 1.

### Claude Code as it is called

The reviewer is `claude -p --output-format stream-json --verbose --json-schema <the schema>`, the
prompt on stdin, resumed with `--resume <session id>`; the result is the `result` event's
`structured_output`, which the helper keeps in the round's `result.json` as Codex's final message
is kept.

- Not `--bare`: it accepts only an API key, and the sandbox's sign-in is a claude.ai login. So the
  session runs under the managed settings, the image's plugins and the project's CLAUDE.md, with
  `--setting-sources ""` (no user, project or local settings file), `--disable-slash-commands` and
  `--strict-mcp-config` (no MCP server, so no connector a `claude.ai` login would otherwise load).
- `--tools Bash,Read,Grep,Glob,WebFetch,WebSearch` with `--permission-prompts none`, which denies
  every tool call a permission prompt would gate, and `--allowedTools` for the git read commands
  and the web tools. On a host with the default permission mode the reviewer can therefore only
  read; under the image's managed `bypassPermissions` nothing prompts, and the digest check is the
  enforcement, as for Codex.
- The failure is in the result object, not the exit status: an API error can end a print-mode run
  with exit status 0, `is_error` true and the error text in `result` (anthropics/claude-code
  #79500). The helper treats a `result` event with `is_error` or a `subtype` other than `success`
  as the turn's failure, and its `errors` or `result` text as the reviewer's words.
- `CLAUDE_CODE_EFFORT_LEVEL` overrides `--effort` (code.claude.com/docs/en/env-vars), so the
  helper sets the variable to the chosen effort in the reviewer's environment, on `start` and on
  every resumed round. A managed `env` block would replace it, so `start` refuses, with
  `REVIEWER_CHOICE_REFUSED`, an effort other than the one such a block sets.
- The reviewer session spends this project's Claude Code usage, as a Claude author does, and its
  transcript lands in `~/.claude/projects/` like any session's, where `claude --resume` can open
  it.
- Measured with Claude Code 2.1.283 in a session of the image, with a claude.ai sign-in:
  - a nested `claude -p` runs from Claude Code's Bash tool;
  - `--resume` of the print-mode session answers from the earlier turn's context and returns the
    same `session_id`, and `--resume` of an unknown id exits 1 with
    `No conversation found with session ID`;
  - `--json-schema` returns the parsed object in `structured_output`;
  - `--bare` fails with `Not logged in · Please run /login` and `is_error` true at exit status 0;
  - `stream-json` without `--verbose` is refused.


## Tests

`src/test/python/ko_review_test.py`, run by `KoReviewTest` on Linux, drives the helper against one
fake script installed as both `codex` and `claude` on `PATH`, each imitating its CLI's events.

- It covers thread continuity and mismatch, every failure class, the digest over each kind of
  change, the snapshot refs and their absence under a read-only Git directory, the base range,
  the export, the lock, the round limit, escalation, and state namespacing.
- The tests marked `both_reviewers` run against each fake; the rest, whose subject is the helper's
  own logic, run against the fake Codex only.
- Tests in the test's own process load the helper as a module: `stream_events` with a timeout
  callback paused into the cleanup, with an interrupt raised inside it and with a failing reader,
  and `children_of` with a child whose command name is not UTF-8, cases a fake reviewer cannot
  force.
- Claude's own tests cover its command line, the effort variable in its environment, the effort
  a managed `env` block sets, and the sources of its defaults.
- `KoReviewTest` also runs `claude plugin validate` on the plugin when `claude` is on `PATH`, and
  inside the image checks that the installed copy is readable.
- With `codex` on `PATH`, it has `codex debug prompt-input`, which calls no model, list a copy of
  the skill; the test fails unless Codex names it `ko-review`. Inside the image, it checks that
  Codex's copy equals the plugin's and that `/usr/local/bin/ko-review` resolves to the helper.
- A run against a real reviewer spends model quota, so it is done by hand.
- Measured with codex-cli 0.156.1 in a session of the image: the skill in Claude Code drove a Codex
  review through fixes, re-reviews and a retry after a usage limit to an approval on one thread,
  and a second invocation opened a new thread.
- Measured with Codex 0.157.1 as the author and Claude Code 2.1.284 as the reviewer in the
  image: `$ko-review` asked for the reviewer, model and effort in replies, then ran a Claude
  Fable review at high effort to approval. `verify` confirmed that approval covered the working
  tree.
