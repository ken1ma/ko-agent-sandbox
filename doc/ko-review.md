# Codex review from Claude Code

`/ko-review:codex` has Codex review the working tree, then has Claude fix or rebut each finding on
the same Codex thread until Codex approves the exact tree or asks for a decision only the user can
make. One invocation is one Codex thread; invoking the skill again starts a new thread, which is
how an independent audit of an approved tree is obtained.

- Only the user invokes the skill: `disable-model-invocation` keeps its description out of Claude's
  context, and the sandbox's AGENTS.md has Claude offer it after a non-trivial change.
- The plugin `ko-review` (`container/ko-agent-sandbox/claude-code/plugins/ko-review`) holds the
  skill, named after its reviewer so that another reviewer can join as another skill, the helper
  `ko-review`, the reviewer prompts and the result schema.
- The image loads it from `/etc/claude-code/plugins` through `CLAUDE_CODE_PLUGIN_DIRS` (Claude Code
  2.1.280 or later). The helper needs only `codex`, `git` and Python 3, so
  `claude --plugin-dir <the plugin directory>` loads it on a host too.
- The project must be a Git working tree. A `start` elsewhere fails with `NOT_A_GIT_REPOSITORY`
  before Codex runs; its message gives the `git init` and empty `git commit` that make one while
  leaving every file uncommitted, and so in the review's scope.


## The cycle

1. Claude writes a Markdown summary of the task, its changes and its verification, and runs
   `ko-review start codex --message-file FILE`. The helper opens a Codex thread with the reviewer
   prompt and that summary; Codex reads the repository itself.
   - `--base REF` has Codex review the changes since that commit or branch, committed since then
     or not, by the commit id the ref resolved to at `start`, so a branch that moves during the
     review does not move the scope. Without it Codex reviews the working tree against HEAD, so
     work committed during the session is out of scope.
     - The skill passes a base only from its argument, for the reason its scope paragraph gives.
     - Codex compares the working tree with the base's tree, so commits merged or pulled since
       the base are in scope too.
   - An empty scope is refused with `NOTHING_TO_REVIEW` before a review exists: the working tree
     equals the base commit, HEAD without `--base`, and no file is untracked. A dirty checkout
     whose edits restore the base's content counts as empty. A Codex turn on nothing would yield
     an approval that looks like one of the session's committed work.
   - `--instructions-file FILE` adds the user's own instructions, from the skill's argument, to
     every round's prompt after the reviewer instructions, which they take precedence over.
   - `--model` and `--effort` choose the Codex model and reasoning effort for every round, through
     `codex exec --model` and the `model_reasoning_effort` configuration key. The skill asks the
     user before every `start`, offering first what `ko-review defaults codex` reports
     ("Defaults", below).
2. Codex answers with a structured result: `disposition` `APPROVED`, `CHANGES_REQUESTED` or
   `USER_DECISION_REQUIRED`, a summary, findings with stable ids, and for the user's decision the
   issue, Codex's position, why evidence cannot decide it and the decision requested.
3. Claude fixes the findings it accepts, rebuts the others with evidence, runs the tests, and
   sends both with `ko-review continue REVIEW_ID --message-file FILE` to the same thread.
   - `--instructions-file FILE` on `continue` replaces the standing instructions from that round
     on, which is how an instruction the user gives mid-review reaches Codex. It voids the
     current approval, since Codex never approved the tree under the new instructions.
4. This repeats until `APPROVED`, or until `maxRounds` rounds Codex answered (12 unless
   `start codex --max-rounds` says otherwise) end the review with `LOOP_LIMIT_REACHED`.
   - A user decision Codex proposes becomes terminal only when Claude agrees and runs
     `ko-review escalate REVIEW_ID --message-file FILE`; otherwise Claude argues the point on the
     same thread.
5. Before reporting consensus, Claude runs `ko-review verify REVIEW_ID`, which succeeds only when
   the approval covers the current working tree.

The skill has Claude show each round's text in its reply, and, when the review ends, the `inspect`
lines: the commands with which the user sees how the review went, lists the checkout's reviews and
deletes this one. Claude's own model and effort are the session's, set with `/model` or the launch
options; the skill runs in that session.


## Commands

Every command but `export`, which prints Markdown, and `diff`, which prints git's output, prints
one JSON object and exits 1 when it holds `error`. Each summary, and each failure once a review
exists, carries the review id, `snapshots` and `inspect`.

- `list`: one short entry per review of this checkout, oldest first, for the id the other
  commands take.
- `show REVIEW_ID`, `digest`: read state. For a round in progress, `show` adds
  `activity`: the event log's path, known as soon as the round starts, the time elapsed, and the
  type and time of the last event received, which says when Codex last wrote, not that it is
  still working.
- `export REVIEW_ID [--round N]`: the transcript as Markdown, one section per round, or that
  round's alone.
- `diff REVIEW_ID [--round N] [-- git options]`: the working tree, untracked files included,
  against a round's snapshot; the approved round unless one is named.
- `delete REVIEW_ID`: the review's state and its refs, on the user's request only. The tag and
  tree objects nothing else points to become eligible for a later garbage collection, which by
  default keeps recent unreachable objects for two weeks.
- `defaults codex`: the model and effort Codex's local configuration selects for this repository,
  the models Codex's `/model` picker offers with each one's efforts, and a `recommended` pair
  ("Defaults", below).

The helper never commits, stages or moves HEAD: Claude's fixes during a review are working-tree
edits like any other, and the user commits them when and as they choose.


## What the helper guarantees

- **The same thread.** Every round of a review runs on the Codex thread its first round opened;
  a resumed turn that names another thread is `CODEX_RESUME_MISMATCH`.
  - The thread id is the `thread_id` of Codex's `thread.started` event, persisted the moment it
    arrives, and resumed with `codex exec resume <that id>`. Claude never chooses a thread, and
    nothing uses `--last`.
- **Approval binds to the exact tree.** Any change after approval makes `verify` fail with
  `STALE_APPROVAL`, and `staleReasons` says what moved; `continue` obtains a new approval.
  - The digest covers HEAD, the index and every file's raw content ("The digest", below).
  - Staging or committing the approved changes keeps the approval, a staged deletion or rename
    included: the digest moves, but the content digest recorded with the approval still matches
    and the index, written as a tree, equals the approved snapshot's tree. Unreviewed staged
    content fails that second check. A changed HEAD alone is never a reason.
  - `staleReasons`, in `show` and in `verify`'s error, names "working files changed" with the
    paths, from the manifest of hashes the round saved beside its snapshot; "unreviewed content
    staged" with the paths; or that the instructions changed after the approval.
- **Each round's tree and transcript are kept in Git**, under
  `refs/ko-review/<review id>/round-NNN`, without touching the user's index, HEAD or files.
  - The ref points at a tag object whose message is the round's transcript, the author's message
    and Codex's result or the error; the tag object points at the tree of the working tree as
    reviewed.
  - `git for-each-ref --format='%(contents)' <ref>` prints the transcript alone, since `git show`
    follows it with a listing of the tree's top level.
  - `git diff` between two rounds' refs shows what Claude changed in response to a finding.
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
- **A tree that changes during a turn voids the turn.** The digest is taken before and after Codex
  runs; a difference is `WORKTREE_CHANGED_DURING_REVIEW`, with the paths, and the result is
  discarded. Nothing is reverted, and the helper does not say who changed the tree: a host editor
  or another session may have.
- **Failures are never outcomes.** A failed turn leaves `status` at the previous outcome and
  records the failure in `lastError` and the journal; a `continue` retries on the same thread
  once Codex has named one, and opens a thread when the failure came before `thread.started`.
  - The thread id is persisted the moment `thread.started` arrives, so whatever ends the turn
    after that, a timeout, an interrupt or termination signal, unparsable later output or a helper
    bug (`HELPER_FAILED`), the retry resumes that thread.
  - The retry's prompt carries again every author message since the last round Codex answered,
    oldest first and as written, since a failed turn may not have left its message in the thread.
    Before any round has completed, the retry sends the reviewer prompt again.
  - A round that ends in an error does not count toward `maxRounds`, so retries after a usage
    limit do not use up the review.
  - Whatever ends the turn, the helper kills Codex's process group and waits for it before it
    returns, so no Codex turn runs on past the lock that serialized it.
  - `CODEX_AUTH_FAILED`: `codex login status` reports no sign-in, whichever credential store Codex
    uses; sign in to `codex` in this project's sandbox.
  - `CODEX_EGRESS_DENIED`: the ruleset in `KO_AGENT_SANDBOX_EGRESS_RULESET` allows neither
    `api.openai.com` nor `chatgpt.com`, as under `--egress=deny-unless-model claude`; relaunch
    under the default profile.
  - `CODEX_FAILED`: any other failure of Codex. When Codex said why, `message` ends with its words,
    such as a usage limit and when it resets, from its last failure event, else its last line of
    stderr. A thread Codex no longer has is also `CODEX_FAILED`, and its message says to start a new
    review.
  - `INVALID_RESULT`: Codex's final message does not follow the schema exactly; the helper
    validates it before touching state, `--output-schema` only asks.
  - Also `TURN_INTERRUPTED` and `REVIEW_BUSY`. The helper never edits the egress rules or Codex's
    configuration.
- **One mutation per review at a time.** `start`, `continue` and `escalate` take `flock` on the
  review's lock file before reading the state they act on; a second one fails at once with
  `REVIEW_BUSY` instead of waiting behind a Codex turn. `state.json` is replaced atomically, so
  `show` and `list` read it without a lock.


## Where the state is

```text
$HOME/persistent-volume/ko-review/repositories/<sha256 of the checkout path>/
├── repository.json          the unhashed path
└── reviews/<review id>/
    ├── state.json           status, round, Codex thread id, last reviewed and approved digests
    ├── journal.jsonl        every author message, Codex result, escalation and error, in order
    ├── review.lock
    └── rounds/NNN-{input.md,manifest.json,codex.jsonl,codex.stderr,result.json}
```

and, in the repository's own Git directory, `refs/ko-review/<review id>/round-NNN` for each round's
transcript and tree, which `delete` removes with the directory above.

- A review id is its local start minute, `2026-09-24-1005-`, plus eight hex digits: the state
  directory and the refs group by start minute, in an arbitrary order within one, and the id can
  be typed.
- State is namespaced by checkout path because a persistent volume can be shared by several
  projects (`KO_AGENT_SANDBOX_PERSISTENT_VOLUME`) or by a main worktree and its linked worktrees,
  and a review is about one checkout. Codex's own session files stay in `~/.codex`; sharing them
  is safe because every continuation names its thread id. `--reset` removes both.
- Outside the sandbox the state root is `$XDG_STATE_HOME/ko-review`, default
  `~/.local/state/ko-review`; `KO_REVIEW_STATE` overrides either.


## Why it is built this way

### The digest

- The working-tree digest is SHA-256 over the HEAD id, every record of
  `git status --porcelain=v2 -z --untracked-files=all --no-renames` sorted by path, which carries
  the index's and HEAD's object ids and modes, and a content digest.
- The content digest covers every file Git would review, from
  `git ls-files --cached --others --exclude-standard`, by its raw content with its executable bit
  or its symlink target; an absent path contributes nothing. Raw content, because `git status`
  calls a file clean when its content after the clean filter matches the index, so the status
  records alone miss a change a filter strips.
- A submodule or nested repository is digested the same way as a tree of its own, since its
  status record carries dirty flags, not what changed. No `git diff` runs, so no diff or textconv
  driver shapes the digest.
- The digest, the content digest and the manifest come from one scan of the checkout, made once
  per command, and twice per turn, before and after Codex runs, since those are two observations.

### The snapshot

- The tree and its ref are written before Codex runs, so the ref names what Codex reviewed; the
  transcript's tag object replaces the tree on the ref when the round ends, with a result or with
  an error.
- The scratch index starts as a copy of the entries of the user's index, so the tracked paths are
  the checkout's, staged additions and removals included, whatever the ignore rules say of them;
  `git add -A` then adds untracked files and leaves ignored ones out. Each `diff` invocation
  writes its own scratch index, so overlapping ones do not disturb each other.
- The transcript is a tag object rather than a commit: a tag object on a tree contributes nothing to
  `git log --all`, and each round gets a distinct object even when two rounds' trees are equal,
  which git notes, keyed by the tree id, would merge. The tagger is `ko-review`, since neither the
  user nor Codex wrote the whole message.

### Defaults

- `defaults codex` reads Codex's local configuration in Codex's precedence: the project's
  `.codex/config.toml` when the user configuration trusts the project, then the user's, then the
  image's system layer; the catalog comes from `codex debug models`.
- The catalog leaves out the models `codex debug models` marks `"visibility": "hide"`, which
  Codex's `/model` picker omits too; a configured hidden model still gets its efforts in
  `recommended`. The catalog keeps Codex's order, which is its `/model` picker's order.
- Its `recommended` fills a missing effort from the catalog's default for the model; a value still
  null is Codex's built-in default, which the skill leaves to Codex by passing no option.
- It is marked `partial`: a cloud-managed layer, which Codex ranks above the user's file, is not on
  disk, so the skill passes each chosen value explicitly rather than relying on the default it
  displayed.

### The reviewer prompt

`prompts/reviewer.md` is the default for every review: it asks for skepticism toward the author's
claims, tells Codex not to run tests or builds but to read the tests and judge what they prove,
and invites questions about the premises, better solutions and sources from other projects.
Instruction changes are journaled in the round they take effect, and the export shows them there.

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


## Tests

`src/test/python/ko_review_test.py`, run by `KoReviewTest` on Linux, drives the helper against a
fake `codex` on `PATH`: thread continuity and mismatch, every failure class, the digest over each
kind of change, the snapshot refs and their absence under a read-only Git directory, the base
range, the export, the lock, the round limit, escalation, and state namespacing. `KoReviewTest`
also runs `claude plugin validate` on the plugin when `claude` is on `PATH`, and inside the image
checks that the installed copy is readable. A run against the real Codex spends model quota, so it
is done by hand.
- Measured with codex-cli 0.156.1 in a session of the image: `/ko-review:codex` drove a review
  through fixes, re-reviews and a retry after a usage limit to an approval on one thread, and a
  second invocation opened a new thread.
