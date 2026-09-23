---
name: codex
description: Have Codex review the working tree on one persistent thread, then fix or rebut its findings on that same thread until it approves the tree or the user must decide.
argument-hint: [a review id to continue, or a base commit, model, effort and instructions for Codex]
disable-model-invocation: true
---

# Codex review cycle

`ko-review` (on PATH from this plugin) runs the cycle. Each `start` opens a fresh Codex thread,
and every later command of that review reuses that exact thread: Codex keeps the whole debate.
Codex reads the repository itself; your messages are context for it, not evidence.

- Every command but `export` (Markdown) and `diff` (git's output) prints one JSON object. A
  non-zero exit status is a failure: the output is then JSON holding `error`, or a usage message
  from the argument parser.
- The helper keeps every file you send: the round's `input.md` under the review directory holds
  the prompt Codex received, and `export` renders the text per round, so the scratchpad copy need
  not outlive the session.

A new review's scope is the uncommitted change against HEAD. When the argument names a base
commit or branch, the scope is the change since that commit, committed or not. Take a base only
from the argument: neither the conversation nor the history tells reliably which commits are this
session's.

- With a review id as the argument, the continued review keeps the scope it recorded.
- Otherwise, without a base and with a clean `git status`, tell the user there is nothing to
  review and that a base in the argument brings committed work into scope, and stop.
- With a base, the step 2 summary still reports only what this session did, and says so.

## Steps

1. If the skill's argument is a review id, skip to step 5 with it: a continuation keeps the
   review's model and effort. Otherwise, without a base, run `git status --porcelain` and stop on
   an empty output as above. Then, before reading the change, run `ko-review defaults codex` and
   ask the user for the Codex model and its reasoning effort in one AskUserQuestion call holding
   both questions, unless the argument names them. The user can type a value no option offers.
   - Each question's first option is `recommended`'s value, labeled "(current)" when the
     configuration set it (`model` or `effort` is not null) and "(default)" otherwise, as Codex's
     `/model` picker labels them. A null value is a first option reading "Codex's default".
   - Model options: after the first, the catalog's other models in its order, up to four
     options, each with its `description`.
   - A non-null `recommended.upgrade` names the model Codex recommends over a retiring one: offer
     it second, labeled "(recommended upgrade)", with its `migrationMarkdown` as the description.
   - With a null `catalog` or fewer than two models in it, AskUserQuestion, which needs two
     options, cannot ask: leave the model question out, take `recommended.model`, and say so.
   - Effort options: after the first, the other `recommended.efforts` in their order, up to four
     options; without `efforts`, `low`, `medium` and `high`.
   - For a model other than `recommended.model`, a "(default)" effort means that model's
     `defaultEffort`. When its `efforts` in the catalog lack the chosen effort, ask again for the
     effort alone, from those efforts, its `defaultEffort` first.
   - Where you cannot ask, as in a non-interactive session, take `recommended` and say so.
2. Write a Markdown file in your scratchpad with these sections: `## Task` (what was requested),
   `## Changes` (what you changed), `## Verification` (checks run and their results), `## Notes`
   (ambiguities and known tradeoffs).
3. Run `ko-review start codex --message-file FILE` from inside the repository, and note
   `reviewId` from the output.
   - Add `--model NAME` and `--effort LEVEL` from step 1, each only when it is not null:
     `defaults` reads the local configuration only, so the choice counts once passed explicitly,
     and a null is Codex's to fill.
   - If the argument holds instructions for Codex, write them verbatim, without the base, model
     and effort it names, to a second file and add `--instructions-file FILE`; Codex reads them
     every round, ahead of your messages.
   - If the argument names a base, add `--base REF` with it.
4. Tell the user in one or two lines how the round went: the disposition, the open findings, each
   id with a few words, and what you do next. `ko-review export REVIEW_ID --round N` prints the
   round's full text for the user who asks.
5. Evaluate every finding independently: fix the ones you accept, rebut the ones you reject with
   concrete evidence (file and line, a test result, a specification). Do not accept a finding to
   end the review, and do not reject one without evidence.
6. Run the relevant tests and checks after your fixes.
7. Write a response file with `## Changes since the previous review`, `## Accepted findings`
   (what was fixed and how), `## Rebutted findings` (the evidence for each rejection) and
   `## Verification`, then run `ko-review continue REVIEW_ID --message-file FILE`.
   - If the user sent instructions for Codex meanwhile, write them to a file and add
     `--instructions-file FILE`; they replace the standing instructions from that round on.
     Instructions for you apply at once.
8. Repeat from step 4 until `disposition` is `APPROVED`.
   - If `disposition` is `USER_DECISION_REQUIRED`, read `userDecision`. If technical evidence can
     settle it, put that evidence in a response file and `continue` the same review.
   - Only if you agree that no technical evidence can settle it, write the question for the user
     in a file, run `ko-review escalate REVIEW_ID --message-file FILE`, and put the decision to
     the user in your reply.
9. Immediately before reporting consensus, run `ko-review verify REVIEW_ID`. It succeeds only
   when the approval covers the current working tree; when it fails, its `staleReasons` name what
   moved and where, and you `continue` the review for a new approval.

## When the review ends

However it ends, report:

- every round, as a table from `ko-review export REVIEW_ID` with a row per round: Codex's
  disposition, or the error that ended the round; the findings it raised, each id with a few
  words; and what your next message did about each, fixed or rebutted;
- for each rebutted finding, the evidence you gave;
- the review id, and the `inspect` lines of the last output as a code block: the commands with
  which the user sees how the review went, lists the checkout's reviews and deletes this one. A
  failure's JSON carries them too once a review exists.

What the `inspect` lines use:

- Each round's transcript and tree are on `refs/ko-review/REVIEW_ID/round-NNN`, for `git diff`
  between rounds.
- `ko-review export REVIEW_ID` prints the transcript; `diff REVIEW_ID` compares the working tree
  with the approved round; `delete REVIEW_ID` deletes the refs and the state, on the user's
  request only.

## Errors

An `error` is an operational failure, never a review outcome.

- `NOT_A_GIT_REPOSITORY`, `CODEX_AUTH_FAILED`, `CODEX_EGRESS_DENIED`: they say what the user
  must do. Stop, and put the message in your reply verbatim.
- `NOTHING_TO_REVIEW`: the tree equals HEAD, or the base commit. Tell the user there is nothing
  to review, and without a base, that a base in the argument brings committed work into scope.
- `CODEX_FAILED`: `message` ends with Codex's own words when it gave any, such as a usage limit
  and when it resets. Stop, and put the message and the review id in your reply. Unless the
  message says to start a new review, the user continues with `/ko-review:codex REVIEW_ID` once
  Codex can run; the helper sends Codex the unanswered message again, so the next one says only
  what changed since.
- `REVIEW_BUSY`: another session runs a command on the same review.
- `WORKTREE_CHANGED_DURING_REVIEW`: the tree changed while Codex read it, possibly from the
  host. Check the tree and `continue` again.
- `LOOP_LIMIT_REACHED`: the review is over. Report what stayed open.

## Do not

- Do not start another review after an approval on your own: a new `start` is an independent
  audit the user asks for.
- Do not choose a thread or review by recency; every command names the review id.
