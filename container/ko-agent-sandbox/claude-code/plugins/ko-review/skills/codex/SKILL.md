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
- With a base, the step 1 summary still reports only what this session did, and says so.

## Steps

1. Write a Markdown file in your scratchpad with these sections: `## Task` (what was requested),
   `## Changes` (what you changed), `## Verification` (checks run and their results), `## Notes`
   (ambiguities and known tradeoffs).
2. If the skill's argument is a review id, skip to step 5 with it: a continuation keeps the
   review's model and effort. Otherwise run `ko-review defaults codex` and ask the user with the
   AskUserQuestion tool for the Codex model, then, in a second question, for its reasoning
   effort, unless the argument names them. The user can type a value no option offers.
   - Model options: the first four models of `catalog`, in its order, each with its
     `description`; `recommended.model`, marked recommended, replaces the fourth if it is not
     among them. A null `recommended.model` is a first option reading "Codex's default", followed
     by the catalog's first three.
   - When `catalog` is null or offers fewer than two models, AskUserQuestion, which needs two
     options, cannot ask: skip the model question, take `recommended.model`, and say so.
   - Effort options: the first four of the chosen model's `efforts`, in their order; its
     recommended effort, marked recommended, replaces the fourth if it is not among them. That is
     `recommended.effort` for the recommended model and the catalog's `defaultEffort` for another.
     Without `efforts`, offer `low`, `medium` and `high`.
   - Where you cannot ask, as in a non-interactive session, take `recommended` and say so.
3. Run `ko-review start codex --message-file FILE` from inside the repository, and note
   `reviewId` from the output.
   - Add `--model NAME` and `--effort LEVEL` from step 2, each only when it is not null:
     `defaults` reads the local configuration only, so the choice counts once passed explicitly,
     and a null is Codex's to fill.
   - If the argument holds instructions for Codex, write them verbatim, without the base, model
     and effort it names, to a second file and add `--instructions-file FILE`; Codex reads them
     every round, ahead of your messages.
   - If the argument names a base, add `--base REF` with it.
4. Show the user the round: put the output of `ko-review export REVIEW_ID --round N`, with N the
   output's `round`, in your reply verbatim, then say in one or two lines what you do next. Do the
   same after `escalate`.
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

However it ends, report which findings were fixed, which were rebutted and why, the review id, and
the `inspect` lines of the last output as a code block: the commands with which the user sees how
the review went, lists the checkout's reviews and deletes this one. A failure's JSON carries them
too once a review exists.

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
