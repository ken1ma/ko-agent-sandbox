---
name: codex
description: Have Codex review the working tree on one persistent thread, then fix or rebut its findings on that same thread until it approves the tree or the user must decide.
argument-hint: [instructions for Codex, or a review id to continue]
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

## Steps

1. Write a Markdown file in your scratchpad with these sections: `## Task` (what was requested),
   `## Changes` (what you changed), `## Verification` (checks run and their results), `## Notes`
   (ambiguities and known tradeoffs).
2. If the skill's argument is a review id, skip to step 5 with it: a continuation keeps the
   review's model and effort. Otherwise ask the user which Codex model and reasoning effort to
   use, unless the argument names them: run `ko-review defaults codex` and ask with the
   AskUserQuestion tool.
   - The first option is `recommended`: its `model` at its `effort`, marked recommended; a null
     there is Codex's built-in default and reads "Codex's default".
   - The other options are that model at the other levels in `efforts`, highest first, or, when
     `efforts` is null, `high`, `medium` and `low`. The user can type another model or effort.
   - Where you cannot ask, as in a non-interactive session, take `recommended` and say so.
3. Run `ko-review start codex --message-file FILE` from inside the repository, and note
   `reviewId` from the output.
   - Add `--model NAME` and `--effort LEVEL` from step 2, each only when it is not null:
     `defaults` reads the local configuration only, so the choice counts once passed explicitly,
     and a null is Codex's to fill.
   - If the user gave instructions for Codex as the skill's argument, write them verbatim to a
     second file and add `--instructions-file FILE`; Codex reads them every round, ahead of your
     messages.
   - If the work includes commits, add `--base REF` with the branch or commit the work started
     from, so Codex reviews the whole range rather than the uncommitted part.
4. Tell the user in one or two lines how the round went: the disposition, how many findings are
   open, and what you do next.
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
the review went. A failure's JSON carries them too once a review exists.

- Each round's transcript and tree are on `refs/ko-review/REVIEW_ID/round-NNN`, for `git show`
  and `git diff` between rounds.
- `ko-review export REVIEW_ID` prints the transcript; `diff REVIEW_ID` compares the working tree
  with the approved round; `delete REVIEW_ID` deletes the refs and the state, on the user's
  request only.

## Errors

An `error` is an operational failure, never a review outcome.

- `NOT_A_GIT_REPOSITORY`, `CODEX_AUTH_FAILED`, `CODEX_EGRESS_DENIED`: they say what the user
  must do. Stop, and put the message in your reply verbatim.
- `NOTHING_TO_REVIEW`: the tree equals HEAD. If the work was committed, `start` again with
  `--base REF`; otherwise tell the user there is nothing to review.
- `REVIEW_BUSY`: another session runs a command on the same review.
- `WORKTREE_CHANGED_DURING_REVIEW`: the tree changed while Codex read it, possibly from the
  host. Check the tree and `continue` again.
- `LOOP_LIMIT_REACHED`: the review is over. Report what stayed open.

## Do not

- Do not start another review after an approval on your own: a new `start` is an independent
  audit the user asks for.
- Do not choose a thread or review by recency; every command names the review id.
