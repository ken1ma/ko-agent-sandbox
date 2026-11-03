---
name: ko-review
description: >-
  Have a separate Codex or Claude Code session review the working tree on one persistent thread,
  then fix or dispute its findings and answer its suggestions until it approves the tree or the
  user must decide. Invoke it only when the user asks for such a review.
argument-hint: >-
  [codex|claude] [model] [effort] [base-commit] [instructions] |
  [review-id-to-continue]
---

# Independent review cycle

The `ko-review` command runs a review by the reviewer the user chooses, `codex` or `claude`.

The skill's argument is the text after `/ko-review` in Claude Code. Codex passes a skill no
argument, so there the argument is the text after `$ko-review` in the user's message. When you
invoke the skill because the user asked in words, the argument holds only what they named: a
reviewer, base, model, effort or instructions, or the id of a review this conversation printed that
their request refers to, such as "the last review". Before the first command, tell the user in one
line that you invoked the skill, quoting their request.

## Steps

To ask the user, make one AskUserQuestion call in Claude Code. In Codex, end your turn with the
questions and their numbered options.

1. A review id as the argument continues that review, with its reviewer, model, effort and scope:
   go to step 6. Otherwise:
   - Take a base only from the argument: neither this conversation nor the git history shows
     reliably which commits are this session's.
   - Without a base, run `git status --porcelain`. On an empty output, stop as `NOTHING_TO_REVIEW`
     under "Errors" says.
   - Run `ko-review approvals`, with `--base REF` for the argument's base. Offer an entry only when
     the argument names no instructions, and no reviewer, model or effort other than the entry's.
     - When the first such entry has `approvalFresh` true and an empty `newPaths`, tell the user
       that review REVIEW_ID already approves the tree, and ask whether to stop or start a new
       review. For a new review, offer no entry.
   - Ask for the reviewer, unless the argument names one and you offer no entry. Offer those
     entries first, as "continue REVIEW_ID (REVIEWER, MODEL, EFFORT): it approved N of the M paths
     in scope", then `codex` and `claude`, each under its own sign-in and usage limit in this
     workspace.
     - Choosing an entry skips step 2.
2. Run `ko-review defaults REVIEWER`. Unless the argument names them, ask for the model and the
   effort in one call.
   - Model: `recommended.model` first, labeled "(current)" when `model` is not null and
     "(default)" otherwise; a null value reads "REVIEWER's default". A non-null
     `recommended.upgrade` comes second, labeled "(recommended upgrade)", with its
     `migrationMarkdown` as the description. Then the catalog's other models in its order, up to
     four options, each with its `description`. For `claude` the catalog is `fable`, `opus`,
     `sonnet` and `haiku`.
   - Effort: a non-null `effort` first, labeled "(current)". Otherwise `high` first, labeled
     "(recommended)", where `efforts` list it or are null, and then `recommended.effort` as
     "(default)", or "REVIEWER's default" when it is null. Then the other `recommended.efforts`
     in their order, up to four options in all; with a null `efforts`, `low`, `medium` and `high`
     not yet offered.
   - Leave out the model question when `catalog` is null or has fewer than two models: take
     `recommended.model`, and say so. Leave out the effort question when `efforts` is an empty
     list: pass no `--effort`, and say so.
   - For a model other than `recommended.model`, "(default)" means that model's `defaultEffort`.
     When the model's `efforts` lack the chosen effort, ask again for the effort alone, from those
     efforts, `defaultEffort` first.
   - Where you cannot ask, take `codex` and `recommended`, and say so.
3. Re-read every changed hunk with the unchanged lines around it against `AGENTS.md`, as the
   reviewer will, and fix what you find, so that the reviewer does not spend a round on what you
   could catch yourself. Then write a Markdown brief outside the repository, so that the review does
   not include it: in your scratchpad, else in a `mktemp -d` directory.
   - Sections: `## Task`, `## Changes`, `## Verification` and `## Notes` (ambiguities and known
     tradeoffs).
   - For a review continued from step 1, describe the work since its approval.
   - Without a base, the review covers only uncommitted changes; describe only those.
   - With a base, report only what this session did, and say so.
4. Run `ko-review start REVIEWER --message-file FILE`. For a review continued from step 1, run
   `ko-review continue REVIEW_ID --message-file FILE` instead, with none of the options below.
   - Pass the values from step 2 with `--model NAME` and `--effort LEVEL`. Omit an option whose
     value is null.
   - Write the argument's instructions for the reviewer verbatim, without the reviewer, base,
     model and effort, to a second file, and add `--instructions-file FILE`.
   - Add `--base REF` for the argument's base.
5. Tell the user how the round went: the outcome, each open finding and suggestion by id in one
   sentence, and what you do next.
   - Name each adopted suggestion that changes an interface, such as a command, an option, a
     schema or a file format, or how the work splits into components.
   - `ko-review transcript REVIEW_ID --round N` prints the round in full for a user who asks.
6. Fix the findings you accept, and run the relevant tests and checks. Dispute the other findings
   with evidence: a file and line, a test result, a specification. Never accept a finding to end
   the review.
   - A suggestion never blocks approval. Adopt it or dispute it as you would a finding.
   - The user decides a finding or a suggestion that depends on what the user owns, the task's
     scope, ownership of the work, a recorded decision, a product requirement or a risk
     acceptance, or a disagreement evidence cannot settle. Ask the user to decide it in your reply,
     with why evidence cannot decide it, and do not adopt it.
7. Write a response with `## Changes since the previous review`, `## Accepted findings` (what you
   fixed and how), `## Disputed findings` (the evidence against each), `## Suggestions` (each
   adopted, disputed with the reason, or left to the user with why the user decides it) and
   `## Verification`. Then run `ko-review continue REVIEW_ID --message-file FILE`.
   - Write instructions for the reviewer that the user sent meanwhile to a file, and add
     `--instructions-file FILE`. They replace the instructions given earlier.
8. Repeat from step 5 until `disposition` is `APPROVED` and you adopt none of the round's
   suggestions.
   - On `USER_DECISION_REQUIRED`, read `userDecision`. When evidence can settle it, `continue`
     with that evidence.
   - Otherwise write the question for the user in a file, run
     `ko-review escalate REVIEW_ID --message-file FILE`, and ask the user to decide.
9. Immediately before reporting an approval, run `ko-review check-approval REVIEW_ID`. When it
   fails, its `staleReasons` name what changed; run `continue` for a new approval.

## When the review ends

However it ends, report:

- a table from `ko-review transcript REVIEW_ID` with a row per round: the outcome or the error that
  ended the round, each finding and suggestion by id in one sentence, and what your next message
  did with each;
- for each finding you disputed, the evidence you gave against it;
- each suggestion you left to the user, with the reviewer's reason, your view and why the user
  decides it;
- this command with the review id, as a code block and the reply's only `inspect` line:

      ko-review transcript REVIEW_ID    # its footer lists the other commands

## Errors

- `NOT_A_GIT_REPOSITORY`, `REVIEWER_AUTH_FAILED`, `REVIEWER_EGRESS_DENIED`: stop, and quote the
  message.
- `REVIEWER_CHOICE_REFUSED`: managed settings set the effort that the message names. Start again
  with that effort or without one, as the user chooses.
- `NOTHING_TO_REVIEW`: tell the user there is nothing to review, and without a base, that a base in
  the argument also reviews the commits since that base. Stop.
- `REVIEWER_FAILED`: stop, and quote the message and the review id. Unless the message says to
  start a new review, the user continues with `/ko-review REVIEW_ID`, in Codex
  `$ko-review REVIEW_ID`, once the reviewer can run. Your next message then says only what changed.
- `WORKTREE_CHANGED_DURING_REVIEW`: the change may come from the host. Check the tree, and
  `continue` again.
- `LOOP_LIMIT_REACHED`: the review is over. Report what stayed open.
- `REVIEW_CLOSED`: start a new review.
