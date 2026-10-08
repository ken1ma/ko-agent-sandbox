---
name: ko-review
description: >-
  Have a separate Codex or Claude Code session review the working tree on one persistent thread,
  then fix or dispute its findings on that same thread until it approves the tree or the user
  must decide. Invoke it only when the user asks for such a review, never on your own.
argument-hint: [a review id to continue, or a reviewer, base commit, model, effort and instructions]
---

# Independent review cycle

`ko-review` (on PATH) runs the cycle with the reviewer the user chooses, `codex` or `claude`;
REVIEWER below stands for that name. Each `start` opens a fresh reviewer thread, and later rounds
of that review reuse that exact thread: the reviewer keeps the whole discussion. The reviewer
reads the repository itself; your messages are context for it, not evidence.

- A reviewer using the same product as you, `claude` for Claude Code or `codex` for Codex, runs
  in a separate session. It does not see this conversation, and you never answer its findings
  from memory.
- Every command but `export` (Markdown) and `diff` (git's output) prints one JSON object. A
  non-zero exit status is a failure: the output is then JSON containing an `error` field, or a
  usage message from the argument parser.
- The helper keeps every file you send: the round's `input.md` under the review directory holds
  the prompt the reviewer received, and `export` renders the text per round, so your copy need
  not outlive the session.

A new review's scope is the uncommitted change against HEAD. When the argument names a base
commit or branch, the scope is the change since that commit, committed or not. Take a base only
from the argument: neither the conversation nor the history tells reliably which commits are this
session's.

- With a review id as the argument, the continued review keeps the scope it recorded.
- Otherwise, without a base and with a clean `git status`, tell the user there is nothing to
  review and that a base in the argument brings committed work into scope, and stop.
- With a base, the step 3 summary still reports only what this session did, and says so.

In Claude Code the argument is the text after the skill's name. Codex passes a skill no argument,
so there it is the text after `$ko-review` in the user's message. When you invoke the skill
because the user asked in words, the argument holds only what they named: a reviewer, base,
model, effort or instructions they stated, or the id of a review this conversation printed that
their request points to, such as "the last review". Otherwise it is empty. Before the first
command, tell the user in one line that you invoked the skill, quoting their request.

## Steps

To ask the user, make one AskUserQuestion call in Claude Code. In Codex, whose default mode has no
question tool, end your turn with the questions and their numbered options, and go on with the
answer.

1. Ask the user which reviewer, unless the argument names one.
   - If the argument is a review id, skip to step 6 with it instead: a continuation keeps
     the review's reviewer, model and effort.
   - Without a base, first run `git status --porcelain` and stop on an empty output as above.
   - The options are `codex` (Codex, under this project's Codex sign-in and usage limit) and
     `claude` (Claude Code, under this project's Claude Code sign-in and usage).
2. Before reading the change, run `ko-review defaults REVIEWER` and ask the user for the
   reviewer's model and its reasoning effort, both questions at once, unless the argument names
   them. The user can type a value no option offers, such as a full Claude model name.
   - Each question's first option is `recommended`'s value, labeled "(current)" when the
     configuration set it (`model` or `effort` is not null) and "(default)" otherwise, as Codex's
     `/model` picker labels them. A null value is a first option reading "REVIEWER's default".
   - Model options: after the first, the catalog's other models in its order, up to four
     options, each with its `description`. For `claude` the catalog is the four aliases Claude
     Code documents, `fable`, `opus`, `sonnet` and `haiku`.
   - A non-null `recommended.upgrade` names the model Codex recommends over a retiring one: offer
     it second, labeled "(recommended upgrade)", with its `migrationMarkdown` as the description.
   - With a null `catalog` or fewer than two models in it, leave the model question out, since
     AskUserQuestion needs two options; take `recommended.model`, and say so.
   - Effort options: after the first, the other `recommended.efforts` in their order, up to four
     options; with a null `efforts`, which says the model's levels are unknown, `low`, `medium`
     and `high`.
   - A model whose `efforts` is an empty list takes no effort: leave the effort question out, pass
     no `--effort`, and say so.
   - For a model other than `recommended.model`, a "(default)" effort means that model's
     `defaultEffort`. When its `efforts` in the catalog lack the chosen effort, ask again for the
     effort alone, from those efforts, its `defaultEffort` first.
   - Where you cannot ask, as in a non-interactive session, take `codex` and `recommended` and
     say so.
3. Write a Markdown file outside the repository, since a file inside it joins the reviewed tree:
   in your scratchpad, else in a `mktemp -d` directory. Its sections are `## Task` (what was
   requested), `## Changes` (what you changed), `## Verification` (checks run and their results),
   `## Notes` (ambiguities and known tradeoffs).
4. Run `ko-review start REVIEWER --message-file FILE` from inside the repository, and note
   `reviewId` from the output.
   - Pass each selected value from step 2 explicitly with `--model NAME` and `--effort LEVEL`,
     since `defaults` reads only the local configuration. For a null value, omit the option so
     the reviewer uses its default.
   - If the argument holds instructions for the reviewer, write them verbatim, without the
     reviewer, base, model and effort it names, to a second file and add
     `--instructions-file FILE`; the reviewer reads them every round, ahead of your messages.
   - If the argument names a base, add `--base REF` with it.
5. Tell the user in one or two lines how the round went: the review outcome, the open findings,
   each id with a few words, and what you do next. `ko-review export REVIEW_ID --round N` prints
   the round's full text for the user who asks.
6. Evaluate every finding independently: fix the ones you accept, dispute the ones you reject with
   concrete evidence (file and line, a test result, a specification). Do not accept a finding to
   end the review, and do not reject one without evidence.
7. Run the relevant tests and checks after your fixes.
8. Write a response file with `## Changes since the previous review`, `## Accepted findings`
   (what was fixed and how), `## Disputed findings` (the evidence for each rejection) and
   `## Verification`, then run `ko-review continue REVIEW_ID --message-file FILE`.
   - If the user sent instructions for the reviewer meanwhile, write them to a file and add
     `--instructions-file FILE`; they replace the standing instructions from that round on.
     Instructions for you apply at once.
9. Repeat from step 5 until `disposition` is `APPROVED`.
   - If `disposition` is `USER_DECISION_REQUIRED`, read `userDecision`. If technical evidence can
     settle it, put that evidence in a response file and `continue` the same review.
   - Only if you agree that no technical evidence can settle it, write the question for the user
     in a file, run `ko-review escalate REVIEW_ID --message-file FILE`, and put the decision to
     the user in your reply.
10. Immediately before reporting that the reviewer approved the changes, run
    `ko-review verify REVIEW_ID`. It succeeds only when the approval covers the current working
    tree. When it fails, its `staleReasons` name what changed and where; run `continue` for a new
    approval.

## When the review ends

However it ends, report:

- every round, as a table from `ko-review export REVIEW_ID` with a row per round: the review
  outcome, or the error that ended the round; the findings the reviewer raised, each id with a few
  words; and what your next message did about each, fixed or disputed;
- for each disputed finding, the evidence you gave;
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

An `error` is an operational failure, never a review outcome. When the reviewer failed, its
`reviewer` field identifies it.

- `NOT_A_GIT_REPOSITORY`, `REVIEWER_AUTH_FAILED`, `REVIEWER_EGRESS_DENIED`: they say what the
  user must do. Stop, and put the message in your reply verbatim.
- `REVIEWER_CHOICE_REFUSED`: the managed settings set the effort, and the message names it. Tell
  the user, and start again with that effort or without one, as they choose.
- `NOTHING_TO_REVIEW`: the tree equals HEAD, or the base commit. Tell the user there is nothing
  to review, and without a base, that a base in the argument brings committed work into scope.
- `REVIEWER_FAILED`: `message` ends with the reviewer's own words when it gave any, such as a
  usage limit and when it resets. Stop, and put the message and the review id in your reply.
  Unless the message says to start a new review, the user continues with `/ko-review REVIEW_ID`,
  in Codex `$ko-review REVIEW_ID`, once the reviewer can run; the helper sends the reviewer the
  unanswered message again, so the next one says only what changed since.
- `REVIEW_BUSY`: another session runs a command on the same review.
- `WORKTREE_CHANGED_DURING_REVIEW`: the tree changed while the reviewer read it, possibly from
  the host. Check the tree and `continue` again.
- `LOOP_LIMIT_REACHED`: the review is over. Report what stayed open.
- `REVIEW_CLOSED`: a `continue` on a review that ended. Start a new review.

## Do not

- Do not start another review after an approval on your own: a new `start` is an independent
  audit the user asks for.
- Do not choose a thread or review based on when it was created; use its review id.
