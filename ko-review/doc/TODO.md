# TODO

This file lists remaining work on ko-review, the review plugin that `design.md` describes.

## agy as a third reviewer

- [ ] Add agy, Antigravity's CLI, as a reviewer beside `codex` and `claude`. The measurement suite
  runs `agy -p --output-format stream-json` and resumes with `agy --conversation <id> -p`
  (`src/test/measurement/MeasureAgents.scala`). Still to measure before the helper can call it:
  - a final message that follows the result schema, and whether agy enforces a schema or only asks;
  - the conversation id in the event stream, as the helper reads Codex's and Claude's thread ids;
  - a command that reports the sign-in without starting a session;
  - the options for model and reasoning effort, and the catalog `defaults` would offer;
  - a mode that keeps the reviewer from writing, or else the check after each turn as for Codex;
  - agy's hosts, for `REVIEWER_EGRESS_DENIED`.

## Codex's questions as menus

- [ ] Have a Codex coordinator ask the skill's three questions, reviewer, model and effort, as
  selectable menus, as a Claude coordinator does with AskUserQuestion. A Codex coordinator asks them
  instead in its reply, with numbered options that the user types back (`design.md`). Codex's
  `request_user_input` can be that menu once both of these hold:
  - Codex's default mode offers the tool as a stable feature;
  - the tool allows more than three options per question.

  Until both hold, the skill keeps the prose question.
  - `default_mode_request_user_input` is under development (`design.md` has the measurement).
    Once the feature is stable but still off, the image's Codex defaults enable it.
  - The tool's schema asks for "2-3 mutually exclusive choices" (openai/codex `main`, 2026-10-18).
    That limit leaves out choices such as `high` after the default, `low` and `medium`, and
    free-form entry does not replace a selectable option. The option limit of
    `request_user_input_async` is unverified.
  - Codex's default-mode prompt reserves the tool for optional questions and has required ones
    asked in plain text. So the menu words each question as optional, with the recommended choice
    first.

## Another reviewer, model or effort mid-review

- [ ] Let `continue` change the reviewer, model or effort, which each turn already records.
  - A reviewer CLI cannot resume another CLI's thread, so a change of reviewer opens a new thread
    on the same review. A change of model or effort may keep the thread where the CLI allows it.
  - Decide whether an approval then holds only for the reviewer, model and effort it was given,
    as it holds only for its instructions.

## An advisor's second opinion

- [ ] Let the coordinator ask an advisor, another model or tool, for a second opinion on the
  reviewer's findings, suggestions or a dispute before it answers (`design.md`, the four roles).
  - The advisor decides nothing: the coordinator still accepts or disputes each item, and the user
    decides what the escalation rule leaves to the user.
  - Record the advisor in the turn's `request.json`, a field added later under the format's rule 3,
    and show its opinion in the transcript.

## A fork from an earlier turn

- [ ] Let a coordinator continue a review from turn N with another message or reviewer, keeping the
  later turns. `request.json` would gain `parent`, the turn whose thread and tree the turn
  continues, with the default "the previous turn", which every earlier review satisfies. `from`
  already names any turn.
  - `parent` bumps the format's minor version, so that an older helper refuses to continue a
    forked review rather than read its turns in a line.

## Version control other than Git

- [ ] Review a worktree that another version control system manages, such as a jj workspace that
  is not colocated with Git, which fails today with `NOT_A_GIT_REPOSITORY`.
  - `from`'s `store` names the system, and a turn without `from` has no patch, so the files need
    no new meaning.
  - The helper would compute the scope and the patch with that system, as with `jj diff --git`.

## Binary files in the patches

- [ ] Keep binary files' content in `start.patch`, as `git diff --binary` writes it and
  `git apply` applies it. A rebuilt turn would then have every file, not text files alone.
  - The cost is disk: each turn that changes a binary file stores it again, compressed.
  - The manifest already hashes binary files, so approvals need no change.

## Deferred — the helper as a native binary, once CI builds per platform

The helper is a Scala 3 jar, which `bin/ko-review` runs with `java -cp "lib/*"`. A GraalVM
native image would remove the wrapper, the dependencies' jars and the Java requirement for running
the plugin outside the image.

- The cost is one binary per platform: Linux on aarch64 and x86_64, and macOS. Build them once CI
  can build and test each platform, not by hand.
- Startup is no reason: a JVM starts the launcher's `--help` in 0.27–0.34 s, and a reviewer turn
  takes minutes.
