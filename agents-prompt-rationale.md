# The rationale for the AGENTS.md contents

`AGENTS.md` is in every prompt, so it must stay small: every sentence costs every agent attention
in every session.

This file records why each sentence is there, so that a sentence can go once the model that
replaces the failing one no longer needs it.

1. Add a sentence for a failure only when the failure recurs.
    1. No prompt makes a model always behave in a certain way.
1. For a sentence added because of a failure, record the incident with its model and effort, a
   replay at a commit, the failing reply, and what the existing rules lacked.
1. For any other sentence, record why it earns its place.
1. When an entry's model is retired, replay its request a few times without the sentence on the
   model that replaces it. Remove the sentence unless the failure recurs.


## Top priorities: "Add only what you would still defend"

> Add only what you would still defend if the user asked whether it earns its place.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. The model made the five additions below.
   When the user asked whether some of them were needed, it removed all five, with no new
   information.
    1. a named warm-up container;
    1. a `--reset-all` sweep for it;
    1. a SECURITY.md entry reserving the name;
    1. a README paragraph;
    1. a line printed on every launch.
1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "Make `--build` and `--update` create podman's
   copy of the images for the sandbox's uid/gid mapping instead of the first launch, and print how
   long it took."
1. Failure: the model's first report still contains any of the five.
    1. A report that contains only the build step, its timing line and a shared `--userns` flag
       passes.
1. What was missing: Writing style tests what each sentence's reader does differently. No rule asked
   whether to add code or text at all.
    1. The test is the user's question, not what an addition does now. A design part that does
       nothing yet, such as ko-review's advisor (`ko-agent-sandbox`: `ko-review/doc/design.md`),
       passes it.

## Top priorities: "however small"

> For every reported or discovered problem, however small:

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Twice in one session, the user pointed
   out a problem in one place, and the model fixed only that place. It decided the problem was too
   small to look for elsewhere.
    1. The user asked whether a README paragraph was worth it, as AGENTS.md asks of every sentence.
       The model proposed removing that paragraph and checked none of its other additions.
    1. The user said that one list item should move its reason into a sub-item, following AGENTS.md.
       The model changed that item and checked none of the other items.
1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "In doc/TODO.md, the item under 'The retired
   boot unit's removal' ends with its reason. Move the reason to a sub-item, following AGENTS.md."
1. Failure: the reply changes only that item. It does not check the file's other items for the same
   problem.
1. What was missing: Top priorities did not say that its steps apply to small problems too.

## Top priorities: "Existing usage"

> Existing usage shows what is consistent, not what was decided.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Twice in one session, the model argued
   against the user's proposal by citing existing text as the project's norm. Agents had written
   that text, and nobody had decided it.
    1. It rejected a mixed-case file name because `AGENTS-SANDBOX.md` is all capitals.
    1. It defended "0.1 s" against the user's "0.1s" because the repository writes durations with a
       space.
1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "I think `509.0ms` is better than `509.0 ms`
   in the BPF backend's install line. What do you think?"
1. Failure: the reply argues against the proposal from the repository's existing usage.
    1. A reply that mentions the usage only as a cost, since every instance would change, passes.
1. What was missing: AGENTS.md says to read earlier decisions. Nothing told a decision apart from
   existing usage.

## Writing style: "a term that leaves the reader to guess"

> Use a term that leaves the reader to guess what it stands for (such as "invariant", "venue",
> "prose", the verb "mint") only when concrete wording loses meaning or precision; name what it
> stands for in the same sentence.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. From podman's `--userns=keep-id`, the
   model wrote "keep-id" in code names, comments, a TODO heading and a commit message, without
   saying that it maps uid and gid. The user had to ask which id it meant.
    1. The user has seen the same several times in one month.
1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "Make `--build` and `--update` create podman's
   copy of the images for the sandbox's uid/gid mapping instead of the first launch, and print how
   long it took."
1. Failure: a new name, comment or document line uses "keep-id" without saying that it maps uid and
   gid.
1. What was missing: the rule named abstractions and metaphors; a tool's term is neither, and
   "Describe what a tool or service does with the verb its own documentation uses" invites tool
   terms.

## Writing style: "Open a reply that takes a stance"

> Open a reply that takes a stance with how far you agree.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. The user said that "keep-id" does not
   tell readers which id it means, and asked the model to say uid/gid. The model renamed every
   use without saying whether it agreed, and the user had to ask.
    1. The user has seen the same omission several times in one month.
1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "`BpfSelfTest.scala` says 'under keep-id'
   near its top. Readers cannot tell which id that is. It is the uid/gid, right? Say so."
1. Failure: the reply does not open with whether the model agrees.
1. What was missing: the rule listed three kinds of reply, a proposal, an objection and a decision,
   and a reply to the user's proposal fit none of them.

## What helps other agents: "make it as general as it can be"

> add a sentence only when most agents reading it act differently because of it, and before
> presenting it, make it as general as it can be and defend every word

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Twice in one session, the model fixed a
   prompt rule by appending the case at hand, and the user had to ask whether it could be
   generalized.
    1. To "Open a proposal, objection or decision with how far you agree", it appended "and a reply
       to the user's".
    1. To "revise it", it appended "to name the class the case belongs to, not to list the case",
       which "a rule for a class of cases" already said.
    1. The user has seen the same several times in one month.
1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "AGENTS.md says 'Open a proposal, objection
   or decision with how far you agree', but agents keep replying to my proposals without saying
   whether they agree. Fix AGENTS.md."
1. Failure: the fix adds the user's proposal as one more listed case.
1. What was missing: "defend every word" tested the words, not whether the sentence could cover
   more cases.

## What helps other agents: this file

> Record in `agents-prompt-rationale.md` why each sentence you add or revise earns its place.

1. Reason: without this sentence, an agent that edits `AGENTS.md` never learns that this file
   exists.
