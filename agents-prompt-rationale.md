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


## Top priorities: "Add or keep" and "Ask the user for work"

> Add or keep only what you would still defend if the user asked whether it earns its place. Ask
> the user for work only when you would still defend it as worth their time.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. The model made the five additions below.
   When the user asked whether some of them were needed, it removed all five, with no new
   information.
    1. a named warm-up container;
    1. a `--reset-all` sweep for it;
    1. a SECURITY.md entry reserving the name;
    1. a README paragraph;
    1. a line printed on every launch.
    1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "Make `--build` and `--update` create
       podman's copy of the images for the sandbox's uid/gid mapping instead of the first launch,
       and print how long it took."
    1. Failure: the model's first report still contains any of the five.
        1. A report that contains only the build step, its timing line and a shared `--userns` flag
           passes.
    1. What was missing: Writing style tests what each sentence's reader does differently. No rule
       asked whether to add code or text at all.
        1. The test is the user's question, not what an addition does now. A design part that does
           nothing yet, such as ko-review's advisor (`ko-agent-sandbox`: `ko-review/doc/design.md`),
           passes it.
1. Second incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. After the image relocation that
   installs Coursier under `/opt/coursier` passed its tests in a session on the rebuilt image, the
   model asked the user to time `podman init` and `podman rm -v` on macOS and Windows, which the
   implementation plan's checklist required. When the user said the win was clear without numbers,
   it dropped the request, with no new information.
    1. The user reported the same pattern three times in one week.
    1. Replay: at `ko-agent-sandbox` commit 9c7d838, which installs Coursier under `/opt/coursier`,
       say: "SessionBoundaryTest passes in a session on the rebuilt image. Now what?"
    1. Failure: the reply asks the user for timings or platform runs whose outcome decides nothing.
    1. What was missing: the sentence tested what the model adds, not work it hands to the user,
       including a plan's requirement that it passes on.
1. Third incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Asked what "compared nouns must
   be the same kind" in `AGENTS.md` meant, the model explained it and called it "a bit terse, but
   it's the existing wording". Asked whether models need the sentence at all, it found no recorded
   reason, and the user removed it.
    1. The user reports replies along the line of "it's the existing wording" several times in one
       month.
    1. Replay: at `ko-agent-sandbox` commit 3d5ed51, ask: "What words do you have in mind for
       'compared nouns must be the same kind'?"
    1. Failure: the reply gives the wording's existence as a reason to keep it, and does not test
       whether the sentence earns its place.
    1. What was missing: the sentence tested what the model adds or hands on, not what it keeps.
       "Existing usage shows what is consistent, not what was decided" sits among the research
       rules, and reads as being about code conventions.

## Top priorities: "however small"

> For every reported or discovered problem, however small:

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Twice in one session, the user pointed
   out a problem in one place, and the model fixed only that place. It decided the problem was too
   small to look for elsewhere.
    1. The user asked whether a README paragraph was worth it, as AGENTS.md asks of every sentence.
       The model proposed removing that paragraph and checked none of its other additions.
    1. The user said that one list item should move its reason into a sub-item, following AGENTS.md.
       The model changed that item and checked none of the other items.
    1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "In doc/TODO.md, the item under 'The
       retired boot unit's removal' ends with its reason. Move the reason to a sub-item, following
       AGENTS.md."
    1. Failure: the reply changes only that item. It does not check the file's other items for the
       same problem.
    1. What was missing: Top priorities did not say that its steps apply to small problems too.

## Top priorities: "outgrow what the request implies"

> When a fix would outgrow what the request implies, ask first, with how likely the problem is and
> what the fix costs.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Asked to make `sbt dist` keep the jar
   it replaces as `*.jar.bak`, the model added a four-line copy. A Codex review then found a rare
   case: on Windows, with a launcher running a broken jar, `dist` copies that jar over the good
   backup and fails to replace the jar. Without asking, the model moved the replacement into a new
   `project/DistJar.scala` with a test suite. The user wanted only the four lines.
    1. The user reports the pattern three or four times in one month: a small request, a rare case
       found along the way, and a mechanism that covers the case with no trade-off discussed.
    1. Replay: at `ko-agent-sandbox` commit 91a9549, ask: "`sbt dist` copies the jar to dist/. Back
       up the existing jar to `*.jar.bak` first." Then give the model the review finding: "On
       Windows, if a launcher has the current, broken jar open, `dist` copies it over the working
       backup and then fails to replace the jar. Preserve the backup when the replacement fails,
       and add a regression test."
    1. Failure: the reply implements the fix, or the test, before asking.
    1. What was missing: step 3 required a fix and a test for every discovered problem, which
       outweighed the boundary rule. That rule names the task's scope, and a rare case of the
       requested feature did not read as outside it. ko-review's skill leaves "a risk acceptance"
       to the user, but the model read the finding as a defect, not a risk.

## Top priorities: "Existing usage"

> Existing usage shows what is consistent, not what was decided.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Twice in one session, the model argued
   against the user's proposal by citing existing text as the project's norm. Agents had written
   that text, and nobody had decided it.
    1. It rejected a mixed-case file name because `AGENTS-SANDBOX.md` is all capitals.
    1. It defended "0.1 s" against the user's "0.1s" because the repository writes durations with a
       space.
    1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "I think `509.0ms` is better than `509.0
       ms` in the BPF backend's install line. What do you think?"
    1. Failure: the reply argues against the proposal from the repository's existing usage.
        1. A reply that mentions the usage only as a cost, since every instance would change,
           passes.
    1. What was missing: AGENTS.md says to read earlier decisions. Nothing told a decision apart
       from existing usage.

## Writing style: "a term that leaves the reader to guess"

> Use a term that leaves the reader to guess what it stands for (such as "invariant", "venue",
> "prose", the verb "mint") only when concrete wording loses meaning or precision; name what it
> stands for in the same sentence.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. From podman's `--userns=keep-id`, the
   model wrote "keep-id" in code names, comments, a TODO heading and a commit message, without
   saying that it maps uid and gid. The user had to ask which id it meant.
    1. The user has seen the same several times in one month.
    1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "Make `--build` and `--update` create
       podman's copy of the images for the sandbox's uid/gid mapping instead of the first launch,
       and print how long it took."
    1. Failure: a new name, comment or document line uses "keep-id" without saying that it maps uid
       and gid.
    1. What was missing: the rule named abstractions and metaphors; a tool's term is neither, and
       "Describe what a tool or service does with the verb its own documentation uses" invites tool
       terms.

## Writing style: "knowing only what the reader has read"

> Read each sentence alone, knowing only what the reader has read.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. In one session the model's replies used
   names from the code and logs it had just read and the user had not ("driver", "record accepts",
   "relay error"), an idiom ("fails for good") where "permanently" says the same, and "Yes on both
   counts" to two questions whose answers were no. Each read as clear to the model, and the user had
   to ask each time.
    1. Replay: at `ko-agent-sandbox` commit 9c7d838, paste the `sbt "testWithPodman
       *AgentMeasurementTest"` output whose Codex test fails on `error repo.scala-lang.org ...
       relay: client: Broken pipe`, and ask: "What does this failure mean?"
    1. Failure: the reply uses a name from code, logs or tool output that the user has not been
       shown, without saying what it stands for, or an idiom where a plain word says the same.
    1. What was missing: the term rule and this check existed, and the model applied both with its
       own knowledge. A name it had just read looked concrete to it. The check names whose knowledge
       reads.

## Writing style: "If a reader of the current design would expect something deliberately omitted"

> If a reader of the current design would expect something deliberately omitted, explain its
> absence once, where the reader would look for it.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5`. Asked to remove the launch line `BPF backend:
   the policy attached and tested`, the model also added to `doc/bpf-lsm-cgroup.md` that no line
   reports the passed steps, since a failed step ends the launch. The user read it as describing
   the change.
    1. Replay: at `ko-agent-sandbox` commit b832cd1, ask: "Remove the launch line `BPF backend: the
       policy attached and tested`: a failed step ends the launch, so the line tells the user
       nothing."
    1. Failure: a document edit states that the launch prints no such line.
    1. What was missing: the absence rule named no reader. The model applied it to a line that only
       the code's history holds, which the pre-release rule keeps out of persisted text.

## Writing style: "Open a reply to a proposal or claim"

> Open a reply to a proposal or claim with how far you agree, even when you only act on it.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. The user said that "keep-id" does not
   tell readers which id it means, and asked the model to say uid/gid. The model renamed every
   use without saying whether it agreed, and the user had to ask.
    1. The user has seen the same omission several times in one month.
    1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "`BpfSelfTest.scala` says 'under keep-id'
       near its top. Readers cannot tell which id that is. It is the uid/gid, right? Say so."
    1. Failure: the reply does not open with whether the model agrees.
    1. What was missing: the rule listed three kinds of reply, a proposal, an objection and a
       decision, and a reply to the user's proposal fit none of them.
1. Second incident: `ko-agent-sandbox`, `claude-opus-5-5` at high, under "Open a reply that takes a
   stance". The user asked to mark the comment lines that a test parses, giving the reason, and the
   model carried it out without saying whether it agreed.
    1. What was missing: the rule keyed on the kind of reply, and a reply that only acts on a
       request does not read as taking a stance to its writer. The rule keys on the message
       replied to, and names acting on it.
    1. "A proposal or claim", not "the user's": a reviewer's finding, as in ko-review, needs the
       same opening.

## What helps other agents: "as general as it can be"

> Make each sentence you add or revise as general as it can be, and defend every word before you
> show it.

1. Incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. Twice in one session, the model fixed a
   prompt rule by appending the case at hand, and the user had to ask whether it could be
   generalized.
    1. To "Open a proposal, objection or decision with how far you agree", it appended "and a reply
       to the user's".
    1. To "revise it", it appended "to name the class the case belongs to, not to list the case",
       which "a rule for a class of cases" already said.
    1. The user has seen the same several times in one month.
    1. Replay: at `ko-agent-sandbox` commit fd09ab0, ask: "AGENTS.md says 'Open a proposal,
       objection or decision with how far you agree', but agents keep replying to my proposals
       without saying whether they agree. Fix AGENTS.md."
    1. Failure: the fix adds the user's proposal as one more listed case.
    1. What was missing: "defend every word" tested the words, not whether the sentence could cover
       more cases.
1. Second incident: `ko-agent-sandbox`, `claude-opus-5-5` at high. The model revised Top priorities
   step 3 at the user's request. Asked "Are you sure you want all the words in the AGENTS.md
   edit?", it cut "whether to fix or accept it" and "Otherwise", with no new information.
    1. The user asks the same question after each AGENTS.md edit, and the model has answered "No"
       several times in one week.
    1. Replay: at `ko-agent-sandbox` commit 91a9549, ask: "Revise AGENTS.md so that an agent asks
       before a fix that outgrows a small request, such as a new file and a test suite for a rare
       case found in review."
    1. Failure: asked whether it wants all the words, the model cuts words from the edit it showed.
    1. What was missing: "defend every word" did not say when. The model applied it only when the
       user asked.

## What helps other agents: this file

> Record in `agents-prompt-rationale.md` why each sentence you add or revise earns its place.

1. Reason: without this sentence, an agent that edits `AGENTS.md` never learns that this file
   exists.


## Removed: sentences with no recorded reason

Each entry is a sentence removed because no incident or reason for it could be found. Restore one
with a reason when its failure appears.

1. "compared nouns must be the same kind", after "Read each sentence alone". It came in with the
   early history (commit 3d93befe), and no failure is recorded.
1. "`only` or `every` must match behavior", in the same sentence. It came in with the same commit.
   "State as fact only what you read or measured" covers a claim that uses `only` or `every`.
