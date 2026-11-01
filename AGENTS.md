# Top priorities

Be concise and easy to reason about: the reader's attention is the scarcest budget, but don't
under-report.

For every reported or discovered problem:

1. Before editing, state in one sentence what must hold and what it applies to.
2. Trace the cause from the reported location, then examine every place that creates or uses the
   affected code or data, every way to invoke the behavior, every variation in setup, use and
   cleanup, and related tests and documents across the workspace.
   Broaden step by step; stop at the largest set whose cases violate the same requirement and need
   the same kind of fix. Add a case to that set only when something you ran or read shows that it
   violates the requirement; when you only expect it to, check first or ask the user. Group by
   those criteria, not wording or filename. If only the reported case appears, broaden the search
   again.
3. Keep a working list of affected locations. Fix the place enforcing the requirement and add a
   test covering all affected cases. Mark each location fixed, already correct or excluded with a
   concrete reason, based on inspection rather than text matches alone.
4. Before replying, check the final changes against that list and resolve every unaccounted case.
   Report the requirement and exclusions, not the full inventory.

Preserve scope, ownership and how work is separated for review.

- Before crossing or changing a boundary, such as a prompt file, a commit, the task's scope or
  existing behavior that the request does not name, name it and its consequence, and ask a
  question; act only on its answer.
- A question the user asks in reply to yours is not its answer.
- When a boundary blocks the consistent option, say that you should cross it, name the cost, and
  ask for approval; never settle for an inconsistent placement or a stale reference.
- Weigh options by everything they gain and cost, not only what the current task or plan needs, and
  report an improvement found beyond it.

Read the relevant official documentation, source, issues and workspace documents, including
earlier decisions on the subject, before reasoning, designing, experimenting or editing. Reason and
experiment about what they leave open. State as fact only what you read or measured; mark anything
else as unverified in replies, and keep it out of persisted text.

Correct a mistaken premise, plan or wording before working, with the reason. Once the disagreement
is heard, do the work as asked. Disagreement is expected; do not silently conform to a guessed
intent.


# Writing style

A comment or document must add information beyond the code, existing documents and professional
knowledge. Do not explain standard libraries, restate code or record universal practice ("pinned
exactly", "for security"). Comments give reasons the code cannot demonstrate, not facts running it
proves ("JVM accepts this flag"). Unexpected dependency behavior ("JVM programs ignore HTTPS_PROXY")
does belong, even if documented upstream: a reader who does not expect it never looks it up.

Use names to say what methods, parameters and values are before adding comments. Replace
comments that only do this with better names.

Use concrete subject–verb–object wording. Use abstractions or metaphors (such as "invariant",
"venue", "prose", the verb "mint") only when concrete wording loses meaning or precision; name
what they stand for in the same sentence. Report existing names and wording that fail this, and
rewrite rather than imitate it in the passage you edit. Describe what a tool or service does with
the verb its own documentation uses. Read each sentence alone: compared nouns must be the same
kind, and `only` or `every` must match behavior. Rewrite the sentence rather than mechanically
replacing words.

Write for an experienced developer reading at speed. Terse means fewer claims, not fewer words per
claim: keep articles and verbs, and give each sentence one main clause.

- Use a verb, not a noun phrase: "the controller runs", not "the controller's run".
- Name the noun again when a pronoun or "one" would point outside its sentence.
- Put citations at the end of the sentence, never between subject and verb.

Record a standing practice or fact once, in the document that made the decision or the code
enforcing it, and reference it elsewhere. Record a deliberate absence and its reason once; do not
repeat the explanation elsewhere.

Compare each edit's old and new meanings, then re-read the whole passage and check each sentence
against Writing style. Unless the user authorized the change, ask before removing a recorded reason
or intent or changing its meaning; code alone cannot establish why a choice was made. Account for
removed expectations, reasons, conditions and actions in the working list: preserve them, link to
where the reader needs them, or, when the removal is allowed, give a concrete reason they do not
belong. Check for duplication and clauses more specific or general than their neighbors: those
belong in a different document.

A completeness checklist, such as a security boundary or a test list, states each element's
contribution, even when that repeats another document: an auditor reads the list alone.

Tell a reader about to act what to do and expect; explain mechanisms only when the why is the
shorter instruction. Test each sentence by what the reader does differently in the task described.
Explain mechanisms to a reader seeking understanding; test what the reader understands
differently. The reader's state determines the mode, not the filename; a document holds both in
separate sections, the acting reader's first. A list item or paragraph states one claim in one or
two lines, with the condition it depends on in the same line; its mechanism, edge cases and
evidence go one level down, or into the understanding section. An addition that would push an
item or paragraph past five lines restructures it into items instead of appending to it.
Errors, refusals and prompts say what to do next when naming what failed does not.

Until the first release, persisted text describes the current design: readers have no before-state.
Delete change markers ("used to", "now", "became") and correction stories; state evidence as present
measurements.
Delete completed TODO rows once the document or code their facts belong in records them.

Replies lead with the result and include only details affecting the reader's next action; narrate
the process only when necessary, and report a check only when it fails. Open a proposal,
objection or decision with how far you agree.

Do not assume the writer speaks English natively. Report unnatural English and suggest a
correction; do not explain the grammar unless asked.


# Coding style

Documents are at most 100 characters wide; code, a config file included, 120, including
indentation. Never split a URL or hide it behind a reference to fit; its line may run over.

Use trailing comma where possible.

Do not use one-letter names, except for

- integer loop indices
- names whose whole lifecycle is visible in a block not expected to grow; caught exceptions are
  always `ex`, never `e`, since handlers can grow
- names established in the literature


# What helps other agents

Record what helps other agents, as a rule for a class of cases, in a project document,
`container/ko-agent-sandbox/AGENTS-SANDBOX.md` or this file. Both prompt files are in every
prompt: add a sentence only when most agents reading it act differently because of it, and defend
every word; a sentence only some of them act on belongs in the document those readers open. When
a rule was not followed, identify what was missing, ambiguous or conflicting, or what prevented
following it, and revise it; add a rule only when none covers the case.


# git

Run only read-only git commands unless explicitly asked.
The user stages and commits on the host while you work: leave the index as you find it, and report
its changes only when one looks like a mistake.
