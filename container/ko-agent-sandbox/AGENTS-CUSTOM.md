# Top priorities

Be concise and keep everything easy to reason about: the human reader's attention is the
scarcest budget, but don't under-report.

Anything pointed out or found while working is evidence of a class, never its extent. Define the
class as a violated invariant and mechanism — not the wording or file that exposed it.
Inventory every producer, consumer, entry point, lifecycle variant, test, and document that could
violate it; account for each as fixed, conforming, or deliberately excluded with a concrete
reason. Search structure and trace behavior — wording search is not an inventory. If only the
reported instance appears, assume the class is too narrow. Fix the canonical enforcement point,
add a test over the whole class, and do not report completion until every member is accounted for.

Preserve the boundaries, such as scope and ownership, including how work is separated for review.
If completing the request requires changing or crossing a boundary, name it and its consequence
and ask.

Before reasoning, designing, or experimenting about how anything works, read what already states
it — the official documentation, the source, the issue tracker, this repository's own documents.
Experiments and reasoning are for what those leave open, never a substitute for reading them.


# Writing style

A comment or document earns its place only by what it adds over the code, this repository's existing
documents, and professional knowledge. Do not explain standard libraries, restate what code shows,
or write down universal practice ("pinned exactly", "for security"). A comment argues a decision
the code cannot demonstrate; it never reassures about a fact running the code demonstrates
("JVM accepts this flag"). A dependency behaving contrary to reasonable expectation
("JVM tools ignore HTTPS_PROXY") does earn its place, even when its own documentation says so: a
reader who does not expect the behavior never looks it up.

A name says what it can before a comment is written: a comment that only says what a method,
parameter or value is becomes its name, and the comment goes.

An abstract term or metaphor — "invariant", "venue", and their kind — earns each use by its
object, named in the same sentence: an invariant *of what*, a venue *among which*. Where a
concrete noun serves — the host build, the container, the machine that ran the test — the
concrete noun wins. Reaching for the abstract term because it is already at hand is the sign
that it does not fit.

A deliberate absence is worth recording once, with its why; the sites that omit it stay silent — a
note per site is the volume the rule exists to save.

A standing practice or fact is recorded once, where it binds — the document that made the
decision, or the code that enforces it — and referenced everywhere else. Duplication is a defect,
not a preference.

After inserting or trimming, re-read the merged unit and test every clause against its new
neighbors — for duplication a sentence drafted in isolation smuggles in, and for level: a clause
more specific or more general than its neighbors belongs in a different document.

In an enumeration that exists to be checked for completeness — a security boundary, a deny
surface, a test checklist — each element states what it contributes: restatement there is audit
completeness, not noise.

A document whose reader is about to act — the agent instructions, a troubleshooting entry, a
README section — says what to do and what to expect, not how the thing works — unless the why is
the shorter instruction. Test each sentence by what the reader does differently.
Reference for a reader trying to *understand* — the security model, the design documents — is the
opposite, and its test is what the reader *understands* differently. Which mode a passage is in
follows the reader's state, not the file it sits in, and one document holds both. A message read
while blocked — an error, a refusal, a prompt — is act mode and names what to do next.

Until the first release, persisted text states the end, never the journey: no reader has a
before-state, so change markers ("used to", "now", "became") and correction stories are
deletions waiting to happen. Evidence is stated as a measurement of the present.
A completed TODO row whose facts have reached their canonical sites is deleted.

Replies follow the earns-its-place rule: lead with the result, include only detail that changes
what the reader does next, and do not narrate your process unless necessary. When the
user proposes something, lead with whether and how far you agree, and only then do the work.

Do not assume the writer is a native English speaker. Report unnatural English, but do not play the
schoolteacher.


# Coding style

Documents are at most 100 characters wide; code is at most 120 — its indentation uses the
extra. A URL is never split or hidden behind a reference to fit; its line may run over.

Use trailing comma where possible.

Do not use one-letter names, except for

1. integer loop indices
2. names whose whole lifecycle is in view, in a block not expected to grow — though a caught
   exception is always `ex`, never `e`: some handler outgrows that, and one spelling beats two
3. names established in the literature


# git

Do not change the git state: no `add` / `commit` / `rebase` / `push` unless explicitly asked.
