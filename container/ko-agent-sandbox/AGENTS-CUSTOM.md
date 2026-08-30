# Top priorities

Be concise, go straight to the point, and keep everything easy to reason about.
The human reader's attention is the most valuable budget while AI review is cheap.

Anything pointed out is evidence of a class, never its extent. Before answering, define the class as
a violated invariant and mechanism — not the syntax, flag, wording, or file that exposed it.
Inventory every producer, consumer, entry point, lifecycle variant, test, and document that could
violate it; account for each as fixed, conforming, or deliberately excluded with a concrete
reason. Search structure and trace behavior — wording search is not an inventory. If only the
reported instance appears, assume the class is too narrow. Fix the canonical enforcement point,
add a population-level test, and do not report completion until every member is accounted for.

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
("podman accepts this order"), and never defends against a tool this project does not use. A
dependency behaving contrary to reasonable expectation ("JVM tools ignore HTTPS_PROXY") does earn
its place, even when its own documentation says so: a reader who does not expect the behavior
never looks it up.

A name carries what it can before a comment is written: a comment that only says what a method,
parameter or value is becomes its name, and the comment goes.

A deliberate absence is worth recording once, with its why; the sites that omit it stay silent — a
note per site is the volume the rule exists to save.

A standing practice worth recording is recorded once, at its canonical site, and referenced — never
repeated per instance. When a fact has two homes, it lives where it binds: the document that made
the decision, or the code that enforces it.

Deduplicate by fact, not by file: a table of claim → every site that states it → which one binds.
Every non-binding site then becomes a pointer or is deleted — no third option, and no new homes.
Duplication is a defect, not a preference: do not ask permission.

After inserting or trimming, re-read the merged unit and test every clause against its new
neighbors — for duplication a sentence drafted in isolation smuggles in, and for altitude: a
clause more specific or more general than its neighbors belongs in a different document.

In an enumeration that exists to be checked for completeness — a security boundary, a deny
surface, a test checklist — each element states what it contributes: restatement there is audit
completeness, not noise.

A document whose reader is about to act — the agent instructions, a troubleshooting entry, a
README section — says what to do, not how the thing works. Test each sentence by what the reader
does differently. Quoting an error they will cause and then read teaches nothing in advance,
while quoting a benign message they must recognise and ignore is the instruction itself.
Reference for a reader trying to *understand* — the security model, the design documents — is the
opposite, and the same knife takes substance there. Which mode a passage is in follows the reader's
state, not the file it sits in, and one document holds both. A message read while blocked — an
error, a refusal, a prompt — is act mode and names what to do next. A code comment is reference: it
says why the code is as it is, and earns its place by that alone.

Until the first release, persisted text states the end, never the journey: no reader has a
before-state, so change markers ("used to", "now", "became") and correction stories are
deletions waiting to happen. Evidence is stated as a measurement of the present.
A completed TODO row whose facts have reached their canonical sites is deleted.

Replies follow the earns-its-place rule: lead with the result, include only detail that changes
what the reader does next, and do not narrate your process unless absolutely necessary. When the
user proposes something, lead with whether and how far you agree.

Do not assume the writer is a native English speaker. Report unnatural English, but do not play the
schoolteacher.


# Coding style

Documents are at most 100 characters wide; code is at most 120 — its indentation earns the extra.

Use trailing comma where possible.

Do not use one-letter names, except for

1. integer loop indices
2. names whose whole lifecycle is in view, in a block not expected to grow — though a caught
   exception is always `ex`, never `e`: some handler outgrows that, and one spelling beats two
3. names established in the literature


# git

Do not change the git state: no `add` / `commit` / `rebase` / `push` unless explicitly asked.
