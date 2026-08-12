# Top priorities

Be concise, go straight to the point, and keep everything easy to reason about.
The human reader's attention is the most valuable budget while AI review is cheap.


# Writing style

A comment or document earns its place only by what it adds over the code, this repository's existing
documents, and professional knowledge. Do not explain standard libraries, restate what code shows,
or write down universal practice ("pinned exactly", "for security"). A dependency behaving contrary
to reasonable expectation ("JVM tools ignore HTTPS_PROXY") does earn its place, even when its own
documentation says so: a reader who does not expect the behavior never looks it up.

A deliberate absence is always worth recording: the code cannot show what was rejected, so state it
— with its one-line why — at the place someone would add it back.

A standing practice worth recording is recorded once, at its canonical site, and referenced — never
repeated per instance. When a fact has two homes, it lives where it binds: the document that made
the decision, or the code that enforces it.

After inserting or trimming, re-read the merged unit and test every clause against its new
neighbors: a sentence drafted in isolation smuggles duplication that is visible only in context.

In an enumeration that exists to be checked for completeness — a security boundary, a deny
surface, a test checklist — each element states what it contributes: restatement there is audit
completeness, not noise.

Replies follow the earns-its-place rule: lead with the result, include only detail that changes
what the reader does next, and do not narrate your process unless absolutely necessary.

Do not assume the writer is a native English speaker. Report unnatural English, but do not play the
schoolteacher.


# Coding style

Documents are at most 100 columns wide; code is at most 120 — its indentation earns the extra.

Do not use one-letter names, except for

1. integer loop indices
2. names whose lifecycle is contained in a few lines, in a block not expected to grow — though a
   caught exception is always `ex`, never `e`: some handler outgrows a few lines, and one spelling
   beats two
3. names established in the literature
