# Top priorities

Be concise, go straight to the point, and keep everything easy to reason about.
The human reader's attention is the most valuable budget while AI review is cheap.

Anything pointed out is one instance of a class, not the extent of it — a review finding, a remark,
a failing test, a mistake you catch yourself. Before answering, name the class and look wherever it
could occur: the code, its tests' names and prose, every document that describes it. Searching for
the words finds only that wording; the same error said differently is what survives a per-site fix
and comes back. Fix the class, and report what else it caught.


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

Deduplicate by fact, not by file: a table of claim → every site that states it → which one binds.
Going file by file finds per-file problems and is blind to one fact stated in three, because no
single file reads wrong; searching for the wording finds only that wording. Every non-binding site
then becomes a pointer or is deleted — no third option, and no new homes. Duplication is a defect,
not a preference: do not ask permission, and do not report it as "worth weighing".

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
opposite, and the same knife takes substance there.

Until the first release, persisted text states the end, never the journey: no reader has a
before-state, so change markers ("used to", "now", "became") and correction stories are
deletions waiting to happen. Evidence is stated as a measurement of the present.
A completed TODO row whose facts have reached their canonical sites is deleted.

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
