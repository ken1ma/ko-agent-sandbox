# External security research log

A living record of the outside research this design rests on: git's own CVE history (the catalog of
how repository state becomes host code execution) and the FUSE / `openat2` semantics the filter's
correctness depends on. The git *conclusions* live in `git-metadata.md` ("Prior art"); this file is
the *process* — what was reviewed, when, what to watch for, how to redo it — plus the FUSE/openat2
findings. The runs that verify a claim on a real platform are `verification-log.md`. Refresh
periodically (a git or kernel upgrade is a good trigger) and update the dates.

**Last reviewed:** 2026-08-13, against git 2.47.3. To refresh, re-read the advisories linked at the
foot of this file, ask of each new one *does it let repository state cause host-side code
execution?*, and give any that qualifies a verdict below. Re-read the existing findings against the
current code too: one that has since been acted on is no longer a finding.


## Watch-list — the classes that matter to this filter

A new git CVE is relevant to `ko-agent-fs` if it touches one of these:

- **Hooks / `core.hooksPath` / a new config→command mechanism.** A brand-new config *source*, or a
  new worktree-data→command path, would undermine P0 (`git-metadata.md`). The sharpest one.
- **"Trick git into writing into `.git`"** (symlink + case-insensitivity + submodules). We backstop
  this on the sandbox side because we classify the *resolved* destination; still worth tracking.
- **Hardlink handling.** Inode aliasing is the class the `link` source-side rule closes.
- **`.gitmodules` / submodule name or path parsing.** `.gitmodules` is writable worktree data, so a
  git bug here is the accepted "hostile data + git bug" residual — but track it.
- **Config parsing bugs** (CR, quoting, encoding). Same residual class as `.gitmodules`.
- **A new repository-discovery name** other than `.git` (would extend the name rule / P6).
- **`.gitmodules` `!command`** ever being honored again (would break P5).


## Reviewed CVEs (snapshot 2026-08-13)

Verdicts: *validated* = confirms a rule we already have; *backstopped* = we deny the final `.git`
write on the sandbox side; *residual* = accepted hostile-data-plus-git-bug, mitigated by a patched
host git; *test-vector* = a name spelling for the per-backing name-rule corpus.

- **CVE-2014-9390** — `.Git`/`.GIT` writing into `.git/hooks` on case-insensitive filesystems, plus
  HFS+ ignorable codepoints and Windows 8.3 names. *Validated* (the case-fold name rule) and
  *test-vector* (`.gi<U+200C>t`, `GIT~1`).
- **CVE-2021-21300** — symlink + case-insensitive checkout writes into `.git`. *Backstopped* by the
  resolved-destination gate.
- **CVE-2024-32002** — recursive clone: symlink + case-insensitivity + submodule writes a hook into
  `.git`. *Backstopped* on the sandbox side; *residual* for a host-side clone.
- **CVE-2024-32021** — git creates hardlinks during a local clone. *Validated* (the `link`
  source-side / inode-aliasing rule).
- **CVE-2018-11235** — crafted `.gitmodules` name → traversal into `$GIT_DIR/modules`, hook runs.
  *Residual* (hostile `.gitmodules` + git bug).
- **CVE-2025-48384** — CR inconsistency in a config/submodule path + symlink plants a hook.
  *Residual*; no name-rule change (NTFS forbids control chars; Linux treats `.git\r` as distinct).
- **CVE-2017-1000117** — `ssh://` / submodule `!command` injection. Premise **P5** (git refuses
  `!command` from `.gitmodules`).


## Real-filesystem case-folding: APFS and NTFS (reviewed 2026-08-13)

What the backing filesystem treats as "the same name" decides how wide the `.git` name rule must be.
Findings the rule rests on:

- **Normalization is a non-issue, and that is load-bearing.** APFS is normalization-insensitive (a
  hash of the normalized form) in both variants — the headline difference from HFS+. But NFC/NFD
  only relate composed and decomposed forms of one character, never yielding an ASCII `g`, `i` or
  `t`. `.git` is pure ASCII, so normalization creates no collision: the audited core needs **no**
  Unicode normalization dependency. Stated in `git-metadata.md` and pinned by a test.
- **Invisible/ignorable code points are a real collapse vector**, so the rule drops U+00AD,
  U+200B–U+200D, U+2060 and U+FEFF before comparing. This is the HFS+ half of CVE-2014-9390; whether
  APFS still ignores them is exactly the sort of table detail we should not have to know.
- **NTFS folds through a *per-volume* `$UpCase` table** — table-driven and volume-specific, so the
  exact fold set is *not statically knowable*, and a crafted volume can even remap ASCII (out of our
  threat model, but it shows the mechanism). This is the strongest argument for the
  conservative-superset-plus-empirical-test posture rather than trying to mirror a fold table.

## FUSE correctness & openat2 semantics (reviewed 2026-08-13)

Beyond git's CVEs, two areas of prior art bear on the filter's own correctness. Findings the code
rests on:

- **`openat2` implies `RESOLVE_NO_MAGICLINKS` only "for now."** openat2(2) documents that
  `RESOLVE_IN_ROOT` currently disables magic-link (procfs) resolution but that this may change. We
  set `RESOLVE_NO_MAGICLINKS` explicitly so the guarantee does not depend on that.
- **`openat2` can return `EAGAIN` under a concurrent rename** and the caller is *expected to retry*
  (returned when it cannot prove `..` stayed within the root), so the resolver retries, bounded.
  Without it, an attacker renaming a parent could turn a legitimate op into a spurious failure.
- **Metadata TTL 0 is not data-cache coherency.** The FUSE I/O model shows cached/mmap'd
  *pages* can lag a host write even at attr TTL 0, which is why `AUTO_INVAL_DATA` is negotiated at
  `init`.
- **A readdir that re-reads and paginates by index skips or duplicates entries** when the directory
  changes mid-scan — a known FUSE issue, which libfuse's `passthrough_hp` avoids by keeping the
  directory stream in the handle. What the filter does instead: `fs.rs`, `opendir`.

What these findings settled into — which alternatives were weighed and rejected, and why — is
`TODO.md`'s Non-TODOs. Decisions live there, findings here; a decision kept in both places is the
one that goes stale.

Sources: <https://man7.org/linux/man-pages/man2/openat2.2.html>,
<https://www.kernel.org/doc/html/latest/filesystems/fuse-io.html>,
<https://github.com/libfuse/libfuse/blob/master/example/passthrough_hp.cc>.


## Sources

- advisories: <https://github.com/git/git/security/advisories>
- CVE-2024-32002: <https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv>
- round-up: <https://github.blog/open-source/git/git-security-vulnerabilities-announced-6/>
- CVE-2014-9390: <https://developer.atlassian.com/blog/2014/12/securing-your-git-server/>
- CVE-2024-32002 walkthrough: <https://amalmurali.me/posts/git-rce/>
