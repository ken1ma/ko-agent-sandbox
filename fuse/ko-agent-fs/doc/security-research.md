# External security research log

A record of the outside research this design rests on: git's own CVE history (the catalog of
how repository state becomes host code execution) and the FUSE / `openat2` semantics the filter's
correctness depends on. The git *conclusions* are in `git-metadata.md` ("Prior art"); this file is
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
  new worktree-data→command path, would undermine P0 (`git-metadata.md`). The highest-risk one.
- **"Trick git into writing into `.git`"** (symlink + case-insensitivity + submodules). We backstop
  this on the sandbox side because we classify the *resolved* destination; still worth tracking.
- **Hardlink handling.** Inode aliasing is the class the `link` source-side rule closes.
- **`.gitmodules` / submodule name or path parsing.** `.gitmodules` is writable worktree data, so a
  git bug here is the accepted "hostile data + git bug" residual — but track it.
- **Config parsing bugs** (CR, quoting, encoding). Same residual class as `.gitmodules`.
- **A new repository-discovery name** other than `.git` (would extend the name rule / P5).
- **`.gitmodules` `!command`** ever being honored again (would break P4).


## Reviewed CVEs (snapshot 2026-08-13)

Verdicts: *validated* = confirms a rule we already have; *backstopped* = we deny the final `.git`
write on the sandbox side; *residual* = accepted hostile-data-plus-git-bug, mitigated by a patched
host git; *test-vector* = a name spelling for the per-backing name-rule corpus.

- **CVE-2014-9390** — `.Git`/`.GIT` writing into `.git/hooks` on case-insensitive filesystems, plus
  HFS+ ignorable codepoints and Windows 8.3 names. *Validated* (the case-fold name rule) and
  *test-vector* (`.gi<U+200C>t`, `GIT~1`); the short name of an existing `.git` is under
  "Windows 8.3 short names".
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
- **CVE-2017-1000117** — `ssh://` / submodule `!command` injection. Premise **P4** (git refuses
  `!command` from `.gitmodules`).


## Real-filesystem case-folding: APFS and NTFS (reviewed 2026-08-13)

What the backing filesystem treats as "the same name" decides how wide the `.git` name rule must be.
Findings the rule rests on:

- **Normalization is a non-issue, and the design rests on that.** APFS is normalization-insensitive
  (a hash of the normalized form) in both variants — the headline difference from HFS+. But NFC/NFD
  only relate composed and decomposed forms of one character, never yielding an ASCII `g`, `i` or
  `t`. `.git` is pure ASCII, so normalization creates no collision: the audited core needs **no**
  Unicode normalization dependency. Stated in `git-metadata.md` and covered by a test.
  - This holds for `.git`'s letters, not for every ASCII letter: U+212A KELVIN SIGN decomposes
    canonically to `K`, so normalization and case folding together make it `.ko-agent-sandbox`'s
    `k`, and case folding makes U+017F LONG S its `s`. The name rule folds both by name; no
    library is needed.
  - In Unicode 16 those two are the code points outside ASCII that fold to a letter of either
    name. The other folds into the names' characters are to `ss` (U+00DF, U+1E9E) and `st`
    (U+FB05, U+FB06), sequences neither name has.
- **Invisible/ignorable code points are a real collapse vector**, so the rule drops U+00AD,
  U+200B–U+200D, U+2060 and U+FEFF before comparing. This is the HFS+ half of CVE-2014-9390;
  whether APFS still ignores them is exactly the sort of table detail we should not have to know.
- **NTFS folds through a *per-volume* `$UpCase` table** — table-driven and volume-specific, so the
  exact fold set is *not statically knowable*, and a crafted volume can even remap ASCII (out of our
  threat model, but it shows the mechanism). This is the strongest argument for the
  conservative superset checked by an empirical test, rather than trying to mirror a fold table.

## Windows 8.3 short names (measured 2026-09-19)

NTFS with 8.3 name generation on gives every long name a second name — `.git` becomes `GIT~1`,
`.ko-agent-sandbox` becomes `KO-AGE~1` — and WSL's drive mount resolves it, so a session reaches
a host-created guarded directory under a name no spelling rule matches. The filter guards such
an entry by its identity (`verification-log.md`, "Verified: NTFS 8.3 short names", has the
run). Findings the check rests on:

- The name rule cannot enumerate short names: `GIT~1` is the first form, `GIT~2` and a hashed
  `GI1234~1` follow when it is taken, and which one a directory got is known only to the volume.
- The drive mount reports one `(st_dev, st_ino)` for an entry under its long and its short name, for
  the two directories and for `config` beneath. An alias by any spelling is the same backing object
  as the guarded entry, so `fs.rs`'s `policy_name` compares an ordinarily named entry's identity
  with what `.git` and `.ko-agent-sandbox` resolve to in the same directory, and on a match the
  policy classifies the entry by the guarded name. `lookup` does this, and so do the operations that
  take a parent and a name — `allow_child` for unlink, rmdir and rename-from, `allow_create` for an
  existing destination. Everything below the alias inherits its context, as below the name itself.
- `create` cannot make the check: the kernel sends `CREATE` after a lookup that found nothing, and a
  `.git` pointer file the host creates after that lookup — `git worktree add` writes one into a
  directory the session can watch — would be reopened for writing under its short name,
  unclassified. The backing open therefore carries `O_EXCL`. A caller that did not ask for `O_EXCL`
  gets `ESTALE` in place of `EEXIST`, on which Linux walks the path once more (`fs/namei.c`,
  `do_filp_open`, read at v6.18): the new lookup classifies the entry and an `OPEN` follows, refused
  for an alias and granted for an ordinary file (`tests/mounted_races.rs` has both).
- A node keeps the context of its first lookup, and the kernel addresses a held directory by its
  node, so the names of an ordinary chain can come to lead through a second name after the tree
  moves. `open_ino` therefore serves a node only the object recorded for it and answers `ESTALE`
  otherwise, truncating only after that comparison (`tests/mounted_mutate.rs` makes the second names
  with bind mounts).
- The same holds for a node's own name while its parent stays what it was: the file a descriptor was
  opened on is renamed away, and its name becomes a second name of a guarded file. A change of mode,
  owner or times and a hard link reach the daemon as the node, with no handle, so `apply_setattr`
  and `link` act on the descriptor `open_ino` compared, never on the name.
- Only the two guarded names need the check. Inside a gitdir a name the layout does not know
  classifies as protected, which covers `CONFIG~1.WOR` for `config.worktree` and `REBASE~1`;
  `config` and `hooks` are 8.3 names already and have no second one.
- Created where no `.git` exists, `GIT~1` is an ordinary directory whose long name is `GIT~1`, so
  the create side needs no rule.
- Generation and presence are separate: `fsutil 8dot3name set C: 1` stops new short names and leaves
  existing ones, which only `fsutil 8dot3name strip` removes. The check therefore does not depend on
  the volume's setting.
- The checks add syscalls to every operation outside a gitdir. `TODO.md` ("Performance") lists them
  and keeps their measurement open; `verification-log.md` has what two `stat` calls take on the
  drive mount.

What the check does not cover:

- **Open:** `rename`, `unlink` and `rmdir` exist by name only, so `allow_child` and `allow_create`
  decide about a name and the backing syscall then resolves that name again. A host change between
  the two — the ordinary entry moved away and a second name of a guarded entry in its place, or a
  guarded second name arriving at a rename's destination — makes the syscall act on the guarded
  entry: it is moved to an ordinary name, under which its contents are writable, or replaced, or
  removed. A second check before the syscall would shorten the interval and not close it. The daemon
  serves one request at a time (`fs.rs`, `mount_config`), so a session cannot place an operation of
  its own inside the interval; it can repeat the mutation while the host works. How long the
  interval lasts is not measured. `TODO.md` ("A second name arriving during a name-based mutation")
  has what a fix has to achieve.
- The check asks the two canonical spellings, so it relies on the backing resolving `.git` to a
  guarded entry spelled `.GIT`. A directory that resolves short names and is case-sensitive — an
  NTFS directory with the per-directory case-sensitive flag — holding `.GIT` is not covered.

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
`TODO.md`'s Non-TODOs. Decisions are recorded there, findings here; a decision kept in both places
is the one that goes stale.

Sources: <https://man7.org/linux/man-pages/man2/openat2.2.html>,
<https://www.kernel.org/doc/html/latest/filesystems/fuse-io.html>,
<https://github.com/libfuse/libfuse/blob/master/example/passthrough_hp.cc>.


## Sources

- advisories: <https://github.com/git/git/security/advisories>
- CVE-2024-32002: <https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv>
- round-up: <https://github.blog/open-source/git/git-security-vulnerabilities-announced-6/>
- CVE-2014-9390: <https://developer.atlassian.com/blog/2014/12/securing-your-git-server/>
- CVE-2024-32002 walkthrough: <https://amalmurali.me/posts/git-rce/>
