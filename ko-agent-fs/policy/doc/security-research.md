# External security research log

This file records the outside research the design rests on:

- git's own CVE history, which lists the ways repository state has become host code execution;
- the FUSE and `openat2` behavior the FUSE backend's correctness depends on.

`git-metadata.md` ("Prior art") has the git *conclusions*. This file has the *process*: what was
reviewed, when, what to watch for and how to redo it. It also has the FUSE and `openat2` findings.
`../../fuse/doc/verification-log.md` has the runs that verify a claim on a real platform.

Refresh this file from time to time, for example after a git or kernel upgrade, and update the
dates.

**Last reviewed:** 2026-08-13, against git 2.47.3. To refresh:

1. Re-read the advisories linked at the end of this file.
2. Ask of each new one: *does it let repository state cause host-side code execution?*
3. Give each one that does a verdict below.
4. Re-read the existing findings against the current code too. A finding the code has since acted
   on is no longer a finding.


## Watch-list — the classes that matter to the workspace policy

A new git CVE matters to `ko-agent-fs` if it touches one of these:

- **Hooks, `core.hooksPath`, or a new way for configuration to name a command.** This is the
  highest-risk class. A brand-new config *source*, or a new path from worktree data to a command,
  would undermine P0 (`git-metadata.md`).
- **"Trick git into writing into `.git`"** (symlink, case-insensitivity and submodules). We still
  track it, although the sandbox side denies the final write: we classify the *resolved*
  destination.
- **Hard-link handling.** The `link` source-side rule closes this class, inode aliasing.
- **Parsing of a `.gitmodules` submodule name or path.** `.gitmodules` is writable worktree data,
  so a git bug here belongs to the accepted residual "hostile data plus a git bug". Track it anyway.
- **Config parsing bugs** (CR, quoting, encoding). They belong to the same residual class as
  `.gitmodules`.
- **A new repository-discovery name** other than `.git`. It would extend the name rule (P5).
- **`.gitmodules` `!command`** honored again. It would break P4.


## Reviewed CVEs (snapshot 2026-08-13)

The verdicts:

- *validated*: the CVE confirms a rule we already have;
- *write denied*: the sandbox side denies the final `.git` write;
- *residual*: an accepted case of hostile data plus a git bug, which a patched host git mitigates;
- *test-vector*: a name spelling for the name-rule corpus of each backing filesystem.

The CVEs:

- **CVE-2014-9390**: `.Git` or `.GIT` writes into `.git/hooks` on case-insensitive filesystems;
  HFS+ ignorable code points and Windows 8.3 names do the same.
  - *Validated* by the case-fold name rule.
  - *Test-vector*: `.gi<U+200C>t`, `GIT~1`.
  - "Windows 8.3 short names" covers the short name of an existing `.git`.
- **CVE-2021-21300**: a symlink and a case-insensitive checkout write into `.git`. *Write denied*
  by the resolved-destination check.
- **CVE-2024-32002**: a recursive clone writes a hook into `.git` through a symlink,
  case-insensitivity and a submodule. *Write denied* on the sandbox side; *residual* for a clone on
  the host.
- **CVE-2024-32021**: git creates hard links during a local clone. *Validated* by the `link`
  source-side rule, which closes inode aliasing.
- **CVE-2018-11235**: a crafted `.gitmodules` name traverses into `$GIT_DIR/modules`, and a hook
  runs. *Residual*: a hostile `.gitmodules` plus a git bug.
- **CVE-2025-48384**: an inconsistent CR in a config or submodule path, together with a symlink,
  plants a hook. *Residual*.
  - No name-rule change: NTFS forbids control characters, and Linux treats `.git\r` as a distinct
    name.
- **CVE-2017-1000117**: `ssh://` or submodule `!command` injection. Premise **P4**: git refuses
  `!command` from `.gitmodules`.


## Real-filesystem case-folding: APFS and NTFS (reviewed 2026-08-13)

What the backing filesystem treats as "the same name" decides how wide the `.git` name rule must
be. The rule rests on these findings:

- **Normalization creates no collision, and the design relies on that.**
  - APFS is normalization-insensitive in both variants: it hashes the normalized form. This is the
    main difference from HFS+.
  - NFC and NFD only relate the composed and decomposed forms of one character. Neither ever
    yields an ASCII `g`, `i` or `t`.
  - `.git` is pure ASCII, so normalization creates no collision with it. The audited core
    therefore needs **no** Unicode normalization dependency. `git-metadata.md` states this, and a
    test covers it.
  - This holds for `.git`'s letters, not for every ASCII letter. U+212A KELVIN SIGN decomposes
    canonically to `K`, so normalization and case folding together make it the `k` of
    `.ko-agent-sandbox`. Case folding makes U+017F LONG S its `s`. The name rule folds both by
    name, so no library is needed.
  - In Unicode 16, those two are the only code points outside ASCII that fold to a letter of either
    name. The other folds into the names' characters produce `ss` (U+00DF, U+1E9E) and `st`
    (U+FB05, U+FB06), sequences neither name contains.
- **Invisible and ignorable code points can make two names collapse into one.**
  - So the rule drops U+00AD, U+200B–U+200F, U+202A–U+202E, U+2060, U+206A–U+206F and U+FEFF
    before it compares.
  - This is the HFS+ half of CVE-2014-9390. The list holds every code point git's `next_hfs_char`
    skips.
  - Whether APFS still ignores them is a table detail we should not have to know.
- **NTFS folds through a *per-volume* `$UpCase` table.**
  - The table drives the fold and belongs to the volume, so the exact set of folds *cannot be known
    in advance*.
  - A crafted volume can even remap ASCII. That is outside our threat model, but it shows how the
    folding works.
  - This is the strongest argument for a conservative superset checked by an empirical test, rather
    than a copy of a fold table.

## Windows 8.3 short names (measured 2026-09-19)

NTFS with 8.3 name generation on gives every long name a second name: `.git` becomes `GIT~1`, and
`.ko-agent-sandbox` becomes `KO-AGE~1`. WSL's drive mount resolves these names. A session therefore
reaches a guarded directory the host created under a name no spelling rule matches. The FUSE backend
guards such an entry by its identity (`../../fuse/doc/verification-log.md`, "Verified: NTFS 8.3
short names", has the run). The check rests on these findings:

- The name rule cannot list the short names. `GIT~1` is the first form; `GIT~2` and a hashed
  `GI1234~1` follow when it is taken. Only the volume knows which one a directory got.
- The drive mount reports one `(st_dev, st_ino)` for an entry under its long name and under its
  short name. This holds for the two directories and for `config` beneath them.
  - An alias under any spelling is therefore the same backing object as the guarded entry.
  - So `fs.rs`'s `policy_name` compares the identity of an ordinarily named entry with what `.git`
    and `.ko-agent-sandbox` resolve to in the same directory. On a match, the policy classifies the
    entry by the guarded name.
  - `lookup` does this. So do the operations that take a parent and a name: `allow_child` for
    unlink, rmdir and rename-from, and `allow_create` for an existing destination.
  - Everything below the alias inherits its context, as everything below the name itself does.
- `create` cannot run the check, so its backing open carries `O_EXCL`.
  - The kernel sends `CREATE` after a lookup that found nothing. The host can create a `.git`
    pointer file after that lookup: `git worktree add` writes one into a directory the session can
    watch. Without `O_EXCL`, that file would be reopened for writing under its short name,
    unclassified.
  - A caller that did not ask for `O_EXCL` gets `ESTALE` instead of `EEXIST`. Linux then walks the
    path once more (`fs/namei.c`, `do_filp_open`, read at v6.18).
  - The new lookup classifies the entry, and an `OPEN` follows. The `OPEN` is refused for an alias
    and granted for an ordinary file (`../../fuse/tests/mounted_races.rs` has both).
- A node keeps the context of its first lookup, and the kernel addresses a held directory by its
  node.
  - So after the tree moves, the names of an ordinary chain can come to lead through a second name.
  - `open_ino` therefore serves a node only the object recorded for it, and answers `ESTALE`
    otherwise. It truncates only after that comparison (`../../fuse/tests/mounted_mutate.rs` makes
    the second names with bind mounts).
- The same holds for a node's own name while its parent stays the same.
  - Example: the file a descriptor was opened on is renamed away, and its name becomes a second name
    of a guarded file.
  - A change of mode, owner or times, and a hard link, reach the daemon as the node, with no handle.
    So `apply_setattr` and `link` act on the descriptor `open_ino` compared, never on the name.
- Only the two guarded names need the check.
  - Inside a gitdir, a name the layout does not know classifies as protected. This covers
    `CONFIG~1.WOR` for `config.worktree`, and `REBASE~1`.
  - `config` and `hooks` are 8.3 names already and have no second name.
- The create side needs no rule. Where no `.git` exists, a created `GIT~1` is an ordinary directory
  whose long name is `GIT~1`.
- Generating short names and having them are separate. `fsutil 8dot3name set C: 1` stops new short
  names and keeps existing ones; only `fsutil 8dot3name strip` removes those. The check therefore
  does not depend on the volume's setting.
- The checks add syscalls to every operation outside a gitdir. `../../fuse/doc/TODO.md`
  ("Performance") lists them and keeps their measurement open. `../../fuse/doc/verification-log.md`
  has what two `stat` calls take on the drive mount.

What the check does not cover:

- **Open:** the `create` test failed in two of three runs on Windows: a create opened the host's
  pointer file. `../../fuse/doc/TODO.md` ("A second name arriving during a name-based mutation") has
  the runs and the unverified cause.
- **Open:** `rename`, `unlink` and `rmdir` exist by name only.
  - So `allow_child` and `allow_create` decide about a name, and the backing syscall then resolves
    that name again.
  - A host change between the two makes the syscall act on the guarded entry. The change can be the
    ordinary entry moved away and a second name of a guarded entry put in its place, or a guarded
    second name arriving at a rename's destination.
  - The guarded entry is then moved to an ordinary name, under which its contents are writable, or
    replaced, or removed.
  - A second check before the syscall would shorten the interval, not close it.
  - The daemon serves one request at a time (`fs.rs`, `mount_config`), so a session cannot place an
    operation of its own inside the interval. It can repeat the mutation while the host works.
  - How long the interval lasts is not measured.
  - `../../fuse/doc/TODO.md` ("A second name arriving during a name-based mutation") has what a fix
    has to achieve.
- The check asks for the two canonical spellings only. It therefore relies on the backing resolving
  `.git` to a guarded entry spelled `.GIT`. It does not cover a directory that resolves short names,
  is case-sensitive and holds `.GIT`: an NTFS directory with the per-directory case-sensitive flag.

## FUSE correctness & openat2 semantics (reviewed 2026-08-13)

Beyond git's CVEs, prior art in two areas bears on the FUSE backend's own correctness. The code
rests on these findings:

- **`openat2` implies `RESOLVE_NO_MAGICLINKS` only "for now."** openat2(2) documents that
  `RESOLVE_IN_ROOT` currently disables magic-link (procfs) resolution, and that this may change. We
  set `RESOLVE_NO_MAGICLINKS` explicitly, so the guarantee does not depend on that.
- **`openat2` can return `EAGAIN` under a concurrent rename, and the caller is *expected to
  retry*.** It returns `EAGAIN` when it cannot prove that `..` stayed within the root. The resolver
  therefore retries, a bounded number of times. Without the retry, an attacker renaming a parent
  could turn a legitimate operation into a spurious failure.
- **Metadata TTL 0 does not make the data cache coherent.** The FUSE I/O model shows that cached or
  mmap'd *pages* can lag a host write even at attribute TTL 0. This is why the FUSE backend
  negotiates `AUTO_INVAL_DATA` at `init`.
- **A readdir that re-reads the directory and pages by index skips or duplicates entries** when the
  directory changes during the scan. This is a known FUSE issue. libfuse's `passthrough_hp` avoids
  it by keeping the directory stream in the handle. `fs.rs`, `opendir`, has what the FUSE backend
  does instead.

`../../fuse/doc/TODO.md`'s Non-TODOs record what these findings settled into: which alternatives
were weighed and rejected, and why. Decisions are recorded there and findings here: a decision kept
in both places is the one that goes stale.

Sources: <https://man7.org/linux/man-pages/man2/openat2.2.html>,
<https://www.kernel.org/doc/html/latest/filesystems/fuse-io.html>,
<https://github.com/libfuse/libfuse/blob/master/example/passthrough_hp.cc>.


## Sources

- advisories: <https://github.com/git/git/security/advisories>
- CVE-2024-32002: <https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv>
- round-up: <https://github.blog/open-source/git/git-security-vulnerabilities-announced-6/>
- CVE-2014-9390: <https://developer.atlassian.com/blog/2014/12/securing-your-git-server/>
- CVE-2024-32002 walkthrough: <https://amalmurali.me/posts/git-rce/>
