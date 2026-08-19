# External security research log

A living record of the outside research this design rests on: git's own CVE history (the catalog of
how repository state becomes host code execution) and the FUSE / `openat2` semantics the filter's
correctness depends on. The git *conclusions* live in `git-metadata.md` ("Prior art"); this file is
the *process* — what was reviewed, when, what to watch for, how to redo it — plus the FUSE/openat2
findings. Refresh periodically (a git or kernel upgrade is a good trigger) and update the dates.

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

### Verified: APFS case-insensitive (macOS 26.4.1, build 25E253; 2026-08-14)

The empirical run the posture calls for, on the default macOS volume (File System Personality:
APFS, the case-insensitive variant), through the full production stack — filtered sandbox session →
FUSE filter → virtiofs → APFS — using `probe/apfs-name-rule-probe.py`:

- All 14 denied spellings (`.git` itself, the four ASCII case variants, the Turkish i-family, the
  four ignorable-code-point forms, the three trailing-punctuation forms) failed with exactly
  `EPERM`.
- All six allowed names were created, and afterwards the host's `lstat(".git")` found nothing and
  `git status` discovered no repository — the property itself, on the real fold table.
- Bonus observation: the NFC and NFD spellings of `.gít` collapsed to **one** file — APFS's
  normalization-insensitivity seen live through the whole stack, confirming both halves of the
  normalization finding above: the filesystem really does treat the forms as one name, and neither
  resolves anywhere near `.git`.

Fold tables are OS-version-specific, so this verifies **this** release against macOS 26.4.1;
re-run the probe when either side moves. Still unverified: ext4 (the control) and NTFS — the
release ships with Windows marked experimental (`TODO.md`).

### Verified: APFS case-sensitive (macOS 26.4.1, build 25E253; 2026-08-18)

The same corpus on the case-sensitive variant, through the same production stack, against a
case-sensitive sparse-image volume mounted under `$HOME` — `probe/name-rule-cs-apfs.sh` drives
the whole run, host-side checks included:

- All 14 denied spellings failed with exactly `EPERM`, and all six allowed names were created.
- Afterwards the host-side `lstat(".git")` found nothing and git discovered no repository at the
  project — the property itself, on this variant's fold table.

### Verified: NTFS (Windows Server 24H2; 2026-08-19)

The corpus through the full Windows production stack — filtered session → FUSE filter in the WSL2
podman machine → the host's `C:` NTFS volume served at `/mnt/c`: every denied spelling failed with
exactly `EPERM`, every allowed name was created, and the host-side `dir .git` and git discovery
found nothing afterwards.

- The 8.3 row answered on a live table: short-name generation is active on the volume — creating
  `GIT~1` through the mount met `EEXIST`, an existing allowed name having already generated it as
  its short name — and host git still discovered no repository, which is the aliasing question
  confirmed rather than assumed.
- NTFS kept the NFC and NFD spellings of `.gít` as two files — normalization-sensitive where APFS
  collapsed them — and neither resolves anywhere near `.git` on either backing.

### Verified: end-to-end coherency, filtered stack (macOS 26.4.1; 2026-08-14)

`probe/coherency-probe.py` on the same machine and stack as the name-rule run: a host-side write
became visible to a fresh `read()` inside the filtered session within the 10 ms polling window, and
a page **mapped before the write** showed the new bytes 0 ms after `read()` did — `AUTO_INVAL_DATA`
invalidating the cached page as designed. The sandbox→host direction holds on the same stack, and
is pinned at the filter's own layer by the rig suite.

The virtiofs premise, as observed on the same machine: the host shares (`/Users`, `/private`,
`/var/folders` — the first is the one project directories live under) mount in the VM as
`virtiofs (rw,relatime,context=system_u:object_r:nfs_t:s0)` — **no `cache=` option appears**, so
the caching mode is decided host-side by the hypervisor (vfkit/applehv) and is not introspectable
from the guest. The premise is therefore behavioral, not declarative: the coherency result above,
plus the perf control's observation that the VM does cache virtiofs *metadata* across processes.
Re-run `coherency-probe.py` after a podman or macOS upgrade — it, not the mount table, is what
notices a changed default. (The `nfs_t` SELinux context is also why the launcher never applies
`:Z` relabeling to machine-shared sources.)

### Measured: coherency on Windows — fresh when unheld, locked when held (Server 24H2; 2026-08-19)

On a Windows host (podman 6.1.0, machine on WSL2, kernel 6.18.33.2-microsoft-standard-WSL2),
measured with host-side ground truth at every step:

- A host-created file, and a host rewrite of a file nothing held open, both reached an in-session
  `read()` promptly — host→session visibility holds for unheld files, and session→host held
  already (the NTFS name-rule run).
- A host write to a file a live session held open failed with a sharing violation ("used by
  another process") until the session released it: the daemon's backing fd reaches NTFS through
  the machine's 9p server, whose handle carries Windows sharing semantics. Isolated below the
  filter: a bare 9p hold (`tail -f` in the machine, no session involved) reproduces the refusal,
  and the write succeeds the moment the hold ends.

Together they close the mmap question by construction: a mapped file cannot go stale under a host
write, because the write is refused while the mapping holds — `probe/coherency-probe.py`'s mmap
half therefore cannot and need not run there. What the lock costs is co-editing, and SECURITY.md
("The project checkout") carries it: a host editor's save is refused while a session holds that
file open.

The Windows 8.3 short name `GIT~1` is in the empirical corpus to be *confirmed* rather than assumed,
not because it is evidence of a git-side gap: the 8.3 leg of CVE-2014-9390 was **Mercurial's**, not
git's, and an 8.3 short name should not be able to alias a dot-leading name like `.git` — which the
NTFS run above confirmed on a volume with generation active.


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
  directory stream in the handle. `opendir` snapshots the entry names into the handle instead.

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
