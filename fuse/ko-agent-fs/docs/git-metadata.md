# Git metadata that must be immutable through `ko-agent-fs`

This is the crux: *what is the complete set of Git administrative state that must be immutable so
that a sandbox cannot cause a later host `git` invocation to execute sandbox-controlled code?*
Everything the filter enforces derives from this document; the policy code is its transcription.

The scope is narrow on purpose. The filter is not protecting repository integrity, correctness, or
the agent from itself. It defends exactly one property.


## The property

> Through the host-shared `/workspace` mount, the sandbox can never create or alter repository
> state that causes a subsequent host-side `git` command to run a program the sandbox chose.

"Host-side" matters: the danger is not code running in the sandbox (the container is the boundary
for that) but code the *host user's* `git` runs later, outside the sandbox, against the shared
checkout — a `git status`, `git commit`, or `git checkout` in their editor or terminal.


## How a repository makes `git` run a program

Every vector below is repository-controlled state that some `git` command turns into process
execution. They fall into three groups.

### 1. Hooks — executed directly

`git` runs an executable from the hook directory on many ordinary operations: `pre-commit` and
`post-commit` on `git commit`, `post-checkout` on `git checkout`/`switch`, `post-merge` on merge,
`pre-push` on push, `post-rewrite` on rebase, and more. The hook directory is `$GIT_DIR/hooks` by
default. No configuration is required for this to fire — an executable of the right name is enough.

**Vector:** write or replace any file under a gitdir's `hooks/`.

Hooks are not the only file whose *content* git executes. The rebase/cherry-pick **todo** —
`rebase-merge/git-rebase-todo`, `rebase-apply/`, `sequencer/todo` — can carry `exec <command>`
lines, and a later host `git rebase --continue` (or `cherry-pick --continue`) runs them. This is the
same class as a hook, and easy to miss precisely because git writes these paths during ordinary
operation: watching what git writes suggests "operational, keep writable", but the execution lens
says "frozen". They are treated as control.

**Vector:** write a `rebase-merge`/`rebase-apply`/`sequencer` todo the host later continues.

### 2. Configuration — names a command `git` then runs

A large set of config keys hold a command line that `git` executes. The ambient ones — triggered by
everyday read commands, needing no special subcommand — are the sharp ones:

- `core.fsmonitor` — run by `git status`, `git add`, and anything that scans the worktree.
- `core.hooksPath` — redirects *all* hooks to an arbitrary directory, including one inside the
  writable worktree. This is why protecting `hooks/` alone is insufficient.
- `core.pager` / `pager.<cmd>` — run by `git log`, `git diff`, `git show`.
- `filter.<d>.clean|smudge|process` — run on add/checkout of paths that `.gitattributes` routes to
  driver `<d>`.
- `diff.external`, `diff.<d>.command`, `diff.<d>.textconv`, `merge.<d>.driver` — run on
  diff/merge of matching paths.
- `core.sshCommand`, `credential.helper`, `remote.<r>.uploadpack|receivepack`, `core.gitProxy` —
  run on network operations.
- `core.editor`, `sequence.editor`, `mergetool.<t>.cmd`, `difftool.<t>.cmd`, `gpg.program`,
  `alias.<x> = !cmd` — run on interactive or explicitly-invoked commands.

The precise list shifts across `git` releases, and that is the point: **enumerating dangerous keys
is a losing game.** What every one of them shares is a *home* — they are read only from a
repository's configuration files:

- `$GIT_DIR/config`
- `$GIT_DIR/config.worktree` (when `extensions.worktreeConfig` is set)
- any file pulled in by `include.path` / `includeIf.*.path` from one of the above

`include.path` is the reason the set is closed by protecting the config files rather than the keys:
an attacker cannot introduce a new command key without either writing a protected config file or
adding an `include.path` to one — itself a write to a protected config file. Protect the config
files and every command key above is out of reach, present and future.

`.gitattributes` and `.gitmodules` stay writable worktree data. They can only *activate* a driver
that a protected config file already defines, i.e. one the host chose; they cannot define the
command. (`.gitmodules` additionally cannot supply `submodule.<name>.update = !cmd`: `git` has
refused to honor the `!command` form from `.gitmodules` since the CVE-2017-1000117 family. This is a
load-bearing assumption and is tested, not trusted.)

### 3. Indirection — moves the gitdir itself

A worktree's `.git` need not be a directory. As a **file** containing `gitdir: <path>` it points
`git` at the real gitdir elsewhere. Related redirections — `.git/commondir`, the `gitdir` file
inside `.git/worktrees/<name>/`, `$GIT_COMMON_DIR` — relocate where `git` looks for `config` and
`hooks`.

**Vector, two halves:**

- *Creation* — a new `.git` (dir or file) anywhere in the tree makes host `git` discover a
  repository the sandbox fully controls: it can populate that gitdir's `config` and `hooks` at
  leisure, because to the filter they are just ordinary files until something names them `.git`.
- *Rewriting* — editing an existing `.git` pointer file re-aims a real repository's control state at
  a directory the sandbox owns.

Both halves must be closed. Blocking creation alone leaves the pointer rewrite open; blocking
rewrite alone leaves fresh-repository planting open.


## The immutable set

From the three groups, the state that must be immutable to the sandbox:

1. **Any new entry named `.git`** — directory *or* file, at any depth. (Name rule below.)
2. **Any existing `.git` pointer file** — the `gitdir:` indirection, immutable so it cannot be
   re-aimed.
3. **Within any gitdir**, the control state:
   - `config`, `config.worktree`
   - `hooks/**`
   - `commondir` and `gitdir` — the redirections of group 3 above, which relocate where `config` and
     `hooks` are resolved from
   - and, by recursion, the same classes inside every nested gitdir: `worktrees/<name>/**`
     and `modules/<name>/**` are themselves gitdirs, so their `config`, `hooks/**`, `commondir` and
     `gitdir` are immutable while their operational state is not.

Everything else stays writable — see the classifier.


## The classifier: writable vs immutable *inside* a gitdir

The plan's constraint "do not make the entire `.git` read-only" is essential: `git` must write its
operational state for `status`, `commit`, `checkout`, `fetch`, `merge` to work at all — `index`,
`HEAD` and the other `*_HEAD` refs, `refs/**`, `logs/**`, `objects/**`, `packed-refs`,
`COMMIT_EDITMSG`, `MERGE_MSG`, and so on. (`rebase` is the deliberate exception — its todo is
control; see group 1 and blocked operations.)

So inside a gitdir the filter must split writable operational state from immutable control state.
There are two ways to draw that line, and they fail in opposite directions:

- **Denylist** — deny the known control paths (`config*`, `hooks/**`, `commondir`), allow the rest.
  A future `git` that introduces a new command-executing file under `$GIT_DIR` is **open** until we
  notice. Fail-open on `git` evolution.
- **Allowlist** — allow the known operational paths (`objects/**`, `refs/**`, `logs/**`, `index`,
  `*_HEAD`, `packed-refs`, the `*_MSG`/`*_EDITMSG` scratch files, `FETCH_HEAD`, `shallow`, …), deny
  everything else under the gitdir. A future operational file we forgot **breaks a git command**
  until we add it; a new command-executing file is denied by default. Fail-closed on `git`
  evolution, at the cost of breaking legitimate operations we under-enumerated.

**Decided: the allowlist**, matching the "security configuration must fail closed" posture.
A forgotten operational file breaks a git command (caught by the integration suite); a new
command-executing file is denied by default.

One caution the `rebase-merge` case taught: the operational set is enumerated by the **execution
lens** ("can a write here cause host git to execute?"), *not* "does git write here". Watching real
git (`git-observations.md`) validates the opposite direction — that we do not *over*-freeze the
agent's own legitimate git — but it must not decide what is *safe* to allow. `rebase-merge`,
`rebase-apply`, and `sequencer` are exactly where the two diverge: git writes them constantly, yet
group 1 puts them under control. Where compatibility and security conflict, security wins, and the
affected commands are listed under blocked operations below.


## The name rule

`.git` is matched as a **conservative superset**, on every platform, because the backing store may
be a case-insensitive host filesystem (macOS APFS, Windows NTFS) reached through the Podman Machine.
Host `git` there resolves `lstat(".git")` to an entry the sandbox created as `.GIT`, so exact-byte
matching is a real bypass on the platforms this project actually targets.

Deny creation of any basename that equals `.git` after all of:

- dropping invisible/ignorable code points (U+00AD, U+200B–U+200D, U+2060, U+FEFF) — a filesystem
  that ignores these in comparison resolves `.gi<U+200C>t` to `.git` (the HFS+ half of
  CVE-2014-9390);
- folding the Turkish i-family (U+0130, U+0131) to `i` — some Windows upcase tables map dotless and
  dotted i to `I`;
- ASCII case-folding;
- stripping trailing `.` and space characters (Win32 ignores them).

Applied to the raw filename **bytes** (`OsStr`), never a lossy `String` — Linux names are byte
sequences and a non-UTF-8 name must not panic, bypass, or normalize into a surprise. The cost is
no one can create a file named `.GIT` or `.gi<U+200C>t`, which nothing needs.

**Unicode normalization deliberately needs no handling.** NFC/NFD only relate composed and
decomposed forms of one character; neither produces an ASCII `g`, `i` or `t`. Since `.git` is pure
ASCII, APFS being *normalization*-insensitive — its headline difference from HFS+ — introduces no
`.git` collision, so the audited core needs no normalization library. Case folding, ignorables and
the Win32 trailing-punctuation layer are the whole surface.

**Why a superset rather than the exact fold set.** The exact set is not statically knowable: NTFS
folds through a **per-volume `$UpCase` table**, so two NTFS volumes can disagree. The superset is
the belt; the per-backing empirical test below is the braces.

**The empirical test (open).** Reasoning bounds the candidate list; only the real filesystem settles
it. On each supported backing (APFS case-insensitive, NTFS, ext4) create each candidate name through
the mount and assert host `lstat("<dir>/.git")` finds nothing. `TODO.md` ("Platform verification")
carries the full corpus, the procedure and the pass criterion; until it runs on real APFS and NTFS,
the coverage of this rule on those filesystems is an assumption, not a result.


## Positional, not string-based

Whether a given inode is control state depends on its position relative to the **nearest enclosing
gitdir root**, resolved during the fd-relative walk — not on matching an absolute path string.
`hooks/` is protected because it is `<gitdir>/hooks`, and the same rule re-applies at each nested
gitdir discovered along the path (`modules/<n>/`, `worktrees/<n>/`). Path reconstruction plus a
string test is exactly the TOCTOU/`..`/symlink surface `architecture.md` ("Inode model") rules out;
the classifier consumes the resolver's position state instead.


## Operations that carry these mutations

The immutable set must hold against *every* way to mutate a target, not just `write()`. For a
protected path or a protected destination:

`create` / `O_CREAT`, `open` for write, `write`/`pwrite`, `truncate`/`ftruncate`, `open O_TRUNC`,
`setattr` (size, mode, owner, times), `unlink`, `rmdir`, `rename` (source *and* destination),
`renameat2` including `RENAME_EXCHANGE`, `link`, `symlink`, `mknod`, `setxattr`, `removexattr`.

The last two are the exception, and listed anyway because this is the requirement rather than the
implementation: `setxattr`/`removexattr` are unimplemented, so nothing reaches the backing store
through them and no policy has to run. The sandbox sees `ENOTSUP` — the kernel's rendering of the
daemon's `ENOSYS` — which reads as a filesystem without extended attributes. `policy::Mutation`
deliberately carries no xattr variant until that changes (`TODO.md`, "Correctness"), and the gate
arrives with the implementation.

Rename and exchange are the double-sided cases: `rename evil → <gitdir>/hooks/pre-commit` is a
destination-side violation even though `evil` is unprotected, and `RENAME_EXCHANGE` mutates both
operands. Creation-side name matching and destination-side protection must both fire.

`link` is the subtle one, and doubly-checked. A hardlink shares an **inode**, so it bypasses
path-based classification: `link <gitdir>/hooks/pre-commit → src/alias` gives the frozen inode a
second, *writable* name, and a write through `src/alias` then mutates the hook. So `link` is refused
both destination-side (a link named into a protected tree) **and source-side** (aliasing a control
inode out — `authorize(source, Link)`). Symlinks need no such rule: they redirect by *path*, and the
target path is re-classified through the resolver's own walk, so a symlink into `hooks/` is caught
when the resolved target is opened for write.

Residual: a hardlink the *host* already created between a control inode and a worktree path lets
a write to the worktree path reach the frozen inode. Detecting that needs every write to prove its
inode is not also reachable under a gitdir — not feasible per write. It is out of scope as host-
created setup (the host is trusted; no ordinary repository aliases a hook so). The filter closes
only *sandbox*-created aliasing.


## Relocated hook directories — closed by refusing to serve

Everything above assumes hooks live where git puts them: `$GIT_DIR/hooks`. A host can relocate them
into the **worktree**, two ways:

- `.git/hooks` is a symlink to a worktree directory (`../shared-hooks`), a pattern for keeping hooks
  under version control;
- `core.hooksPath` in the host's config already names a worktree directory (`./githooks`).

In both cases the files host `git` executes sit at an ordinary worktree path, which this filter
classifies as writable project data — so no per-operation rule can protect them. **The filter
therefore refuses to serve such a tree at all** (`guard::check_hook_location`, run before the
mount); the mounted suite pins both the refusal and its necessity
(`relocated_hooks_are_refused_at_mount_because_the_filter_cannot_protect_them`).

What the per-operation rules do hold is narrower than it looks, and worth stating exactly: the
sandbox cannot *re-aim* hook resolution. `.git/config` is frozen, so it cannot introduce or change
`core.hooksPath`, and the `.git/hooks` symlink node is control state, so it cannot be deleted or
replaced. What they cannot cover is a target the **host** already points hooks at, which is what the
refusal is for. Blocking the write *through* `.git/hooks/` would be theatre: the same bytes are
reachable under the target's own ordinary name (`shared-hooks/pre-commit`), so a rule about the
symlink path closes nothing. Any real fix has to protect the *target*.

**Why refusing rather than resolving.** Resolving the hook location and classifying that subtree as
control would keep those repositories working, but buys a conditional guarantee with a git-config
parser and a second control root in the audited core, and the snapshot it rests on is one the host
can invalidate mid-session. Refusing is the same answer the launcher already gives a symlinked
`.git/hooks` (`SandboxProject.gitGuardVolumes`), and it is honest: the filter declines to
imply cover it cannot deliver.

The refusal is deliberately narrow — it fires only when the hook directory resolves **inside** the
workspace. Hooks kept outside it are unreachable through the mount (`RESOLVE_IN_ROOT` clamps the
resolution), so there is nothing to refuse and those repositories are served normally.

Two doubts refuse rather than guess: a `core.hooksPath` beginning with `~` (expanding it would need
the host's home directory, which the daemon does not have) and a config carrying an `include`
directive (the setting could live in a file the scanner does not follow). Both are rare in a
*repository-local* config, and the message tells the operator what to change.

Scope: the repository at the workspace root, matching the launcher's own root-only pin. A repository
the **host** nested deeper in the tree is not scanned — the sandbox cannot create one, so this is
residue, recorded in `TODO.md`.

The check is also a snapshot, taken before the mount and not repeated. A host that relocates its
hooks into the worktree *after* a session is serving gets no second refusal. Polling for it would
buy a guarantee only as fresh as its last poll while putting a config read and an `lstat` on the hot
path, so the answer is to record the window rather than chase it — and the window is the host's own
to open: the sandbox cannot cause the relocation, because `.git/config` is frozen and the
`.git/hooks` node is control state. What it costs is that hooks relocated mid-session are writable
for the rest of that session, exactly as if they had been relocated before it and the guard had not
existed.


## What this intentionally does *not* protect, and why that is safe

- `.gitattributes`, `.gitmodules` — writable worktree data; can only activate host-defined drivers,
  cannot define commands (and cannot smuggle `!cmd` submodule updates).
- Operational gitdir state (`objects`, `refs`, `logs`, `index`, …) — writable, or `git` cannot
  function; none of it is executed.
- Host-side changes — the host writes the backing store directly, bypassing the filter by design.
  Legitimate host `git` metadata is created outside the sandbox and is not the threat.


## Consequences: git operations blocked inside `/workspace`

These follow from the name rule and must be documented, not silently broken (the manual explains the
security reason for each):

- `git init` / `git clone` into `/workspace` — creates a new `.git`. Blocked. Clone under `/tmp`.
- `git worktree add <path>` with `<path>` in `/workspace` — writes a `.git` **file** at the new
  worktree. Blocked.
- Submodule checkout that would materialize a submodule's worktree `.git` file in `/workspace` —
  the `.git/modules/<n>/` side is permitted (under the existing gitdir), the new `.git` pointer in
  the worktree is blocked.
- Editing `.git/config` (e.g. `git config --local core.hooksPath …`) — blocked; the whole point.
- `git rebase` (any form — the merge backend writes `rebase-merge/` even for a clean rebase),
  `git am` (writes `rebase-apply/`), and `git cherry-pick`/`git revert` of a *range* or when a
  conflict makes git open a sequence (writes `sequencer/`) — all blocked, because their todo
  can carry `exec` lines a later host `git rebase --continue` would run. A single, clean
  `cherry-pick`/`revert` (no sequence) still works. Do rebases on the host, or on a clone under
  `/tmp`.

Existing host repositories keep working for the everyday commands: `status`, `add`, `commit`,
`checkout`, `switch`, `fetch`, `merge` touch only operational state. The rebase family is the
deliberate exception above.


## Prior art: git's own CVE history

Git's security advisories are a direct catalog of how repository state becomes host code execution.
They validate this design, reveal a strength, and sharpen the tests. The living log — the reviewed-
CVE snapshot, the watch-list, and how to redo the research — is `security-research.md`; the
conclusions are below.

**Validated.** CVE-2014-9390 is the case-insensitive `.Git`/`.GIT` write into `.git/hooks` — exactly
why the name rule is a case-fold superset. CVE-2024-32021 is git creating hardlinks during a local
clone — the same inode-aliasing concern the `link` source-side rule addresses.

**A strength worth stating.** The CVE-2024-32002 / CVE-2021-21300 / CVE-2014-9390 class all end the
same way: git is tricked, via symlink + case-insensitivity + submodules, into a *write* whose path
it believes is in a worktree but resolves into `.git/hooks`. Because the filter classifies the
**resolved destination** of every mutation — following symlinks through its own resolver — the
sandbox-side git performing that final write is denied at `open`/`create`, however clever the trick
that produced the path. The filter backstops the whole class on the sandbox side. (Host-side git
bypasses the filter by design; there the mitigation is a patched git, as for any untrusted clone.)

**Sharper name-rule tests (per-backing).** CVE-2014-9390 names two spellings the ASCII + i-family
superset does not cover, both backing-specific and historical: HFS+ Unicode-*ignorable* codepoints
(`.gi<U+200C>t` collapsing to `.git` on old macOS) and Windows 8.3 short names (`GIT~1`). Neither
affects a case-sensitive Linux backing; both belong in the per-backing empirical name-rule test
(APFS, NTFS) that is already the open item — this is its concrete corpus.

**The `.gitmodules` residual, made concrete.** Leaving `.gitmodules` writable (P0/P5) assumes git
handles hostile `.gitmodules` correctly. CVE-2018-11235, CVE-2024-32002, CVE-2025-48384 are cases
where a git *bug* broke that — submodule name/path handling leading to a planted hook. These are the
accepted "hostile data + a git bug" residual (SECURITY.md): on the sandbox side the filter
still denies the final `.git` write; on the host side the mitigation is keeping git patched.


## Test list (each vector → a test through the real FUSE mount)

Policy unit tests cover the classifier in isolation; these run against a mounted filesystem.

**Name rule / creation (group 3a):** `mkdir`, `open(O_CREAT)`, `mknod`, `symlink`, `link`, `rename`
into, `renameat2` `RENAME_EXCHANGE` into — for basenames `.git`, `.GIT`, `.Git`, `.git.`, `.git `
(trailing space), and a non-UTF-8 name; each must fail. Control names `.git<newline>`, `.gitignore`,
`.github` must **succeed** (only exact-fold `.git` is special).

**Pointer rewrite (group 3b):** with an existing `.git` file present, every mutation op above must
fail against it.

**Hooks (group 1):** `write`, `pwrite`, `truncate`, `ftruncate`, `open O_TRUNC`, `chmod`, `chown`,
`unlink`, `rmdir`, `rename` from/to, `link`, `symlink`, `mknod`, `setxattr`, `removexattr` against
`<gitdir>/hooks/**` — each fails. Same suite against `modules/<n>/hooks/**` and
`worktrees/<n>/hooks/**` to prove the recursion.

**Config (group 2):** direct mutation of `config`, `config.worktree`, `commondir` fails; real
`git config --local core.hooksPath …` and `git config --local core.fsmonitor …` fail. An
`include.path` cannot be added. Assert that a host-defined filter activated by an agent-written
`.gitattributes` runs only the host's command (documents the accepted boundary), and that a
`!command` in an agent-written `.gitmodules` is not honored.

**Operational writability (classifier):** the happy-path Git-integration suite —
`status/add/commit/checkout/switch/fetch/merge` on a host repo through the mount — must pass, so the
writable set is complete enough. Under the allowlist choice, a missing operational path surfaces
here. Separately, `git rebase`/`am`/ranged `cherry-pick` must **fail** (their todo state is frozen);
assert the block, so a later widening of the allowlist that reopened them would be caught.

**Symlink / escape:** `<gitdir>/hooks` is itself a symlink (protect the link, not just its target);
a symlink whose target escapes the backing root; `.git/hooks/x → outside`. Cannot mutate the
protected object; cannot escape the root.

**Races (TOCTOU):** rename vs open, rename vs classifier lookup, host-side rename while the sandbox
holds a descriptor — concurrency tests aimed specifically at the resolve-then-act window.


## Settled decisions

**Denylist vs allowlist inside a gitdir** (see the classifier section): **allowlist / fail-closed**.
The operational set is enumerated by the execution lens and guarded by the integration suite; a
forgotten operational file breaks a git command loudly rather than opening a hole.

**Rebase/sequencer todo state** (`rebase-merge`, `rebase-apply`, `sequencer`): **control** (group 1
has the why). The cost — no rebase/am/sequenced cherry-pick there — is accepted; security over
convenience.

The remaining open item is the name rule's Unicode completeness on a case-insensitive backing — a
per-backing empirical test, not a code-review question (see "The name rule").
