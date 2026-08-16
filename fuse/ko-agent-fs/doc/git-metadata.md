# Git metadata that must be immutable through `ko-agent-fs`

This is the crux: *what is the complete set of Git administrative state that must be immutable so
that a sandbox cannot cause a later host `git` invocation to execute sandbox-controlled code?*
The policy code is this document's transcription, and the git half of the filter is all of it.

The scope is narrow on purpose. The filter is not protecting repository integrity, correctness, or
the agent from itself. It defends exactly one property.

One rule in `policy.rs` derives from elsewhere: `.ko-agent-sandbox` cannot be created or written
either — the launcher's own boundary configuration, protected for the reason `SECURITY.md` ("A
project loosening its own confinement") gives rather than for anything about git. It shares this
document's name rule, because the launcher resolves that name on the same case-folding backing.


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

The whole of `.git` cannot be read-only: `git` must write its
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
git ("Premises", below) validates the opposite direction — that we do not *over*-freeze the
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

**A superset, not the exact fold set**, because the exact set is not statically knowable — NTFS
folds through a per-volume `$UpCase` table. Unicode normalization needs no handling at all, `.git`
being pure ASCII. Both are settled decisions, in `TODO.md`'s Non-TODOs, on the research
`security-research.md` records.

**The empirical test.** Reasoning bounds the candidate list; only the real filesystem settles it. On
each supported backing, create every candidate name through the mount and assert host
`lstat("<dir>/.git")` finds nothing. `TODO.md` ("Platform verification") carries the corpus, the
procedure and the pass criterion; `security-research.md` carries each run with its OS and filesystem
versions, since a fold table is specific to both. APFS case-insensitive — the default macOS volume —
passes. On case-sensitive APFS, ext4 and NTFS this rule's coverage is an assumption, not a result.


## Positional, not string-based

Whether a given inode is control state depends on its position relative to the **nearest enclosing
gitdir root**, resolved during the fd-relative walk — not on matching an absolute path string.
`hooks/` is protected because it is `<gitdir>/hooks`, and the same rule re-applies at each nested
gitdir discovered along the path (`modules/<n>/`, `worktrees/<n>/`). Path reconstruction plus a
string test is exactly the TOCTOU/`..`/symlink surface `architecture.md` ("Inode model") rules out;
the classifier consumes the resolver's position state instead.

Position is derived from names with one exception, and it is worth knowing where the exception is.
A submodule's name defaults to its *path*, so `modules/a/b` is `a/b`'s gitdir when the submodule is
at `a/b` and `a`'s own subdirectory when it is at `a` — the same string, two positions, and nothing
in the path distinguishes them ("Premises", P1). The FUSE layer therefore asks the tree
which it is, by the `HEAD` a gitdir holds, and the core is told rather than deriving it. The
untold answer is the strict one: until a root is identified, everything under `modules/` is control,
which is also what stops the sandbox writing a `HEAD` into a namespace to be asked a question it
chose the answer to.


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

The scanner behind it does not read section headers, so it cannot tell `core.hooksPath` from a
`hooksPath` under a section git never consults for hooks. It therefore judges **every** `hooksPath`
the file states and refuses if any one of them lands inside the workspace. Keeping only the last
would be the fail-open shape: a stray `[tool] hooksPath = /opt/hooks` after a real
`[core] hooksPath = ./githooks` would answer for both, and the worktree hooks git actually runs
would be served as ordinary writable data. The price is over-refusing a config whose only
inside-workspace `hooksPath` is one git ignores — a refused mount, never a lost guarantee.

The doubts refuse rather than guess, each of them a value the scanner would otherwise compare in a
different spelling than the one hooks run from: a `~` (expanding it needs the host's home directory,
which the daemon does not have), a backslash (git decodes escapes the scanner does not), an
unterminated quote, and a bare `path` key, which under `include` or `includeIf` names a file the
scanner never opens. All are rare in a *repository-local* config, and the message tells the operator
what to change.

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

- `git init` / `git clone` into `/workspace` — creates a new `.git`. Blocked. Clone under `~`.
- `git worktree add <path>` with `<path>` in `/workspace` — writes a `.git` **file** at the new
  worktree. Blocked.
- Submodule checkout that would materialize a submodule's worktree `.git` file in `/workspace` —
  the operational state of the `.git/modules/<n>/` side is permitted (that gitdir's own control
  state is frozen like any other's, by the recursion in "The immutable set"), the new `.git`
  pointer in the worktree is blocked.
- Editing `.git/config` (e.g. `git config --local core.hooksPath …`) — blocked; the whole point.
- `git rebase` (any form — the merge backend writes `rebase-merge/` even for a clean rebase),
  `git am` (writes `rebase-apply/`), and `git cherry-pick`/`git revert` of a *range* or when a
  conflict makes git open a sequence (writes `sequencer/`) — all blocked, because their todo
  can carry `exec` lines a later host `git rebase --continue` would run. A single, clean
  `cherry-pick`/`revert` (no sequence) still works. Do rebases on the host, or on a clone under
  `~`.

Existing host repositories keep working for the everyday commands: `status`, `add`, `commit`,
`checkout`, `switch`, `fetch`, `merge` touch only operational state. The rebase family is the
deliberate exception above.


## Prior art: git's own CVE history

Git's security advisories are a direct catalog of how repository state becomes host code execution.
The per-CVE verdicts, the watch-list and how to redo the research are `security-research.md`; the
two conclusions that shape this policy are below.

**The filter backstops a whole class.** The CVE-2024-32002 / CVE-2021-21300 / CVE-2014-9390 class
all end the same way: git is tricked, via symlink + case-insensitivity + submodules, into a *write*
whose path it believes is in a worktree but resolves into `.git/hooks`. Because the filter
classifies the **resolved destination** of every mutation — following symlinks through its own
resolver — the sandbox-side git performing that final write is denied at `open`/`create`, however
clever the trick that produced the path. (Host-side git bypasses the filter by design; there the
mitigation is a patched git, as for any untrusted clone.)

**The `.gitmodules` residual.** Leaving `.gitmodules` writable rests on "Premises"'s P0 and
P5, so it assumes git handles hostile `.gitmodules` correctly — and CVE-2018-11235, CVE-2024-32002
and CVE-2025-48384 are cases where a git bug broke that. Accepted as "hostile data plus a git bug"
(SECURITY.md): on the sandbox side the filter still denies the final `.git` write; on the host side
the mitigation is keeping git patched.


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
protected object; cannot escape the root. And the stale-handle case, which is neither of those: a
directory the sandbox renames while still holding it open, with a symlink to a gitdir left at the
name it vacated — the held handle must not reach what its old name no longer describes, at the
workspace root or inside a gitdir's operational tree.

**Races (TOCTOU):** rename vs open, rename vs classifier lookup, host-side rename while the sandbox
holds a descriptor — concurrency tests aimed specifically at the resolve-then-act window.


## Premises: the git behaviour this rests on

Everything above is derived from how a specific `git` lays out and writes its metadata. Those are
**premises**, not universal truths: a future `git` could change them, and the classifier's
correctness assumptions change with it.

**Observed under `git 2.47.3`.** `probe/observe-git.sh` re-derives them — it drives a real git
through init/commit/branch/switch/merge/rebase/tag/stash/fetch/gc/`worktree add`/`submodule add` and
classifies everything written under `.git` with the actual policy. Run it after a git upgrade,
compare against the premises below, and record the new version here.

That script validates *compatibility* — that the allowlist does not over-freeze the legitimate git
the agent itself runs. It is not a security oracle, for the reason the classifier section gives, and
it has three blind spots worth knowing: it sees only state that *persists* after a command, so a
clean `git rebase` (which creates and deletes `rebase-merge/` in one command) never appears in a
run, and neither does any `.lock`, which git renames away within the same command; and a path being
written does not make it safe to allow. Only real git against a real mount exercises the locks, so
`tests/mounted_git.rs` is the authority for the operational set — the script maps the layout.

- **P0 — command execution is configured only through the config files** (group 2 has the set and
  the argument). The whole design rests on it. Re-check on upgrade by scanning git's release notes
  for a new configuration *source*, or a new worktree-data→command path; human judgement, not a
  scripted check.
- **P1 — nested gitdirs live at `modules/<name>` and `worktrees/<name>`, one of them depth 1.**
  A submodule's name defaults to its path, so `git submodule add <url> libs/foo` yields
  `[submodule "libs/foo"]` and the gitdir `.git/modules/libs/foo`; a linked worktree is named for
  the *basename* of its path, so `git worktree add ../wt/deep/foo` yields `.git/worktrees/foo`,
  always one component (both measured, git 2.47). Any submodule under `deps/`, `vendor/` or
  `third_party/` has a multi-component name, so this is the common shape, not an edge case. If it
  drifted, a submodule's writable `objects/` would be judged against the wrong root and frozen —
  fail-closed, but quiet. Guarded by `tests/git_corpus.rs`, `tests/mounted_git.rs`
  (`a_submodule_in_a_subdirectory_works_like_any_other`) and `observe-git.sh`, which locates roots
  by the `HEAD` they hold rather than by depth.
- **P2 — a `<name>.lock` inherits the class of what it locks.** git writes one beside anything it
  locks and renames it into place, so `HEAD.lock` and `AUTO_MERGE.lock` are operational while
  `config.lock` is not — a rule rather than a list, since a list freezes whichever name it forgot.
  A new operational file that is *not* listed is frozen by default: a broken git command in the
  live-mount tests, not a hole, but a maintenance signal to add it to the allowlist and to
  `git_corpus.rs`. The `rebase-merge`/`rebase-apply`/`sequencer` exception is group 1's; do not add
  them back on the grounds that git writes them.
- **P3 — the control files are written only at creation time.** `config`, `config.worktree`,
  `hooks/**`, `commondir`, `gitdir`, `description`, `branches/**` are written by init,
  `submodule add` and `worktree add`, never during ordinary commit/checkout/merge/fetch — which is
  why freezing them costs an existing repository nothing, and why creating a submodule or linked
  worktree inside `/workspace` is blocked ("Consequences", above). Guarded by `tests/git_corpus.rs`.
- **P5 — `.gitmodules` cannot define a command**, which is what lets it stay writable worktree
  data (group 2). Re-check on upgrade that git still refuses a `submodule.<name>.update = !command`
  sourced from it; if that ever changed, `.gitmodules` would need protecting.
- **P6 — repository discovery keys on an entry named exactly `.git`**, a directory or a `gitdir:`
  pointer file. That is the basis of the name rule and of freezing the pointer entry. Re-check on
  upgrade that git introduces no second discovery name.

Most drift shows up as a broken git command rather than a silent hole — P2 especially. **P0 and P5
are the two that could weaken the boundary if they regressed**, and neither is caught by a script:
both need a human read of git's release notes on upgrade.
