# Git metadata that must be immutable through `ko-agent-fs`

This document answers one question: *which Git administrative state must be immutable, so that a
sandbox cannot make a later host `git` command run sandbox-controlled code, or open a path the
sandbox chose?*

- The policy code implements this document, and that code is the whole git half of the workspace
  policy.
- The scope is narrow on purpose. The workspace policy does not protect repository integrity,
  correctness, or the agent from itself. It defends exactly the property below.
- One rule in `policy.rs` comes from elsewhere: `.ko-agent-sandbox` cannot be created or written
  either.
  - It is the launcher's own boundary configuration. It is protected for the reason `SECURITY.md`
    ("A workspace loosening its own confinement") gives, not for anything about git.
  - It shares this document's name rule, because the launcher resolves that name on the same
    case-folding backing.


## The property

> Through the host-shared workspace mount, the sandbox can never create or alter repository
> state that causes a subsequent host-side `git` command to run a program the sandbox chose, or
> to open an object directory at a path the sandbox chose.

"Host-side" matters. The danger is not code running in the sandbox: the container is the boundary
for that. The danger is code that the *host user's* `git` runs later, outside the sandbox, against
the shared workspace: a `git status`, `git commit` or `git checkout` in their editor or terminal.


## How a repository makes `git` run a program or open a path

Every vector below is state the repository controls, which some `git` command turns into running
a process, or, in group 4, into opening a path. The vectors fall into four groups.

### 1. Hooks — executed directly

`git` runs an executable from the hook directory on many ordinary operations:

- `pre-commit` and `post-commit` on `git commit`;
- `post-checkout` on `git checkout`/`switch`;
- `post-merge` on merge, `pre-push` on push, `post-rewrite` on rebase, and more.

The hook directory is `$GIT_DIR/hooks` by default. No configuration is needed for a hook to run:
an executable with the right name is enough.

**Vector:** write or replace any file under a gitdir's `hooks/`.

Hooks are not the only files whose *content* git executes. The rebase and cherry-pick **todo**
files (`rebase-merge/git-rebase-todo`, `rebase-apply/`, `sequencer/todo`) can contain
`exec <command>` lines. A later host `git rebase --continue` or `cherry-pick --continue` runs them.

- This is the same class as a hook. It is easy to miss, because git writes these paths during
  ordinary operation.
- Watching what git writes suggests "operational, keep writable". The execution question, "can a
  write here make host git execute?", says "frozen". The workspace policy protects them against
  modification.

**Vector:** write a `rebase-merge`, `rebase-apply` or `sequencer` todo that the host later
continues.

### 2. Configuration — names a command `git` then runs

Many config keys hold a command line that `git` executes. The ambient ones carry the highest risk:
everyday read commands trigger them, with no special subcommand.

- `core.fsmonitor`: run by `git status`, `git add`, and anything that scans the worktree.
- `core.hooksPath`: redirects *all* hooks to any directory, including one inside the writable
  worktree. This is why protecting `hooks/` alone is not enough.
- `core.pager` and `pager.<cmd>`: run by `git log`, `git diff`, `git show`.
- `filter.<d>.clean|smudge|process`: run on add or checkout of paths that `.gitattributes` routes to
  driver `<d>`.
- `diff.external`, `diff.<d>.command`, `diff.<d>.textconv`, `merge.<d>.driver`: run on diff or
  merge of matching paths.
- `core.sshCommand`, `credential.helper`, `remote.<r>.uploadpack|receivepack`, `core.gitProxy`: run
  on network operations.
- `core.editor`, `sequence.editor`, `mergetool.<t>.cmd`, `difftool.<t>.cmd`, `gpg.program`,
  `alias.<x> = !cmd`: run on interactive or explicitly invoked commands.

The exact list changes across `git` releases, and that is the point: **listing dangerous keys is a
losing game.** All of them share one *home*: git reads them only from a repository's configuration
files.

- `$GIT_DIR/config`
- `$GIT_DIR/config.worktree` (when `extensions.worktreeConfig` is set)
- any file pulled in by `include.path` or `includeIf.*.path` from one of the above

`include.path` is why protecting the config files, not the keys, closes the set:

- An attacker cannot add a new command key without writing a protected config file, or adding an
  `include.path` to one, which is itself a write to a protected config file.
- With the config files protected, every command key above is out of reach, present and future.
- A worktree file that a host-chosen command names or runs stays writable
  (`../../../SECURITY.md`, "The host's git executing what the sandbox wrote").

`.gitattributes` and `.gitmodules` stay writable worktree data:

- They can only *activate* a driver that a protected config file already defines, that is, one the
  host chose. They cannot define the command.
- `.gitmodules` also cannot supply `submodule.<name>.update = !cmd`. Since the CVE-2017-1000117
  family, `git` refuses the `!command` form from `.gitmodules`. The design rests on this
  assumption ("Premises", P4).

### 3. Indirection — moves the gitdir itself

A worktree's `.git` need not be a directory. A **file** `.git` containing `gitdir: <path>` points
`git` at the real gitdir elsewhere. Related redirections change where `git` looks for `config` and
`hooks`: `.git/commondir`, the `gitdir` file inside `.git/worktrees/<name>/`, and
`$GIT_COMMON_DIR`.

**Vector, two halves:**

- *Creation*: a new `.git`, directory or file, anywhere in the tree makes host `git` discover a
  repository the sandbox fully controls.
  - The sandbox can fill that gitdir's `config` and `hooks` at leisure. To the workspace policy
    they are ordinary files until a `.git` entry names them.
- *Rewriting*: editing an existing `.git` pointer file points a real repository's Git metadata at
  a directory the sandbox owns.

Both halves must be closed. Blocking creation alone leaves the pointer rewrite open. Blocking the
rewrite alone leaves the planting of a fresh repository open.

### 4. Alternates — opens a path the sandbox names

`objects/info/alternates` lists more object directories, at any path, and host `git` opens each
one when it looks up objects. Nothing runs. But the path can name a network location, such as a
Windows UNC path, which the host opens outside the egress proxy.

- Inside the operational `objects/**`, only `objects/info` lists the entries it allows.
  - A directory holding an `alternates` could be written elsewhere and moved into place.
  - So `objects` and `objects/info` are created only by `mkdir`, and never renamed or unlinked.
- A symlink the host made at either directory, or at an alternates file, would lead the protected
  name to a name the sandbox writes. The mount-time guard checks the root repository:
  - it refuses such a link in a gitdir inside the workspace when the link leads back into the
    workspace;
  - for such a link in a gitdir outside the workspace, it serves the workspace entry the link
    leads to read-only.
- `objects/info/http-alternates` names object stores by URL, for a client fetching the repository
  over dumb HTTP. Git never writes it, so protecting it costs nothing.

**Vector:** write `objects/info/alternates`, or move a directory holding one onto `objects/info` or
`objects`.


## The immutable set

From the four groups, this state must be immutable to the sandbox:

1. **Any new entry named `.git`**: a directory *or* a file, at any depth (name rule below). The BPF
   backend allows the directory alone, and keeps it from gaining a `HEAD`
   (`../../../doc/bpf-lsm-cgroup.md`, "Directories").
2. **Any existing `.git` pointer file**: the `gitdir:` indirection, immutable so it cannot be
   pointed elsewhere.
3. **Within any gitdir**, the protected entries:
   - `config`, `config.worktree`;
   - `hooks/**`;
   - `commondir` and `gitdir`: the redirections of group 3 above, which change where `config` and
     `hooks` are resolved from;
   - `objects/info/**`, except what git writes there for itself (`commit-graph`,
     `commit-graphs/**`, `packs`). This covers `alternates` and `http-alternates` (group 4).
     `objects` and `objects/info` themselves are created only by `mkdir`, and never renamed or
     unlinked;
   - every other entry the classifier's allowlist does not name, among them the rebase and
     sequencer state (group 1) and `rr-cache`;
   - by recursion, the same classes inside every nested gitdir. `worktrees/<name>/**` and
     `modules/<name>/**` are gitdirs themselves, so their `config`, `hooks/**`, `commondir` and
     `gitdir` are immutable, while their operational state is not.
4. **A hook directory the host relocated into the worktree**: read-only as a root, with the
   components its chain passes through pinned ("Relocated hook directories", below).

Everything else stays writable (see the classifier), except what the file rules list
(`../../../doc/file-rules.md`).


## The classifier: writable vs immutable *inside* a gitdir

The whole of `.git` cannot be read-only. `git` must write its operational state for `status`,
`commit`, `checkout`, `fetch` and `merge` to work at all: `index`, `HEAD` and the other `*_HEAD`
refs, `refs/**`, `logs/**`, `objects/**`, `packed-refs`, `COMMIT_EDITMSG`, `MERGE_MSG`, and so on.
`rebase` is the deliberate exception: its state is protected (see group 1 and the blocked
operations).

So inside a gitdir, the workspace policy must keep operational state writable and protect the other
entries. There are two ways to draw that line, and they fail in opposite directions:

- **Denylist**: deny the known protected paths (`config*`, `hooks/**`, `commondir`) and allow the
  rest.
  - A future `git` that adds a new command-executing file under `$GIT_DIR` leaves it **open** until
    we notice. This fails open as `git` evolves.
- **Allowlist**: allow the known operational paths (`objects/**`, `refs/**`, `logs/**`, `index`,
  `*_HEAD`, `packed-refs`, the `*_MSG`/`*_EDITMSG` scratch files, `FETCH_HEAD`, `shallow`, …) and
  deny everything else under the gitdir.
  - A future operational file we forgot **breaks a git command** until we add it. A new
    command-executing file is denied by default.
  - This fails closed as `git` evolves, at the cost of breaking legitimate operations we failed to
    list.

**Decided: the allowlist**, matching the rule that security configuration must fail closed.

- A forgotten operational file breaks a git command, and the integration suite catches it.
- A new command-executing file is denied by default.
- The operational set is listed by the **execution question**: "can a write here make host git
  execute, or open a path the sandbox chose?" It is *not* listed by "does git write here".
  Watching real git ("Premises", below) checks only that legitimate git is not frozen *too much*.
  It never shows what is safe to allow.
  - The question is asked of every host git a user may run, not only of the image's version.
  - The bisect state is the one answer that depends on that version. From git 2.34 it is data
    (`classify_within_gitdir`). Through 2.33, `git bisect` is a shell script that `eval`s
    `BISECT_NAMES`.
  - The bisect state is writable, and the launcher warns on a host git older than 2.34.
- Where the two questions disagree (`rebase-merge`, `rebase-apply`, `sequencer`), security wins.
  The affected commands are listed under the blocked operations below.


## The name rule

`.git` is matched as a **conservative superset**, on every platform:

- The backing store may be a case-insensitive host filesystem (macOS APFS, Windows NTFS) reached
  through the podman machine.
- Host `git` there resolves `lstat(".git")` to an entry the sandbox created as `.GIT`. Matching
  exact bytes is therefore a real bypass on the platforms this project targets.

Creation is denied for any basename that equals `.git` after all of these steps:

- dropping invisible and ignorable code points (U+00AD, U+200B–U+200F, U+202A–U+202E, U+2060,
  U+206A–U+206F, U+FEFF):
  - a filesystem that ignores these when comparing resolves `.gi<U+200C>t` to `.git` (the HFS+
    half of CVE-2014-9390);
  - the list holds every code point git's `next_hfs_char` (utf8.c) skips;
- folding the Turkish i-family (U+0130, U+0131) to `i`: some Windows upcase tables map the dotless
  and the dotted i to `I`;
- folding U+212A KELVIN SIGN to `k` and U+017F LATIN SMALL LETTER LONG S to `s`:
  - APFS resolves both to the ASCII letter (`../../fuse/doc/verification-log.md`);
  - `.git` has neither letter. `.ko-agent-sandbox`, matched through the same fold
    (`policy::is_sandbox_config_name`), has both;
- ASCII case folding;
- stripping trailing `.` and space characters, which Win32 ignores.

How the rule is applied:

- To the raw filename **bytes** (`OsStr`), never a lossy `String`. Linux names are byte sequences,
  and a non-UTF-8 name must not panic, bypass the rule, or normalize into a surprise.
- The cost: no one can create a file named `.GIT` or `.gi<U+200C>t`, which nothing needs.

**A superset, not the exact set of folds**, because the exact set cannot be known in advance:

- NTFS folds through a `$UpCase` table that each volume has.
- Unicode normalization needs no library. In Unicode 16, the one code point that normalizes to an
  ASCII letter is U+212A, to `K`, and the fold above names it.
- Both are settled decisions, in `../../fuse/doc/TODO.md`'s Non-TODOs, based on the research
  `security-research.md` records.

A rule over spellings covers the names a filesystem folds to `.git`. It does not cover a second
name the filesystem gives an existing `.git`: an NTFS 8.3 short name, or a hard link to a pointer
file.

- The FUSE backend recognizes those by the backing object (`security-research.md`, "Windows 8.3
  short names").
- The BPF backend records the identities of the guarded objects at launch, and judges any name of
  them as the object. Its design states what remains open (`../../bpf/doc/architecture.md`, "The
  policy", the second-name rule).

**The empirical test.** Reasoning narrows the list of candidates; only the real filesystem settles
it.

- On each supported backing, create every candidate name through the mount, and assert that host
  `lstat("<dir>/.git")` finds nothing.
- `../../fuse/doc/TODO.md` ("Platform verification") has the corpus, the procedure and the pass
  criterion.
- `../../fuse/doc/verification-log.md` records each run with its OS and filesystem versions, since
  a fold table is specific to both.
- On a backing without a run there, this rule's coverage is an assumption.
  `../../fuse/doc/TODO.md` lists which backings those are.


## Positional, not string-based

Whether an inode is protected depends on its position relative to the **nearest enclosing gitdir
root**. The fd-relative walk resolves that position; matching an absolute path string does not.

- `hooks/` is protected because it is `<gitdir>/hooks`. The same rule applies again at each nested
  gitdir found along the path (`modules/<n>/`, `worktrees/<n>/`).
- Rebuilding a path and then testing the string is exactly what the TOCTOU, `..` and symlink
  attacks exploit, which `../../fuse/doc/architecture.md` ("Inode model") rules out. The classifier
  uses the resolver's position state instead.

Position is derived from names, with one exception worth knowing:

- A submodule's name defaults to its *path*. So `modules/a/b` is the gitdir of `a/b` when the
  submodule is at `a/b`, and a subdirectory of `a`'s gitdir when the submodule is at `a`. The same
  string has two positions, and nothing in the path tells them apart ("Premises", P1).
- The FUSE layer therefore asks the tree which one it is, by the `HEAD` a gitdir holds. The core is
  told the answer rather than deriving it.
- Until a root is identified, the answer is the strict one: everything under `modules/` is
  protected.
  - This also stops the sandbox from writing a `HEAD` into a namespace, which would let it choose
    the answer to the question the workspace policy asks.


## Operations that make these mutations

The immutable set must hold against *every* way to change a target, not just `write()`. For a
protected path or a protected destination:

`create` / `O_CREAT`, `open` for write, `write`/`pwrite`, `truncate`/`ftruncate`, `open O_TRUNC`,
`setattr` (size, mode, owner, times), `unlink`, `rmdir`, `rename` (source *and* destination),
`renameat2` including `RENAME_EXCHANGE`, `link`, `symlink`, `mknod`, `setxattr`, `removexattr`.

The last two are the exception. They are listed anyway, because this list is the requirement, not
the implementation:

- `setxattr` and `removexattr` are not implemented, so nothing reaches the backing store through
  them, and no policy has to run (`fs.rs`'s mutation-coverage note has what a caller sees).
- `policy::Mutation` deliberately has no xattr variant until that changes
  (`../../fuse/doc/TODO.md`, "Non-TODOs"). Whoever implements them adds the variants and their
  policy checks in the same change.

Rename and exchange act on two sides:

- `rename evil → <gitdir>/hooks/pre-commit` violates the destination side, even though `evil` is
  unprotected.
- `RENAME_EXCHANGE` changes both operands.
- The name match on the creation side and the protection of the destination must both apply.

`link` is the subtle case, and it is checked twice:

- A hard link shares an **inode**, so it bypasses classification by path.
  - `link <gitdir>/hooks/pre-commit → src/alias` gives the frozen inode a second, *writable* name.
  - A write through `src/alias` then changes the hook.
- So `link` is refused on the destination side (a link named into a protected tree) **and on the
  source side** (giving a protected inode a name outside, `authorize(source, Link)`).
- The source-side decision is about the node. So the link is made from the descriptor the resolver
  compared with the node's object, never from the node's name, which can lead elsewhere by then
  (`fs.rs`, `link`).
- Symlinks need no such rule.
  - They redirect by *path*, and the resolver's own walk classifies the target path again. So a
    symlink into `hooks/` is caught when the resolved target is opened for write.
  - The file rules refuse a symlink whose target names a `.git` entry, for their own reason
    (`../../../doc/file-rules.md`).

What remains open: a hard link the *host* already created between a protected inode and a
worktree path. A write to the worktree path then reaches the frozen inode.

- Detecting that would need every write to prove its inode is not also reachable under a gitdir.
  That is not feasible per write.
- It is out of scope as setup the host created. The host is trusted, and Git's default layout
  creates no hard link between a hook and a worktree path. The workspace policy closes only aliasing
  the *sandbox* creates.


## Relocated hook directories — served read-only

Everything above assumes hooks are where git puts them: `$GIT_DIR/hooks`. A host can move them into
the **worktree** in two ways:

- `.git/hooks` is a symlink to a worktree directory (`../shared-hooks`), a pattern for keeping
  hooks under version control;
- `core.hooksPath` in the host's config already names a worktree directory (`./githooks`). husky
  sets `.husky/_` in every repository it installs into.

In both cases, the files host `git` executes are stored at an ordinary worktree path. The `.git`
name rule classifies that path as ordinary workspace data.

- **So the guard resolves each such directory before the mount** (`guard::resolve`). The workspace
  policy then serves it as a read-only root.
  - Every ordinary component its chain passes through is pinned against rename and replacement.
  - This is a `read-only-path` line of the resolved file rules (`../../../doc/file-rules.md`).
- The mounted suite's `relocated_hooks_are_served_read_only` checks that the served directory
  refuses writes at its own name.
- A chain through a gitdir's writable state (`.git/objects/...`) refuses the mount. Git rewrites
  that state, so no read-only root can hold it.
- A hook directory that is the workspace root itself (`core.hooksPath = .`) refuses the mount too.
  Its hooks are top-level files, and only making the whole tree read-only could hold them.

The rules for single operations hold something narrower, worth stating exactly: the sandbox cannot
*point hook resolution elsewhere*.

- `.git/config` is frozen, so the sandbox cannot add or change `core.hooksPath`.
- The `.git/hooks` symlink node is protected, so the sandbox cannot delete or replace it.
- They cannot cover a target the **host** already points hooks at. The read-only root is for that.
- Blocking the write *through* `.git/hooks/` would protect nothing. The same bytes are reachable
  under the target's own ordinary name (`shared-hooks/pre-commit`), so a rule about the symlink path
  closes nothing. Any real fix has to protect the *target*.

**Why resolving rather than refusing.**

- Resolving costs two things, and both come anyway:
  - a scan of the git config, which a refusal needs too;
  - a second protected root in the audited core, which the file rules bring anyway. A path the
    guard finds is one more anchored line of the same kind (`policy.rs`, `RuleLine`).
- Refusing would leave every husky repository without a writable session.
- The host can invalidate the snapshot the root rests on mid-session, just as it could a refusal's
  check. The window is recorded below.

**The binding rule.** Relocated hooks are one case of a class the guard closes whole: Git
configuration, hooks and redirection files must not be reachable through a workspace path the
policy classifies as writable.

- The guard resolves every source, component by component:
  - the gitdir a `.git` pointer names;
  - its `commondir` and the common config behind it;
  - `config` and `config.worktree`;
  - each `hooksPath` value, from every directory git runs hooks in: the worktree for most hooks,
    `$GIT_DIR` for the receive side, and the common gitdir, to be safe. A relative value means a
    different directory to each;
  - the hook directory and every entry in it.
- Every component inside the workspace that a chain passes through must classify as `Protected`,
  or the chain must have left the workspace for good.
  - A hook directory's chain may instead pass through ordinary data. That data then becomes a
    read-only root or a pinned component (above).
- The rule covers components, not only symlink nodes.
  - An operational *directory* on a chain is a future slot for a symlink: the sandbox can rename it
    away and plant a symlink in its place.
  - A chain that leaves the workspace falls under the rule again if a link points back in.
- `canonicalize` cannot express this: it returns the endpoint and erases the chain. So the walk is
  explicit, with a bound on symlink hops.
- It classifies against the same submodule gitdir roots the runtime finds by their `HEAD`. So
  `Protected` for the guard means `Protected` at runtime (`.git/modules/<sub>/objects` is writable
  at runtime, and no exemption here).
- Whether an entry exists cannot weaken the answer: a missing operational name is one the sandbox
  can create.
  - Only NotFound means absent. An unreadable step, or a config that is not UTF-8, refuses the
    mount.
  - Absent in the daemon's view means absent on the host only where the daemon sees the host's
    objects. So a step outside them refuses too (below).

The rule also makes the mount-time snapshot last:

- A snapshot is sound only over paths its subject cannot change.
- Every allowed chain is made of `Protected`, read-only or pinned components, which the sandbox can
  neither write nor rename.
- Only the host can invalidate the snapshot. That is the window recorded below.

The same recognition covers the layout with no `.git` name at all:

- A workspace root that is itself laid out as a gitdir is refused. Ascending discovery would adopt
  it, and its config and hooks have ordinary writable names.
  - The layout is a valid `HEAD` plus `objects/` and `refs/`: git's own `is_git_directory` triple.
    Reftable repositories keep it precisely so that old gits recognize them.
- Check the triple against git's discovery rules again on each git upgrade (P5).

The read-only root is added only when the hook directory resolves **inside** the workspace.

- Hooks kept outside it cannot be reached through the mount (`RESOLVE_IN_ROOT` clamps the
  resolution). There is nothing to protect, and those repositories are served normally.
- That holds where the daemon sees the host's own objects: all of them on native Linux, and through
  a podman machine only the directories the machine shares.
- A chain leaving those directories refuses the mount, since the host could follow it back into the
  workspace without the daemon seeing it.

The scanner skips section headers without reading their names. So it cannot tell `core.hooksPath`
from a `hooksPath` under a section git never consults for hooks.

- It therefore judges **every** `hooksPath` the file states, and serves each one that resolves
  inside the workspace read-only.
- Keeping only the last one would fail open. A stray `[tool] hooksPath = /opt/hooks` after a real
  `[core] hooksPath = ./githooks` would answer for both. The worktree hooks git actually runs would
  then be served as ordinary writable data.
- The price is a read-only directory for a `hooksPath` git ignores, never a lost guarantee.

The scanner reads the forms git's `git_parse_source` (config.c) reads, so that the value it judges
is the one hooks run from:

- it skips a leading BOM. A key may follow one or more section headers on its line
  (`[core] hooksPath = ./githooks`), and their quoted subsection may hold `]`;
- it removes quote characters anywhere in the value, and keeps whitespace inside them;
- it keeps whitespace outside quotes when another character or a quote character follows it. It
  judges that whitespace both as written, which git 2.47 reads, and with each character replaced by
  a space, which git 2.39 reads.

When in doubt, the scanner refuses rather than guesses. In each case below it would otherwise
compare a spelling other than the one hooks run from, or miss a `hooksPath` git reads:

- a `~`: expanding it needs the host's home directory, which the daemon does not have;
- a backslash: git decodes escapes the scanner does not;
- an unterminated quote;
- a section header left open on its line;
- a bare `path` key, which under `include` or `includeIf` names a file the scanner never opens.

All of these are rare in a *repository-local* config, and the message tells the operator what to
change.

Scope: the repository at the workspace root, plus the bare-root check above. What lies below the
root is unchecked. `../../fuse/doc/TODO.md` records this, and `SECURITY.md` names it:

- A repository the **host** nested deeper.
  - Its protected entries under `.git` names are frozen like any other repository's.
  - But Git metadata the host routed into the worktree (relocated hooks, a redirected gitdir) is
    served writable, unless a file rule lists it, as `read-only .husky` does for husky.
  - The sandbox cannot create this layout.
- A **bare layout**, which the sandbox *can* create.
  - `git init --bare` and `git clone --bare|--mirror` write only ordinary names. No rule per name
    can refuse `HEAD`, `objects` and `refs` one by one without refusing legitimate projects
    ("Consequences", below).
  - It is unchecked anywhere below the root.
  - It is unchecked at the root itself once the mount-time check has passed: a session that starts
    in a workspace without a repository can lay the triple at the root mid-session.

The check is also a snapshot, taken before the mount and not repeated.

- A host that moves its hooks into the worktree *after* a session is serving gets no second
  resolution.
- Polling for that would buy a guarantee only as fresh as its last poll, and it would put a config
  read and an `lstat` on the hot path. So the window is recorded rather than chased.
- Only the host can open the window: the binding rule allows only chains the sandbox cannot change.
- The cost: Git configuration or hooks the host moves into writable workspace paths stay writable
  for the rest of that session, just as they would without the mount-time guard.


## What this intentionally does *not* protect, and why that is safe

- `.gitattributes`, `.gitmodules`: writable worktree data.
  - They can only activate drivers the host defined. They cannot define commands, and cannot
    smuggle in `!cmd` submodule updates.
  - A host's git-lfs filter still connects where `.lfsconfig` says, and reads the objects a session
    may have placed in `.git/lfs/` (`SECURITY.md`, "The workspace").
- Operational gitdir state (`objects`, `refs`, `logs`, `index`, …): writable, or `git` cannot work.
  None of it is executed, and `alternates` is the one path in it git opens (group 4).
- Changes on the host side: the host writes the backing store directly, bypassing both backends by
  design. Legitimate host `git` metadata is created outside the sandbox and is not the threat.


## Consequences: git operations blocked inside the workspace

These follow from the name rule and the classifier. They must be documented, not silently broken.
SECURITY.md ("The host's git executing what the sandbox wrote" and "The workspace") has the
security reason for each.

- `git init` and `git clone` into the workspace create a new `.git`. Blocked. Clone under `~`.
  - The **bare-layout forms are not blocked**. `git init --bare` and `git clone --bare|--mirror`
    write only ordinary names (`HEAD`, `objects/`, `refs/`, `config`, `hooks/`). No rule per name
    can refuse them without refusing legitimate projects that have those names.
  - The guard refuses a bare layout at the workspace root at mount. One the sandbox creates, below
    the root or at the root after that check, is the gap SECURITY.md records ("The workspace"):
    running host git inside a directory the agent created is running the agent's output.
- `git worktree add <path>` with `<path>` in the workspace writes a `.git` **file** at the new
  worktree. Blocked.
- A submodule checkout that would create the submodule's worktree `.git` file in the workspace:
  - operational state in `.git/modules/<n>/` stays writable;
  - its protected entries stay frozen, by the recursion in "The immutable set";
  - the new `.git` pointer in the worktree is refused.
- Editing `.git/config` (for example `git config --local core.hooksPath …`) is blocked. That is
  the whole point.
  - So is every command that records something there: `git remote add`, `git push -u`,
    `git branch --set-upstream-to`, `git switch --track`, `git sparse-checkout`.
  - `git branch -m` renames the branch and then fails. `git branch -d` deletes it and warns.
- `git rerere`: its `rr-cache/` stays protected, since creating it enables rerere for host merges
  (`classify_within_gitdir` explains why).
- Removing `objects/info/alternates` after `git repack -a`, to detach a repository from the object
  directories it borrows from, is blocked (group 4). Do it on the host.
  - Git writes the file only when it creates a repository with `git clone --shared` or
    `--reference`, which is blocked already.
- Blocked, because their todo can contain `exec` lines that a later host `git rebase --continue`
  would run:
  - `git rebase`, in any form: the merge backend writes `rebase-merge/` even for a clean rebase;
  - `git am`, which writes `rebase-apply/`;
  - `git cherry-pick` and `git revert` of a *range*, or when a conflict makes git open a sequence;
    both write `sequencer/`.
  - A single, clean `cherry-pick` or `revert` (no sequence) still works.
  - Do rebases on the host, or on a clone under `~`.

Existing host repositories keep working for the everyday commands. `status`, `add`, `commit`,
`checkout`, `switch`, `fetch`, `merge`, `stash`, `gc` and `bisect` touch only operational state.
The rebase family and the commands that write config are the deliberate exceptions above. `bisect`
is safe for a host git of 2.34 or later; the launcher warns on an older one ("The classifier").

`git filter-repo`, which the image has, runs. Unverified under the FUSE backend:

- its `filter-repo/` metadata is operational;
- at the end it runs `git remote rm origin`, whose config write is refused. filter-repo does not
  check that step (`git_filter_repo.py`, the `subproc.call` after "Removing 'origin' remote"), so
  `origin` stays.


## Prior art: git's own CVE history

Git's security advisories list exactly how repository state has become host code execution.
`security-research.md` has the verdict for each CVE, the watch-list and how to redo the research.
The two conclusions this policy rests on are below.

**The FUSE backend denies the final write of a whole class.**

- The class of CVE-2024-32002, CVE-2021-21300 and CVE-2014-9390 always ends the same way. Through a
  symlink, case-insensitivity and submodules, git is tricked into a *write* whose path it believes
  is in a worktree, but which resolves into `.git/hooks`.
- The FUSE backend classifies the **resolved destination** of every mutation, following symlinks
  through its own resolver. So when git on the sandbox side performs that final write, `open` or
  `create` denies it, however clever the trick that produced the path.
- git on the host side bypasses both backends by design. There, the mitigation is a patched git, as
  for any untrusted clone.

**What `.gitmodules` leaves open.**

- Leaving `.gitmodules` writable rests on P0 and P4 of "Premises". So it assumes git handles a
  hostile `.gitmodules` correctly. CVE-2018-11235, CVE-2024-32002 and CVE-2025-48384 are cases
  where a git bug broke that.
- This is accepted as "hostile data plus a git bug" (SECURITY.md). On the sandbox side, the
  workspace policy still denies the final `.git` write. On the host side, the mitigation is keeping
  git patched.


## Test list (each vector → a test through the real FUSE mount)

Policy unit tests cover the classifier alone; these tests run against a mounted filesystem.

**Name rule / creation (group 3a):**

- `mkdir`, `open(O_CREAT)`, `mknod`, `symlink`, `link`, `rename` into, and `renameat2`
  `RENAME_EXCHANGE` into, for the basenames `.git`, `.GIT`, `.Git`, `.git.` and `.git ` (trailing
  space). Each must fail.
- The control names `.git<newline>`, `.gitignore`, `.github` and a non-UTF-8 name must **succeed**:
  only `.git` up to folding is special.

**Pointer rewrite (group 3b):** with an existing `.git` file present, every mutation above must
fail against it.

**A second name (groups 3a, 3b):** with a host hard link to a `.git` file and to a
`.ko-agent-sandbox` file:

- append, `open(O_CREAT)`, `unlink`, `rename` from and onto, and `link` through the link's name must
  fail;
- while the host keeps making such a file and link, an `open(O_CREAT)` of the link's name never
  opens the host's file;
- a directory handle opened on ordinary names that come to lead through a second name of `.git` or
  `.ko-agent-sandbox` must fail with `ESTALE`;
- so must `fchmod`, `futimens` and a link through a file descriptor whose name has become such a
  second name. The guarded file's metadata and link count stay as they were.

**Hooks (group 1):**

- `write`, `pwrite`, `truncate`, `ftruncate`, `open O_TRUNC`, `chmod`, `chown`, `unlink`, `rmdir`,
  `rename` from and to, `link`, `symlink` and `mknod` against `<gitdir>/hooks/**`. Each fails.
- The same suite against `modules/<n>/hooks/**` and `worktrees/<n>/hooks/**`, to prove the
  recursion.
- Not `setxattr` or `removexattr` ("Operations that make these mutations" explains why).

**Config (group 2):**

- Direct mutation of `config`, `config.worktree` and `commondir` fails. Real
  `git config --local core.hooksPath …` and `git config --local core.fsmonitor …` fail.
- An `include.path` cannot be added.
- Assert that a host-defined filter, activated by a `.gitattributes` the agent wrote, runs only the
  host's command. This documents the accepted boundary. Assert too that a `!command` in a
  `.gitmodules` the agent wrote is not honored.

**Alternates (group 4):**

- creating or symlinking `objects/info/alternates` and `http-alternates` fails, in the gitdir and
  in a submodule's;
- renaming `objects` or `objects/info`, and renaming or symlinking a directory onto
  `objects/info`, fails.

**Operational writability (classifier):**

- The happy-path Git integration suite must pass: `status/add/commit/checkout/switch/fetch/merge`
  on a host repo through the mount. This shows the writable set is complete enough. With the
  allowlist, a missing operational path fails here.
- Separately, `git rebase`, `am` and a ranged `cherry-pick` must **fail**, since their todo state is
  frozen. Assert the block, so that a later widening of the allowlist that reopened them would be
  caught.

**Symlink / escape:**

- `<gitdir>/hooks` is itself a symlink (protect the link, not just its target); a symlink whose
  target escapes the backing root; `.git/hooks/x → outside`. None may change the protected object
  or escape the root.
- The stale-handle case, which is neither of those: the sandbox renames a directory while it still
  holds it open, and a symlink to a gitdir is left at the name the directory vacated. The held
  handle must not reach what its old name no longer describes, at the workspace root or inside a
  gitdir's operational tree.

**Races (TOCTOU):** rename vs open, rename vs classifier lookup, and a host-side rename while the
sandbox holds a descriptor. These concurrency tests aim at the window between resolving and acting.


## Premises: the git behavior this rests on

Everything above comes from how a specific `git` lays out and writes its metadata. These are
**premises**, not universal truths. A future `git` could change them, and the assumptions the
classifier's correctness rests on would change with it.

**Observed under `git 2.47.3`.** `probe/observe-git.sh` derives them again:

- It drives a real git through init, commit, branch, switch, merge, rebase, tag, stash, fetch, gc,
  `worktree add` and `submodule add`, and classifies everything written under `.git` with the
  actual policy.
- Run it after a git upgrade, compare the result with the premises below, and record the new
  version here.

That script checks *compatibility*: that the allowlist does not freeze the legitimate git the agent
itself runs. It is not a security oracle, for the reason the classifier section gives. It has three
blind spots worth knowing:

- it sees only state that *persists* after a command. A clean `git rebase` creates and deletes
  `rebase-merge/` in one command, so it never appears in a run;
- it does not see any file git removes or renames away within the same command either: every
  `.lock`, and `git stash`'s `index.stash.<pid>`, `git gc`'s `gc.pid` and `packed-refs.new`.
  `strace -f` around single commands sees them, and `tests/git_corpus.rs` records what it saw;
- a path being written does not make it safe to allow.

Only real git against a real mount exercises the locks. So `../../fuse/tests/mounted_git.rs`
establishes which git commands work through the FUSE backend; the script records the files each
command leaves.

- **P0: command execution is configured only through the config files** (group 2 has the set and
  the argument). The whole design rests on it.
  - Check again on each upgrade, by scanning git's release notes for a new configuration *source*,
    or a new path from worktree data to a command. This needs human judgement; no script checks it.
- **P1: nested gitdirs are at `modules/<name>` and `worktrees/<name>`, one of them at depth 1.**
  - A submodule's name defaults to its path. `git submodule add <url> libs/foo` yields
    `[submodule "libs/foo"]` and the gitdir `.git/modules/libs/foo`.
  - A linked worktree is named for the *basename* of its path. `git worktree add ../wt/deep/foo`
    yields `.git/worktrees/foo`, always one component. Both were measured with git 2.47.
  - Any submodule under `deps/`, `vendor/` or `third_party/` has a name of several components, so
    this is the common layout, not an edge case.
  - If it drifted, a submodule's writable `objects/` would be judged against the wrong root and
    frozen. That fails closed, but quietly.
  - `tests/git_corpus.rs`, `../../fuse/tests/mounted_git.rs`
    (`a_submodule_in_a_subdirectory_works_like_any_other`) and `observe-git.sh` guard it.
    `observe-git.sh` finds roots by the `HEAD` they hold rather than by depth.
- **P2: a `<name>.lock` has the class of what it locks.**
  - git writes one beside anything it locks, and renames it into place. So `HEAD.lock` and
    `AUTO_MERGE.lock` are operational, while `config.lock` is not. This is a rule rather than a
    list, since a list freezes whichever name it forgot.
  - A new operational file that is *not* listed is frozen by default. That shows as a broken git
    command in the live-mount tests, not as a hole. It signals that the file belongs in the
    allowlist and in `git_corpus.rs`.
  - The `rebase-merge`/`rebase-apply`/`sequencer` exception belongs to group 1. Do not add them on
    the grounds that git writes them.
- **P3: the protected entries are written only when a repository is created.**
  - init, `submodule add` and `worktree add` write `config`, `config.worktree`, `hooks/**`,
    `commondir`, `gitdir`, `description` and `branches/**`. Ordinary commit, checkout, merge and
    fetch never do.
  - That is why freezing them costs an existing repository nothing. It is also why creating a
    submodule or a linked worktree inside the workspace is blocked ("Consequences", above).
  - `tests/git_corpus.rs` guards it.
- **P4: `.gitmodules` cannot define a command.** This is what lets it stay writable worktree data
  (group 2).
  - Check again on each upgrade that git still refuses a `submodule.<name>.update = !command`
    taken from it. If that ever changed, `.gitmodules` would need protecting.
- **P5: repository discovery looks for an entry named exactly `.git`, or a directory that is itself
  a gitdir.**
  - The entry named `.git` is a directory or a `gitdir:` pointer file. This form is the basis of
    the name rule and of freezing the pointer entry.
  - A directory that is itself a gitdir is the bare layout: a valid `HEAD`, `objects/` and `refs/`,
    git's `is_git_directory` triple. Reftable repositories keep it so that old gits recognize them.
    The guard's bare-root check mirrors this form, and the bare-layout gap is recorded for it.
  - Check again on each upgrade that git adds no third form of discovery and does not change the
    triple.

Most drift shows up as a broken git command rather than a silent hole, P2 especially. **P0 and P4
could weaken the boundary if they regressed**, and no script catches either: both need a human to
read git's release notes on each upgrade.
