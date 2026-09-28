# Git metadata that must be immutable through `ko-agent-fs`

This is the crux: *what is the complete set of Git administrative state that must be immutable so
that a sandbox cannot cause a later host `git` invocation to execute sandbox-controlled code, or to
open a path the sandbox chose?*

- The policy code is this document's transcription, and the git half of the filter is all of it.
- The scope is narrow on purpose. The filter is not protecting repository integrity, correctness,
  or the agent from itself. It defends exactly the property below.
- One rule in `policy.rs` derives from elsewhere: `.ko-agent-sandbox` cannot be created or written
  either — the launcher's own boundary configuration, protected for the reason `SECURITY.md` ("A
  project loosening its own confinement") gives rather than for anything about git. It shares
  this document's name rule, because the launcher resolves that name on the same case-folding
  backing.


## The property

> Through the host-shared project mount, the sandbox can never create or alter repository
> state that causes a subsequent host-side `git` command to run a program the sandbox chose, or
> to open an object directory at a path the sandbox chose.

"Host-side" matters: the danger is not code running in the sandbox (the container is the boundary
for that) but code the *host user's* `git` runs later, outside the sandbox, against the shared
project directory — a `git status`, `git commit`, or `git checkout` in their editor or terminal.


## How a repository makes `git` run a program or open a path

Every vector below is repository-controlled state that some `git` command turns into process
execution, or, in group 4, into opening a path. They fall into four groups.

### 1. Hooks — executed directly

`git` runs an executable from the hook directory on many ordinary operations:

- `pre-commit` and `post-commit` on `git commit`;
- `post-checkout` on `git checkout`/`switch`;
- `post-merge` on merge, `pre-push` on push, `post-rewrite` on rebase, and more.

The hook directory is `$GIT_DIR/hooks` by default. No configuration is required for this to
fire — an executable of the right name is enough.

**Vector:** write or replace any file under a gitdir's `hooks/`.

Hooks are not the only file whose *content* git executes. The rebase/cherry-pick **todo** —
`rebase-merge/git-rebase-todo`, `rebase-apply/`, `sequencer/todo` — can contain `exec <command>`
lines, and a later host `git rebase --continue` (or `cherry-pick --continue`) runs them.

- This is the same class as a hook, and easy to miss precisely because git writes these paths
  during ordinary operation.
- Watching what git writes suggests "operational, keep writable", but the execution question —
  can a write here make host git execute? — says "frozen". The filter protects them against
  modification.

**Vector:** write a `rebase-merge`/`rebase-apply`/`sequencer` todo the host later continues.

### 2. Configuration — names a command `git` then runs

A large set of config keys hold a command line that `git` executes. The ambient ones — triggered by
everyday read commands, needing no special subcommand — are the highest-risk ones:

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

- An attacker cannot introduce a new command key without either writing a protected config file
  or adding an `include.path` to one — itself a write to a protected config file.
- Protect the config files and every command key above is out of reach, present and future.

`.gitattributes` and `.gitmodules` stay writable worktree data:

- They can only *activate* a driver that a protected config file already defines, i.e. one the
  host chose; they cannot define the command.
- `.gitmodules` additionally cannot supply `submodule.<name>.update = !cmd`: `git` has refused to
  honor the `!command` form from `.gitmodules` since the CVE-2017-1000117 family. The design
  rests on this assumption ("Premises", P4).

### 3. Indirection — moves the gitdir itself

A worktree's `.git` need not be a directory. As a **file** containing `gitdir: <path>` it points
`git` at the real gitdir elsewhere. Related redirections — `.git/commondir`, the `gitdir` file
inside `.git/worktrees/<name>/`, `$GIT_COMMON_DIR` — relocate where `git` looks for `config` and
`hooks`.

**Vector, two halves:**

- *Creation* — a new `.git` (dir or file) anywhere in the tree makes host `git` discover a
  repository the sandbox fully controls: it can populate that gitdir's `config` and `hooks` at
  leisure, because to the filter they are just ordinary files until a `.git` entry names them.
- *Rewriting* — editing an existing `.git` pointer file re-aims a real repository's Git metadata at
  a directory the sandbox owns.

Both halves must be closed. Blocking creation alone leaves the pointer rewrite open; blocking
rewrite alone leaves fresh-repository planting open.

### 4. Alternates — opens a path the sandbox names

`objects/info/alternates` lists further object directories, by any path, and host `git` opens each
one when it looks up objects. Nothing runs, but the path can name a network location, such as a
Windows UNC path, which the host opens outside the egress proxy.

- Inside the operational `objects/**`, `objects/info` alone allowlists its entries. A directory
  holding an `alternates` could be written elsewhere and moved into place, so `objects` and
  `objects/info` are created only by `mkdir` and never renamed or unlinked.
- A symlink the host made at either directory or at an alternates file would lead the protected
  name to one the sandbox writes. The mount-time guard checks the root repository: it refuses such
  a link in a gitdir inside the workspace when it leads back into the workspace, and serves
  read-only the workspace entry one in a gitdir outside it leads to.
- `objects/info/http-alternates` names object stores by URL for a client fetching the repository
  over dumb HTTP. Git never writes it, so it is protected at no cost.

**Vector:** write `objects/info/alternates`, or move a directory holding one onto
`objects/info` or `objects`.


## The immutable set

From the four groups, the state that must be immutable to the sandbox:

1. **Any new entry named `.git`** — directory *or* file, at any depth. (Name rule below.)
2. **Any existing `.git` pointer file** — the `gitdir:` indirection, immutable so it cannot be
   re-aimed.
3. **Within any gitdir**, the protected entries:
   - `config`, `config.worktree`
   - `hooks/**`
   - `commondir` and `gitdir` — the redirections of group 3 above, which relocate where `config`
     and `hooks` are resolved from
   - `objects/info/**` except what git writes there for itself — `commit-graph`,
     `commit-graphs/**`, `packs` — so `alternates` and `http-alternates` (group 4); `objects` and
     `objects/info` themselves are created only by `mkdir` and never renamed or unlinked
   - every other entry the classifier's allowlist does not name, among them the rebase and
     sequencer state (group 1), the bisect state and `rr-cache`
   - and, by recursion, the same classes inside every nested gitdir: `worktrees/<name>/**`
     and `modules/<name>/**` are themselves gitdirs, so their `config`, `hooks/**`, `commondir` and
     `gitdir` are immutable while their operational state is not.
4. **A hook directory the host relocated into the worktree**, read-only as a root, with the
   components its chain traverses pinned ("Relocated hook directories", below).

Everything else stays writable — see the classifier — except what the file rules list
(`../../../doc/file-rules.md`).


## The classifier: writable vs immutable *inside* a gitdir

The whole of `.git` cannot be read-only: `git` must write its operational state for `status`,
`commit`, `checkout`, `fetch`, `merge` to work at all — `index`, `HEAD` and the other `*_HEAD`
refs, `refs/**`, `logs/**`, `objects/**`, `packed-refs`, `COMMIT_EDITMSG`, `MERGE_MSG`, and so
on. (`rebase` and `bisect` are the deliberate exceptions — their state is protected; see group 1
and blocked operations.)

So inside a gitdir the filter must keep operational state writable while protecting the other
entries. There are two ways to draw that line, and they fail in opposite directions:

- **Denylist** — deny known protected paths (`config*`, `hooks/**`, `commondir`), allow the rest.
  A future `git` that introduces a new command-executing file under `$GIT_DIR` is **open** until we
  notice. Fail-open on `git` evolution.
- **Allowlist** — allow the known operational paths (`objects/**`, `refs/**`, `logs/**`, `index`,
  `*_HEAD`, `packed-refs`, the `*_MSG`/`*_EDITMSG` scratch files, `FETCH_HEAD`, `shallow`, …), deny
  everything else under the gitdir. A future operational file we forgot **breaks a git command**
  until we add it; a new command-executing file is denied by default. Fail-closed on `git`
  evolution, at the cost of breaking legitimate operations we under-enumerated.

**Decided: the allowlist**, matching the rule that security configuration must fail closed.

- A forgotten operational file breaks a git command (caught by the integration suite).
- A new command-executing file is denied by default.
- The operational set is enumerated by the **execution question** ("can a write here cause host
  git to execute, or to open a path the sandbox chose?"), *not* "does git write here": watching
  real git ("Premises", below) checks only that legitimate git is not *over*-frozen, never what is
  safe to allow.
  - The question is asked of every host git a user may run, not of the image's version alone:
    through 2.33, `git bisect` is a shell script that `eval`s `BISECT_NAMES`, which is why the
    bisect state stays protected.
- Where the two diverge — `rebase-merge`, `rebase-apply`, `sequencer` — security wins, and the
  affected commands are listed under blocked operations below.


## The name rule

`.git` is matched as a **conservative superset**, on every platform:

- The backing store may be a case-insensitive host filesystem (macOS APFS, Windows NTFS) reached
  through the Podman Machine.
- Host `git` there resolves `lstat(".git")` to an entry the sandbox created as `.GIT`, so
  exact-byte matching is a real bypass on the platforms this project actually targets.

Deny creation of any basename that equals `.git` after all of:

- dropping invisible/ignorable code points (U+00AD, U+200B–U+200F, U+202A–U+202E, U+2060,
  U+206A–U+206F, U+FEFF) — a filesystem that ignores these in comparison resolves `.gi<U+200C>t`
  to `.git` (the HFS+ half of CVE-2014-9390). The list holds every code point git's
  `next_hfs_char` (utf8.c) skips;
- folding the Turkish i-family (U+0130, U+0131) to `i` — some Windows upcase tables map dotless and
  dotted i to `I`;
- folding U+212A KELVIN SIGN to `k` and U+017F LATIN SMALL LETTER LONG S to `s` — APFS resolves
  both to the ASCII letter (`verification-log.md`). `.git` has neither letter;
  `.ko-agent-sandbox`, matched through the same fold (`policy::is_sandbox_config_name`), has both;
- ASCII case-folding;
- stripping trailing `.` and space characters (Win32 ignores them).

How it is applied:

- To the raw filename **bytes** (`OsStr`), never a lossy `String` — Linux names are byte
  sequences and a non-UTF-8 name must not panic, bypass, or normalize into a surprise.
- The cost is no one can create a file named `.GIT` or `.gi<U+200C>t`, which nothing needs.

**A superset, not the exact fold set**, because the exact set is not statically knowable:

- NTFS folds through a per-volume `$UpCase` table.
- Unicode normalization needs no library: in Unicode 16 the one code point that normalizes to an
  ASCII letter is U+212A, to `K`, and the fold above names it.
- Both are settled decisions, in `TODO.md`'s Non-TODOs, on the research `security-research.md`
  records.

A rule over spellings covers the names a filesystem folds to `.git`, not a second name it gives
an existing `.git` — an NTFS 8.3 short name, a hard link to a pointer file. Those the filter
recognizes by the backing object (`security-research.md`, "Windows 8.3 short names").

**The empirical test.** Reasoning bounds the candidate list; only the real filesystem settles it.

- On each supported backing, create every candidate name through the mount and assert host
  `lstat("<dir>/.git")` finds nothing.
- `TODO.md` ("Platform verification") has the corpus, the procedure and the pass criterion.
- `verification-log.md` records each run with its OS and filesystem versions, since a fold table
  is specific to both.
- A backing without a run there has this rule's coverage as an assumption, and `TODO.md` lists
  which those are.


## Positional, not string-based

Whether an inode is protected depends on its position relative to the **nearest enclosing
gitdir root**, resolved during the fd-relative walk — not on matching an absolute path string.

- `hooks/` is protected because it is `<gitdir>/hooks`, and the same rule re-applies at each
  nested gitdir discovered along the path (`modules/<n>/`, `worktrees/<n>/`).
- Path reconstruction plus a string test is exactly the TOCTOU, `..` and symlink attacks
  `architecture.md` ("Inode model") rules out; the classifier consumes the resolver's position
  state instead.

Position is derived from names with one exception, and it is worth knowing where the exception is.

- A submodule's name defaults to its *path*, so `modules/a/b` is `a/b`'s gitdir when the
  submodule is at `a/b` and `a`'s own subdirectory when it is at `a` — the same string, two
  positions, and nothing in the path distinguishes them ("Premises", P1).
- The FUSE layer therefore asks the tree which it is, by the `HEAD` a gitdir holds, and the core
  is told rather than deriving it.
- The untold answer is the strict one: until a root is identified, everything under `modules/` is
  protected, which is also what stops the sandbox writing a `HEAD` into a namespace to be asked a
  question it chose the answer to.


## Operations that make these mutations

The immutable set must hold against *every* way to mutate a target, not just `write()`. For a
protected path or a protected destination:

`create` / `O_CREAT`, `open` for write, `write`/`pwrite`, `truncate`/`ftruncate`, `open O_TRUNC`,
`setattr` (size, mode, owner, times), `unlink`, `rmdir`, `rename` (source *and* destination),
`renameat2` including `RENAME_EXCHANGE`, `link`, `symlink`, `mknod`, `setxattr`, `removexattr`.

The last two are the exception, and listed anyway because this is the requirement rather than the
implementation:

- `setxattr`/`removexattr` are unimplemented, so nothing reaches the backing store through them
  and no policy has to run (`fs.rs`'s mutation-coverage note has what a caller sees).
- `policy::Mutation` deliberately has no xattr variant until that changes (`TODO.md`,
  "Non-TODOs"); whoever implements them adds the variants and their policy checks in the same
  change.

Rename and exchange are the double-sided cases:

- `rename evil → <gitdir>/hooks/pre-commit` is a destination-side violation even though `evil` is
  unprotected.
- `RENAME_EXCHANGE` mutates both operands.
- Creation-side name matching and destination-side protection must both fire.

`link` is the subtle one, and doubly-checked.

- A hardlink shares an **inode**, so it bypasses path-based classification:
  `link <gitdir>/hooks/pre-commit → src/alias` gives the frozen inode a second, *writable* name,
  and a write through `src/alias` then mutates the hook.
- So `link` is refused both destination-side (a link named into a protected tree) **and
  source-side** (aliasing a protected inode out — `authorize(source, Link)`).
- The source-side decision is about the node, so the link is made from the descriptor the
  resolver compared with the node's object, never from the node's name, which can lead elsewhere
  by then (`fs.rs`, `link`).
- Symlinks need no such rule: they redirect by *path*, and the target path is re-classified
  through the resolver's own walk, so a symlink into `hooks/` is caught when the resolved target
  is opened for write. The file rules refuse a symlink whose target names a `.git` entry for
  their own reason (`../../../doc/file-rules.md`).

Residual: a hardlink the *host* already created between a protected inode and a worktree path lets
a write to the worktree path reach the frozen inode.

- Detecting that needs every write to prove its inode is not also reachable under a gitdir — not
  feasible per write.
- It is out of scope as host-created setup (the host is trusted; Git's default layout creates no
  hardlink between a hook and a worktree path). The filter closes only *sandbox*-created
  aliasing.


## Relocated hook directories — served read-only

Everything above assumes hooks are where git puts them: `$GIT_DIR/hooks`. A host can relocate them
into the **worktree**, two ways:

- `.git/hooks` is a symlink to a worktree directory (`../shared-hooks`), a pattern for keeping hooks
  under version control;
- `core.hooksPath` in the host's config already names a worktree directory (`./githooks`); husky
  sets `.husky/_` in every repository it installs into.

In both cases the files host `git` executes are stored at an ordinary worktree path, which the
`.git` name rule classifies as ordinary project data.

- **The guard therefore resolves each such directory before the mount** (`guard::resolve`) and the
  filter serves it as a read-only root, with every ordinary component its chain traverses pinned
  against rename and replacement — a `readonly-path` line of the resolved file rules
  (`../../../doc/file-rules.md`).
- The mounted suite's `relocated_hooks_are_served_read_only` checks that the served directory
  refuses writes at its own name.
- A chain through a gitdir's writable state (`.git/objects/...`) refuses the mount: git
  rewrites that state, so no read-only root can hold it.
- So does a hook directory that is the workspace root itself (`core.hooksPath = .`): its hooks
  are top-level files, and only the whole tree read-only could hold them.

What the per-operation rules hold on their own is narrower, and worth stating exactly: the sandbox
cannot *re-aim* hook resolution.

- `.git/config` is frozen, so it cannot introduce or change `core.hooksPath`.
- The `.git/hooks` symlink node is protected, so it cannot be deleted or replaced.
- What they cannot cover is a target the **host** already points hooks at, which is what the
  read-only root is for.
- Blocking the write *through* `.git/hooks/` would protect nothing: the same bytes are reachable
  under the target's own ordinary name (`shared-hooks/pre-commit`), so a rule about the symlink
  path closes nothing. Any real fix has to protect the *target*.

**Why resolving rather than refusing.**

- Resolving costs a git-config scan, which a refusal needs too, and a second protected root in the
  audited core, which the file rules bring anyway: a guard-found path is one more anchored line of
  the same kind (`policy.rs`, `RuleLine`).
- Refusing would leave every husky repository without a writable session.
- The snapshot the root rests on is one the host can invalidate mid-session, as a refusal's check
  would be; the window is recorded below.

**The binding rule.** Relocated hooks are one instance of a class the guard closes whole: Git
configuration, hooks and redirection files must not be reachable through a workspace path the
policy classifies as writable.

- The guard resolves every source, component by component:
  - the gitdir a `.git` pointer names;
  - its `commondir` and the common config behind it;
  - `config` and `config.worktree`;
  - each `hooksPath` value from every directory git runs hooks in — the worktree for most hooks,
    `$GIT_DIR` for the receive side, the common gitdir conservatively — since a relative value
    means a different directory to each;
  - the hook directory and every entry in it.
- Every workspace-resident component traversed must classify as `Protected`, or the resolution
  has permanently left the workspace. A hook directory's chain may instead pass through ordinary
  data, which then becomes a read-only root or a pinned component (above).
- Components, not only symlink nodes: an operational *directory* on a chain is a future symlink
  slot the sandbox can rename away and replant, and a chain that leaves the workspace re-enters
  the rule if a link points back in.
- `canonicalize` cannot express this — it returns the endpoint and erases the chain — so the walk
  is explicit and bounded in symlink hops.
- It classifies against the same submodule gitdir roots the runtime discovers by their `HEAD`, so
  guard-`Protected` means runtime-`Protected` (`.git/modules/<sub>/objects` is writable at
  runtime and no exemption here).
- Existence cannot weaken the answer — a missing operational name is one the sandbox can
  create — and only NotFound means absent: an unreadable step, or a config that is not UTF-8,
  refuses the mount. Absent in the daemon's view is absent on the host only where the daemon sees
  the host's objects, so a step outside them refuses too (below).

The rule is also what makes the mount-time snapshot durable: a snapshot is sound only over paths
its subject cannot mutate, and every allowed chain is made of `Protected`, read-only or pinned
components the sandbox can neither write nor rename. Only the host can invalidate it, which is the
window recorded below.

The same recognition covers the layout with no `.git` name at all:

- A workspace root that is itself laid out as a gitdir — a valid `HEAD` plus `objects/` and
  `refs/`, git's own `is_git_directory` triple, which reftable repositories keep precisely so old
  gits recognize them — is refused, since ascending discovery would adopt it and its config and
  hooks have ordinary writable names.
- Re-check the triple against git's discovery rules on upgrade (P5).

The read-only root is added only when the hook directory resolves **inside** the workspace.

- Hooks kept outside it are unreachable through the mount (`RESOLVE_IN_ROOT` clamps the
  resolution), so there is nothing to protect and those repositories are served normally.
- That holds where the daemon sees the host's own objects: all of them on native Linux, and
  through a podman machine only the directories the machine shares. A chain leaving those refuses
  the mount, since the host could follow it back into the workspace unseen.

The scanner behind it skips section headers without reading their names, so it cannot tell
`core.hooksPath` from a `hooksPath` under a section git never consults for hooks.

- It therefore judges **every** `hooksPath` the file states and serves each one resolving inside
  the workspace read-only.
- Keeping only the last would be the fail-open reading: a stray `[tool] hooksPath = /opt/hooks`
  after a real `[core] hooksPath = ./githooks` would answer for both, and the worktree hooks git
  actually runs would be served as ordinary writable data.
- The price is a read-only directory for a `hooksPath` git ignores, never a lost guarantee.

It reads the forms git's `git_parse_source` (config.c) reads, so that the value it judges is the
one hooks run from:

- a leading BOM is skipped, and a key may follow one or more section headers on its line
  (`[core] hooksPath = ./githooks`), whose quoted subsection may hold `]`;
- quote characters anywhere in the value are removed, and whitespace inside them is kept;
- whitespace outside quotes is kept when another character or a quote character follows it, and
  judged both as written, which git 2.47 reads, and with each character replaced by a space,
  which git 2.39 reads.

The doubts refuse rather than guess: with each, the scanner would otherwise compare a different
spelling than the one hooks run from, or miss a `hooksPath` git reads:

- a `~` (expanding it needs the host's home directory, which the daemon does not have);
- a backslash (git decodes escapes the scanner does not);
- an unterminated quote;
- a section header left open on its line;
- a bare `path` key, which under `include` or `includeIf` names a file the scanner never opens.

All are rare in a *repository-local* config, and the message tells the operator what to change.

Scope: the repository at the workspace root, plus the bare-root check above. What lies below the
root is unchecked, recorded in `TODO.md` and named in `SECURITY.md`:

- A repository the **host** nested deeper — its protected entries under `.git` names are frozen
  like any other's, but Git metadata the host routed into the worktree (relocated hooks, a
  redirected gitdir) are served writable unless a file rule lists them, as `readonly .husky`
  does husky's; the sandbox cannot create this layout.
- A **bare layout**, which the sandbox *can* create — `git init --bare` and
  `git clone --bare|--mirror` write only ordinary names, and no per-name rule can refuse `HEAD`,
  `objects` and `refs` individually without refusing legitimate projects ("Consequences",
  below) — anywhere below the root, or at the root itself once the mount-time check has passed:
  a session starting in a repository-less workspace can lay the triple at the root mid-session.

The check is also a snapshot, taken before the mount and not repeated.

- A host that relocates its hooks into the worktree *after* a session is serving gets no second
  resolution.
- Polling for it would buy a guarantee only as fresh as its last poll while putting a config read
  and an `lstat` on the hot path, so the answer is to record the window rather than chase it.
- The window is the host's own to open: the binding rule allows only chains the sandbox cannot
  mutate.
- What it costs is that Git configuration or hooks the host relocates into writable project paths
  remain writable for the rest of that session, just as they would without the mount-time guard.


## What this intentionally does *not* protect, and why that is safe

- `.gitattributes`, `.gitmodules` — writable worktree data; can only activate host-defined drivers,
  cannot define commands (and cannot smuggle `!cmd` submodule updates). A host's git-lfs filter
  still connects where `.lfsconfig` says (`SECURITY.md`, "The project directory").
- Operational gitdir state (`objects`, `refs`, `logs`, `index`, …) — writable, or `git` cannot
  function; none of it is executed, and `alternates` is the one path in it git opens (group 4).
- Host-side changes — the host writes the backing store directly, bypassing the filter by design.
  Legitimate host `git` metadata is created outside the sandbox and is not the threat.


## Consequences: git operations blocked inside the project

These follow from the name rule and the classifier and must be documented, not silently broken
(SECURITY.md, "The host's git executing what the sandbox wrote" and "The project directory", has
the security reason for each):

- `git init` / `git clone` into the project — creates a new `.git`. Blocked. Clone under `~`.
  - The **bare-layout forms are not blocked**: `git init --bare` and `git clone --bare|--mirror`
    write only ordinary names (`HEAD`, `objects/`, `refs/`, `config`, `hooks/`), which no per-name
    rule can refuse without refusing legitimate projects that have them.
  - The guard refuses a bare layout at the workspace root at mount; one the sandbox creates —
    below the root, or at the root after that check — is the gap SECURITY.md records ("The
    project directory"): running host git inside an agent-created directory is running the
    agent's output.
- `git worktree add <path>` with `<path>` in the project — writes a `.git` **file** at the new
  worktree. Blocked.
- Submodule checkout that would create a submodule's worktree `.git` file in the project —
  operational state in `.git/modules/<n>/` stays writable, while its protected entries stay frozen
  by the recursion in "The immutable set". The new `.git` pointer in the worktree is refused.
- Editing `.git/config` (e.g. `git config --local core.hooksPath …`) — blocked; the whole point.
  - So is every command that records something there: `git remote add`, `git push -u`,
    `git branch --set-upstream-to`, `git switch --track`, `git sparse-checkout`. `git branch -m`
    renames the branch and then fails; `git branch -d` deletes it and warns.
- `git bisect` — its state stays protected, because a host git through 2.33 evaluates
  `BISECT_NAMES` as shell code (`classify_within_gitdir` in `src/policy.rs` has the details).
- `git rerere` — its `rr-cache/` stays protected, since creating it enables rerere for host merges
  (`classify_within_gitdir` has why).
- Removing `objects/info/alternates` to detach a repository from the object directories it
  borrows, after `git repack -a` — blocked (group 4). Do it on the host. Git writes the file only
  when it creates a repository, `git clone --shared` or `--reference`, which is blocked already.
- `git rebase` (any form — the merge backend writes `rebase-merge/` even for a clean rebase),
  `git am` (writes `rebase-apply/`), and `git cherry-pick`/`git revert` of a *range* or when a
  conflict makes git open a sequence (writes `sequencer/`) — all blocked, because their todo
  can contain `exec` lines a later host `git rebase --continue` would run.
  - A single, clean `cherry-pick`/`revert` (no sequence) still works.
  - Do rebases on the host, or on a clone under `~`.

Existing host repositories keep working for the everyday commands: `status`, `add`, `commit`,
`checkout`, `switch`, `fetch`, `merge`, `stash`, `gc` touch only operational state. The rebase
family, bisect and the commands writing config are the deliberate exceptions above.


## Prior art: git's own CVE history

Git's security advisories are a direct catalog of how repository state becomes host code execution.
The per-CVE verdicts, the watch-list and how to redo the research are `security-research.md`; the
two conclusions this policy rests on are below.

**The filter denies the final write of a whole class.**

- The CVE-2024-32002 / CVE-2021-21300 / CVE-2014-9390 class all end the same way: git is tricked,
  via symlink + case-insensitivity + submodules, into a *write* whose path it believes is in a
  worktree but resolves into `.git/hooks`.
- Because the filter classifies the **resolved destination** of every mutation — following
  symlinks through its own resolver — the sandbox-side git performing that final write is denied
  at `open`/`create`, however clever the trick that produced the path.
- Host-side git bypasses the filter by design; there the mitigation is a patched git, as for any
  untrusted clone.

**The `.gitmodules` residual.**

- Leaving `.gitmodules` writable rests on "Premises"'s P0 and P4, so it assumes git handles
  hostile `.gitmodules` correctly — and CVE-2018-11235, CVE-2024-32002 and CVE-2025-48384 are
  cases where a git bug broke that.
- Accepted as "hostile data plus a git bug" (SECURITY.md): on the sandbox side the filter still
  denies the final `.git` write; on the host side the mitigation is keeping git patched.


## Test list (each vector → a test through the real FUSE mount)

Policy unit tests cover the classifier in isolation; these run against a mounted filesystem.

**Name rule / creation (group 3a):**

- `mkdir`, `open(O_CREAT)`, `mknod`, `symlink`, `link`, `rename` into, `renameat2`
  `RENAME_EXCHANGE` into — for basenames `.git`, `.GIT`, `.Git`, `.git.` and `.git ` (trailing
  space); each must fail.
- Control names `.git<newline>`, `.gitignore`, `.github` and a non-UTF-8 name must **succeed**
  (only exact-fold `.git` is special).

**Pointer rewrite (group 3b):** with an existing `.git` file present, every mutation op above must
fail against it.

**A second name (groups 3a, 3b):** with a host hard link to a `.git` file and to a
`.ko-agent-sandbox` file:

- append, `open(O_CREAT)`, `unlink`, `rename` from and onto, and `link` through the link's name
  must fail;
- while the host keeps making such a file and link, an `open(O_CREAT)` of the link's name never
  opens the host's file;
- a directory handle opened on ordinary names that come to lead through a second name of `.git`
  or `.ko-agent-sandbox` must fail with `ESTALE`, and so must `fchmod`, `futimens` and a link
  through a file descriptor whose name has become such a second name, leaving the guarded file's
  metadata and link count as they were.

**Hooks (group 1):**

- `write`, `pwrite`, `truncate`, `ftruncate`, `open O_TRUNC`, `chmod`, `chown`, `unlink`, `rmdir`,
  `rename` from/to, `link`, `symlink`, `mknod` against `<gitdir>/hooks/**` — each fails.
- Same suite against `modules/<n>/hooks/**` and `worktrees/<n>/hooks/**` to prove the recursion.
- Not `setxattr`/`removexattr` ("Operations that make these mutations" has why).

**Config (group 2):**

- Direct mutation of `config`, `config.worktree`, `commondir` fails; real
  `git config --local core.hooksPath …` and `git config --local core.fsmonitor …` fail.
- An `include.path` cannot be added.
- Assert that a host-defined filter activated by an agent-written `.gitattributes` runs only the
  host's command (documents the accepted boundary), and that a `!command` in an agent-written
  `.gitmodules` is not honored.

**Alternates (group 4):** creating or symlinking `objects/info/alternates` and
`http-alternates` fails, in the gitdir and a submodule's; renaming `objects` or `objects/info`, and
renaming or symlinking a directory onto `objects/info`, fails.

**Operational writability (classifier):**

- The happy-path Git-integration suite — `status/add/commit/checkout/switch/fetch/merge` on a
  host repo through the mount — must pass, so the writable set is complete enough. Under the
  allowlist choice, a missing operational path fails here.
- Separately, `git rebase`/`am`/ranged `cherry-pick` must **fail** (their todo state is frozen);
  assert the block, so a later widening of the allowlist that reopened them would be caught.

**Symlink / escape:**

- `<gitdir>/hooks` is itself a symlink (protect the link, not just its target); a symlink whose
  target escapes the backing root; `.git/hooks/x → outside`. Cannot mutate the protected object;
  cannot escape the root.
- The stale-handle case, which is neither of those: a directory the sandbox renames while still
  holding it open, with a symlink to a gitdir left at the name it vacated — the held handle must
  not reach what its old name no longer describes, at the workspace root or inside a gitdir's
  operational tree.

**Races (TOCTOU):** rename vs open, rename vs classifier lookup, host-side rename while the sandbox
holds a descriptor — concurrency tests aimed specifically at the resolve-then-act window.


## Premises: the git behavior this rests on

Everything above is derived from how a specific `git` lays out and writes its metadata. Those are
**premises**, not universal truths: a future `git` could change them, and the classifier's
correctness assumptions change with it.

**Observed under `git 2.47.3`.** `probe/observe-git.sh` re-derives them:

- It drives a real git through init/commit/branch/switch/merge/rebase/tag/stash/fetch/gc/
  `worktree add`/`submodule add` and classifies everything written under `.git` with the actual
  policy.
- Run it after a git upgrade, compare against the premises below, and record the new version
  here.

That script validates *compatibility* — that the allowlist does not over-freeze the legitimate git
the agent itself runs. It is not a security oracle, for the reason the classifier section gives,
and it has three blind spots worth knowing:

- it sees only state that *persists* after a command, so a clean `git rebase` (which creates and
  deletes `rebase-merge/` in one command) never appears in a run;
- neither does any file git removes or renames away within the same command: every `.lock`, and
  `git stash`'s `index.stash.<pid>`, `git gc`'s `gc.pid` and `packed-refs.new`. `strace -f`
  around single commands sees them; `tests/git_corpus.rs` records what it saw;
- a path being written does not make it safe to allow.

Only real git against a real mount exercises the locks, so `tests/mounted_git.rs` is what
establishes which git commands work through the filter — the script records the files each
command leaves.

- **P0 — command execution is configured only through the config files** (group 2 has the set and
  the argument). The whole design rests on it. Re-check on upgrade by scanning git's release notes
  for a new configuration *source*, or a new worktree-data→command path; human judgement, not a
  scripted check.
- **P1 — nested gitdirs are at `modules/<name>` and `worktrees/<name>`, one of them depth 1.**
  - A submodule's name defaults to its path, so `git submodule add <url> libs/foo` yields
    `[submodule "libs/foo"]` and the gitdir `.git/modules/libs/foo`; a linked worktree is named
    for the *basename* of its path, so `git worktree add ../wt/deep/foo` yields
    `.git/worktrees/foo`, always one component (both measured, git 2.47).
  - Any submodule under `deps/`, `vendor/` or `third_party/` has a multi-component name, so this
    is the common layout, not an edge case.
  - If it drifted, a submodule's writable `objects/` would be judged against the wrong root and
    frozen — fail-closed, but quiet.
  - Guarded by `tests/git_corpus.rs`, `tests/mounted_git.rs`
    (`a_submodule_in_a_subdirectory_works_like_any_other`) and `observe-git.sh`, which locates
    roots by the `HEAD` they hold rather than by depth.
- **P2 — a `<name>.lock` inherits the class of what it locks.**
  - git writes one beside anything it locks and renames it into place, so `HEAD.lock` and
    `AUTO_MERGE.lock` are operational while `config.lock` is not — a rule rather than a list,
    since a list freezes whichever name it forgot.
  - A new operational file that is *not* listed is frozen by default: a broken git command in the
    live-mount tests, not a hole, but a maintenance signal to add it to the allowlist and to
    `git_corpus.rs`.
  - The `rebase-merge`/`rebase-apply`/`sequencer` exception is group 1's; do not add them on the
    grounds that git writes them.
- **P3 — the protected entries are written only at creation time.**
  - `config`, `config.worktree`, `hooks/**`, `commondir`, `gitdir`, `description`, `branches/**`
    are written by init, `submodule add` and `worktree add`, never during ordinary
    commit/checkout/merge/fetch.
  - That is why freezing them costs an existing repository nothing, and why creating a submodule
    or linked worktree inside the project is blocked ("Consequences", above).
  - Guarded by `tests/git_corpus.rs`.
- **P4 — `.gitmodules` cannot define a command**, which is what lets it stay writable worktree
  data (group 2). Re-check on upgrade that git still refuses a `submodule.<name>.update = !command`
  sourced from it; if that ever changed, `.gitmodules` would need protecting.
- **P5 — repository discovery keys on an entry named exactly `.git`** — a directory or a `gitdir:`
  pointer file — **or on a directory that is itself a gitdir** (the bare layout: valid `HEAD`,
  `objects/`, `refs/`, git's `is_git_directory` triple, which reftable repositories keep so old
  gits recognize them).
  - The first form is the basis of the name rule and of freezing the pointer entry.
  - The second is what the guard's bare-root check mirrors, and what the bare-layout gap is
    recorded for.
  - Re-check on upgrade that git introduces no third discovery form and no change to the triple.

Most drift shows up as a broken git command rather than a silent hole — P2 especially. **P0 and P4
could weaken the boundary if they regressed**, and neither is caught by a script: both need a
human read of git's release notes on upgrade.
