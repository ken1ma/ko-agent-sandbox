# Git-behavior premises

`ko-agent-fs`'s policy is derived from how a specific `git` lays out and writes its metadata. Those
are **premises**, not universal truths — a future `git` could change them, and if it does, the
classifier's correctness assumptions change with it. This file records the premises, the version
they were observed under, how each is guarded, and how to re-check them.

**Observed under:** `git 2.47.3`.
**Re-derive:** `probes/observe-git.sh` drives a real git through init/commit/branch/switch/merge/
rebase/tag/stash/fetch/gc/`worktree add`/`submodule add` and classifies everything it writes under
`.git` with the actual policy. Run it after a git upgrade and compare against the premises below.

The keystone premise (P0) is the one to weigh hardest; the rest are layout details.

**What this observation is, and is not.** It validates *compatibility* — that the allowlist does not
*over*-freeze and break the legitimate git the sandboxed agent itself runs (`status`, `commit`,
`checkout`, …). It is **not** a security oracle: the attacker does not act like git — it writes raw
syscalls and does whatever — so what to *deny* is decided by the execution lens (`git-metadata.md`)
and proven by adversarial tests, never by watching git. Two blind spots follow. First, git writing a
path does not make it safe to allow: `rebase-merge`/`rebase-apply`/`sequencer` are written often
yet frozen, because their todo `exec` lines are host-executable (P2 below). Second, this method only
sees *persisted* state — a clean `git rebase` creates and deletes `rebase-merge/` in one command,
so the observation run never lists it; its exec risk was found by reasoning, not by the script.


## P0 — command execution is configured only through the config files

Every git mechanism that makes a later `git` run a program (`core.hooksPath`, `core.fsmonitor`,
`core.pager`, filters, `credential.helper`, aliases, …) is read **only** from a repository's
`config` / `config.worktree`, or a file pulled in by `include.path` / `includeIf` from one of those.
This is why the filter freezes the config *files* rather than chasing individual keys
(`git-metadata.md`, group 2): protect the files and every command key, present and future, is out of
reach, because introducing a new one requires writing a frozen file.

- **Depends on:** the whole design. If a future git read a command-executing key from some *other*
  writable location under `.git` (a new file, or a worktree-data file like `.gitattributes` gaining
  the ability to *define* rather than merely *activate* a command), P0 would be incomplete.
- **Re-check on upgrade:** scan git's release notes for new configuration *sources* or new
  worktree-data → command paths. This is a human judgement, not a scripted check.


## P1 — nested gitdirs live at `modules/<name>` and `worktrees/<name>`, depth 1

A submodule's gitdir is `$GIT_DIR/modules/<name>`; a linked worktree's `$GIT_DIR/worktrees/<name>`.
Observed exactly (`.git/modules/sub`, `.git/worktrees/wt`); specified in `gitrepository-layout(5)`.

- **Depends on:** `policy::child_context`'s re-root when `rel` is `["modules"]` or `["worktrees"]`.
  If git moved these, a submodule's writable `objects/` would be judged against the outer gitdir and
  wrongly frozen, or worse mis-scoped.
- **Guarded by:** `tests/git_corpus.rs` (nested paths classify correctly) and `observe-git.sh`
  (prints the actual roots).


## P2 — the operational files git writes at a gitdir root

During normal operations git writes and rewrites, at a gitdir root, at least: `HEAD`, `ORIG_HEAD`,
`FETCH_HEAD`, `MERGE_HEAD` (and the other `*_HEAD`), `index` (+ `.lock`), `packed-refs`,
`COMMIT_EDITMSG`, `MERGE_MSG`, and the trees `refs/`, `logs/`, `objects/`, plus `info/`. These must
stay writable or the corresponding git command breaks.

git also writes `<name>.lock` beside anything it locks, then renames it into place. A lock therefore
**inherits the class of its target**: `HEAD.lock` and `AUTO_MERGE.lock` are operational,
`config.lock` is not — a rule rather than a list of lockable names, for the reason the classifier
below records.

- **Depends on:** the operational allowlist in `policy::classify_within_gitdir`.
- **Fail-closed:** a new operational file we have *not* listed is frozen by default — it shows as a
  broken git command in the live-mount integration tests, not as a security hole. That is the safe
  direction, but it is a maintenance signal: add the file to the allowlist and to `git_corpus.rs`.
- **A third blind spot of the observation method:** `observe-git.sh` lists files that *persist*
  after a command, so it can never see a lock — locks are renamed away within the same command —
  and neither can a static corpus. Only real git against a real mount exercises them, so treat
  `tests/mounted_git.rs` as the authority for the operational set; the script maps the layout, it
  does not enumerate the write set.
- **Guarded by:** `tests/git_corpus.rs`; re-checked by `observe-git.sh` (the OPERATIONAL list).
- **The exception:** `rebase-merge/`, `rebase-apply/`, and `sequencer/` are written by git but are
  **not** operational — they are frozen (P2a). Do not add them back by "git writes them, so allow".

### P2a — rebase/sequencer todo is control, not operational

`rebase-merge/git-rebase-todo`, `rebase-apply/`, and `sequencer/todo` are control despite git
writing them constantly; `git-metadata.md` (group 1) has the reason.

- **Consequence:** `git rebase` (any form — the merge backend always writes `rebase-merge/`), `am`,
  and ranged/conflicted `cherry-pick`/`revert` do not work in `/workspace`. Do them on the host or a
  `/tmp` clone. A single clean `cherry-pick`/`revert` still works.
- **Guarded by:** `tests/git_corpus.rs` (`rebase_and_sequencer_todo_state_is_frozen`).


## P3 — the control files, and why freezing them does not break normal ops

The frozen set git creates: `config`, `config.worktree`, `hooks/**`, `commondir`, `gitdir`,
`description`, `branches/**`. Observation confirms git writes these only at *creation* time (init,
`submodule add`, `worktree add`) — never during ordinary commit/checkout/merge/fetch. So freezing
them costs nothing for normal operation of an existing repository.

- **Consequence (P4):** creating a submodule or linked worktree *inside* `/workspace` writes control
  state and is therefore blocked — a documented limitation, not a bug. Do those on the host, or in
  `/tmp`.
- **Guarded by:** `tests/git_corpus.rs` (control paths stay frozen).


## P5 — `.gitmodules` cannot define a command

`.gitmodules` stays writable worktree data because git refuses to honor a `submodule.<name>.update =
!command` sourced from it (the CVE-2017-1000117 family), reading `!command` only from `.git/config`.

- **Depends on:** leaving `.gitmodules` unprotected (`git-metadata.md`, group 2).
- **Re-check on upgrade:** confirm git still refuses `!command` from `.gitmodules`. If that ever
  changed, `.gitmodules` would need protecting.


## P6 — repository discovery keys on an entry named exactly `.git`

Host `git` discovers a repository by finding an entry named `.git` (a directory, or a pointer file
containing `gitdir:`) at a worktree location. That is the basis of the name rule and of freezing the
`.git` pointer entry.

- **Depends on:** `policy::is_dotgit_name` and the `NotGit → InGit([])` transition on a `.git` name.
- **Re-check on upgrade:** confirm git introduces no second discovery name. (Independently, whether
  the name rule's *superset* covers a given backing filesystem's case-folding is the separate open
  item — a per-backing empirical test, see `git-metadata.md`.)


## When a premise changes

The fail-closed design means most drift shows up as a *broken git command*, never as a silent hole —
P2 especially. But P0 and P5 are the ones that could weaken the boundary if they regressed, and
neither is caught by a script: both need a human read of git's release notes on upgrade. Record the
new observed version here when re-validated.
