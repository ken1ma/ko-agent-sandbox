# TODO — Windows

This file lists the remaining work that only a Windows host has (`design-win.md`), under the
criteria that `TODO.md` states for its own items. The Windows rows of a section that covers every
host stay in `TODO.md`.

## Deferred — a linked worktree's absolute pointer on Windows

`git worktree add` writes the pointer as `C:/Users/<me>/repo/.git/worktrees/<name>`, which the
container's git cannot follow at `/mnt/c/...`, so the read-only bind is skipped there
(`SandboxWorkspace.linkedGitdirBind`).

The launch is refused after the no-git warning. Both backends run the workspace policy's guard
(`guard.rs`, `locate_gitdir`), which reads `C:/...` as a relative path. The refusal names
`<mountPath>/C:` as "inside the workspace and writable by the sandbox" (BPF backend, Windows,
2026-11-23).

Two routes give the container's git the repository:

- A relative pointer resolves under `/mnt/c` as it does under `C:`, and the bind serves one.
  - But `git worktree add --relative-paths`, or `git worktree repair --relative-paths` for an
    existing worktree (git 2.48 or later), also sets `extensions.relativeWorktrees`. The image's
    git, Debian trixie's 2.47.3, refuses a repository with an extension it does not know, in the
    main worktree as in the linked one.
  - The launch reads the extension from the common config, and keeps the no-git warning with a
    note rather than promise git (`SandboxWorkspace.setsRelativeWorktrees`).
  - The route opens when the image's git is 2.48 or later, and that check goes with the upgrade.
    Until then only a hand-written relative pointer works, and `git worktree repair` rewrites such
    a pointer absolute.
  - A hand-written pointer gives the session read-only git (`TODO.md`, "The workspace root mounted
    at its own path", Recorded Windows results).
- [ ] For an absolute pointer, bind a launcher-written pointer file naming the `/mnt/<drive>`
  spelling over `<mountPath>/.git`. The bind hides the FUSE backend's protected pointer from the
  container alone.
  - The guard reads the host's own `.git`, so it must also read a drive path as
    `/mnt/<drive>/...`, in the pointer, `commondir`, `core.worktree` and `core.hooksPath` alike.
    Without the bind, a launch past the guard has no git.
  - Setting `GIT_DIR` and `GIT_WORK_TREE` instead would redirect git in every other repository the
    agent uses, such as clones under `~`.
  - `<main>/.git/worktrees/<name>/gitdir` keeps the `C:/` spelling either way. `git worktree list`
    reads that file, and nothing the read-only bind serves needs it.
