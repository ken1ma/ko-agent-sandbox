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
  - [ ] Option, to open the route before a Debian base whose git is 2.48 or later: build forky's
    git source package on trixie in a build stage, and install the resulting `git` and `git-man`
    packages.
    - The stage adds forky as a `deb-src` entry only, so apt can install no forky binary.
      `apt-get source git/forky` checks the source against the archive's signed index, so the
      Containerfile names no version and no checksum.
    - A version in forky was uploaded to unstable by a Debian developer and waited there some
      days. A release-critical bug that forky's version lacks holds a version back, unless the
      release team forces it (Debian Developer's Reference, "Updates from unstable").
    - The source of git `1:2.53.0-1`, forky's version on 2026-11-25, declares no build dependency
      newer than trixie's `Packages` index has that day:
      https://deb.debian.org/debian/pool/main/g/git/git_2.53.0-1.dsc
    - Not yet run: the build itself.
    - Each image rebuild takes the version forky has that day. A security release needs no edit
      but arrives only after it migrates, and a new minor version arrives unannounced.
    - Upstream git plans to make Rust mandatory in 3.0, and trixie's rustc is 1.85
      (`Documentation/BreakingChanges.adoc` in git 2.53.0). A forky source that build-depends on
      a package newer than trixie's stops this build.
    - Installing forky's binary by apt pinning is excluded: forky's git declares
      `libc6 (>= 2.42)` and trixie has 2.41, so apt would replace the image's C library.
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
