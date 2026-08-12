//! The operational allowlist, checked against the paths real `git` writes.
//!
//! These paths were observed by driving git through init/commit/branch/switch/merge/rebase/tag/
//! stash/fetch/gc/`worktree add`/`submodule add` and enumerating everything written under `.git`
//! (the `classify_paths` example reproduces the run). The corpus is static so the test is
//! deterministic and needs no git at test time; the live FUSE-mount integration tests are the
//! ultimate gate. If a future git version writes a new operational file at a gitdir root, the
//! fail-closed classifier will freeze it — caught there as a broken git command, and worth adding
//! here once identified.

use ko_agent_fs::policy::{classify_relative_path, GitPathClass};

#[track_caller]
fn operational(path: &str) {
    assert_eq!(
        classify_relative_path(path.as_bytes()),
        GitPathClass::Operational,
        "expected {path} to be writable"
    );
}

#[track_caller]
fn control(path: &str) {
    assert_eq!(
        classify_relative_path(path.as_bytes()),
        GitPathClass::Control,
        "expected {path} to be frozen"
    );
}

#[test]
fn operational_state_git_writes_during_normal_ops_stays_writable() {
    for path in [
        // Refs and their reflogs, the scratch messages, the ref-store files.
        ".git/HEAD",
        ".git/ORIG_HEAD",
        ".git/FETCH_HEAD",
        ".git/MERGE_HEAD",
        ".git/index",
        ".git/packed-refs",
        // A lock inherits its target's class; `policy::classify_within_gitdir` has why that is a
        // rule rather than an enumeration.
        ".git/index.lock",
        ".git/HEAD.lock",
        ".git/AUTO_MERGE.lock",
        ".git/REBASE_HEAD.lock",
        ".git/packed-refs.lock",
        ".git/AUTO_MERGE",
        ".git/REBASE_HEAD",
        ".git/COMMIT_EDITMSG",
        ".git/MERGE_MSG",
        ".git/refs/heads/main",
        ".git/refs/tags/v1",
        ".git/refs/remotes/donor/main",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/main",
        ".git/objects/pack/pack-0123.pack",
        ".git/objects/ab/cdef0123456789",
        ".git/info/exclude",
        // A submodule's own gitdir (.git/modules/<name>) re-roots, so its state is writable.
        ".git/modules/sub/HEAD",
        ".git/modules/sub/index",
        ".git/modules/sub/refs/heads/main",
        ".git/modules/sub/objects/ab/cd",
        ".git/modules/sub/logs/HEAD",
        // A linked worktree's gitdir (.git/worktrees/<name>) re-roots; its per-worktree state too.
        ".git/worktrees/wt/HEAD",
        ".git/worktrees/wt/ORIG_HEAD",
        ".git/worktrees/wt/index",
        ".git/worktrees/wt/logs/HEAD",
    ] {
        operational(path);
    }
}

#[test]
fn control_state_stays_frozen() {
    for path in [
        // The command-defining config files and the hook tree — the crown jewels.
        ".git/config",
        ".git/config.worktree",
        ".git/hooks/pre-commit",
        ".git/hooks/post-checkout.sample",
        // A submodule gitdir's own config and hooks, reached through the re-root.
        ".git/modules/sub/config",
        ".git/modules/sub/hooks/pre-commit",
        // A worktree's redirection markers — re-aiming these would relocate config/hooks resolution.
        ".git/worktrees/wt/gitdir",
        ".git/worktrees/wt/commondir",
        ".git/worktrees/wt/config.worktree",
        // A lock on control state is control: the inheritance rule must not become a way in.
        ".git/config.lock",
        ".git/config.worktree.lock",
    ] {
        control(path);
    }
}

#[test]
fn rebase_and_sequencer_todo_state_is_frozen() {
    // Frozen like hooks despite git writing them constantly (`docs/git-metadata.md`, group 1): the
    // one place security overrides compatibility, so those commands do not work in /workspace.
    for path in [
        ".git/rebase-merge/git-rebase-todo",
        ".git/rebase-apply/0001",
        ".git/sequencer/todo",
    ] {
        control(path);
    }
}

#[test]
fn the_dotgit_entry_itself_is_frozen_however_it_is_named() {
    // A new `.git` (dir or pointer file) is name-refused at create; an existing one is immutable.
    for path in [".git", "sub/.git", "deep/nested/.git"] {
        control(path);
    }
}
