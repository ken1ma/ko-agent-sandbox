//! Real `git` driven through a real mount: the everyday commands must keep working on a host
//! repository, and the deliberately-blocked ones must fail.
//!
//! This is the compatibility half of the evidence (`docs/git-observations.md`): the allowlist is
//! fail-closed, so an operational path we failed to enumerate shows up here as a broken git command
//! rather than as a security hole. The blocked commands are asserted too, so a later widening of the
//! allowlist that quietly reopened them would be caught.
//!
//! Needs `/dev/fuse` and `CAP_SYS_ADMIN` (the dev rig), and `git` on PATH.

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use common::TestMount;

fn git_in(directory: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("run git")
}

#[track_caller]
fn succeeds(what: &str, output: Output) -> String {
    assert!(
        output.status.success(),
        "{what} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[track_caller]
fn fails(what: &str, output: Output) {
    assert!(
        !output.status.success(),
        "{what} SUCCEEDED, but the filter is supposed to block it"
    );
}

/// A host repository with two commits and a side branch, built directly in the backing tree — the
/// host's own `git`, unfiltered, exactly as a user's checkout arrives.
fn host_repository(backing: &Path) {
    succeeds(
        "host git init",
        git_in(backing, &["init", "-q", "-b", "main"]),
    );
    fs::write(backing.join("file.txt"), b"one\n").unwrap();
    succeeds("host git add", git_in(backing, &["add", "file.txt"]));
    succeeds(
        "host git commit",
        git_in(backing, &["commit", "-qm", "first"]),
    );

    succeeds("host branch", git_in(backing, &["branch", "side"]));
    fs::write(backing.join("file.txt"), b"one\ntwo\n").unwrap();
    succeeds("host git add", git_in(backing, &["add", "file.txt"]));
    succeeds(
        "host git commit",
        git_in(backing, &["commit", "-qm", "second"]),
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn the_everyday_commands_work_on_a_host_repository() {
    let mount = TestMount::new(host_repository);
    let workspace = mount.at("");

    succeeds("git status", git_in(&workspace, &["status", "--porcelain"]));
    succeeds("git log", git_in(&workspace, &["log", "--oneline"]));
    succeeds("git diff", git_in(&workspace, &["diff"]));

    fs::write(mount.at("file.txt"), b"one\ntwo\nthree\n").unwrap();
    succeeds("git add", git_in(&workspace, &["add", "file.txt"]));
    succeeds(
        "git commit",
        git_in(&workspace, &["commit", "-qm", "third"]),
    );

    let log = succeeds("git log", git_in(&workspace, &["log", "--oneline"]));
    assert_eq!(log.lines().count(), 3, "the commit did not land:\n{log}");

    // And the host sees the new commit, because the backing tree is the same tree.
    let host_log = succeeds(
        "host git log",
        git_in(&mount.backing, &["log", "--oneline"]),
    );
    assert_eq!(host_log.lines().count(), 3);
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn branch_switching_and_merging_work() {
    let mount = TestMount::new(host_repository);
    let workspace = mount.at("");

    succeeds("git switch", git_in(&workspace, &["switch", "-q", "side"]));
    fs::write(mount.at("side.txt"), b"side\n").unwrap();
    succeeds("git add", git_in(&workspace, &["add", "side.txt"]));
    succeeds(
        "git commit",
        git_in(&workspace, &["commit", "-qm", "side work"]),
    );

    succeeds(
        "git switch back",
        git_in(&workspace, &["switch", "-q", "main"]),
    );
    succeeds(
        "git merge",
        git_in(&workspace, &["merge", "--no-edit", "-q", "side"]),
    );
    assert!(
        mount.at("side.txt").exists(),
        "the merge did not bring the file across"
    );

    succeeds(
        "git checkout",
        git_in(&workspace, &["checkout", "-q", "side"]),
    );
    succeeds("git tag", git_in(&workspace, &["tag", "v1"]));
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn the_deliberately_blocked_commands_fail() {
    // Each of these is documented in `git-metadata.md` as a known limitation, with its reason.
    // Asserting the block keeps a later allowlist widening from silently reopening it.
    let mount = TestMount::new(host_repository);
    let workspace = mount.at("");

    // Give `side` a commit of its own, so the histories genuinely diverge: rebasing an up-to-date
    // branch is a no-op git short-circuits without ever writing `rebase-merge/`, which would make
    // this assertion vacuous rather than meaningful.
    succeeds("git switch", git_in(&workspace, &["switch", "-q", "side"]));
    fs::write(mount.at("side.txt"), b"side\n").unwrap();
    succeeds("git add", git_in(&workspace, &["add", "side.txt"]));
    succeeds(
        "git commit",
        git_in(&workspace, &["commit", "-qm", "side work"]),
    );
    succeeds(
        "git switch back",
        git_in(&workspace, &["switch", "-q", "main"]),
    );

    // Writes rebase-merge/, whose todo can carry `exec` lines a later host resume would run.
    fails("git rebase", git_in(&workspace, &["rebase", "-q", "side"]));
    assert!(
        !mount.backing_at(".git/rebase-merge").exists(),
        "rebase state was created despite the block"
    );

    // Would rewrite .git/config — the file that defines every command-executing key.
    fails(
        "git config --local",
        git_in(
            &workspace,
            &["config", "--local", "core.hooksPath", "/tmp/evil"],
        ),
    );

    // Would plant a new repository for the host to discover.
    fs::create_dir_all(mount.at("newproject")).unwrap();
    fails(
        "git init in the workspace",
        git_in(&mount.at("newproject"), &["init", "-q"]),
    );

    // The host's config is untouched by any of it.
    let config = fs::read_to_string(mount.backing_at(".git/config")).unwrap();
    assert!(
        !config.contains("hooksPath"),
        "the config was modified despite the block:\n{config}"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_hook_the_host_installed_still_runs_for_the_host() {
    // The filter freezes hooks against the sandbox; it must not break the host's own hook, which is
    // the thing being protected rather than disabled.
    let mount = TestMount::new(|backing| {
        host_repository(backing);
        let hook = backing.join(".git/hooks/pre-commit");
        fs::write(&hook, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(&hook).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        fs::set_permissions(&hook, permissions).unwrap();
    });

    fs::write(mount.at("file.txt"), b"changed\n").unwrap();
    succeeds("git add", git_in(&mount.at(""), &["add", "file.txt"]));
    succeeds(
        "git commit with the host's hook present",
        git_in(&mount.at(""), &["commit", "-qm", "with hook"]),
    );
}
