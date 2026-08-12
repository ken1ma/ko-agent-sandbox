//! The deny surface, exercised through a real mount by an attacker who is *not* git: raw filesystem
//! operations against every path that could make a later host `git` execute code.
//!
//! Each refusal is asserted to be `EPERM` specifically — a policy denial, not merely "an error".
//! Needs `/dev/fuse` and `CAP_SYS_ADMIN` (the dev rig).

mod common;

use std::ffi::CString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use common::{allowed, denied, denied_nix, TestMount};
use nix::sys::stat::{mknodat, Mode, SFlag};

const HOOK: &str = ".git/hooks/pre-commit";
const HOOK_BODY: &str = "#!/bin/sh\n# the host's own hook\n";

/// `RENAME_EXCHANGE` through the raw syscall, which is what `fs.rs` issues and for the reason stated
/// there. Going through the syscall here too means the test drives the exact request the filter has
/// to decide on, on either libc.
fn rename_exchange(dirfd: &OwnedFd, old: &str, new: &str) -> nix::Result<()> {
    let old = CString::new(old).expect("an old path without a NUL");
    let new = CString::new(new).expect("a new path without a NUL");
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dirfd.as_raw_fd(),
            old.as_ptr(),
            dirfd.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(nix::errno::Errno::last())
    }
}

/// A host repository plus an ordinary source tree — the realistic starting state.
fn repository(backing: &Path) {
    fs::create_dir_all(backing.join(".git/hooks")).unwrap();
    fs::create_dir_all(backing.join(".git/refs/heads")).unwrap();
    fs::create_dir_all(backing.join(".git/objects")).unwrap();
    fs::create_dir_all(backing.join(".git/modules/sub/hooks")).unwrap();
    fs::create_dir_all(backing.join(".git/worktrees/wt")).unwrap();
    fs::write(backing.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(backing.join(".git/config"), b"[core]\n\tbare = false\n").unwrap();
    fs::write(backing.join(HOOK), HOOK_BODY).unwrap();
    fs::write(
        backing.join(".git/worktrees/wt/gitdir"),
        b"/elsewhere/.git\n",
    )
    .unwrap();
    fs::write(backing.join(".git/worktrees/wt/commondir"), b"../..\n").unwrap();
    fs::create_dir_all(backing.join("src")).unwrap();
    fs::write(backing.join("src/main.rs"), b"fn main() {}\n").unwrap();
}

// ---------------------------------------------------------------------------
// Planting a new repository for the host to discover
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn creating_a_dotgit_entry_is_refused_in_every_shape() {
    let mount = TestMount::new(repository);

    denied("mkdir .git", fs::create_dir(mount.at("src/.git")));
    denied("create a .git file", File::create(mount.at("src/.git")));
    denied(
        "symlink named .git",
        symlink("/etc/passwd", mount.at("src/.git")),
    );
    denied(
        "hardlink named .git",
        fs::hard_link(mount.at("src/main.rs"), mount.at("src/.git")),
    );

    // A rename is the same violation seen from the destination side.
    allowed(
        "stage an ordinary file",
        fs::write(mount.at("src/decoy"), b"x"),
    );
    denied(
        "rename a file to .git",
        fs::rename(mount.at("src/decoy"), mount.at("src/.git")),
    );

    let dirfd = mount.mount_dirfd();
    denied_nix(
        "mknod named .git",
        mknodat(
            &dirfd,
            "src/.git",
            SFlag::S_IFREG,
            Mode::from_bits_truncate(0o644),
            0,
        ),
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn the_name_rule_covers_the_case_folded_and_collapsing_spellings() {
    // The spellings a case-insensitive or ignorable-collapsing backing resolves to `.git`
    // (CVE-2014-9390's classes). Denied on every platform, because the backing may be either.
    let mount = TestMount::new(repository);
    for name in [
        ".GIT",
        ".Git",
        ".gIt",
        ".git.",
        ".git ",
        ".gıt",         // U+0131 dotless i
        ".gİt",         // U+0130 dotted capital I
        ".gi\u{200c}t", // zero width non-joiner
        ".g\u{200b}it", // zero width space
        "\u{feff}.git", // byte order mark
        ".git\u{00ad}", // soft hyphen
    ] {
        denied(
            &format!("mkdir {name:?}"),
            fs::create_dir(mount.at(&format!("src/{name}"))),
        );
    }
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn ordinary_dot_git_prefixed_names_are_still_allowed() {
    // The superset must not have swallowed the names real projects use.
    let mount = TestMount::new(repository);
    for name in [
        ".gitignore",
        ".gitattributes",
        ".gitmodules",
        ".github",
        "git",
    ] {
        allowed(
            &format!("create {name}"),
            fs::write(mount.at(&format!("src/{name}")), b"ordinary\n"),
        );
    }
    // An accented name in both normalization forms: the control proving we need no normalization
    // handling, and that we have not started rejecting legitimate Unicode.
    allowed("NFC name", fs::write(mount.at("src/.gít"), b"x"));
    allowed("NFD name", fs::write(mount.at("src/.gi\u{301}t"), b"x"));
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn an_existing_dotgit_pointer_file_is_immutable() {
    // A `.git` file holding `gitdir:` re-aims a real repository's control state; rewriting it must
    // be refused, not just its creation.
    let mount = TestMount::new(|backing| {
        fs::create_dir_all(backing.join("linked")).unwrap();
        fs::write(backing.join("linked/.git"), b"gitdir: /host/real/.git\n").unwrap();
    });
    denied(
        "rewrite a .git pointer file",
        fs::write(mount.at("linked/.git"), b"gitdir: /tmp/attacker\n"),
    );
    denied(
        "truncate a .git pointer file",
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(mount.at("linked/.git")),
    );
    denied(
        "delete a .git pointer file",
        fs::remove_file(mount.at("linked/.git")),
    );
    assert_eq!(
        fs::read_to_string(mount.backing_at("linked/.git")).unwrap(),
        "gitdir: /host/real/.git\n"
    );
}

// ---------------------------------------------------------------------------
// Mutating an existing repository's control state
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn existing_hooks_are_immutable_against_every_mutation() {
    let mount = TestMount::new(repository);
    let hook = mount.at(HOOK);

    denied("write a hook", fs::write(&hook, b"evil"));
    denied(
        "open a hook for writing",
        OpenOptions::new().write(true).open(&hook),
    );
    denied(
        "O_TRUNC a hook",
        OpenOptions::new().write(true).truncate(true).open(&hook),
    );
    denied(
        "chmod a hook",
        fs::set_permissions(&hook, Permissions::from_mode(0o755)),
    );
    denied("delete a hook", fs::remove_file(&hook));
    denied(
        "create a new hook",
        File::create(mount.at(".git/hooks/post-checkout")),
    );
    denied(
        "symlink into hooks",
        symlink("/etc/passwd", mount.at(".git/hooks/pre-push")),
    );
    denied(
        "mkdir inside hooks",
        fs::create_dir(mount.at(".git/hooks/sub")),
    );

    allowed(
        "stage an ordinary file",
        fs::write(mount.at("src/evil"), b"evil\n"),
    );
    denied(
        "rename a file onto a hook",
        fs::rename(mount.at("src/evil"), &hook),
    );

    let dirfd = mount.mount_dirfd();
    denied_nix(
        "mknod inside hooks",
        mknodat(
            &dirfd,
            ".git/hooks/pre-merge",
            SFlag::S_IFREG,
            Mode::from_bits_truncate(0o755),
            0,
        ),
    );

    // The payoff assertion: after every attempt, the host's hook is byte-for-byte untouched.
    assert_eq!(
        fs::read_to_string(mount.backing_at(HOOK)).unwrap(),
        HOOK_BODY
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn config_and_redirections_are_immutable() {
    let mount = TestMount::new(repository);

    denied(
        "write .git/config",
        fs::write(mount.at(".git/config"), b"[core]\n\thooksPath = /tmp\n"),
    );
    denied(
        "append to .git/config",
        OpenOptions::new()
            .append(true)
            .open(mount.at(".git/config")),
    );
    denied(
        "delete .git/config",
        fs::remove_file(mount.at(".git/config")),
    );
    denied(
        "create config.worktree",
        File::create(mount.at(".git/config.worktree")),
    );
    denied(
        "rewrite a worktree gitdir pointer",
        fs::write(mount.at(".git/worktrees/wt/gitdir"), b"/tmp/attacker\n"),
    );
    denied(
        "rewrite a worktree commondir",
        fs::write(mount.at(".git/worktrees/wt/commondir"), b"/tmp/attacker\n"),
    );
    // A nested gitdir's own control state is protected by the same rules, through the re-root.
    denied(
        "write a submodule gitdir's config",
        fs::write(mount.at(".git/modules/sub/config"), b"[core]\n"),
    );
    denied(
        "create a submodule hook",
        File::create(mount.at(".git/modules/sub/hooks/pre-commit")),
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn rebase_and_sequencer_todo_state_is_immutable() {
    // Their `exec` lines are run by a later host `git rebase --continue`: the same class as a hook.
    let mount = TestMount::new(repository);
    denied(
        "create rebase-merge",
        fs::create_dir(mount.at(".git/rebase-merge")),
    );
    denied(
        "create rebase-apply",
        fs::create_dir(mount.at(".git/rebase-apply")),
    );
    denied(
        "create sequencer",
        fs::create_dir(mount.at(".git/sequencer")),
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn hardlink_aliasing_cannot_smuggle_control_state_out() {
    // A hardlink shares the inode, so aliasing a hook to a writable name would let a write through
    // the alias mutate the frozen inode. Refused on the source side as well as the destination.
    let mount = TestMount::new(repository);

    denied(
        "hardlink a hook out to a writable name",
        fs::hard_link(mount.at(HOOK), mount.at("src/hooklink")),
    );
    denied(
        "hardlink config out to a writable name",
        fs::hard_link(mount.at(".git/config"), mount.at("src/cfglink")),
    );
    assert!(!mount.at("src/hooklink").exists());
    assert_eq!(
        fs::read_to_string(mount.backing_at(HOOK)).unwrap(),
        HOOK_BODY
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn rename_exchange_is_refused_on_a_protected_operand() {
    // RENAME_EXCHANGE mutates both operands, so each is checked as both source and destination —
    // swapping an ordinary file with a hook would install the file as the hook.
    let mount = TestMount::new(repository);
    allowed(
        "stage an ordinary file",
        fs::write(mount.at("src/evil"), b"evil\n"),
    );
    let dirfd = mount.mount_dirfd();

    denied_nix(
        "RENAME_EXCHANGE an ordinary file with a hook",
        rename_exchange(&dirfd, "src/evil", HOOK),
    );
    denied_nix(
        "RENAME_EXCHANGE in the other direction",
        rename_exchange(&dirfd, HOOK, "src/evil"),
    );
    assert_eq!(
        fs::read_to_string(mount.backing_at(HOOK)).unwrap(),
        HOOK_BODY
    );
}

/// A repository whose hooks the host has relocated into the worktree, by symlink.
fn relocated_hooks(backing: &Path) {
    fs::create_dir_all(backing.join(".git")).unwrap();
    fs::create_dir_all(backing.join("shared-hooks")).unwrap();
    fs::write(backing.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        backing.join("shared-hooks/pre-commit"),
        b"#!/bin/sh\n# host\n",
    )
    .unwrap();
    symlink("../shared-hooks", backing.join(".git/hooks")).unwrap();
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_symlinked_hooks_entry_cannot_be_re_aimed() {
    // What does hold: the symlink *node* is control state, so the sandbox cannot point hook
    // resolution at a directory of its choosing. (Where the host already points it is the separate,
    // documented gap below.)
    let mount = TestMount::new(relocated_hooks);

    denied(
        "delete the hooks symlink",
        fs::remove_file(mount.at(".git/hooks")),
    );
    // A *file*, not a directory: renaming a directory onto a non-directory is refused by the kernel
    // with ENOTDIR before the request ever reaches the filter, which would test nothing.
    allowed(
        "stage a decoy file",
        fs::write(mount.at("decoy"), b"evil\n"),
    );
    denied(
        "rename something onto the hooks symlink",
        fs::rename(mount.at("decoy"), mount.at(".git/hooks")),
    );
    assert_eq!(
        fs::read_link(mount.backing_at(".git/hooks")).unwrap(),
        Path::new("../shared-hooks"),
        "the hooks symlink was re-aimed"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn relocated_hooks_are_refused_at_mount_because_the_filter_cannot_protect_them() {
    // If the host relocated its hook directory into the worktree, the files host `git` executes sit
    // at an ordinary worktree path that the classifier calls writable project data — and blocking
    // the write *through* `.git/hooks/` would be theatre, since the same bytes are reachable under
    // the target's own name. The answer is not a per-operation rule but a refusal to serve the tree
    // at all (`guard::check_hook_location`, `docs/git-metadata.md`).
    //
    // Both halves are asserted here: that the guard refuses such a tree, and — mounting past the
    // guard, which only the harness can do — *why* it must, since the FUSE layer alone would let the
    // write through.
    let mount = TestMount::new(relocated_hooks);

    let refusal = ko_agent_fs::guard::check_hook_location(&mount.backing)
        .expect_err("the guard must refuse a workspace whose hooks live inside it");
    assert!(
        refusal.reason.contains("symlink into the workspace"),
        "unexpected refusal: {refusal}"
    );

    // Why the guard is the only workable answer: past it, the target is ordinary writable data.
    assert!(
        fs::write(mount.at("shared-hooks/pre-commit"), b"#!/bin/sh\nevil\n").is_ok(),
        "the classifier now protects the relocated target; the guard may no longer be needed — \
         revisit `docs/git-metadata.md`, \"Relocated hook directories\""
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn an_ordinary_repository_passes_the_startup_guard() {
    // The refusal must stay narrow: a repository with hooks in the default place is served.
    let mount = TestMount::new(repository);
    assert!(ko_agent_fs::guard::check_hook_location(&mount.backing).is_ok());
}

// ---------------------------------------------------------------------------
// What must keep working
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn ordinary_project_work_is_unaffected() {
    let mount = TestMount::new(repository);

    allowed(
        "edit a source file",
        fs::write(mount.at("src/main.rs"), b"fn main() { }\n"),
    );
    allowed(
        "create a source file",
        fs::write(mount.at("src/new.rs"), b"x\n"),
    );
    allowed("create a directory", fs::create_dir(mount.at("src/sub")));
    allowed(
        "create .gitignore",
        fs::write(mount.at(".gitignore"), b"target\n"),
    );
    allowed(
        "rename a source file",
        fs::rename(mount.at("src/new.rs"), mount.at("src/moved.rs")),
    );
    allowed(
        "hardlink an ordinary file",
        fs::hard_link(mount.at("src/main.rs"), mount.at("src/alias.rs")),
    );
    allowed(
        "symlink an ordinary file",
        symlink("main.rs", mount.at("src/link.rs")),
    );
    allowed(
        "chmod an ordinary file",
        fs::set_permissions(mount.at("src/main.rs"), Permissions::from_mode(0o600)),
    );
    allowed(
        "delete an ordinary file",
        fs::remove_file(mount.at("src/moved.rs")),
    );

    // The host sees the sandbox's work immediately.
    assert_eq!(
        fs::read_to_string(mount.backing_at("src/main.rs")).unwrap(),
        "fn main() { }\n"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn operational_git_state_stays_writable() {
    // Freezing control state must not freeze the state git rewrites constantly, or no git command
    // would work inside the workspace at all.
    let mount = TestMount::new(repository);

    allowed(
        "write a ref",
        fs::write(mount.at(".git/refs/heads/main"), b"0000\n"),
    );
    allowed("write the index", fs::write(mount.at(".git/index"), b"idx"));
    allowed(
        "write an index lock",
        fs::write(mount.at(".git/index.lock"), b"lock"),
    );
    allowed(
        "rename the index lock into place",
        fs::rename(mount.at(".git/index.lock"), mount.at(".git/index")),
    );
    allowed(
        "write HEAD",
        fs::write(mount.at(".git/HEAD"), b"ref: refs/heads/other\n"),
    );
    allowed("write a loose object", {
        fs::create_dir_all(mount.at(".git/objects/ab"))
            .and_then(|()| fs::write(mount.at(".git/objects/ab/cdef"), b"object"))
    });
    allowed("write a reflog", {
        fs::create_dir_all(mount.at(".git/logs"))
            .and_then(|()| fs::write(mount.at(".git/logs/HEAD"), b"log"))
    });
    allowed(
        "write COMMIT_EDITMSG",
        fs::write(mount.at(".git/COMMIT_EDITMSG"), b"msg"),
    );
    // A submodule gitdir re-roots, so its operational state is writable too.
    allowed(
        "write a submodule's HEAD",
        fs::write(mount.at(".git/modules/sub/HEAD"), b"ref: x\n"),
    );
}
