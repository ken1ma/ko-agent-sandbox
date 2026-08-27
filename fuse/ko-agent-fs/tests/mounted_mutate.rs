//! The deny surface, exercised through a real mount by an attacker who is *not* git: raw filesystem
//! operations against every path that could make a later host `git` execute code.
//!
//! Each refusal is asserted to be `EPERM` specifically — a policy denial, not merely "an error".
//! The exception is the pair of stale-handle tests at the end, whose refusal comes from the
//! resolver rather than the policy and is `ELOOP` for the reason `stale` gives.
//! Needs `/dev/fuse` and `CAP_SYS_ADMIN` (the dev rig).

mod common;

use std::ffi::CString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use common::{TestMount, allowed, denied, denied_nix};
use nix::errno::Errno;
use nix::sys::stat::{Mode, SFlag, mknodat};

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

/// `openat(2)` on a directory handle the caller still holds — the operation the stale-handle tests
/// below are about, and one no path-based call can express: the kernel addresses the directory by
/// the handle, so the daemon is asked about an inode rather than about a path the kernel has just
/// walked for it.
fn openat_write(dirfd: &File, relative: &str) -> nix::Result<OwnedFd> {
    let path = CString::new(relative).expect("a relative path without a NUL");
    let raw = unsafe {
        libc::openat(
            dirfd.as_raw_fd(),
            path.as_ptr(),
            libc::O_WRONLY | libc::O_TRUNC,
        )
    };
    if raw < 0 {
        Err(Errno::last())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

/// `linkat(2)` from a held directory handle to a name at the mount root: the same stale-handle
/// question asked of the source-side rule that refuses aliasing a control inode out to a writable
/// name (`doc/git-metadata.md`, "Operations that carry these mutations").
fn linkat_out(dirfd: &File, relative: &str, root: &OwnedFd, newname: &str) -> nix::Result<()> {
    let old = CString::new(relative).expect("a relative path without a NUL");
    let new = CString::new(newname).expect("a name without a NUL");
    let result = unsafe {
        libc::linkat(
            dirfd.as_raw_fd(),
            old.as_ptr(),
            root.as_raw_fd(),
            new.as_ptr(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Errno::last())
    }
}

/// Assert the resolver refused to serve a handle whose reconstructed path no longer names it.
/// `ELOOP` and not `EPERM`, because no policy decision is reached: the path runs through a symlink,
/// which means it stopped describing the object the classification was computed for, and
/// `RESOLVE_NO_SYMLINKS` declines it there (`src/fs.rs`, `open_ino`). Two other answers would also
/// be closed but would mean a different layer refused first — `EIO` from the kernel invalidating a
/// reused inode number, `ESTALE` from the chain's own entry having been forgotten — so they fail
/// here rather than pass quietly, since either would leave this test proving nothing about the
/// resolver.
#[track_caller]
fn stale<T>(what: &str, result: nix::Result<T>) {
    match result {
        Ok(_) => panic!("SECURITY: {what} succeeded"),
        Err(errno) => assert_eq!(
            errno,
            Errno::ELOOP,
            "{what} failed with {errno}, but not as a refused resolution (ELOOP)"
        ),
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
    // The submodule's own `HEAD`, which is what makes `.git/modules/sub` a gitdir rather than a
    // directory named like one — and what the filter asks the tree in order to tell them apart
    // (`fs.rs`, `is_gitdir_root`). Without it this fixture asserts nothing about a submodule.
    fs::write(
        backing.join(".git/modules/sub/HEAD"),
        b"ref: refs/heads/main\n",
    )
    .unwrap();
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
fn the_launcher_configuration_directory_cannot_be_created_or_written() {
    // The launcher mounts `.ko-agent-sandbox` back over itself read-only, and that mount is the
    // first line. This is the second, for when it is not there: a mount cannot follow its source,
    // so a host that removes the directory takes the mount with it and leaves the name free inside
    // a writable workspace — where writing it would set the egress policy the *next* launch reads.
    let mount = TestMount::new(repository);

    denied(
        "mkdir .ko-agent-sandbox",
        fs::create_dir(mount.at(".ko-agent-sandbox")),
    );
    denied(
        "create a .ko-agent-sandbox file",
        File::create(mount.at(".ko-agent-sandbox")),
    );
    denied(
        "symlink named .ko-agent-sandbox",
        symlink("/etc/passwd", mount.at(".ko-agent-sandbox")),
    );
    denied(
        "case-folded spelling",
        fs::create_dir(mount.at(".KO-AGENT-SANDBOX")),
    );
    // A launch takes its policy from the directory it starts in, so a subdirectory's copy is
    // boundary configuration too.
    denied(
        "mkdir a nested .ko-agent-sandbox",
        fs::create_dir(mount.at("src/.ko-agent-sandbox")),
    );

    allowed("stage an ordinary file", fs::write(mount.at("decoy"), b"x"));
    denied(
        "rename a file to .ko-agent-sandbox",
        fs::rename(mount.at("decoy"), mount.at(".ko-agent-sandbox")),
    );

    // Nothing under a host-created one is writable either — the case where the host replaced the
    // directory, so it exists in the backing while its read-only mount does not.
    let mount = TestMount::new(|backing| {
        repository(backing);
        fs::create_dir_all(backing.join(".ko-agent-sandbox/egress")).unwrap();
        fs::write(
            backing.join(".ko-agent-sandbox/egress/allowed"),
            b"+host docs.python.org\n",
        )
        .unwrap();
    });

    allowed(
        "read the policy the host wrote",
        fs::read_to_string(mount.at(".ko-agent-sandbox/egress/allowed")).map(|_| ()),
    );
    denied(
        "rewrite a policy file",
        fs::write(
            mount.at(".ko-agent-sandbox/egress/allowed"),
            b"+host evil.example unrestricted\n",
        ),
    );
    denied(
        "add a policy file",
        File::create(mount.at(".ko-agent-sandbox/egress/denied")),
    );
    denied(
        "remove a policy file",
        fs::remove_file(mount.at(".ko-agent-sandbox/egress/allowed")),
    );
    denied(
        "remove the directory",
        fs::remove_dir_all(mount.at(".ko-agent-sandbox/egress")),
    );
    denied(
        "rename the policy directory away",
        fs::rename(
            mount.at(".ko-agent-sandbox"),
            mount.at(".ko-agent-sandbox-old"),
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

/// The starting state for the two stale-handle tests: `repository`, plus the directories they hold
/// open across a rename. Both are names a real project has — a `hooks/` module in the source tree,
/// a `hooks/*` branch namespace under `refs/heads` — and that is what makes them the right
/// fixtures rather than a contrivance: the divergence needs the *held* directory's own basename to
/// exist under the gitdir the planted symlink aims at, since that basename is the last component of
/// the path the resolver reconstructs.
fn repository_with_hook_named_directories(backing: &Path) {
    repository(backing);
    fs::create_dir_all(backing.join("src/hooks")).unwrap();
    fs::write(backing.join("src/hooks/use-thing.ts"), b"export {}\n").unwrap();
    fs::create_dir_all(backing.join(".git/refs/heads/hooks")).unwrap();
    fs::write(backing.join(".git/refs/heads/hooks/add-precommit"), b"0\n").unwrap();
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_handle_held_across_a_rename_cannot_be_re_aimed_at_a_gitdir() {
    // The resolver reconstructs an inode's path from the names it was looked up under, and the
    // kernel goes on addressing a renamed directory by the inode it already holds. So the sandbox
    // can rename a directory it is inside, leave a symlink to `.git` at the name that directory
    // vacated, and reach the gitdir through the handle — carrying the ordinary directory's
    // classification, because the classification is a function of that stale chain. Nothing races:
    // three ordinary operations, in order.
    //
    // The handle is on `src/hooks` rather than on `src` itself, and that is load-bearing. Planting
    // the symlink re-reports the *vacated* name's inode number with a new file type, which the
    // kernel answers by invalidating that inode — so a handle on `src` would be stopped by the
    // kernel rather than by this filter, and would prove nothing about either. A handle one level
    // down is a different inode number, untouched by that, and its reconstructed path runs through
    // the symlink all the same.
    let mount = TestMount::new(repository_with_hook_named_directories);

    // Taken while `src/hooks` is what its name says.
    let held = File::open(mount.at("src/hooks")).expect("open the source directory");

    // Both steps stay allowed, and must: renaming a directory and creating a symlink are what a
    // build does all day, and a symlink's target is not the filter's to police *for policy* — the
    // kernel resolves a symlink itself and the resolved path is classified on its own names. The
    // one refusal a target does earn is unrelated to policy and is asserted separately below
    // (`a_symlink_target_in_a_nonportable_shape_is_refused_and_an_ordinary_one_is_not`).
    allowed(
        "rename an ordinary directory",
        fs::rename(mount.at("src"), mount.at("old")),
    );
    allowed(
        "symlink the vacated name at .git",
        symlink(".git", mount.at("src")),
    );

    // The third step, which must not follow from the first two.
    stale(
        "write a hook through the held handle",
        openat_write(&held, "pre-commit"),
    );
    stale(
        "alias a hook out through the held handle",
        linkat_out(&held, "pre-commit", &mount.mount_dirfd(), "hooklink"),
    );

    assert_eq!(
        fs::read_to_string(mount.backing_at(HOOK)).unwrap(),
        HOOK_BODY,
        "the host's hook was written through a handle held across a rename"
    );
    assert!(
        !mount.backing_at("hooklink").exists(),
        "a hook was aliased out through a handle held across a rename"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_handle_held_across_a_rename_inside_a_gitdir_cannot_reach_its_control_state() {
    // The same divergence reached from inside a gitdir, which is why the answer cannot be a rule
    // about the workspace root: everything under `refs/` is operational, so renaming a directory
    // there and symlinking the vacated name back at the gitdir root are both legitimately allowed —
    // and the handle then reaches `hooks/` while classified through `refs/`.
    let mount = TestMount::new(repository_with_hook_named_directories);

    let held = File::open(mount.at(".git/refs/heads/hooks")).expect("open a branch namespace");

    allowed(
        "rename an operational directory",
        fs::rename(mount.at(".git/refs/heads"), mount.at(".git/refs/moved")),
    );
    // `..` and not `../..`: a symlink's target resolves against the directory *holding* the link,
    // which is `.git/refs`, so one level up is the gitdir root and two would be the workspace's.
    allowed(
        "symlink the vacated name at the gitdir root",
        symlink("..", mount.at(".git/refs/heads")),
    );

    stale(
        "write a hook through the held handle",
        openat_write(&held, "pre-commit"),
    );

    assert_eq!(
        fs::read_to_string(mount.backing_at(HOOK)).unwrap(),
        HOOK_BODY,
        "the host's hook was written through a handle held across a rename inside the gitdir"
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
    // at all (`guard::check_hook_location`, `doc/git-metadata.md`).
    //
    // Both halves are asserted here: that the guard refuses such a tree, and — mounting past the
    // guard, which only the harness can do — *why* it must, since the FUSE layer alone would let the
    // write through.
    let mount = TestMount::new(relocated_hooks);

    let refusal = ko_agent_fs::guard::check_hook_location(&mount.backing)
        .expect_err("the guard must refuse a workspace whose hooks live inside it");
    assert!(
        refusal.reason.contains("inside the workspace"),
        "unexpected refusal: {refusal}"
    );

    // Why the guard is the only workable answer: past it, the target is ordinary writable data.
    assert!(
        fs::write(mount.at("shared-hooks/pre-commit"), b"#!/bin/sh\nevil\n").is_ok(),
        "the classifier now protects the relocated target; the guard may no longer be needed — \
         revisit `doc/git-metadata.md`, \"Relocated hook directories\""
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
fn a_symlink_target_in_a_nonportable_shape_is_refused_and_an_ordinary_one_is_not() {
    // The refusal in this file that is not about git, and the only one about what the *host* would
    // make of what a session wrote — which it reads through a path of its own, so a target that is
    // absolute or climbs above the workspace root cannot be assumed to mean there what it means
    // here. A shape is asserted and nothing more: `fs.rs`, `target_has_portable_shape`, has where
    // shape and meaning come apart, and what a later rename or hardlink can do to a conforming
    // link.
    //
    // sbt 2 is why it exists: a build-cache hit is materialized as a link into ~/.cache/sbt, and the
    // host's next compile fails writing its own class files through what the session left behind.
    let mount = TestMount::new(repository);
    allowed(
        "a subdirectory to link from",
        fs::create_dir(mount.at("src/sub")),
    );

    denied(
        "symlink to an absolute path outside the workspace",
        symlink("/home/nonroot/.cache/blob", mount.at("src/cached.o")),
    );
    // Refused for being absolute, not for where it points: the shape decides, and this one names
    // the mount itself.
    denied(
        "symlink to an absolute path inside the workspace",
        symlink(mount.at("src/main.rs"), mount.at("src/self.rs")),
    );
    denied(
        "symlink up out of the workspace",
        symlink("../../elsewhere", mount.at("src/escape.rs")),
    );
    denied(
        "symlink up out of the workspace and back down",
        symlink("../../../etc/passwd", mount.at("src/sub/passwd")),
    );

    // What the rule must not cost: everything landing inside, `..` included.
    allowed(
        "symlink to a sibling",
        symlink("main.rs", mount.at("src/sibling.rs")),
    );
    allowed(
        "symlink up and across",
        symlink("../main.rs", mount.at("src/sub/up.rs")),
    );
    // The last `..` that is still the workspace: the root itself.
    allowed(
        "symlink at the workspace root",
        symlink("../..", mount.at("src/sub/top")),
    );

    // The allowed ones reach the host as themselves, unresolved.
    assert_eq!(
        fs::read_link(mount.backing_at("src/sibling.rs")).unwrap(),
        Path::new("main.rs")
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
