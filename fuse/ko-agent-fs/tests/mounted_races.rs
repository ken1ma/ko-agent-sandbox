//! Concurrency at the resolve-then-act window: the host mutates the tree underneath while the
//! sandbox is resolving through it.
//!
//! The property is not "every operation succeeds" — under a concurrent rename a failure is a correct
//! answer. It is that the filter never serves the *wrong* object, never panics, and never leaves the
//! daemon wedged. These also drive `openat2`'s `EAGAIN` path, which nothing else reaches.
//!
//! Needs `/dev/fuse` and `CAP_SYS_ADMIN` (the dev rig).

mod common;

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::TestMount;

const CORRECT: &str = "the correct payload\n";
const DECOY: &str = "the decoy payload\n";
const HOOK: &str = "#!/bin/sh\n# host\n";

fn two_trees(backing: &Path) {
    fs::create_dir_all(backing.join("deep/nested")).unwrap();
    fs::write(backing.join("deep/nested/payload"), CORRECT).unwrap();
    fs::create_dir_all(backing.join("decoy")).unwrap();
    fs::write(backing.join("decoy/payload"), DECOY).unwrap();
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_concurrent_host_rename_never_yields_another_file() {
    let mount = TestMount::new(two_trees);
    let stop = Arc::new(AtomicBool::new(false));

    // The host renames the directory the sandbox is resolving through, back and forth.
    let churn = {
        let stop = Arc::clone(&stop);
        let backing = mount.backing.clone();
        thread::spawn(move || {
            let here = backing.join("deep/nested");
            let there = backing.join("deep/moved");
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::rename(&here, &there);
                let _ = fs::rename(&there, &here);
            }
        })
    };

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut served = 0usize;
    while Instant::now() < deadline {
        match fs::read_to_string(mount.at("deep/nested/payload")) {
            // The only acceptable success is the right file's content — never the decoy's, and
            // never a partial read.
            Ok(content) => {
                assert_eq!(content, CORRECT, "resolution served the wrong object");
                served += 1;
            }
            // The name genuinely was not there at that instant.
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            // A stale handle is the honest answer to "the tree moved under you".
            Err(err) if err.raw_os_error() == Some(libc::ESTALE) => {}
            Err(err) => panic!("unexpected failure during a concurrent rename: {err}"),
        }
    }

    stop.store(true, Ordering::Relaxed);
    churn.join().expect("the churn thread panicked");

    // The daemon must still be serving after the storm, not wedged or dead.
    let _ = fs::rename(
        mount.backing_at("deep/moved"),
        mount.backing_at("deep/nested"),
    );
    assert_eq!(
        fs::read_to_string(mount.at("deep/nested/payload")).unwrap(),
        CORRECT,
        "the filter did not recover after concurrent renames"
    );
    assert!(served > 0, "the reader never observed the file at all");
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_concurrent_rename_cannot_smuggle_a_write_into_a_frozen_tree() {
    // The adversarial version: the sandbox hammers a write at a hook while the host renames the
    // gitdir out from under that very path and back. No interleaving may land a byte in the hooks
    // tree — the classifier and the resolution must agree about which object is being written. The
    // churn moves the gitdir itself rather than a sibling, because a sibling's name is not on the
    // path being written and would leave the agreement untested.
    let mount = TestMount::new(|backing| {
        fs::create_dir_all(backing.join(".git/hooks")).unwrap();
        fs::write(backing.join(".git/hooks/pre-commit"), HOOK).unwrap();
    });

    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let stop = Arc::clone(&stop);
        let backing = mount.backing.clone();
        thread::spawn(move || {
            let gitdir = backing.join(".git");
            let parked = backing.join("gitswap");
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::rename(&gitdir, &parked);
                let _ = fs::rename(&parked, &gitdir);
            }
        })
    };

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut frozen = 0usize;
    while Instant::now() < deadline {
        match fs::write(mount.at(".git/hooks/pre-commit"), b"evil") {
            Ok(()) => panic!("SECURITY: a hook write landed during a concurrent rename"),
            // The policy refusing is the answer that matters; the other two are the gitdir simply
            // not being there at that instant, which is the honest answer to a name that moved.
            Err(err) if err.raw_os_error() == Some(libc::EPERM) => frozen += 1,
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) if err.raw_os_error() == Some(libc::ESTALE) => {}
            Err(err) => panic!("the hook write failed for the wrong reason: {err}"),
        }
    }

    stop.store(true, Ordering::Relaxed);
    churn.join().expect("the churn thread panicked");
    // The churn may have stopped with the gitdir parked under its other name.
    let _ = fs::rename(mount.backing_at("gitswap"), mount.backing_at(".git"));

    assert!(
        frozen > 0,
        "the gitdir was never present when a write arrived; the classifier was not exercised"
    );
    assert_eq!(
        fs::read_to_string(mount.backing_at(".git/hooks/pre-commit")).unwrap(),
        HOOK,
        "the host's hook was modified under concurrency"
    );
}
