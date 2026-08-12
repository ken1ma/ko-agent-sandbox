//! The read path through a real mount: what the sandbox sees must be the backing tree, live.
//!
//! Needs `/dev/fuse` and `CAP_SYS_ADMIN` (the dev rig).

mod common;

use std::fs;
use std::os::unix::fs::symlink;

use common::TestMount;

fn tree(backing: &std::path::Path) {
    fs::write(
        backing.join("greeting.txt"),
        b"hello from the backing store\n",
    )
    .unwrap();
    fs::create_dir_all(backing.join("src")).unwrap();
    fs::write(backing.join("src/main.rs"), b"fn main() {}\n").unwrap();
    symlink("greeting.txt", backing.join("link.txt")).unwrap();
    fs::create_dir_all(backing.join(".git/refs/heads")).unwrap();
    fs::create_dir_all(backing.join(".git/hooks")).unwrap();
    fs::write(backing.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn files_read_back_through_the_mount() {
    let mount = TestMount::new(tree);
    assert_eq!(
        fs::read_to_string(mount.at("greeting.txt")).unwrap(),
        "hello from the backing store\n"
    );
    assert_eq!(
        fs::read_to_string(mount.at("src/main.rs")).unwrap(),
        "fn main() {}\n"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn directories_list_their_entries() {
    let mount = TestMount::new(tree);
    let mut names: Vec<String> = fs::read_dir(mount.at(""))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec![".git", "greeting.txt", "link.txt", "src"]);
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_directory_scan_is_stable_while_the_host_changes_the_directory() {
    // `opendir` snapshots, so a scan cannot skip or duplicate entries when the tree moves under it.
    // Every name present at the start must appear exactly once, whatever the host does mid-scan.
    let mount = TestMount::new(|backing| {
        for index in 0..200 {
            fs::write(backing.join(format!("file-{index:03}")), b"x").unwrap();
        }
    });

    let mut seen: Vec<String> = Vec::new();
    let mut reader = fs::read_dir(mount.at("")).unwrap();
    // Take a few entries, then churn the directory hard, then drain the rest.
    for _ in 0..20 {
        if let Some(entry) = reader.next() {
            seen.push(entry.unwrap().file_name().to_string_lossy().into_owned());
        }
    }
    for index in 200..400 {
        fs::write(mount.backing_at(&format!("added-{index:03}")), b"x").unwrap();
    }
    for index in 100..150 {
        fs::remove_file(mount.backing_at(&format!("file-{index:03}"))).unwrap();
    }
    for entry in reader {
        seen.push(entry.unwrap().file_name().to_string_lossy().into_owned());
    }

    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        seen.len(),
        "the scan returned a duplicate entry"
    );

    // The 200 originals were all present when the scan began, so all 200 must have been reported.
    let originals = seen.iter().filter(|name| name.starts_with("file-")).count();
    assert_eq!(
        originals, 200,
        "the scan skipped entries that existed throughout"
    );

    // And a fresh scan sees the new state — the snapshot is per-handle, not a cache.
    let after: Vec<String> = fs::read_dir(mount.at(""))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(after.iter().any(|name| name.starts_with("added-")));
    assert_eq!(
        after
            .iter()
            .filter(|name| name.starts_with("file-"))
            .count(),
        150
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn timestamps_round_trip() {
    // `setattr` times: what `touch -t` and archive extraction need.
    let mount = TestMount::new(tree);
    let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    let file = fs::File::open(mount.at("greeting.txt")).unwrap();
    file.set_times(fs::FileTimes::new().set_accessed(when).set_modified(when))
        .expect("set times through the mount");

    let metadata = fs::metadata(mount.backing_at("greeting.txt")).unwrap();
    assert_eq!(
        metadata.modified().unwrap(),
        when,
        "mtime did not round-trip"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn symlinks_read_back_as_links() {
    let mount = TestMount::new(tree);
    assert_eq!(
        fs::read_link(mount.at("link.txt")).unwrap(),
        std::path::Path::new("greeting.txt")
    );
    // The filter reports the link itself, and following it still reaches the target.
    assert!(fs::symlink_metadata(mount.at("link.txt"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_to_string(mount.at("link.txt")).unwrap(),
        "hello from the backing store\n"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn an_existing_repository_is_readable() {
    // The filter hides nothing: a host repository reads normally, it is only writes that are gated.
    let mount = TestMount::new(tree);
    assert!(mount.at(".git").exists());
    assert_eq!(
        fs::read_to_string(mount.at(".git/HEAD")).unwrap(),
        "ref: refs/heads/main\n"
    );
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_host_write_is_visible_immediately() {
    // The project's defining requirement, and the reason entry/attribute TTLs are zero: no polling,
    // no sleep — the very next read through the mount must already see the host's write.
    let mount = TestMount::new(tree);
    assert_eq!(
        fs::read_to_string(mount.at("greeting.txt")).unwrap(),
        "hello from the backing store\n"
    );

    fs::write(mount.backing_at("greeting.txt"), b"changed underneath\n").unwrap();
    assert_eq!(
        fs::read_to_string(mount.at("greeting.txt")).unwrap(),
        "changed underneath\n",
        "a host write was not visible at once: the coherency invariant is broken"
    );

    // A host-created file appears without any cache flush, and a host-deleted one disappears.
    fs::write(mount.backing_at("appeared.txt"), b"new\n").unwrap();
    assert_eq!(
        fs::read_to_string(mount.at("appeared.txt")).unwrap(),
        "new\n"
    );
    fs::remove_file(mount.backing_at("appeared.txt")).unwrap();
    assert!(!mount.at("appeared.txt").exists());
}

#[test]
#[ignore = "needs /dev/fuse and CAP_SYS_ADMIN; run in the privileged dev rig"]
fn a_sandbox_write_is_visible_to_the_host_immediately() {
    // The other direction of the same requirement.
    let mount = TestMount::new(tree);
    fs::write(mount.at("src/new.rs"), b"// written by the sandbox\n").unwrap();
    assert_eq!(
        fs::read_to_string(mount.backing_at("src/new.rs")).unwrap(),
        "// written by the sandbox\n"
    );
}
