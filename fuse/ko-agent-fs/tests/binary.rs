//! The `ko-agent-fs` binary itself: argument handling and the startup refusal.
//!
//! The mounted suites construct the filesystem in-process, which bypasses `main.rs` entirely. These
//! drive the real binary instead. They need **no** `/dev/fuse` and no privileges, because every case
//! here is one the binary decides *before* it mounts — so unlike the mounted suites, these run
//! everywhere, including a hardened sandbox and CI.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under test. `env!("CARGO_BIN_EXE_...")` bakes an absolute path at *compile* time,
/// and this project's flow compiles in the hardened sandbox (`/workspace/...`) but runs mounted
/// tests in the privileged rig (`/work/...`) — so resolve relative to the running test executable
/// (`target/debug/deps/<test>` → `target/debug/ko-agent-fs`), which holds wherever the tree is.
fn binary() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current test executable");
    test_exe
        .parent()
        .and_then(Path::parent)
        .expect("test executable outside a target directory")
        .join("ko-agent-fs")
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ko-agent-fs-bin-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(source: &Path, mount: &Path) -> Output {
    Command::new(binary())
        .arg("--source")
        .arg(source)
        .arg("--mount")
        .arg(mount)
        .arg("--foreground")
        .output()
        .expect("run ko-agent-fs")
}

#[test]
fn version_reports_the_source_it_was_built_from() {
    // The launcher digests the source it bundles, passes that digest to the build, and compares it
    // with this output — so an installed binary that is not the one it would build is detected.
    let output = Command::new(binary())
        .arg("--version")
        .output()
        .expect("run ko-agent-fs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("ko-agent-fs "),
        "unexpected version line: {stdout}"
    );
    assert!(
        stdout.contains(" source "),
        "the version carries no source id: {stdout}"
    );
}

#[test]
fn incomplete_arguments_are_refused_with_usage() {
    let output = Command::new(binary()).output().expect("run ko-agent-fs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage:"),
        "expected usage text, got: {stderr}"
    );
}

#[test]
fn a_workspace_whose_hooks_live_inside_it_is_refused_before_mounting() {
    // The startup guard, end to end through the binary: a repository whose hook directory the host
    // relocated into the worktree is refused, because no amount of per-operation filtering can
    // protect files that live at an ordinary worktree path (`doc/git-metadata.md`).
    let source = scratch("relocated-source");
    let mount = scratch("relocated-mount");
    fs::create_dir_all(source.join(".git")).unwrap();
    fs::create_dir_all(source.join("shared-hooks")).unwrap();
    std::os::unix::fs::symlink("../shared-hooks", source.join(".git/hooks")).unwrap();

    let output = run(&source, &mount);

    assert!(
        !output.status.success(),
        "the binary served a tree it cannot protect"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to serve") && stderr.contains("inside the workspace"),
        "the refusal did not explain itself: {stderr}"
    );
    // The remedy matters as much as the refusal: the operator has to know what to change.
    assert!(
        stderr.contains("Move them outside it"),
        "no remedy offered: {stderr}"
    );

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&mount);
}

#[test]
fn a_hooks_path_inside_the_workspace_is_refused_before_mounting() {
    let source = scratch("hookspath-source");
    let mount = scratch("hookspath-mount");
    fs::create_dir_all(source.join(".git")).unwrap();
    fs::create_dir_all(source.join("githooks")).unwrap();
    fs::write(
        source.join(".git/config"),
        b"[core]\n\tbare = false\n\thooksPath = ./githooks\n",
    )
    .unwrap();

    let output = run(&source, &mount);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // "hooksPath", not "core.hooksPath": the scanner reads no section headers, so the refusal names
    // what it saw rather than the key it cannot confirm (`guard.rs`, `scan_hooks_path`).
    assert!(stderr.contains("hooksPath"), "unexpected refusal: {stderr}");
    assert!(stderr.contains("githooks"), "unexpected refusal: {stderr}");

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&mount);
}

#[test]
#[ignore = "needs a FUSE-capable environment; run in the privileged dev rig"]
fn the_self_test_passes_where_fuse_is_available() {
    // The launcher's pre-session gate, end to end: mounts a scratch tree with the real mount
    // options and proves the policy refuses before any workspace is served.
    let output = Command::new(binary())
        .arg("--self-test")
        .output()
        .expect("run ko-agent-fs");
    assert!(
        output.status.success(),
        "self-test failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("self-test ok"));
}

#[test]
#[ignore = "needs a FUSE-capable environment; run in the privileged dev rig"]
fn the_binary_mounts_and_serves_end_to_end() {
    // The one flow nothing else drives: main.rs itself — argument parsing, the guard, the mount,
    // the policy — as the launcher runs it. The mounted suites construct the filesystem
    // in-process; the self-test uses a scratch tree of the binary's own making. This serves a
    // caller-provided tree through a caller-visible mountpoint.
    let source = scratch("mount-smoke-source");
    let mountpoint = scratch("mount-smoke-mnt");
    fs::write(source.join("seed"), b"seed\n").unwrap();

    let mut daemon = Command::new(binary())
        .arg("--source")
        .arg(&source)
        .arg("--mount")
        .arg(&mountpoint)
        .arg("--foreground")
        .spawn()
        .expect("spawn ko-agent-fs");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while fs::read_to_string(mountpoint.join("seed")).ok().as_deref() != Some("seed\n") {
        assert!(
            std::time::Instant::now() < deadline,
            "the mount never began serving"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    fs::write(mountpoint.join("written"), b"x").unwrap();
    assert!(
        source.join("written").exists(),
        "a write did not reach the backing"
    );
    let refusal = fs::create_dir(mountpoint.join(".git")).unwrap_err();
    assert_eq!(refusal.raw_os_error(), Some(libc::EPERM));

    // Teardown: unmount first — killing the daemon before unmounting would leave a dead
    // superblock that remove_dir_all then trips over.
    let unmounted = Command::new("fusermount3")
        .args(["-u"])
        .arg(&mountpoint)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !unmounted {
        let path = std::ffi::CString::new(mountpoint.as_os_str().as_encoded_bytes()).unwrap();
        unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
    }
    // fuser::mount returns once the kernel releases the mount; reap rather than kill, proving the
    // daemon's exit path too.
    let status = daemon.wait().expect("reap the daemon");
    assert!(
        status.success(),
        "the daemon did not exit cleanly after unmount: {status}"
    );

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&mountpoint);
}

#[test]
fn a_missing_backing_directory_is_refused() {
    let mount = scratch("absent-mount");
    let output = run(Path::new("/nonexistent/backing/directory"), &mount);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot") || stderr.contains("refusing"),
        "unexpected failure: {stderr}"
    );
    let _ = fs::remove_dir_all(&mount);
}
