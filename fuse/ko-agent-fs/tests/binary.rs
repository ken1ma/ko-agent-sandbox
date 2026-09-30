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
/// and this project compiles in the hardened sandbox (`/workspace/...`) but runs mounted
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

fn resolve(source: &Path, file_rules: Option<&Path>) -> Output {
    let mut command = Command::new(binary());
    command.arg("--source").arg(source).arg("--resolve");
    if let Some(file_rules) = file_rules {
        command.arg("--file-rules").arg(file_rules);
    }
    command.output().expect("run ko-agent-fs --resolve")
}

#[test]
fn a_workspace_whose_config_is_aliased_into_it_is_refused_before_mounting() {
    // The startup guard, end to end through the binary: Git configuration reachable through an
    // ordinary worktree path would be writable by the sandbox and read by the host's git, and no
    // per-operation filtering protects it there (`doc/git-metadata.md`, "The binding rule").
    let source = scratch("aliased-source");
    let mount = scratch("aliased-mount");
    fs::create_dir_all(source.join(".git")).unwrap();
    fs::write(source.join("cfg"), b"[core]\n").unwrap();
    std::os::unix::fs::symlink("../cfg", source.join(".git/config")).unwrap();

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
fn a_workspace_whose_hooks_live_inside_it_is_resolved_with_them_read_only() {
    // A hook directory the host relocated into the worktree — husky's `.husky/_`, a symlinked
    // `.git/hooks` — is served read-only, and `--resolve` prints it after the rule lines, which is
    // what the launcher builds the `--run-on-host` profile from.
    let source = scratch("relocated-source");
    fs::create_dir_all(source.join(".git")).unwrap();
    fs::create_dir_all(source.join("shared-hooks")).unwrap();
    std::os::unix::fs::symlink("../shared-hooks", source.join(".git/hooks")).unwrap();
    fs::create_dir_all(source.join("tools/githooks")).unwrap();
    fs::write(
        source.join(".git/config"),
        b"[core]\n\tbare = false\n\thooksPath = ./tools/githooks\n",
    )
    .unwrap();
    let rules = scratch("relocated-rules").join("file-rules");
    fs::write(&rules, b"host-view /\nreadonly .vscode\n").unwrap();

    let output = resolve(&source, Some(&rules));

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "readonly .vscode\nreadonly-path shared-hooks\nreadonly-path tools/githooks\n\
         pinned-path tools\n",
    );

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(rules.parent().unwrap());
}

#[test]
fn the_ends_of_symlinks_the_rules_reach_are_printed_as_the_profile_reads_them() {
    // A read-only entry's target as a read-only path; a directory a line passes through, reached
    // by a symlink, as the rest of the line below it.
    let source = scratch("alias-source");
    fs::create_dir_all(source.join(".vscode")).unwrap();
    fs::create_dir_all(source.join("shared/claude")).unwrap();
    fs::write(source.join("tasks-data.json"), b"{}").unwrap();
    std::os::unix::fs::symlink("../tasks-data.json", source.join(".vscode/tasks.json")).unwrap();
    std::os::unix::fs::symlink("shared/claude", source.join(".claude")).unwrap();
    let rules = scratch("alias-rules").join("file-rules");
    fs::write(
        &rules,
        b"host-view /\nreadonly .vscode\nreadonly .claude/settings.json\n",
    )
    .unwrap();

    let output = resolve(&source, Some(&rules));

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "readonly .vscode\nreadonly .claude/settings.json\nreadonly-path tasks-data.json\n\
         pinned-path shared\npinned-path shared/claude\nreadonly-under shared/claude settings.json\n",
    );

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(rules.parent().unwrap());
}

#[test]
fn file_rules_the_launcher_did_not_resolve_are_refused_before_mounting() {
    // The launcher owns the grammar; a line it would never write means another version wrote it.
    let source = scratch("bad-rules-source");
    let rules = scratch("bad-rules").join("file-rules");
    fs::write(&rules, b"readonly .VSCODE\n").unwrap();

    let output = resolve(&source, Some(&rules));

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("file rules line 1"),
        "unexpected refusal: {stderr}",
    );

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(rules.parent().unwrap());
}

#[test]
#[ignore = "needs a FUSE-capable environment; run in the privileged dev rig"]
fn the_self_test_passes_where_fuse_is_available() {
    // The launcher's pre-session check, end to end: mounts a scratch tree with the real mount
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
fn trace_is_refused_where_nothing_is_mounted() {
    let source = scratch("trace-resolve-source");
    let output = Command::new(binary())
        .arg("--source")
        .arg(&source)
        .arg("--resolve")
        .arg("--trace")
        .output()
        .expect("run ko-agent-fs");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
    let _ = fs::remove_dir_all(&source);
}

/// Serve a one-file tree with the binary, read the file through the mount, unmount, and return the
/// daemon's log.
fn log_of_a_served_read(name: &str, trace: bool) -> String {
    let source = scratch(&format!("{name}-source"));
    let mountpoint = scratch(&format!("{name}-mnt"));
    fs::write(source.join("seed"), b"seed\n").unwrap();

    let mut command = Command::new(binary());
    command
        .arg("--source")
        .arg(&source)
        .arg("--mount")
        .arg(&mountpoint)
        .stderr(std::process::Stdio::piped());
    if trace {
        command.arg("--trace");
    }
    let daemon = command.spawn().expect("spawn ko-agent-fs");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while fs::read_to_string(mountpoint.join("seed")).ok().as_deref() != Some("seed\n") {
        assert!(
            std::time::Instant::now() < deadline,
            "the mount never began serving"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    unmount(&mountpoint);
    let output = daemon.wait_with_output().expect("reap the daemon");
    assert!(output.status.success());

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&mountpoint);
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
#[ignore = "needs a FUSE-capable environment; run in the privileged dev rig"]
fn trace_writes_a_pair_of_lines_per_request_and_nothing_without_the_flag() {
    let untraced = log_of_a_served_read("untraced", false);
    assert!(
        !untraced.contains("TRACE"),
        "traced without --trace: {untraced}"
    );

    let traced = log_of_a_served_read("traced", true);
    let lines: Vec<&str> = traced
        .lines()
        .filter(|line| line.starts_with("TRACE "))
        .collect();
    assert!(
        lines.iter().any(|line| line.starts_with("TRACE begin_us=")
            && line.ends_with(" op=lookup parent=1:\".\" name=\"seed\"")),
        "no lookup of the seed file: {traced}"
    );
    assert!(
        lines
            .first()
            .is_some_and(|line| line.starts_with("TRACE begin_us=") && line.ends_with(" op=init")),
        "the first request traced is not the initialization: {traced}"
    );
    for op in ["open", "read", "release"] {
        assert!(
            lines
                .iter()
                .any(|line| line.contains(&format!(" op={op} ino=")) && line.contains(":\"seed\"")),
            "no {op} of the seed file: {traced}"
        );
    }
    // Requests are served one at a time, so each `begin_us` line is followed by its `took_us` line.
    assert!(lines.len().is_multiple_of(2), "an unpaired line: {traced}");
    for pair in lines.chunks(2) {
        let request = |line: &str, key: &str| -> String {
            let rest = line
                .strip_prefix(&format!("TRACE {key}="))
                .unwrap_or_else(|| panic!("expected a {key} line: {line}"));
            let (micros, request) = rest.split_once(' ').expect("a request after the time");
            micros.parse::<u64>().expect("microseconds");
            request.to_string()
        };
        assert_eq!(request(pair[0], "begin_us"), request(pair[1], "took_us"));
    }
}

/// Callers unmount before they reap the daemon: killing it first would leave a dead superblock
/// that `remove_dir_all` then trips over.
fn unmount(mountpoint: &Path) {
    let unmounted = Command::new("fusermount3")
        .args(["-u"])
        .arg(mountpoint)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !unmounted {
        let path = std::ffi::CString::new(mountpoint.as_os_str().as_encoded_bytes()).unwrap();
        unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
    }
}

#[test]
#[ignore = "needs a FUSE-capable environment; run in the privileged dev rig"]
fn the_binary_mounts_and_serves_end_to_end() {
    // The one code path nothing else drives: main.rs itself — argument parsing, the guard, the mount,
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

    unmount(&mountpoint);
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
