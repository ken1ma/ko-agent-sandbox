//! The `ko-agent-fs` binary itself: argument handling, the startup refusal, the resolved rules and
//! the BPF records. None needs `/dev/fuse` or privileges, so these run everywhere, including a
//! hardened sandbox and CI.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under test. `env!("CARGO_BIN_EXE_...")` fixes an absolute path at *compile* time.
/// This project compiles in the hardened sandbox (at its host path) but runs tests elsewhere, such
/// as the self-test image's `/suite`. So the path is found relative to the running test executable
/// (`target/debug/deps/<test>` → `target/debug/ko-agent-fs`), which works wherever the tree is.
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
fn a_workspace_whose_config_is_aliased_into_it_is_refused() {
    // The startup guard, end to end through the binary: Git configuration reachable through an
    // ordinary worktree path would be writable by the sandbox and read by the host's git, and no
    // per-operation check protects it there (`doc/git-metadata.md`, "The binding rule").
    let source = scratch("aliased-source");
    fs::create_dir_all(source.join(".git")).unwrap();
    fs::write(source.join("cfg"), b"[core]\n").unwrap();
    std::os::unix::fs::symlink("../cfg", source.join(".git/config")).unwrap();

    let output = resolve(&source, None);

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
    fs::write(&rules, b"host-view /\nread-only .vscode\n").unwrap();

    let output = resolve(&source, Some(&rules));

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "read-only .vscode\nread-only-path shared-hooks\nread-only-path tools/githooks\n\
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
        b"host-view /\nread-only .vscode\nread-only .claude/settings.json\n",
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
        "read-only .vscode\nread-only .claude/settings.json\nread-only-path tasks-data.json\n\
         pinned-path shared\npinned-path shared/claude\nread-only-under shared/claude settings.json\n",
    );

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(rules.parent().unwrap());
}

#[test]
fn file_rules_the_launcher_did_not_resolve_are_refused() {
    // The launcher owns the grammar; a line it would never write means another version wrote it.
    let source = scratch("bad-rules-source");
    let rules = scratch("bad-rules").join("file-rules");
    fs::write(&rules, b"read-only .VSCODE\n").unwrap();

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
fn the_records_header_prints_and_resolve_writes_the_records() {
    use ko_agent_fs::bpf_records::{ROOT_GUARDED_GIT, ROOT_WORKSPACE, Records, c_header};
    let output = Command::new(binary())
        .arg("--bpf-records-header")
        .output()
        .expect("run ko-agent-fs");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), c_header());

    let source = scratch("records-source");
    fs::create_dir_all(source.join(".git")).unwrap();
    let scratch_dir = scratch("records-files");
    let rules = scratch_dir.join("rules");
    fs::write(&rules, "read-only .vscode\nwritable node_modules\n").unwrap();
    let records_file = scratch_dir.join("records");
    let output = Command::new(binary())
        .arg("--source")
        .arg(&source)
        .arg("--resolve")
        .arg("--file-rules")
        .arg(&rules)
        .arg("--bpf-records")
        .arg(&records_file)
        .output()
        .expect("run ko-agent-fs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "read-only .vscode\nwritable node_modules\n"
    );
    let records = Records::parse(&fs::read(&records_file).unwrap()).unwrap();
    assert_eq!(records.rules.len(), 2);
    assert_eq!(records.aliases.len(), 0);
    let guarded: Vec<(u32, &[u8])> = records
        .guarded
        .iter()
        .map(|object| (object.kind, object.path.as_slice()))
        .collect();
    assert_eq!(
        guarded,
        vec![(ROOT_WORKSPACE, &b""[..]), (ROOT_GUARDED_GIT, &b".git"[..])]
    );

    let _ = fs::remove_dir_all(&source);
    let _ = fs::remove_dir_all(&scratch_dir);
}
