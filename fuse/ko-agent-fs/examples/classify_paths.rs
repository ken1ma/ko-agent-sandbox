//! Dev/validation tool: classify workspace-relative paths as OPERATIONAL or CONTROL using the real
//! policy, reproducing the FUSE layer's per-inode context walk from the mount root. Reads
//! newline-separated paths on stdin, writes `VERDICT\tpath` per line.
//!
//! Used to check the operational allowlist against the paths real `git` writes:
//! `probe/observe-git.sh` drives git and pipes its write-set through this. What that run settles
//! is then pinned as a static corpus in `tests/git_corpus.rs`, which needs no git at test time.

use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;

use ko_agent_fs::policy::{GitPathClass, classify_relative_path};

fn main() {
    // Submodule gitdir roots, as workspace-relative paths (`policy::GitContext::ModuleNamespace`).
    // `probe/observe-git.sh` discovers them and passes them here; naming none says there are none.
    let roots: Vec<Vec<u8>> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_vec())
        .collect();
    let roots: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();

    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("read stdin");

    for line in input.split(|&byte| byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let verdict = match classify_relative_path(line, &roots) {
            GitPathClass::Operational => "OPERATIONAL",
            GitPathClass::Control => "CONTROL",
        };
        println!("{verdict}\t{}", String::from_utf8_lossy(line));
    }
}
