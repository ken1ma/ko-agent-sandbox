//! Dev/validation tool: classify workspace-relative paths as OPERATIONAL or CONTROL using the real
//! policy, reproducing the FUSE layer's per-inode context walk from the mount root. Reads
//! newline-separated paths on stdin, writes `VERDICT\tpath` per line.
//!
//! Used to check the operational allowlist against the paths real `git` writes:
//! `probes/observe-git.sh` drives git and pipes its write-set through this. What that run settles
//! is then pinned as a static corpus in `tests/git_corpus.rs`, which needs no git at test time.

use std::io::{self, Read};

use ko_agent_fs::policy::{classify_relative_path, GitPathClass};

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("read stdin");

    for line in input.split(|&byte| byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let verdict = match classify_relative_path(line) {
            GitPathClass::Operational => "OPERATIONAL",
            GitPathClass::Control => "CONTROL",
        };
        println!("{verdict}\t{}", String::from_utf8_lossy(line));
    }
}
