//! `ko-agent-fs-fuse` — the FUSE backend, which serves the workspace policy of `ko-agent-fs`
//! (`ko-agent-fs/policy/`) over a shared workspace.

pub mod fs;
pub mod inode;
