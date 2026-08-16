//! `ko-agent-fs` — a FUSE filter that keeps a sandbox from planting Git metadata that a later
//! host-side `git` would turn into code execution.
//!
//! `doc/git-metadata.md` is the security analysis this code transcribes. `policy` alone decides
//! *whether* an operation is allowed, and imports nothing; `fs`, `inode` and `guard` are the
//! plumbing that decides *where* it is (`doc/architecture.md`, "What stays out of the audited
//! core").

pub mod fs;
pub mod guard;
pub mod inode;
pub mod policy;
