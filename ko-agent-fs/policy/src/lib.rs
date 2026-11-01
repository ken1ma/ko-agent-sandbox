//! `ko-agent-fs` — the policy that keeps a sandbox from planting Git metadata that a later
//! host-side `git` would turn into code execution, for both backends: the FUSE backend
//! (`ko-agent-fs/fuse/`) serves it, and the BPF backend (`ko-agent-fs/bpf/`) enforces the records
//! `bpf_records` compiles from it.
//!
//! `doc/git-metadata.md` is the security analysis this code transcribes. `policy` alone decides
//! *whether* an operation is allowed, and imports nothing; `guard` here and the FUSE backend's `fs`
//! and `inode` are the code that decides *where* it is (`ko-agent-fs/fuse/doc/architecture.md`,
//! "What stays out of the audited core").

pub mod bpf_records;
pub mod guard;
pub mod policy;
pub mod rulefile;
