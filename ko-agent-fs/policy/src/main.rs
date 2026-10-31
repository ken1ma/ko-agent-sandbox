//! `ko-agent-fs --source <backing> --resolve` prints the file rules a filter over the tree would
//! serve, with the guard's additions, or refuses the tree as the filter would.
//!
//! The launcher builds the `--run-on-host` profile from that output, and the BPF backend takes the
//! records `--bpf-records` writes (`bpf_records.rs`). The FUSE filter, `ko-agent-fs-fuse`, resolves
//! the same rules itself when it mounts; this binary keeps the name `ko-agent-fs` so that the
//! launch scripts' calls outlive the filter.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ko_agent_fs::bpf_records;
use ko_agent_fs::guard::GuardedPath;
use ko_agent_fs::policy::FileRules;
use ko_agent_fs::rulefile;

/// The identity the launcher checks (`ko-agent-fs/Containerfile`, `KO_AGENT_FS_SOURCE_ID`).
/// Unstamped when built by hand.
const SOURCE_ID: &str = match option_env!("KO_AGENT_FS_SOURCE_ID") {
    Some(id) => id,
    None => "unstamped",
};

struct Args {
    source: PathBuf,
    /// The launcher's resolved rule lines.
    file_rules: Option<PathBuf>,
    /// Where the BPF backend's records go (`bpf_records.rs`).
    bpf_records: Option<PathBuf>,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: ko-agent-fs --source <backing-dir> --resolve [--file-rules <file>] [--bpf-records <file>]\n\
                ko-agent-fs --bpf-records-header\n\
                ko-agent-fs --version"
    );
    ExitCode::from(2)
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Args, ExitCode> {
    let mut source = None;
    let mut file_rules = None;
    let mut bpf_records = None;
    let mut resolve = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--source") => source = args.next().map(PathBuf::from),
            Some("--file-rules") => file_rules = args.next().map(PathBuf::from),
            Some("--resolve") => resolve = true,
            Some("--bpf-records") => bpf_records = args.next().map(PathBuf::from),
            Some("--bpf-records-header") => {
                print!("{}", bpf_records::c_header());
                return Err(ExitCode::SUCCESS);
            }
            Some("--version") => {
                println!(
                    "ko-agent-fs {} source {SOURCE_ID}",
                    env!("CARGO_PKG_VERSION")
                );
                return Err(ExitCode::SUCCESS);
            }
            _ => return Err(usage()),
        }
    }
    match (source, resolve) {
        (Some(source), true) => Ok(Args {
            source,
            file_rules,
            bpf_records,
        }),
        _ => Err(usage()),
    }
}

/// `--bpf-records`: the records of the resolved rules and the guarded objects, written whole.
fn write_bpf_records(
    path: &Path,
    rules: &FileRules,
    guarded: &[GuardedPath],
) -> Result<(), String> {
    let records = bpf_records::compile(rules, guarded)?;
    std::fs::write(path, records.to_bytes())
        .map_err(|err| format!("cannot write the BPF records {path:?}: {err}"))
}

fn main() -> ExitCode {
    let args = match parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let resolved = rulefile::resolve(&args.source, args.file_rules.as_deref()).and_then(
        |(rules, text, guarded)| {
            if let Some(path) = &args.bpf_records {
                write_bpf_records(path, &rules, &guarded)?;
            }
            Ok(text)
        },
    );
    match resolved {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ko-agent-fs: {message}");
            ExitCode::FAILURE
        }
    }
}
