//! `ko-agent-fs --source <backing> --mount <mountpoint>` mounts the filter in the foreground.
//!
//! The outer launcher owns the lifecycle (`doc/architecture.md`): this process does not daemonize —
//! it runs `fuser::mount` until the filesystem is unmounted, then exits. Policy is built in, not read
//! from a config file the sandbox could reach.

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ko_agent_fs::fs::{KoAgentFs, mount_config};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

/// The identity the launcher checks (`Containerfile`, `KO_AGENT_FS_SOURCE_ID`). Unstamped when built by hand.
const SOURCE_ID: &str = match option_env!("KO_AGENT_FS_SOURCE_ID") {
    Some(id) => id,
    None => "unstamped",
};

struct Args {
    source: PathBuf,
    mount: PathBuf,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: ko-agent-fs --source <backing-dir> --mount <mountpoint> [--foreground]\n\
                ko-agent-fs --self-test\n\
                ko-agent-fs --version"
    );
    ExitCode::from(2)
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Args, ExitCode> {
    let mut source = None;
    let mut mount = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--source") => source = args.next().map(PathBuf::from),
            Some("--mount") => mount = args.next().map(PathBuf::from),
            Some("--foreground") => {} // the only mode; accepted for the launcher's explicitness
            Some("--self-test") => return Err(self_test()),
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
    match (source, mount) {
        (Some(source), Some(mount)) => Ok(Args { source, mount }),
        _ => Err(usage()),
    }
}

/// Which stage a self-test failure came from, because only this code knows. Everything up to and
/// including the mount is the environment's — the scratch tree it needs, and the mount itself — and
/// a caller can answer it by changing the venue; everything after the mount is this filter's own
/// behaviour, which no venue change repairs. The stage reached is the whole of the classification,
/// and it is not a claim about the cause: the accompanying message carries what detail there is —
/// sometimes the exact failure, sometimes an error and the usual suspects — so a caller passes it
/// on rather than narrowing it into a diagnosis nothing here made. A caller that cannot tell the
/// two apart either retries a defect with more privilege or reports a venue as a bug.
enum SelfTestFailure {
    Venue(String),
    Defect(String),
}

/// The exit code for [`SelfTestFailure::Venue`]. Also spelled in the launcher, which reads it to
/// decide whether to retry; a test holds the two together (`KoAgentFsTest`).
const SELF_TEST_VENUE_EXIT: u8 = 3;

/// `--self-test`: prove, against a scratch tree that is never the user's workspace, that this
/// binary can mount in *this* environment, that the policy actually bites, and that a host write
/// reaches both a cached read and an established mapping (`coherency_check`). It runs where the
/// daemon will serve — inside the Podman machine, or on a native Linux host — at install time and
/// again before every session that mounts it (`KoAgentFs.installKoAgentFs`,
/// `ensureKoAgentFsMounted`), aborting
/// either on failure, so the exit code is the contract and the text is for the human reading the
/// log. Beyond the policy, this is the probe for the two environmental assumptions an unprivileged
/// mount rests on: a `fusermount3` on PATH, and `user_allow_other` enabled in /etc/fuse.conf (the
/// mount asks for `allow_other`).
fn self_test() -> ExitCode {
    match self_test_run() {
        Ok(()) => {
            println!("ko-agent-fs self-test ok");
            ExitCode::SUCCESS
        }
        Err(SelfTestFailure::Venue(why)) => {
            eprintln!("ko-agent-fs self-test failed, and the venue is why: {why}");
            ExitCode::from(SELF_TEST_VENUE_EXIT)
        }
        Err(SelfTestFailure::Defect(why)) => {
            eprintln!("ko-agent-fs self-test failed: {why}");
            ExitCode::FAILURE
        }
    }
}

fn self_test_run() -> Result<(), SelfTestFailure> {
    let base = std::env::temp_dir().join(format!("ko-agent-fs-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let backing = base.join("backing");
    let mountpoint = base.join("mnt");
    for directory in [&backing, &mountpoint] {
        std::fs::create_dir_all(directory).map_err(|err| {
            SelfTestFailure::Venue(format!(
                "cannot create scratch directory {directory:?}: {err}"
            ))
        })?;
    }
    std::fs::write(backing.join("seed"), b"seed\n").map_err(|err| {
        SelfTestFailure::Venue(format!("cannot write to the scratch backing: {err}"))
    })?;

    let result = self_test_mounted(&backing, &mountpoint);
    let _ = std::fs::remove_dir_all(&base);
    result
}

fn self_test_mounted(backing: &PathBuf, mountpoint: &PathBuf) -> Result<(), SelfTestFailure> {
    use std::time::{Duration, Instant};

    let root: OwnedFd = open(
        backing,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| SelfTestFailure::Venue(format!("cannot open the scratch backing: {err}")))?;

    let session =
        fuser::spawn_mount(KoAgentFs::new(root), mountpoint, &mount_config()).map_err(|err| {
            SelfTestFailure::Venue(format!(
                "mount failed: {err}\n\
                 Usual causes: no fusermount3 on PATH, or allow_other refused because\n\
                 /etc/fuse.conf lacks user_allow_other\n\
                 (fix: sudo sh -c 'echo user_allow_other >> /etc/fuse.conf')"
            ))
        })?;

    // The mount is asynchronous; nothing below means anything until the mountpoint really is FUSE.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        use nix::sys::statfs::{FUSE_SUPER_MAGIC, statfs};
        match statfs(mountpoint) {
            Ok(stat) if stat.filesystem_type() == FUSE_SUPER_MAGIC => break,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(stat) => {
                return Err(SelfTestFailure::Venue(format!(
                    "the mountpoint never became a FUSE mount (type {:?})",
                    stat.filesystem_type()
                )));
            }
            Err(err) => {
                return Err(SelfTestFailure::Venue(format!(
                    "statfs on the mountpoint kept failing: {err}"
                )));
            }
        }
    }

    let checks = || -> Result<(), String> {
        let seed = std::fs::read_to_string(mountpoint.join("seed"))
            .map_err(|err| format!("reading through the mount failed: {err}"))?;
        if seed != "seed\n" {
            return Err(format!(
                "read through the mount returned wrong content: {seed:?}"
            ));
        }
        std::fs::write(mountpoint.join("written"), b"x")
            .map_err(|err| format!("an ordinary write through the mount was refused: {err}"))?;
        if !backing.join("written").exists() {
            return Err("a write through the mount did not reach the backing".to_string());
        }
        match std::fs::create_dir(mountpoint.join(".git")) {
            Ok(()) => {
                return Err("SECURITY: creating .git through the mount was ALLOWED".to_string());
            }
            Err(err) if err.raw_os_error() == Some(libc::EPERM) => {}
            Err(err) => {
                return Err(format!(
                    ".git creation failed, but with the wrong error (want EPERM): {err}"
                ));
            }
        }
        if backing.join(".git").exists() {
            return Err("SECURITY: a .git entry appeared in the backing".to_string());
        }
        coherency_check(backing, mountpoint)
    };

    let outcome = checks().map_err(SelfTestFailure::Defect);
    match session.umount_and_join() {
        Ok(()) => outcome,
        // A check failure is the more interesting report; an unmount failure alone still fails.
        Err(err) => outcome.and(Err(SelfTestFailure::Defect(format!(
            "unmount failed: {err}"
        )))),
    }
}

/// The coherency invariant measured rather than assumed (`doc/architecture.md`, "Coherency").
/// `init` refuses a kernel that cannot offer `AUTO_INVAL_DATA`, but a kernel that offers it and
/// then does not invalidate would serve a build tool stale bytes — from the page cache, or from a
/// mapping git took before the write. Both of those paths are checked here, and only here:
/// nothing else in the suites holds a mapping across a host write.
///
/// The rewrite is in place — `write(2)` over an already-sized file, never the truncate
/// `fs::write` would do — so the file's length never changes and an invalidation can only have
/// come from the mtime the zero TTL surfaces. It is also repeated until the backing's own mtime
/// moves: on a filesystem stamping whole seconds there is nothing for the kernel to notice inside
/// a tick, and reporting that as an incoherent kernel would abort every launch on a true
/// statement about the clock. This runs over the local scratch tree, so what it proves is what
/// the *kernel* does; the virtiofs share under a real session is the launcher's `--self-test`
/// share rows' to measure, per `doc/TODO.md`.
fn coherency_check(backing: &Path, mountpoint: &Path) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    const OLD: &[u8] = b"page-content-before\n";
    const NEW: &[u8] = b"page-content-after!\n";

    let host = backing.join("coherency");
    let through = mountpoint.join("coherency");
    std::fs::write(&host, OLD).map_err(|err| format!("cannot seed the coherency file: {err}"))?;

    // Read it through the mount first: without that the page cache holds nothing and an
    // invalidation would have nothing to invalidate.
    let cached = std::fs::read(&through)
        .map_err(|err| format!("reading the coherency file through the mount failed: {err}"))?;
    if cached != OLD {
        return Err(format!("the coherency file read back wrong: {cached:?}"));
    }

    let file = std::fs::File::open(&through)
        .map_err(|err| format!("cannot open the coherency file through the mount: {err}"))?;
    // Established before the write, which is the whole point: MAP_SHARED so the kernel may serve
    // it from the same pages AUTO_INVAL_DATA drops.
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            OLD.len(),
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(format!(
            "mmap through the mount failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // read_volatile, because the mapping changes under the compiler's feet by design.
    let mapped_bytes = || -> Vec<u8> {
        (0..OLD.len())
            .map(|i| unsafe { std::ptr::read_volatile((mapped as *const u8).add(i)) })
            .collect()
    };

    let host_mtime = || -> Result<std::time::SystemTime, String> {
        std::fs::metadata(&host)
            .and_then(|meta| meta.modified())
            .map_err(|err| format!("cannot read the coherency file's mtime: {err}"))
    };

    let measure = || -> Result<(), String> {
        if mapped_bytes() != OLD {
            return Err("the mapping did not show the seeded bytes".to_string());
        }

        // Distinct mtimes, or the kernel has nothing to notice and nothing about coherency would
        // be proven. Rewritten until the backing's stamp actually moves, because a filesystem
        // with whole-second granularity needs up to a tick to say anything at all.
        let seeded = host_mtime()?;
        let stamped = Instant::now() + Duration::from_secs(5);
        loop {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&host)
                .map_err(|err| format!("cannot open the coherency file on the backing: {err}"))?;
            file.write_all(NEW)
                .and_then(|()| file.sync_all())
                .map_err(|err| {
                    format!("cannot rewrite the coherency file on the backing: {err}")
                })?;
            if host_mtime()? != seeded {
                break;
            }
            if Instant::now() >= stamped {
                return Err(
                    "the scratch backing did not move the file's mtime within 5 s of rewriting\n\
                     it, so this venue cannot demonstrate the invalidation either way — its\n\
                     timestamps are too coarse. Point the scratch tree at a filesystem with\n\
                     sub-second mtimes (doc/architecture.md, \"Coherency\")"
                        .to_string(),
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let read_path = std::fs::read(&through)
                .map_err(|err| format!("re-reading through the mount failed: {err}"))?;
            let seen = mapped_bytes();
            if read_path == NEW && seen == NEW {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let by_read = if read_path == NEW { "fresh" } else { "stale" };
                let by_mmap = if seen == NEW { "fresh" } else { "stale" };
                return Err(format!(
                    "a host write stayed invisible for 5 s: read() {by_read}, mmap {by_mmap}\n\
                     Its mtime did move on the backing, so AUTO_INVAL_DATA was negotiated and is\n\
                     not invalidating; this kernel cannot serve the workspace coherently\n\
                     (doc/architecture.md, \"Coherency\"; the launcher's --self-test share rows\n\
                     measure the same read and mmap behavior across the host share)"
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };

    let outcome = measure();
    unsafe { libc::munmap(mapped, OLD.len()) };
    outcome
}

fn main() -> ExitCode {
    let args = match parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(code) => return code,
    };

    if let Err(refusal) = ko_agent_fs::guard::check_hook_location(&args.source) {
        eprintln!(
            "ko-agent-fs: refusing to serve {:?}\n{refusal}",
            args.source
        );
        return ExitCode::FAILURE;
    }

    // O_PATH|O_DIRECTORY: a resolution base for openat2, not a readable handle.
    let root: OwnedFd = match open(
        &args.source,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!(
                "ko-agent-fs: cannot open backing directory {:?}: {err}",
                args.source
            );
            return ExitCode::FAILURE;
        }
    };

    // The daemon's first log line: without it, an empty daemon.log cannot distinguish "healthy,
    // nothing denied" from "never started". Same stream as the DENY lines.
    eprintln!(
        "ko-agent-fs {} source {SOURCE_ID} t={} serving {:?} at {:?}",
        env!("CARGO_PKG_VERSION"),
        ko_agent_fs::fs::unix_seconds(),
        args.source,
        args.mount
    );

    match fuser::mount(KoAgentFs::new(root), &args.mount, &mount_config()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ko-agent-fs: mount failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::coherency_check;

    /// The check itself, not the mount (that is `--self-test`'s): with one directory playing both
    /// the backing and the mountpoint, a live page cache satisfies it by construction, so a wrong
    /// mapping length, a read the compiler hoisted out of the poll, or a mapping left behind fails
    /// here instead of at someone's `--build`.
    #[test]
    fn the_coherency_check_holds_where_one_directory_plays_both_sides() {
        let dir =
            std::env::temp_dir().join(format!("ko-agent-fs-coherency-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("cannot create the scratch directory");
        let outcome = coherency_check(&dir, &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(outcome, Ok(()));
    }
}
