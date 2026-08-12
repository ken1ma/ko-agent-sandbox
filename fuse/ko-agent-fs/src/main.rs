//! `ko-agent-fs --source <backing> --mount <mountpoint>` mounts the filter in the foreground.
//!
//! The outer launcher owns the lifecycle (`docs/architecture.md`): this process does not daemonize —
//! it runs `fuser::mount` until the filesystem is unmounted, then exits. Policy is built in, not read
//! from a config file the sandbox could reach.

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::ExitCode;

use ko_agent_fs::fs::{mount_config, KoAgentFs};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;

/// What source this binary was built from. The build stamps it in (see `Containerfile`): the
/// launcher digests the source it bundles, passes that digest as a build argument, and later
/// compares it with what `--version` reports — so an installed binary that is *not* the one this
/// launcher would build is detected rather than trusted. Unstamped when built by hand.
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

/// `--self-test`: prove, against a scratch tree that is never the user's workspace, that this
/// binary can mount in *this* environment and that the policy actually bites. The launcher runs it
/// before a session and aborts the launch on failure — fail closed — so the exit code is the
/// contract; the text is for the human reading the log. Beyond the policy, this is the probe for
/// the two environmental assumptions an unprivileged mount rests on: a `fusermount3` on PATH, and
/// `user_allow_other` enabled in /etc/fuse.conf (the mount asks for `allow_other`).
fn self_test() -> ExitCode {
    match self_test_run() {
        Ok(()) => {
            println!("ko-agent-fs self-test ok");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("ko-agent-fs self-test FAILED: {why}");
            ExitCode::FAILURE
        }
    }
}

fn self_test_run() -> Result<(), String> {
    let base = std::env::temp_dir().join(format!("ko-agent-fs-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let backing = base.join("backing");
    let mountpoint = base.join("mnt");
    for directory in [&backing, &mountpoint] {
        std::fs::create_dir_all(directory)
            .map_err(|err| format!("cannot create scratch directory {directory:?}: {err}"))?;
    }
    std::fs::write(backing.join("seed"), b"seed\n")
        .map_err(|err| format!("cannot write to the scratch backing: {err}"))?;

    let result = self_test_mounted(&backing, &mountpoint);
    let _ = std::fs::remove_dir_all(&base);
    result
}

fn self_test_mounted(backing: &PathBuf, mountpoint: &PathBuf) -> Result<(), String> {
    use std::time::{Duration, Instant};

    let root: OwnedFd = open(
        backing,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| format!("cannot open the scratch backing: {err}"))?;

    let session =
        fuser::spawn_mount(KoAgentFs::new(root), mountpoint, &mount_config()).map_err(|err| {
            format!(
                "mount failed: {err}\n\
                 Usual causes: no fusermount3 on PATH, or allow_other refused because\n\
                 /etc/fuse.conf lacks user_allow_other\n\
                 (fix: sudo sh -c 'echo user_allow_other >> /etc/fuse.conf')"
            )
        })?;

    // The mount is asynchronous; nothing below means anything until the mountpoint really is FUSE.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        use nix::sys::statfs::{statfs, FUSE_SUPER_MAGIC};
        match statfs(mountpoint) {
            Ok(stat) if stat.filesystem_type() == FUSE_SUPER_MAGIC => break,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(stat) => {
                return Err(format!(
                    "the mountpoint never became a FUSE mount (type {:?})",
                    stat.filesystem_type()
                ))
            }
            Err(err) => return Err(format!("statfs on the mountpoint kept failing: {err}")),
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
                return Err("SECURITY: creating .git through the mount was ALLOWED".to_string())
            }
            Err(err) if err.raw_os_error() == Some(libc::EPERM) => {}
            Err(err) => {
                return Err(format!(
                    ".git creation failed, but with the wrong error (want EPERM): {err}"
                ))
            }
        }
        if backing.join(".git").exists() {
            return Err("SECURITY: a .git entry appeared in the backing".to_string());
        }
        Ok(())
    };

    let outcome = checks();
    match session.umount_and_join() {
        Ok(()) => outcome,
        // A check failure is the more interesting report; an unmount failure alone still fails.
        Err(err) => outcome.and(Err(format!("unmount failed: {err}"))),
    }
}

fn main() -> ExitCode {
    let args = match parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(code) => return code,
    };

    // Refuse rather than serve a tree whose hooks the filter cannot protect (`guard`): a repository
    // whose hook directory already lives inside the workspace would be writable by the sandbox and
    // executed by the host's git, and no mount-time filtering can fix that.
    if let Err(refusal) = ko_agent_fs::guard::check_hook_location(&args.source) {
        eprintln!(
            "ko-agent-fs: refusing to serve {:?}\n{refusal}",
            args.source
        );
        return ExitCode::FAILURE;
    }

    // O_PATH|O_DIRECTORY: a resolution base for openat2, not a readable handle. Fails loudly if the
    // backing path is absent or not a directory — the launcher created it, so this is a sanity check.
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
