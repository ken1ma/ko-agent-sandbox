//! Shared harness for the mounted integration tests.
//!
//! These mount a real filter over a throwaway backing tree, so they need `/dev/fuse` and
//! `CAP_SYS_ADMIN` and are `#[ignore]`d. Mounted tests: `doc/testing.md`, "Mounted".

#![allow(dead_code)] // each test binary uses a subset of the harness

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use fuser::BackgroundSession;
use ko_agent_fs::fs::{KoAgentFs, mount_config};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::sys::statfs::{FUSE_SUPER_MAGIC, statfs};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A filter mounted over a throwaway backing tree; unmounted and removed on drop.
pub struct TestMount {
    base: PathBuf,
    pub backing: PathBuf,
    pub mount: PathBuf,
    session: Option<BackgroundSession>,
}

impl TestMount {
    /// Lay out a backing tree with `setup` — the host's side, written directly, bypassing the
    /// filter, exactly as the host does — then mount the filter over it and wait until it serves.
    pub fn new(setup: impl FnOnce(&Path)) -> TestMount {
        let unique = format!(
            "ko-agent-fs-it-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        );
        let base = std::env::temp_dir().join(unique);
        let backing = base.join("backing");
        let mount = base.join("mnt");
        fs::create_dir_all(&backing).expect("create backing directory");
        fs::create_dir_all(&mount).expect("create mountpoint");

        setup(&backing);

        let root = open(
            &backing,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("open the backing root");

        // The product's own options (`fs::mount_config`), not a convenient subset: a suite that
        // mounted differently would be exercising a filesystem no session ever runs.
        let session = fuser::spawn_mount(KoAgentFs::new(root), &mount, &mount_config())
            .expect("mount the filter");

        let harness = TestMount {
            base,
            backing,
            mount,
            session: Some(session),
        };
        harness.await_ready();
        harness
    }

    /// Poll until the mountpoint really is a FUSE filesystem, so a test never races the mount.
    fn await_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(stat) = statfs(&self.mount)
                && stat.filesystem_type() == FUSE_SUPER_MAGIC
            {
                return;
            }
            sleep(Duration::from_millis(20));
        }
        panic!("the filter did not come up at {}", self.mount.display());
    }

    pub fn at(&self, relative: &str) -> PathBuf {
        self.mount.join(relative)
    }

    pub fn backing_at(&self, relative: &str) -> PathBuf {
        self.backing.join(relative)
    }

    /// An `O_PATH` handle on the mount root, for `*at` calls a test needs to make by hand.
    pub fn mount_dirfd(&self) -> std::os::fd::OwnedFd {
        open(
            &self.mount,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("open the mount root")
    }
}

impl Drop for TestMount {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = session.umount_and_join();
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Assert the filter refused an operation — and refused it as *policy*, with `EPERM`, not merely
/// with some error that might mean the tree was shaped differently than the test assumed.
#[track_caller]
pub fn denied<T>(what: &str, result: io::Result<T>) {
    match result {
        Ok(_) => panic!("SECURITY: {what} was ALLOWED"),
        Err(err) => assert_eq!(
            err.raw_os_error(),
            Some(libc::EPERM),
            "{what} failed with {err}, but not as a policy denial (EPERM)"
        ),
    }
}

#[track_caller]
pub fn denied_nix<T>(what: &str, result: nix::Result<T>) {
    match result {
        Ok(_) => panic!("SECURITY: {what} was ALLOWED"),
        Err(errno) => assert_eq!(
            errno,
            nix::errno::Errno::EPERM,
            "{what} failed with {errno}, but not as a policy denial (EPERM)"
        ),
    }
}

#[track_caller]
pub fn allowed<T>(what: &str, result: io::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what} was denied: {err}"),
    }
}
