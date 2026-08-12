//! Venue probe, not part of the product. Mounts a trivial read-only FUSE filesystem, reads one file
//! back through the mount, and reports PASS/FAIL. Its only job is to prove a host can mount and
//! serve FUSE — the `/dev/fuse` device, the mount privilege, and fuser's libfuse-free mount path
//! all working — before the real filesystem is built on top.
//!
//! Run it in the privileged dev rig (`docs/testing.md` has the container), e.g.:
//!   cargo run --example mount_probe -- /tmp/ko-agent-fs-probe

use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner,
    MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};

const TTL: Duration = Duration::from_secs(1);
const CONTENT: &str = "ko-agent-fs mount probe ok\n";
const ROOT_INO: INodeNo = INodeNo(1);
const FILE_INO: INodeNo = INodeNo(2);
const FILE_NAME: &str = "hello.txt";

fn attr(ino: INodeNo, size: u64, kind: FileType, perm: u16) -> FileAttr {
    FileAttr {
        ino,
        size,
        blocks: size.div_ceil(512),
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind,
        perm,
        nlink: if kind == FileType::Directory { 2 } else { 1 },
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        rdev: 0,
        flags: 0,
        blksize: 512,
    }
}

struct HelloFs;

impl Filesystem for HelloFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INO && name.to_str() == Some(FILE_NAME) {
            reply.entry(
                &TTL,
                &attr(FILE_INO, CONTENT.len() as u64, FileType::RegularFile, 0o644),
                Generation(0),
            );
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino == ROOT_INO {
            reply.attr(&TTL, &attr(ROOT_INO, 0, FileType::Directory, 0o755));
        } else if ino == FILE_INO {
            reply.attr(
                &TTL,
                &attr(FILE_INO, CONTENT.len() as u64, FileType::RegularFile, 0o644),
            );
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        _size: u32,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino == FILE_INO {
            let data = CONTENT.as_bytes();
            let start = (offset as usize).min(data.len());
            reply.data(&data[start..]);
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(Errno::ENOENT);
            return;
        }
        let entries = [
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (FILE_INO, FileType::RegularFile, FILE_NAME),
        ];
        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            // `add` returns true once the reply buffer is full.
            if reply.add(*ino, (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() -> std::io::Result<()> {
    let mountpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/ko-agent-fs-probe".to_string());
    std::fs::create_dir_all(&mountpoint)?;

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("ko-agent-fs-probe".to_string()),
    ];
    println!("mounting probe filesystem at {mountpoint} ...");
    let session = fuser::spawn_mount(HelloFs, &mountpoint, &config)?;

    // Let the mount settle, then read the file back through it.
    std::thread::sleep(Duration::from_millis(300));
    let path = std::path::Path::new(&mountpoint).join(FILE_NAME);
    let got = std::fs::read_to_string(&path);

    let pass = matches!(&got, Ok(text) if text == CONTENT);
    match &got {
        Ok(text) => println!("read {}: {:?}", path.display(), text.trim_end()),
        Err(err) => println!("read {} failed: {err}", path.display()),
    }
    println!("PROBE {}", if pass { "PASS" } else { "FAIL" });

    drop(session); // unmounts via umount2
    std::process::exit(if pass { 0 } else { 1 });
}
