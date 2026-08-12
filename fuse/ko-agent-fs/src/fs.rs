//! The FUSE filesystem (model B — `docs/architecture.md`): a coherent passthrough of the backing
//! tree, with every mutation gated through the policy core. Reads (`lookup`/`getattr`/`read`/
//! `readdir`/`readlink`) pass through; creations and mutations (`create`/`mkdir`/`mknod`/`symlink`/
//! `link`/`unlink`/`rmdir`/`rename`/`setattr`/write-`open`) first ask `policy` and return `EPERM`
//! on a denial, with a structured `DENY` log line.
//!
//! Resolution is model B: one `O_PATH` fd for the backing root, and every operation re-resolves via
//! `openat2(root, relpath, RESOLVE_IN_ROOT)` — kernel-contained, TOCTOU-safe, never a path join fed
//! to a plain syscall. A mutation acts on a fresh parent-dir fd plus the final name, so the `.git`
//! name rule sees the exact name and no final symlink is followed. Attribute/entry TTLs are
//! **zero**: the backing tree is shared live with the host, and real-time coherency is a correctness
//! invariant, not a tunable.
//!
//! Deferred: xattrs — unimplemented, so the daemon answers `ENOSYS`, which the kernel converts to
//! `ENOTSUP` for the caller and then latches, never asking again. Tools therefore read the mount as
//! a filesystem that simply has no extended attributes, which is an ordinary answer rather than a
//! failure (measured: `docs/TODO.md`, "Correctness"). Also deferred: the performance mechanisms
//! (READDIRPLUS, multithreading, passthrough).

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, InitFlags, KernelConfig, LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, SessionACL,
    TimeOrNow, WriteFlags,
};
use nix::dir::Dir;
use nix::errno::Errno as NixErrno;
use nix::fcntl::{openat2, AtFlags, OFlag, OpenHow, ResolveFlag};
use nix::sys::stat::{
    fchmodat, fstat, fstatat, mkdirat, mknodat, utimensat, FchmodatFlags, FileStat, Mode, SFlag,
    UtimensatFlags,
};
use nix::sys::time::TimeSpec;
use nix::sys::uio::{pread, pwrite};
use nix::unistd::{fchownat, ftruncate, linkat, symlinkat, unlinkat, Gid, Uid, UnlinkatFlags};

use crate::inode::InodeTable;
use crate::policy::{authorize, authorize_create, child_context, Decision, GitContext, Mutation};

/// Entry/attribute TTL. Zero, always: the host writes the backing tree concurrently, so the kernel
/// must re-ask on every access or it would serve a stale view (`docs/architecture.md`, coherency).
const TTL: Duration = Duration::ZERO;

/// The mount options, in one place because every mount has to be the same mount: a self-test that
/// mounted differently would prove nothing about a session, and an integration suite that did would
/// be exercising a filesystem the product never runs.
///
/// `SessionACL::All` is fuser's spelling of `allow_other`, which the daemon and the sandbox being
/// different uids by construction makes unavoidable; `DefaultPermissions` is what keeps widening
/// *who* may reach the mount from widening what they may do. `docs/architecture.md`, "Who may reach
/// the mount", has the argument for both.
pub fn mount_config() -> Config {
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("ko-agent-fs".to_string()),
        MountOption::DefaultPermissions,
    ];
    config.acl = SessionACL::All;
    config
}

/// One entry of the snapshot `opendir` takes. `ino` is the *backing* inode: in `readdir` it is
/// advisory — the kernel addresses an entry by looking its name up — so no lookup is forced here.
struct DirEntry {
    ino: u64,
    kind: FileType,
    name: OsString,
}

struct Inner {
    table: InodeTable,
    /// Open read handles: fh → the backing fd. `Arc` so a read can clone the handle out from under
    /// the lock and `pread` without serializing on it.
    handles: HashMap<u64, Arc<OwnedFd>>,
    /// Open directory handles: fh → the snapshot taken at `opendir`.
    dirs: HashMap<u64, Arc<Vec<DirEntry>>>,
    next_fh: u64,
}

pub struct KoAgentFs {
    /// `O_PATH` fd of the backing root; every resolution is relative to it.
    root: OwnedFd,
    inner: Mutex<Inner>,
}

impl KoAgentFs {
    pub fn new(root: OwnedFd) -> Self {
        KoAgentFs {
            root,
            inner: Mutex::new(Inner {
                table: InodeTable::new(),
                handles: HashMap::new(),
                dirs: HashMap::new(),
                next_fh: 1,
            }),
        }
    }

    /// The path of `ino` relative to the backing root, as the resolver's `openat2` argument. The
    /// root itself is `"."`.
    fn relpath(&self, ino: u64) -> Option<CString> {
        let components = self.inner.lock().unwrap().table.components(ino)?;
        if components.is_empty() {
            return CString::new(*b".").ok();
        }
        let mut joined = Vec::new();
        for (index, component) in components.iter().enumerate() {
            if index > 0 {
                joined.push(b'/');
            }
            joined.extend_from_slice(component);
        }
        CString::new(joined).ok()
    }

    /// Open `ino` relative to the backing root with kernel-enforced containment. `RESOLVE_IN_ROOT`
    /// clamps `..` and every symlink to the root, so resolution cannot escape the backing tree.
    /// `RESOLVE_NO_MAGICLINKS` is set explicitly: `RESOLVE_IN_ROOT` only *implies* it for now, and
    /// openat2(2) says that may change. `RESOLVE_NO_XDEV` is deliberately not set — a mount the host
    /// placed inside the workspace should stay visible, and crossing into it is lateral, not an
    /// escape above the root.
    fn open_ino(&self, ino: u64, oflag: OFlag) -> Result<OwnedFd, NixErrno> {
        let rel = self.relpath(ino).ok_or(NixErrno::ESTALE)?;
        let how = OpenHow::new()
            .flags(oflag | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        // openat2 returns EAGAIN when it cannot prove a `..` stayed within the root under a
        // concurrent rename; the kernel expects the caller to retry. Bounded, so a relentless racer
        // cannot spin us forever — the attacker only delays their own request.
        let mut attempts = 0;
        loop {
            match openat2(&self.root, rel.as_c_str(), how) {
                Err(NixErrno::EAGAIN) if attempts < 16 => attempts += 1,
                result => return result,
            }
        }
    }

    /// A parent directory fd for `*at` operations on its children, resolved under `RESOLVE_IN_ROOT`.
    fn parent_dir(&self, ino: u64) -> Result<OwnedFd, NixErrno> {
        self.open_ino(ino, OFlag::O_PATH | OFlag::O_DIRECTORY)
    }

    /// The cached git-context of `ino` — the O(1) fast path; `NotGit` for an unknown inode.
    fn context(&self, ino: u64) -> GitContext {
        self.inner
            .lock()
            .unwrap()
            .table
            .get(ino)
            .map_or(GitContext::NotGit, |node| node.git.clone())
    }

    /// Gate a creation of `name` in `parent`: the `.git` name rule plus destination classification.
    fn allow_create(&self, parent: u64, name: &OsStr, op: &str) -> Result<(), Errno> {
        match authorize_create(&self.context(parent), name.as_bytes()) {
            Decision::Allow => Ok(()),
            Decision::Deny(reason) => Err(deny(op, &format!("{name:?}"), reason)),
        }
    }

    /// Gate a mutation of an existing child `name` in `parent` (unlink/rmdir/rename-from).
    fn allow_child(
        &self,
        parent: u64,
        name: &OsStr,
        mutation: Mutation,
        op: &str,
    ) -> Result<(), Errno> {
        let child = child_context(&self.context(parent), name.as_bytes());
        match authorize(&child, mutation) {
            Decision::Allow => Ok(()),
            Decision::Deny(reason) => Err(deny(op, &format!("{name:?}"), reason)),
        }
    }

    /// Gate a mutation of an existing inode (setattr, write-open).
    fn allow_ino(&self, ino: u64, mutation: Mutation, op: &str) -> Result<(), Errno> {
        match authorize(&self.context(ino), mutation) {
            Decision::Allow => Ok(()),
            Decision::Deny(reason) => Err(deny(op, &format!("ino={ino}"), reason)),
        }
    }

    /// The name and parent directory fd for a `*at` operation on `parent/name`.
    fn child_target(&self, parent: u64, name: &OsStr) -> Result<(CString, OwnedFd), Errno> {
        let cname = cstr(name).map_err(to_errno)?;
        let parentfd = self.parent_dir(parent).map_err(to_errno)?;
        Ok((cname, parentfd))
    }

    /// After creating `parent/name`, stat it and reply with a fresh entry.
    fn reply_new_entry(
        &self,
        parent: u64,
        name: &OsStr,
        cname: &CString,
        parentfd: &OwnedFd,
        reply: ReplyEntry,
    ) {
        let st = match fstatat(parentfd, cname.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(err) => return reply.error(to_errno(err)),
        };
        let ino = self.inner.lock().unwrap().table.lookup(parent, name);
        reply.entry(&TTL, &to_file_attr(ino, &st), Generation(0));
    }

    fn remove(&self, parent: u64, name: &OsStr, flags: UnlinkatFlags, reply: ReplyEmpty) {
        let (cname, parentfd) = match self.child_target(parent, name) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        match unlinkat(&parentfd, cname.as_c_str(), flags) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    /// Apply the mutable attributes setattr can change.
    #[allow(clippy::too_many_arguments)] // one per settable attribute; a struct would only rename it
    fn apply_setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
    ) -> Result<(), NixErrno> {
        // O_NOFOLLOW, and NoFollowSymlink on the chmod below, for the reason the module header
        // gives: this re-resolves by name after the policy decided on the *inode*, so following a
        // final symlink would let one swapped in after that decision redirect the mutation. Neither
        // costs a legitimate operation — a size or mode change arrives for the resolved target, so
        // the name it re-resolves is never the link. `fchownat` and `utimensat` already say so.
        if let Some(size) = size {
            let fd = self.open_ino(ino, OFlag::O_WRONLY | OFlag::O_NOFOLLOW)?;
            ftruncate(&fd, size as i64)?;
        }
        let (parent, name) = match self.inner.lock().unwrap().table.parent_and_name(ino) {
            Some(pair) => pair,
            None => return Ok(()), // the mount root; nothing further to apply
        };
        let cname = cstr(&name)?;
        let parentfd = self.parent_dir(parent)?;
        if let Some(mode) = mode {
            let perm = Mode::from_bits_truncate(mode & 0o7777);
            fchmodat(
                &parentfd,
                cname.as_c_str(),
                perm,
                FchmodatFlags::NoFollowSymlink,
            )?;
        }
        if uid.is_some() || gid.is_some() {
            fchownat(
                &parentfd,
                cname.as_c_str(),
                uid.map(Uid::from_raw),
                gid.map(Gid::from_raw),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )?;
        }
        if atime.is_some() || mtime.is_some() {
            utimensat(
                &parentfd,
                cname.as_c_str(),
                &time_spec(atime),
                &time_spec(mtime),
                UtimensatFlags::NoFollowSymlink,
            )?;
        }
        Ok(())
    }
}

/// A requested timestamp as `utimensat` wants it. `None` leaves the field alone (`UTIME_OMIT`), so
/// setting one of the pair does not clobber the other. A time before the epoch clamps to it rather
/// than wrapping into a negative that would mean something else.
fn time_spec(value: Option<TimeOrNow>) -> TimeSpec {
    match value {
        None => TimeSpec::UTIME_OMIT,
        Some(TimeOrNow::Now) => TimeSpec::UTIME_NOW,
        Some(TimeOrNow::SpecificTime(time)) => match time.duration_since(UNIX_EPOCH) {
            Ok(since) => TimeSpec::new(since.as_secs() as i64, since.subsec_nanos() as i64),
            Err(_) => TimeSpec::new(0, 0),
        },
    }
}

/// One structured denial line. Names are rendered with `{:?}` so control characters in an
/// attacker-chosen name are escaped, never injected as fake log lines. Never logs file contents.
/// `t=` is Unix seconds — enough to correlate a denial with a session or an incident, without
/// pulling a time-formatting dependency into the audited build.
/// Full lines up to the cap; then one notice; then a counted summary every thousandth. DENY lines
/// are attacker-triggerable, so an uncapped log is a disk-filling primitive against the machine —
/// the *count* keeps growing in the summaries, so the audit trail loses detail, never magnitude.
const DENY_LOG_CAP: u64 = 10_000;

static DENIALS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// What the nth denial writes to the log.
#[derive(Debug, PartialEq, Eq)]
enum DenyLog {
    Full,
    CapNotice,
    Summary,
    Silent,
}

fn deny_log_action(nth: u64) -> DenyLog {
    if nth <= DENY_LOG_CAP {
        DenyLog::Full
    } else if nth == DENY_LOG_CAP + 1 {
        DenyLog::CapNotice
    } else if nth.is_multiple_of(1_000) {
        DenyLog::Summary
    } else {
        DenyLog::Silent
    }
}

fn deny(op: &str, target: &str, reason: &str) -> Errno {
    let nth = DENIALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    match deny_log_action(nth) {
        DenyLog::Full => eprintln!(
            "DENY t={} op={op} target={target} reason={reason}",
            unix_seconds()
        ),
        DenyLog::CapNotice => eprintln!(
            "DENY t={} log cap reached ({DENY_LOG_CAP} lines); further denials are counted, and \
             every thousandth logs the running total",
            unix_seconds()
        ),
        DenyLog::Summary => eprintln!("DENY t={} suppressed; total={nth}", unix_seconds()),
        DenyLog::Silent => {}
    }
    Errno::EPERM
}

pub fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

fn to_errno(err: NixErrno) -> Errno {
    Errno::from_i32(err as i32)
}

fn cstr(name: &OsStr) -> Result<CString, NixErrno> {
    CString::new(name.as_bytes()).map_err(|_| NixErrno::EINVAL)
}

fn system_time(secs: i64, nsecs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(
                secs as u64,
                nsecs.clamp(0, 999_999_999) as u32,
            ))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs((-secs) as u64))
            .unwrap_or(UNIX_EPOCH)
    }
}

fn file_type(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        _ => FileType::RegularFile,
    }
}

/// Build the reply attributes from a backing `stat`, but with *our* inode number, not the backing
/// one — the kernel addresses us by the number we assigned.
fn to_file_attr(ino: u64, st: &FileStat) -> FileAttr {
    // st_nlink is u32 on aarch64 but u64 on x86_64, so the cast is only redundant on one arch.
    #[allow(clippy::unnecessary_cast)]
    let nlink = st.st_nlink as u32;
    FileAttr {
        ino: INodeNo(ino),
        size: st.st_size as u64,
        blocks: st.st_blocks as u64,
        atime: system_time(st.st_atime, st.st_atime_nsec),
        mtime: system_time(st.st_mtime, st.st_mtime_nsec),
        ctime: system_time(st.st_ctime, st.st_ctime_nsec),
        crtime: UNIX_EPOCH,
        kind: file_type(st.st_mode),
        perm: (st.st_mode & 0o7777) as u16,
        nlink,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: st.st_rdev as u32,
        blksize: st.st_blksize as u32,
        flags: 0,
    }
}

fn dir_type(kind: nix::dir::Type) -> FileType {
    use nix::dir::Type;
    match kind {
        Type::Directory => FileType::Directory,
        Type::File => FileType::RegularFile,
        Type::Symlink => FileType::Symlink,
        Type::Fifo => FileType::NamedPipe,
        Type::Socket => FileType::Socket,
        Type::CharacterDevice => FileType::CharDevice,
        Type::BlockDevice => FileType::BlockDevice,
    }
}

// Mutation coverage — the deny surface. Every FUSE operation that can change the filesystem is
// accounted for one of two ways:
//
//   - implemented below and gated through `policy` before it touches the backing store, or
//   - left unimplemented, so it fails closed with ENOSYS — setxattr, removexattr, fallocate,
//     copy_file_range, ioctl. (fuser's default for an unimplemented op is an error, not success,
//     so an op we forgot cannot silently succeed. For the xattr family the kernel rewrites that
//     ENOSYS to ENOTSUP and stops sending the op, which changes what a caller sees but not what
//     reaches the backing store: nothing.)
//
// The gated ops and what each checks:
//
//   create, mkdir, mknod, symlink  the `.git` name rule + destination classification (allow_create)
//   link                           source (refuse aliasing a control inode out) AND destination
//   unlink, rmdir                  the target child's classification
//   rename                         source (RenameFrom) and destination; RENAME_EXCHANGE both ways
//   setattr (chmod/chown/truncate) the target inode's classification
//   open (write intent)            classification; write() then rides the already-authorized handle
//
// So the deny surface is closed by construction: unimplemented ops fail, and every implemented op is
// gated on *all* of its targets. Reads (lookup/getattr/read/readdir/readlink) are never gated. This
// is the deny side only; whether the *policy* is complete is `docs/git-metadata.md` (P0–P6).
impl Filesystem for KoAgentFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        // Data-cache coherency: the zero metadata TTL keeps *attributes* fresh, but cached or
        // mmap'd file *pages* could still lag a host write. Why this rather than FOPEN_DIRECT_IO
        // is `docs/architecture.md`, "Coherency".
        if config
            .add_capabilities(InitFlags::FUSE_AUTO_INVAL_DATA)
            .is_err()
        {
            eprintln!(
                "ko-agent-fs: kernel lacks AUTO_INVAL_DATA; cached file data may lag host writes"
            );
        }
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let cname = match cstr(name) {
            Ok(value) => value,
            Err(err) => return reply.error(to_errno(err)),
        };
        // Parent dir fd, then stat the child without following a final symlink (report the link).
        let dirfd = match self.open_ino(parent.0, OFlag::O_PATH | OFlag::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let st = match fstatat(&dirfd, cname.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(err) => return reply.error(to_errno(err)),
        };
        let ino = self.inner.lock().unwrap().table.lookup(parent.0, name);
        reply.entry(&TTL, &to_file_attr(ino, &st), Generation(0));
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.inner.lock().unwrap().table.forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let fd = match self.open_ino(ino.0, OFlag::O_PATH | OFlag::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        match fstat(&fd) {
            Ok(st) => reply.attr(&TTL, &to_file_attr(ino.0, &st)),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let (parent, name) = match self.inner.lock().unwrap().table.parent_and_name(ino.0) {
            Some(pair) => pair,
            None => return reply.error(Errno::EINVAL),
        };
        let cname = match cstr(&name) {
            Ok(value) => value,
            Err(err) => return reply.error(to_errno(err)),
        };
        let dirfd = match self.open_ino(parent, OFlag::O_PATH | OFlag::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        match nix::fcntl::readlinkat(&dirfd, cname.as_c_str()) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let accmode = flags.0 & libc::O_ACCMODE;
        let wants_write =
            accmode == libc::O_WRONLY || accmode == libc::O_RDWR || (flags.0 & libc::O_TRUNC) != 0;

        // The write gate: opening a control target for writing is where mutation is refused, so a
        // subsequent write() on the returned handle never needs re-checking.
        if wants_write {
            if let Err(err) = self.allow_ino(ino.0, Mutation::Write, "open-write") {
                return reply.error(err);
            }
        }

        let mut oflag = OFlag::from_bits_truncate(accmode);
        if (flags.0 & libc::O_TRUNC) != 0 {
            oflag |= OFlag::O_TRUNC;
        }
        let fd = match self.open_ino(ino.0, oflag) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let mut inner = self.inner.lock().unwrap();
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.handles.insert(fh, Arc::new(fd));
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let handle = self.inner.lock().unwrap().handles.get(&fh.0).cloned();
        let fd = match handle {
            Some(fd) => fd,
            None => return reply.error(Errno::EBADF),
        };
        let mut buf = vec![0u8; size as usize];
        match pread(fd.as_ref(), &mut buf, offset as i64) {
            Ok(read) => reply.data(&buf[..read]),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.inner.lock().unwrap().handles.remove(&fh.0);
        reply.ok();
    }

    /// Snapshot the directory once, into the handle. A `readdir` scan is then stable: re-reading the
    /// directory on every call, and paginating by index into a *changing* list, silently skips or
    /// duplicates entries when the tree moves under a scan — and a large directory made it O(n²)
    /// besides. POSIX leaves it unspecified whether a scan sees entries added after `opendir`, so a
    /// snapshot is the sanctioned reading; the *next* `opendir` sees the new state, and attributes
    /// stay live because their TTL is zero.
    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let fd = match self.open_ino(ino.0, OFlag::O_RDONLY | OFlag::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let mut dir = match Dir::from_fd(fd) {
            Ok(dir) => dir,
            Err(err) => return reply.error(to_errno(err)),
        };

        let mut entries = Vec::new();
        for entry in dir.iter() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => return reply.error(to_errno(err)),
            };
            entries.push(DirEntry {
                ino: entry.ino(),
                kind: entry
                    .file_type()
                    .map(dir_type)
                    .unwrap_or(FileType::RegularFile),
                name: OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string(),
            });
        }

        let mut inner = self.inner.lock().unwrap();
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.dirs.insert(fh, Arc::new(entries));
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let entries = self.inner.lock().unwrap().dirs.get(&fh.0).cloned();
        let Some(entries) = entries else {
            return reply.error(Errno::EBADF);
        };

        for (index, entry) in entries.iter().enumerate().skip(offset as usize) {
            // The offset handed back is the cookie for the *next* entry.
            if reply.add(
                INodeNo(entry.ino),
                index as u64 + 1,
                entry.kind,
                &entry.name,
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.inner.lock().unwrap().dirs.remove(&fh.0);
        reply.ok();
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if let Err(err) = self.allow_create(parent.0, name, "create") {
            return reply.error(err);
        }
        let (cname, parentfd) = match self.child_target(parent.0, name) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        // O_EXCL is not forced: create() may reopen an existing allowed file. O_NOFOLLOW stops a
        // pre-planted symlink at the target from redirecting the create elsewhere.
        let how = OpenHow::new()
            .flags(OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .mode(Mode::from_bits_truncate(mode & !umask & 0o7777))
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        let fd = match openat2(&parentfd, cname.as_c_str(), how) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let st = match fstat(&fd) {
            Ok(st) => st,
            Err(err) => return reply.error(to_errno(err)),
        };
        let mut inner = self.inner.lock().unwrap();
        let ino = inner.table.lookup(parent.0, name);
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.handles.insert(fh, Arc::new(fd));
        drop(inner);
        reply.created(
            &TTL,
            &to_file_attr(ino, &st),
            Generation(0),
            FileHandle(fh),
            FopenFlags::empty(),
        );
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if let Err(err) = self.allow_create(parent.0, name, "mkdir") {
            return reply.error(err);
        }
        let (cname, parentfd) = match self.child_target(parent.0, name) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        if let Err(err) = mkdirat(
            &parentfd,
            cname.as_c_str(),
            Mode::from_bits_truncate(mode & !umask & 0o7777),
        ) {
            return reply.error(to_errno(err));
        }
        self.reply_new_entry(parent.0, name, &cname, &parentfd, reply);
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        if let Err(err) = self.allow_create(parent.0, name, "mknod") {
            return reply.error(err);
        }
        let (cname, parentfd) = match self.child_target(parent.0, name) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        let kind = SFlag::from_bits_truncate(mode & libc::S_IFMT);
        let perm = Mode::from_bits_truncate(mode & !umask & 0o7777);
        if let Err(err) = mknodat(&parentfd, cname.as_c_str(), kind, perm, rdev as libc::dev_t) {
            return reply.error(to_errno(err));
        }
        self.reply_new_entry(parent.0, name, &cname, &parentfd, reply);
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        if let Err(err) = self.allow_create(parent.0, link_name, "symlink") {
            return reply.error(err);
        }
        let (cname, parentfd) = match self.child_target(parent.0, link_name) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        if let Err(err) = symlinkat(target, &parentfd, cname.as_c_str()) {
            return reply.error(to_errno(err));
        }
        self.reply_new_entry(parent.0, link_name, &cname, &parentfd, reply);
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // Source-side too: aliasing a control inode to a writable name would let a write through the
        // alias mutate the frozen inode (a hardlink shares the inode, bypassing path classification).
        if let Err(err) = self.allow_ino(ino.0, Mutation::Link, "link-source") {
            return reply.error(err);
        }
        if let Err(err) = self.allow_create(newparent.0, newname, "link") {
            return reply.error(err);
        }
        let (oldparent, oldname) = match self.inner.lock().unwrap().table.parent_and_name(ino.0) {
            Some(pair) => pair,
            None => return reply.error(Errno::EINVAL),
        };
        let oldcname = match cstr(&oldname) {
            Ok(value) => value,
            Err(err) => return reply.error(to_errno(err)),
        };
        let (newcname, newparentfd) = match self.child_target(newparent.0, newname) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        let oldparentfd = match self.parent_dir(oldparent) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        if let Err(err) = linkat(
            &oldparentfd,
            oldcname.as_c_str(),
            &newparentfd,
            newcname.as_c_str(),
            AtFlags::empty(),
        ) {
            return reply.error(to_errno(err));
        }
        self.reply_new_entry(newparent.0, newname, &newcname, &newparentfd, reply);
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(err) = self.allow_child(parent.0, name, Mutation::Unlink, "unlink") {
            return reply.error(err);
        }
        self.remove(parent.0, name, UnlinkatFlags::NoRemoveDir, reply);
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(err) = self.allow_child(parent.0, name, Mutation::Rmdir, "rmdir") {
            return reply.error(err);
        }
        self.remove(parent.0, name, UnlinkatFlags::RemoveDir, reply);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let exchange = flags.bits() & libc::RENAME_EXCHANGE != 0;
        // Source must be movable, destination must be creatable. RENAME_EXCHANGE moves both ways,
        // so each operand is checked as both a source and a destination.
        if let Err(err) = self.allow_child(parent.0, name, Mutation::RenameFrom, "rename-from") {
            return reply.error(err);
        }
        if let Err(err) = self.allow_create(newparent.0, newname, "rename-to") {
            return reply.error(err);
        }
        if exchange {
            if let Err(err) =
                self.allow_child(newparent.0, newname, Mutation::RenameFrom, "rename-from")
            {
                return reply.error(err);
            }
            if let Err(err) = self.allow_create(parent.0, name, "rename-to") {
                return reply.error(err);
            }
        }
        let (cname, parentfd) = match self.child_target(parent.0, name) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        let (newcname, newparentfd) = match self.child_target(newparent.0, newname) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        // The raw syscall, not a libc wrapper. nix gates its `renameat2` behind glibc, and the
        // static-musl release links Rust's *bundled* musl libc.a, which lacks the wrapper — the
        // symbol is absent at link time even though the libc crate declares it. The syscall itself
        // is in every kernel since 3.15, which is the actual dependency. The kernel rejects flags it
        // does not know, so FUSE's flag word passes through unfiltered.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parentfd.as_raw_fd(),
                cname.as_ptr(),
                newparentfd.as_raw_fd(),
                newcname.as_ptr(),
                flags.bits() as libc::c_uint,
            )
        };
        if result == 0 {
            reply.ok()
        } else {
            reply.error(Errno::from_i32(NixErrno::last_raw()))
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Err(err) = self.allow_ino(ino.0, Mutation::SetAttr, "setattr") {
            return reply.error(err);
        }
        if let Err(err) = self.apply_setattr(ino.0, mode, uid, gid, size, atime, mtime) {
            return reply.error(to_errno(err));
        }
        // Re-stat and report the result, so the kernel's cached attributes match the backing.
        let fd = match self.open_ino(ino.0, OFlag::O_PATH | OFlag::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        match fstat(&fd) {
            Ok(st) => reply.attr(&TTL, &to_file_attr(ino.0, &st)),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        // The write access was authorized at open(); the handle only exists for an allowed target.
        let handle = self.inner.lock().unwrap().handles.get(&fh.0).cloned();
        let fd = match handle {
            Some(fd) => fd,
            None => return reply.error(Errno::EBADF),
        };
        match pwrite(fd.as_ref(), data, offset as i64) {
            Ok(written) => reply.written(written as u32),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deny_log_caps_detail_but_never_loses_the_count() {
        assert_eq!(deny_log_action(1), DenyLog::Full);
        assert_eq!(deny_log_action(DENY_LOG_CAP), DenyLog::Full);
        assert_eq!(deny_log_action(DENY_LOG_CAP + 1), DenyLog::CapNotice);
        assert_eq!(deny_log_action(DENY_LOG_CAP + 2), DenyLog::Silent);
        // Every thousandth still reports the running total: magnitude survives, detail does not.
        assert_eq!(deny_log_action(11_000), DenyLog::Summary);
        assert_eq!(deny_log_action(11_001), DenyLog::Silent);
        assert_eq!(deny_log_action(1_000_000), DenyLog::Summary);
    }

    #[test]
    fn attr_maps_mode_and_our_inode_number() {
        let mut st: FileStat = unsafe { std::mem::zeroed() };
        st.st_mode = libc::S_IFDIR | 0o755;
        st.st_size = 4096;
        let attr = to_file_attr(42, &st);
        assert_eq!(attr.ino, INodeNo(42));
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
    }

    #[test]
    fn file_type_covers_the_mode_bits() {
        assert_eq!(file_type(libc::S_IFREG), FileType::RegularFile);
        assert_eq!(file_type(libc::S_IFLNK), FileType::Symlink);
        assert_eq!(file_type(libc::S_IFSOCK), FileType::Socket);
    }

    #[test]
    fn negative_and_overflowing_times_do_not_panic() {
        let _ = system_time(-1, 0);
        let _ = system_time(i64::MAX, 1_000_000_000);
        let _ = system_time(0, 999_999_999);
    }
}
