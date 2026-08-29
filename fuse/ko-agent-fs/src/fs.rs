//! The FUSE filesystem (the path inode model — `doc/architecture.md`): a coherent passthrough of the
//! backing tree, with every mutation gated through the policy core. Reads (`lookup`/`getattr`/`read`/
//! `readdir`/`readlink`) pass through; creations and mutations (`create`/`mkdir`/`mknod`/`symlink`/
//! `link`/`unlink`/`rmdir`/`rename`/`setattr`/write-`open`) first ask `policy` and return `EPERM`
//! on a denial, with a structured `DENY` log line.
//!
//! Resolution: `doc/architecture.md`, "Inode model". The deny surface, xattrs included: the note above
//! `impl Filesystem`.

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, InitFlags, KernelConfig, LockOwner, MountOption, OpenFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
    SessionACL, TimeOrNow, WriteFlags,
};
use nix::dir::Dir;
use nix::errno::Errno as NixErrno;
use nix::fcntl::{AtFlags, FcntlArg, OFlag, OpenHow, ResolveFlag, fcntl, openat2};
use nix::sys::stat::{
    FchmodatFlags, FileStat, Mode, SFlag, UtimensatFlags, fchmodat, fstat, fstatat, mkdirat,
    mknodat, utimensat,
};
use nix::sys::time::TimeSpec;
use nix::sys::uio::{pread, pwrite};
use nix::unistd::{
    Gid, Uid, UnlinkatFlags, fchownat, fdatasync, fsync, ftruncate, linkat, symlinkat, unlinkat,
};

use crate::inode::InodeTable;
use crate::policy::{Decision, GitContext, Mutation, authorize, authorize_create, child_context};

/// Entry/attribute TTL. Zero, always: the host writes the backing tree concurrently, so the kernel
/// must re-ask on every access or it would serve a stale view (`doc/architecture.md`, coherency).
const TTL: Duration = Duration::ZERO;

/// The mount options, in one place because every mount has to be the same mount: a self-test that
/// mounted differently would prove nothing about a session, and an integration suite that did would
/// be exercising a filesystem the product never runs.
///
/// `SessionACL::All` is fuser's spelling of `allow_other`, which the daemon and the sandbox being
/// different uids by construction makes unavoidable; `DefaultPermissions` is what keeps widening
/// *who* may reach the mount from widening what they may do. `doc/architecture.md`, "Who may reach
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

/// One open file handle: the backing fd, and whether *that descriptor* currently carries
/// `O_APPEND`.
///
/// It records the backing state rather than the caller's, because the caller's can change without
/// another `open`: `fcntl(F_SETFL)` toggles `O_APPEND` on a live file description, and the kernel
/// sends the flags as they are with every write (`fuse_write_flags` reads `f_flags`). So this is
/// what [`Filesystem::write`] reconciles against, and the reconciliation is not cosmetic — with the
/// two out of step, a positional write on a still-appending descriptor lands at the end and an
/// appending write on a plain one lands at a stale offset.
struct Handle {
    fd: Arc<OwnedFd>,
    append: bool,
}

/// Match a backing descriptor's `O_APPEND` to what the caller's file description carries now.
/// Read-modify-write rather than a bare set, so the other status flags `F_SETFL` honours are left
/// as they are.
fn set_backing_append(fd: &OwnedFd, append: bool) -> Result<(), NixErrno> {
    let current = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    let wanted = if append {
        current | OFlag::O_APPEND
    } else {
        current & !OFlag::O_APPEND
    };
    fcntl(fd, FcntlArg::F_SETFL(wanted))?;
    Ok(())
}

struct Inner {
    table: InodeTable,
    /// Open file handles. The fd is behind an `Arc` so a read, write or sync can clone it out from
    /// under the lock and issue its syscall without serializing on it.
    handles: HashMap<u64, Handle>,
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
    /// clamps `..` to the root, so resolution cannot escape the backing tree.
    /// `RESOLVE_NO_MAGICLINKS` is set explicitly: `RESOLVE_IN_ROOT` only *implies* it for now, and
    /// openat2(2) says that may change. `RESOLVE_NO_XDEV` is deliberately not set — a mount the host
    /// placed inside the workspace should stay visible, and crossing into it is lateral, not an
    /// escape above the root.
    ///
    /// `RESOLVE_NO_SYMLINKS` is what keeps the object this resolves and the object the policy
    /// classified the same object, and it is the flag to understand before changing anything here.
    /// The path above names an inode by the names it was looked up under, and the tree moves after
    /// that: the kernel goes on addressing a renamed directory by the inode it already holds, while
    /// this walk still spells the name that directory vacated. Refusing a symlink costs nothing
    /// legitimate, because the kernel resolves the sandbox's own symlinks — it reads the link and
    /// looks up each resolved component in turn — so every component of a live chain is a directory
    /// and a symlink can only appear in one that has gone stale. Following one there is exactly
    /// what would let a name classified as ordinary project data resolve into a gitdir. With the
    /// flag, the resolved object's path *is* the chain the context was computed from, and a stale
    /// chain fails closed with `ELOOP` — no `DENY` line, because no policy decision was reached.
    ///
    /// The callers that must see a link still do: openat2 exempts `O_PATH | O_NOFOLLOW`, which is
    /// how `getattr` and `setattr` stat one, and `readlink` goes through its parent's fd instead.
    fn open_ino(&self, ino: u64, oflag: OFlag) -> Result<OwnedFd, NixErrno> {
        let rel = self.relpath(ino).ok_or(NixErrno::ESTALE)?;
        let how = OpenHow::new().flags(oflag | OFlag::O_CLOEXEC).resolve(
            ResolveFlag::RESOLVE_IN_ROOT
                | ResolveFlag::RESOLVE_NO_MAGICLINKS
                | ResolveFlag::RESOLVE_NO_SYMLINKS,
        );
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

    /// Whether `name` under `parentfd` is a gitdir root in its own right — the one position the
    /// policy core is told rather than derives ([`GitContext::ModuleNamespace`] has why).
    ///
    /// Asked only where it can matter, and answered by the fact that defines a gitdir: it holds a
    /// `HEAD`. The question is safe to answer from the tree because a namespace classifies as
    /// control, so the sandbox cannot write a `HEAD` into one to manufacture a root — and it is
    /// never asked again once inside a gitdir, so a `HEAD` the sandbox *can* write (under
    /// `objects/`, say) is never a candidate. Any error answers `false`, leaving the namespace
    /// reading, which is the stricter one.
    fn is_gitdir_root(&self, parent: u64, parentfd: &OwnedFd, name: &OsStr, st: &FileStat) -> bool {
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return false;
        }
        if child_context(&self.context(parent), name.as_bytes()) != GitContext::ModuleNamespace {
            return false;
        }
        let mut probe = name.to_os_string();
        probe.push("/HEAD");
        let Ok(head) = cstr(&probe) else {
            return false;
        };
        // A regular file specifically: a submodule named `HEAD` would put a *directory* there, and
        // a gitdir old enough to symlink its `HEAD` is one this would rather freeze than guess at.
        match fstatat(parentfd, head.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st.st_mode & libc::S_IFMT == libc::S_IFREG,
            Err(_) => false,
        }
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
        // Never a gitdir root: creating one under `modules/` is refused, so nothing this replies
        // for can be one (`is_gitdir_root`).
        let ino = self.inner.lock().unwrap().table.lookup(parent, name, false);
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
        // The root has no parent to act through, so it acts on itself: `.` against the backing
        // root's own fd names the same directory. Returning early instead would answer a
        // `chmod`/`chown`/`touch` of the mount root with a success it never performed. Bound before
        // the match, or the lock guard would still be held while the arms take it again.
        let position = self.inner.lock().unwrap().table.parent_and_name(ino);
        let (parentfd, cname) = match position {
            Some((parent, name)) => (self.parent_dir(parent)?, cstr(&name)?),
            None => (
                self.open_ino(ino, OFlag::O_PATH | OFlag::O_DIRECTORY)?,
                cstr(OsStr::new("."))?,
            ),
        };
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

/// The `open`/`create` flags this filter carries through to the backing store, out of whatever the
/// caller asked for. An allowlist, so a flag nobody reasoned about never reaches a backing fd:
///
///   - the access mode, so the handle is no wider than what was asked and a newly created
///     write-only file does not fail the daemon's own read permission;
///   - `O_EXCL`, which is what makes `open(O_CREAT | O_EXCL)` a lock at all. Dropping it lets every
///     contender succeed, and `<gitdir>/index.lock` is exactly that pattern — two of a project's
///     concurrent sessions would each believe they held the index;
///   - `O_TRUNC`, the caller's own request to start from an empty file;
///   - `O_APPEND`, without which an append is not one. The kernel computes an appending write's
///     offset from the size it has cached, and refreshes that size first *only* when writeback
///     caching is on — the kernel's `fuse_cache_write_iter` puts the refresh inside
///     `if (fc->writeback_cache)`, and this filesystem turns writeback off deliberately and
///     permanently (`doc/architecture.md`, "Coherency"). So a host that grew the file leaves that
///     offset stale, and a `pwrite` there overwrites the bytes it should have followed. Carrying
///     the flag puts the guarantee where POSIX puts it, in the backing filesystem, and git appends
///     its reflogs. [`Filesystem::write`] is the other half: an `O_APPEND` fd must be written with
///     `write`, because Linux has `pwrite` on one append regardless of the offset it was given.
///
/// `O_SYNC` and `O_DSYNC` are deliberately absent, and they are the pair most likely to look like
/// an oversight: the kernel already ends a write with `generic_write_sync`, which lands in this
/// filesystem's own `fsync`, so carrying them to the backing fd would buy a second flush per write
/// rather than a guarantee. That reasoning holds only while `fsync` really syncs — which is
/// [`Filesystem::fsync`]'s own subject. Everything else — `O_DIRECT`, `O_NOATIME` — is surface
/// nobody reasoned about, and the allowlist is what keeps that true as the platform grows flags.
fn passthrough_flags(flags: i32) -> OFlag {
    let mut oflag = OFlag::from_bits_truncate(flags & libc::O_ACCMODE);
    for carried in [OFlag::O_EXCL, OFlag::O_TRUNC, OFlag::O_APPEND] {
        if flags & carried.bits() != 0 {
            oflag |= carried;
        }
    }
    oflag
}

/// A requested timestamp as `utimensat` wants it. `None` leaves the field alone (`UTIME_OMIT`), so
/// setting one of the pair does not clobber the other. A time before the epoch is carried as the
/// negative seconds and positive nanoseconds a `timespec` is defined in rather than clamped to the
/// epoch: extracting an archive of pre-1970 files is the ordinary way to meet one, and clamping
/// would silently rewrite the very timestamp the extraction is restoring.
fn time_spec(value: Option<TimeOrNow>) -> TimeSpec {
    match value {
        None => TimeSpec::UTIME_OMIT,
        Some(TimeOrNow::Now) => TimeSpec::UTIME_NOW,
        Some(TimeOrNow::SpecificTime(time)) => match time.duration_since(UNIX_EPOCH) {
            Ok(since) => TimeSpec::new(since.as_secs() as i64, since.subsec_nanos() as i64),
            // `duration_since` reports the magnitude when the time is the earlier one. A
            // `timespec`'s nanoseconds are always positive, so a fractional second borrows one.
            Err(before) => {
                let magnitude = before.duration();
                match (magnitude.as_secs() as i64, magnitude.subsec_nanos() as i64) {
                    (secs, 0) => TimeSpec::new(-secs, 0),
                    (secs, nanos) => TimeSpec::new(-secs - 1, 1_000_000_000 - nanos),
                }
            }
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

/// Whether a symlink `target`, created in a directory `depth` components below the workspace root,
/// has the *shape* of a portable one: relative, and never climbing above the directory it is created
/// in by more than that directory's own depth. `symlink` has the why.
///
/// A conservative shape test, not a decision about meaning, and it errs in both directions rather
/// than claiming a semantics it cannot compute:
///
///   - it accepts a target whose own components are symlinks the host may resolve differently,
///     since it walks the target lexically and resolves nothing;
///   - it refuses every absolute target, including `/workspace/...` — which is right for a host
///     checkout anywhere else, and needlessly strict for a native Linux one that really is at
///     `/workspace`.
///
/// Shape is what a filter serving an unknown host layout can judge. The rule earns its place on the
/// second direction anyway: what a caching tool plants is the container's own store path, which
/// cannot be assumed portable to a host layout this side never sees.
///
/// This is therefore a portability rule and not a containment one — containment is
/// `RESOLVE_IN_ROOT` on every path the daemon itself resolves, and it does not resolve this one.
///
/// The other reason, and the limit to state before anyone leans on this: `depth` is judged once,
/// where the link is created, while a relative target is interpreted afresh from whichever directory
/// holds the link. Moving the link, aliasing it at a shallower name with `link`, or moving a
/// directory above it therefore re-aims it against a depth this never saw, and it can then resolve
/// outside the workspace. Neither `rename` nor `link` re-judges — not an oversight to correct:
/// doing it for a directory means walking everything under it on every rename, at a cost this rule
/// does not earn. What this refuses is a target written in a non-portable shape, which is the accidental
/// tool behaviour the rule is aimed at; a session set on leaving a link that resolves elsewhere
/// still can.
fn target_has_portable_shape(target: &Path, depth: usize) -> bool {
    let mut at = depth;
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match at.checked_sub(1) {
                Some(up) => at = up,
                None => return false,
            },
            Component::Normal(_) => at += 1,
            // Absolute: refused on the shape alone, with nothing resolved or interpreted.
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

fn cstr(name: &OsStr) -> Result<CString, NixErrno> {
    CString::new(name.as_bytes()).map_err(|_| NixErrno::EINVAL)
}

fn system_time(secs: i64, nsecs: i64) -> SystemTime {
    let nsecs = nsecs.clamp(0, 999_999_999) as u32;
    if secs >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(secs as u64, nsecs))
            .unwrap_or(UNIX_EPOCH)
    } else {
        // `time_spec`'s mirror: negative seconds carry positive nanoseconds, so a nonzero
        // nanosecond field means the magnitude is one second less than the seconds field.
        // `unsigned_abs` because `i64::MIN` has no positive counterpart to negate.
        let magnitude = if nsecs == 0 {
            Duration::new(secs.unsigned_abs(), 0)
        } else {
            Duration::new(secs.unsigned_abs() - 1, 1_000_000_000 - nsecs)
        };
        UNIX_EPOCH.checked_sub(magnitude).unwrap_or(UNIX_EPOCH)
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
// is the deny side only; whether the *policy* is complete is `doc/git-metadata.md`, resting on the
// git-behaviour premises `doc/git-metadata.md` records under "Premises".
impl Filesystem for KoAgentFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        // Refused rather than degraded: `doc/architecture.md`, "Coherency". Why this rather than
        // `FOPEN_DIRECT_IO`: `doc/TODO.md`, "Non-TODOs".
        if config
            .add_capabilities(InitFlags::FUSE_AUTO_INVAL_DATA)
            .is_err()
        {
            eprintln!(
                "ko-agent-fs: this kernel does not offer AUTO_INVAL_DATA, so cached and mmap'd\n\
                 pages could lag a host write; refusing to mount rather than serve a stale view"
            );
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let cname = match cstr(name) {
            Ok(value) => value,
            Err(err) => return reply.error(to_errno(err)),
        };
        let dirfd = match self.open_ino(parent.0, OFlag::O_PATH | OFlag::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let st = match fstatat(&dirfd, cname.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(err) => return reply.error(to_errno(err)),
        };
        let root = self.is_gitdir_root(parent.0, &dirfd, name, &st);
        let ino = self
            .inner
            .lock()
            .unwrap()
            .table
            .lookup(parent.0, name, root);
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
        let appending = flags.0 & libc::O_APPEND != 0;
        let wants_write =
            accmode == libc::O_WRONLY || accmode == libc::O_RDWR || (flags.0 & libc::O_TRUNC) != 0;

        // The write gate: opening a control target for writing is where mutation is refused, so a
        // subsequent write() on the returned handle never needs re-checking.
        if wants_write && let Err(err) = self.allow_ino(ino.0, Mutation::Write, "open-write") {
            return reply.error(err);
        }

        let fd = match self.open_ino(ino.0, passthrough_flags(flags.0)) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let mut inner = self.inner.lock().unwrap();
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.handles.insert(
            fh,
            Handle {
                fd: Arc::new(fd),
                append: appending,
            },
        );
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
        let handle = self
            .inner
            .lock()
            .unwrap()
            .handles
            .get(&fh.0)
            .map(|h| h.fd.clone());
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
        flags: i32,
        reply: ReplyCreate,
    ) {
        if let Err(err) = self.allow_create(parent.0, name, "create") {
            return reply.error(err);
        }
        let (cname, parentfd) = match self.child_target(parent.0, name) {
            Ok(pair) => pair,
            Err(err) => return reply.error(err),
        };
        // O_EXCL is not forced but is carried through (`passthrough_flags`): create() may reopen an
        // existing allowed file, and only the caller knows whether it meant to. O_NOFOLLOW stops a
        // pre-planted symlink at the target from redirecting the create elsewhere.
        let how = OpenHow::new()
            .flags(passthrough_flags(flags) | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .mode(Mode::from_bits_truncate(mode & !umask & 0o7777))
            .resolve(
                ResolveFlag::RESOLVE_IN_ROOT
                    | ResolveFlag::RESOLVE_NO_MAGICLINKS
                    | ResolveFlag::RESOLVE_NO_SYMLINKS,
            );
        let fd = match openat2(&parentfd, cname.as_c_str(), how) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let st = match fstat(&fd) {
            Ok(st) => st,
            Err(err) => return reply.error(to_errno(err)),
        };
        let mut inner = self.inner.lock().unwrap();
        let ino = inner.table.lookup(parent.0, name, false);
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.handles.insert(
            fh,
            Handle {
                fd: Arc::new(fd),
                append: flags & libc::O_APPEND != 0,
            },
        );
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
        // Not a policy decision — the target is never what the policy classifies (the mutation
        // tests say why) — but the one thing a session writes whose stored content the host's own
        // kernel follows as a path, with the user's privileges and nothing having to run.
        // `target_has_portable_shape` has the shape this accepts and how far that shape is only an
        // approximation; SECURITY.md, "A symlink is the sharpest case", has the threat.
        //
        // The population is tools that cache outside the project and link into it, and sbt 2 is the
        // measured case at both ends. Unrefused, it materializes a build-cache hit as a link into
        // its own store — `~/.cache/sbt/v2/cas` in here, `~/Library/Caches/sbt/v2/cas` on the
        // host — and the host's next compile of a changed source dies with `NoSuchFileException`
        // writing its own class files through the dangling link, until `git clean -xdf`. Refused,
        // its `DiskActionCacheStore` matches the `Operation not permitted` this returns, stops
        // linking for the session and copies out of the store instead: builds keep working, and the
        // cost is a copy per cached output rather than a link.
        let depth = match self.inner.lock().unwrap().table.components(parent.0) {
            Some(components) => components.len(),
            None => return reply.error(Errno::ESTALE),
        };
        if !target_has_portable_shape(target, depth) {
            return reply.error(deny(
                "symlink",
                &format!("{link_name:?}"),
                "nonportable-target-shape: refusing a target that is absolute or climbs above \
                 the workspace root",
            ));
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
        // Source-side too (`doc/git-metadata.md`, "Operations that carry these mutations").
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
        flags: OpenFlags,
        _lock: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let handle = self
            .inner
            .lock()
            .unwrap()
            .handles
            .get(&fh.0)
            .map(|h| (h.fd.clone(), h.append));
        let Some((fd, backing_append)) = handle else {
            return reply.error(Errno::EBADF);
        };
        // The caller's flags as they are *now*, not as they were at open: `fcntl(F_SETFL)` can add
        // or drop `O_APPEND` on a live file description, and the kernel sends the current word with
        // every write. The backing descriptor is brought into step before the syscall is chosen,
        // because both halves depend on it — `pwrite` on an appending fd ignores its offset.
        let append = flags.0 & libc::O_APPEND != 0;
        if append != backing_append {
            if let Err(err) = set_backing_append(fd.as_ref(), append) {
                return reply.error(to_errno(err));
            }
            if let Some(handle) = self.inner.lock().unwrap().handles.get_mut(&fh.0) {
                handle.append = append;
            }
        }
        // An appending write goes through `write`, not `pwrite`: the end is the backing
        // filesystem's to decide, and the offset the kernel supplies came from a size it does not
        // refresh on this path (`passthrough_flags`). Everything else is positional, which is what
        // that offset means when the description is not appending.
        let outcome = if append {
            nix::unistd::write(fd.as_ref(), data)
        } else {
            pwrite(fd.as_ref(), data, offset as i64)
        };
        match outcome {
            Ok(written) => reply.written(written as u32),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    /// Nothing to do, and that is a property rather than a stub: a `write` is a `pwrite` straight to
    /// the backing fd, so the daemon holds no buffered data a `close(2)` could still lose. Durability
    /// is `fsync`'s question, below.
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

    /// Actually sync. Replying `ok()` without the syscall would be a false guarantee to the caller
    /// that most depends on it: git fsyncs a loose object and a ref before it treats the write as
    /// committed, so a machine that lost power here would leave the user's own checkout corrupt
    /// while every call had reported success.
    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let handle = self
            .inner
            .lock()
            .unwrap()
            .handles
            .get(&fh.0)
            .map(|h| h.fd.clone());
        let fd = match handle {
            Some(fd) => fd,
            None => return reply.error(Errno::EBADF),
        };
        // `datasync` is the caller's own narrowing — fdatasync skips a metadata flush the data does
        // not depend on — so honour it rather than always paying for the wider one.
        let synced = if datasync {
            fdatasync(fd.as_ref())
        } else {
            fsync(fd.as_ref())
        };
        match synced {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_errno(err)),
        }
    }

    /// The directory twin, and needed for the same reason: git syncs the directory holding a ref it
    /// just renamed into place. The `opendir` handle carries a name snapshot rather than an fd, so
    /// this re-resolves the inode — which is what every other operation here does anyway.
    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let fd = match self.open_ino(ino.0, OFlag::O_RDONLY | OFlag::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(err) => return reply.error(to_errno(err)),
        };
        let synced = if datasync { fdatasync(&fd) } else { fsync(&fd) };
        match synced {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(to_errno(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_symlink_target_has_portable_shape_when_it_is_relative_and_lands_inside() {
        let portable =
            |target: &str, depth: usize| target_has_portable_shape(Path::new(target), depth);

        // depth 0 is a link in the workspace root.
        assert!(portable("sibling.rs", 0));
        assert!(portable("./sibling.rs", 0));
        assert!(portable("src/main.rs", 0));
        assert!(!portable("..", 0));
        assert!(!portable("../outside", 0));

        // From src/, one `..` is the root itself — still inside — and the second leaves.
        assert!(portable("..", 1));
        assert!(portable("../src/main.rs", 1));
        assert!(!portable("../..", 1));
        assert!(!portable("../../../../etc/passwd", 1));

        // Descending first buys depth back, and the running count is what decides.
        assert!(portable("a/../b", 0));
        assert!(portable("a/b/../../c", 0));
        assert!(!portable("a/../../b", 0));

        // Absolute is absolute at any depth, and what it names is not consulted — `/workspace/...`
        // is refused with the rest, which is the conservative half of the shape.
        assert!(!portable("/etc/passwd", 9));
        assert!(!portable("/workspace/src/main.rs", 9));
    }

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
        let _ = system_time(i64::MIN, 999_999_999);
        let _ = system_time(i64::MAX, 1_000_000_000);
        let _ = system_time(0, 999_999_999);
    }

    #[test]
    fn a_pre_epoch_time_round_trips_rather_than_clamping() {
        // Extracting an archive of pre-1970 files is the ordinary way to meet one, and the claim
        // this pins is `doc/TODO.md`'s: times round-trip. Clamping would rewrite the timestamp the
        // extraction restores, and a negative time read back without its nanoseconds loses the
        // fractional second.
        for when in [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1, 500_000_000),
            UNIX_EPOCH - Duration::new(1, 0),
            UNIX_EPOCH - Duration::new(0, 500_000_000),
            UNIX_EPOCH - Duration::new(86_400 * 365 * 10, 250_000_000),
        ] {
            let spec = time_spec(Some(TimeOrNow::SpecificTime(when)));
            assert_eq!(
                system_time(spec.tv_sec(), spec.tv_nsec()),
                when,
                "{when:?} did not survive the round trip"
            );
        }
    }

    #[test]
    fn the_carried_open_flags_are_the_allowlist_and_nothing_else() {
        // Reasons: `passthrough_flags`.
        assert_eq!(passthrough_flags(libc::O_WRONLY), OFlag::O_WRONLY);
        assert_eq!(passthrough_flags(libc::O_RDWR), OFlag::O_RDWR);
        assert!(passthrough_flags(libc::O_WRONLY | libc::O_EXCL).contains(OFlag::O_EXCL));
        assert!(passthrough_flags(libc::O_WRONLY | libc::O_TRUNC).contains(OFlag::O_TRUNC));
        assert!(passthrough_flags(libc::O_WRONLY | libc::O_APPEND).contains(OFlag::O_APPEND));
        assert!(!passthrough_flags(libc::O_WRONLY | libc::O_SYNC).contains(OFlag::O_SYNC));
        assert!(!passthrough_flags(libc::O_WRONLY | libc::O_DSYNC).contains(OFlag::O_DSYNC));
        assert!(!passthrough_flags(libc::O_RDONLY | libc::O_NOATIME).contains(OFlag::O_NOATIME));
        assert!(!passthrough_flags(libc::O_WRONLY | libc::O_DIRECT).contains(OFlag::O_DIRECT));
    }
}
