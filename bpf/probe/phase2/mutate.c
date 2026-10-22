// Phase 2 of doc/plan-bpf-lsm-cgroup.md: the exerciser, run inside a container under the attach
// cgroup. It performs the inventory's operations on names the inventory programs recognize, the
// corpus of decisions the representative program must take, and the open loops whose cost the
// walk adds. Static, so the probe image's libc is not needed.
//
//   mutate prepare TREE MODE       the objects the inventory's operations act on, MODE allow or deny
//   mutate inventory TREE MODE [only=N,N|skip=N,N]
//                                  the operations, each printed as `op=NN label=... result=...`
//   mutate make-tree TREE          the corpus fixture, laid out as a workspace
//   mutate corpus TREE             the decisions, each printed as `case=... expect=... got=...`
//   mutate walk-cost PATH N        N opens of PATH for writing, for reading, and N lstat, in ns each
//
// Every object of operation NN is named `kab2-NN-<x>`; the judged one is `kab2-NN-deny-<x>` in
// deny mode, which an attached inventory program refuses. `prepare` runs outside the policy, so
// a deny-named source exists before the operation that must be refused on it.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/fsverity.h>
#include <linux/openat2.h>
#include <linux/posix_acl_xattr.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_file_setattr
#define __NR_file_setattr 469
#endif
// include/uapi/linux/fs.h in Linux 7.2; older headers lack it.
struct probe_file_attr {
	uint64_t fa_xflags;
	uint32_t fa_extsize;
	uint32_t fa_nextents;
	uint32_t fa_projid;
	uint32_t fa_cowextsize;
};
#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif
#ifndef RENAME_WHITEOUT
#define RENAME_WHITEOUT (1 << 2)
#endif
// fs/ext4/ext4.h: EXT4_IOC_SETVERSION is _IOW('f', 4, long).
#define EXT4_IOC_SETVERSION _IOW('f', 4, long)
// <sys/mount.h> and <linux/fs.h> define the MS_* flags twice; the two calls are declared here.
#define PROBE_MS_BIND 4096
extern int mount(const char *source, const char *target, const char *type, unsigned long flags, const void *data);
extern int umount2(const char *target, int flags);

static const char *tree;
static char dir[4096];        // the directory the current invocation's objects live in
static int deny;              // deny mode: the judged object's name carries `-deny`
static int dirfd_;
static int mismatches;

static void die(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "mutate: ");
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(2);
}

static const char *errname(int err)
{
	switch (err) {
	case EPERM: return "EPERM";
	case ENOENT: return "ENOENT";
	case EACCES: return "EACCES";
	case EEXIST: return "EEXIST";
	case ENOTTY: return "ENOTTY";
	case EINVAL: return "EINVAL";
	case ENOSYS: return "ENOSYS";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case EXDEV: return "EXDEV";
	case EBADF: return "EBADF";
	case ENODATA: return "ENODATA";
	case EROFS: return "EROFS";
	case EISDIR: return "EISDIR";
	case ENOTDIR: return "ENOTDIR";
	case ELOOP: return "ELOOP";
	case EMLINK: return "EMLINK";
	case ESTALE: return "ESTALE";
	case EIO: return "EIO";
	case ENOTEMPTY: return "ENOTEMPTY";
	case EBUSY: return "EBUSY";
	case EAGAIN: return "EAGAIN";
	default: return NULL;
	}
}

// `result=ok` or `result=<errno name or number>`.
static const char *result(int rc)
{
	static char text[32];
	int err = errno;

	if (rc >= 0)
		return "ok";
	if (errname(err))
		snprintf(text, sizeof(text), "%s", errname(err));
	else
		snprintf(text, sizeof(text), "errno%d", err);
	return text;
}

static void report(int op, const char *label, const char *detail, int rc)
{
	const char *res = result(rc);

	if (detail && *detail)
		printf("op=%02d label=%s result=%s %s\n", op, label, res, detail);
	else
		printf("op=%02d label=%s result=%s\n", op, label, res);
	fflush(stdout);
}

// The name of operation `op`'s object `suffix`: judged objects carry `-deny` in deny mode.
// Four rotating buffers, so one call's arguments may hold several names.
static char *name_buffer(void)
{
	static char names[4][64];
	static int slot;

	return names[slot++ & 3];
}

static const char *judged(int op, const char *suffix)
{
	char *name = name_buffer();

	snprintf(name, 64, "kab2-%02d-%s%s", op, deny ? "deny-" : "", suffix);
	return name;
}

static const char *helper(int op, const char *suffix)
{
	char *name = name_buffer();

	snprintf(name, 64, "kab2-%02d-%s", op, suffix);
	return name;
}

static const char *path_of(const char *name)
{
	static char path[4][4096];
	static int slot;
	char *out = path[slot++ & 3];

	snprintf(out, 4096, "%s/%s", dir, name);
	return out;
}

static void make_file(const char *name, const char *content)
{
	int fd = open(path_of(name), O_CREAT | O_WRONLY | O_TRUNC, 0644);

	if (fd < 0)
		die("create %s: %s", name, strerror(errno));
	if (content && write(fd, content, strlen(content)) < 0)
		die("write %s: %s", name, strerror(errno));
	close(fd);
}

static void make_dir(const char *name)
{
	if (mkdir(path_of(name), 0755) && errno != EEXIST)
		die("mkdir %s: %s", name, strerror(errno));
}

static int open_rd(const char *name)
{
	int fd = open(path_of(name), O_RDONLY);

	if (fd < 0)
		die("open %s: %s", name, strerror(errno));
	return fd;
}

// The judged file opened read-only for an operation on its descriptor, or -1 with the operation
// reported as `open-failed:<errno>`: under a batch holding `file_open`, the deny name's open is
// refused and the operation has no descriptor, which ends the operation and not the run.
static int open_judged(int op, const char *label, const char *name)
{
	int fd = open(path_of(name), O_RDONLY);

	if (fd < 0) {
		printf("op=%02d label=%s result=open-failed:%s\n", op, label, result(-1));
		fflush(stdout);
	}
	return fd;
}

static int xattr_supported;

// ---------------------------------------------------------------------------------------------
// The inventory
// ---------------------------------------------------------------------------------------------

#define J(suffix) judged(op, suffix)
#define H(suffix) helper(op, suffix)

static int openat2_call(int dfd, const char *name, uint64_t flags, uint64_t mode, uint64_t resolve)
{
	struct open_how how = {.flags = flags, .mode = mode, .resolve = resolve};

	return syscall(__NR_openat2, dfd, name, &how, sizeof(how));
}

// A socket bound at `name` in `dir`: the path is bound relative to the directory, since
// sun_path holds 108 bytes.
static int bind_socket(const char *name)
{
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	int sock = socket(AF_UNIX, SOCK_STREAM, 0), rc, saved;
	char cwd[4096];

	if (sock < 0)
		return -1;
	if (!getcwd(cwd, sizeof(cwd)) || chdir(dir)) {
		close(sock);
		return -1;
	}
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", name);
	rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	saved = errno;
	if (chdir(cwd))
		die("chdir: %s", strerror(errno));
	close(sock);
	errno = saved;
	return rc;
}

// The ACL an `setfacl -m u::rw,g::r,o::r` would set: version 2, three entries.
static size_t acl_blob(unsigned char *out)
{
	struct posix_acl_xattr_header *header = (struct posix_acl_xattr_header *)out;
	struct posix_acl_xattr_entry *entries = (struct posix_acl_xattr_entry *)(out + sizeof(*header));

	header->a_version = POSIX_ACL_XATTR_VERSION;
	entries[0].e_tag = 0x01;	// ACL_USER_OBJ
	entries[0].e_perm = 6;
	entries[0].e_id = 0xffffffff;
	entries[1].e_tag = 0x04;	// ACL_GROUP_OBJ
	entries[1].e_perm = 4;
	entries[1].e_id = 0xffffffff;
	entries[2].e_tag = 0x20;	// ACL_OTHER
	entries[2].e_perm = 4;
	entries[2].e_id = 0xffffffff;
	return sizeof(*header) + 3 * sizeof(*entries);
}

// A child in a new user and mount namespace, mapped to uid 0 there, running `body`; its exit
// status is the body's return, 100 + errno when the namespaces could not be made.
// The child's errno, in a page the child shares with the exerciser; its exit status names the
// step that failed.
static int *child_errno;

static int child_failed(int code)
{
	if (child_errno)
		*child_errno = errno;
	return code;
}

static int in_userns(int (*body)(void), int mount_ns)
{
	pid_t pid;
	int status;

	if (!child_errno)
		child_errno = mmap(NULL, sizeof(*child_errno), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
				   -1, 0);
	if (child_errno == MAP_FAILED)
		die("mmap: %s", strerror(errno));
	*child_errno = 0;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		uid_t uid = getuid();
		gid_t gid = getgid();
		char map[64];
		int fd;

		if (unshare(CLONE_NEWUSER | (mount_ns ? CLONE_NEWNS : 0)))
			_exit(child_failed(45));
		fd = open("/proc/self/setgroups", O_WRONLY);
		if (fd >= 0) {
			if (write(fd, "deny", 4) < 0)
				_exit(child_failed(45));
			close(fd);
		}
		snprintf(map, sizeof(map), "0 %u 1", uid);
		fd = open("/proc/self/uid_map", O_WRONLY);
		if (fd < 0 || write(fd, map, strlen(map)) < 0)
			_exit(child_failed(45));
		close(fd);
		snprintf(map, sizeof(map), "0 %u 1", gid);
		fd = open("/proc/self/gid_map", O_WRONLY);
		if (fd < 0 || write(fd, map, strlen(map)) < 0)
			_exit(child_failed(45));
		close(fd);
		_exit(body());
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int overlay_op;
static char overlay_merged[4096], overlay_opts[8192];

static int overlay_body(void)
{
	int fd;

	if (mount("overlay", overlay_merged, "overlay", 0, overlay_opts))
		return child_failed(40);
	fd = open(path_of(judged(overlay_op, "f")), O_CREAT | O_WRONLY | O_EXCL, 0644);
	if (fd < 0)
		return child_failed(errno == EPERM ? 41 : 42);
	close(fd);
	return 0;
}

static int alias_body(void)
{
	char alias[4096], file[4096];
	int fd;

	snprintf(alias, sizeof(alias), "%s/%s", dir, helper(51, "alias"));
	if (mount(dir, alias, NULL, PROBE_MS_BIND, NULL))
		return child_failed(40);
	snprintf(file, sizeof(file), "%s/%s", alias, judged(51, "f"));
	fd = open(file, O_CREAT | O_WRONLY | O_EXCL, 0644);
	if (fd < 0)
		return child_failed(errno == EPERM ? 41 : 42);
	close(fd);
	return 0;
}

static char capability_path[4096];

static int capability_set_body(void)
{
	// VFS_CAP_REVISION_3 with the effective flag, CAP_NET_RAW permitted and effective, rootid 0:
	// what `setcap cap_net_raw+ep` writes from a user namespace.
	struct vfs_ns_cap_data data = {};

	data.magic_etc = VFS_CAP_REVISION_3 | VFS_CAP_FLAGS_EFFECTIVE;
	data.data[0].permitted = 1u << 13;
	data.data[0].inheritable = 0;
	data.rootid = 0;
	if (setxattr(capability_path, "security.capability", &data, sizeof(data), 0))
		return child_failed(errno == EPERM ? 41 : errno == ENOTSUP ? 43 : errno == EOPNOTSUPP ? 43 : 42);
	return 0;
}

static int capability_remove_body(void)
{
	if (removexattr(capability_path, "security.capability"))
		return child_failed(errno == EPERM ? 41 : errno == ENODATA ? 44 : 42);
	return 0;
}

static const char *userns_result(int rc)
{
	static char text[64];
	const char *step;

	switch (rc) {
	case 0: return "ok";
	case 41: return "EPERM";
	case 43: return "ENOTSUP";
	case 44: return "ENODATA";
	case -1: return "no-child";
	case 40: step = "mount-failed"; break;
	case 45: step = "userns-failed"; break;
	default: step = "failed"; break;
	}
	errno = *child_errno;
	snprintf(text, sizeof(text), "%s:%s", step, result(-1));
	return text;
}

static void prepare_overlay(int op)
{
	char lower[4096];

	make_dir(H("lower"));
	make_dir(H("upper"));
	make_dir(H("work"));
	make_dir(H("merged"));
	snprintf(lower, sizeof(lower), "%s/%s/seed", dir, H("lower"));
	close(open(lower, O_CREAT | O_WRONLY, 0644));
}

// Each operation's prepare and run. `op` numbers the inventory's operations in order; the row
// of "Inventory" each belongs to is in phase2.sh's table.
static void prepare_op(int op)
{
	switch (op) {
	case 9: case 11: case 12: make_file(H("src"), "src\n"); break;
	case 10: make_file(J("src"), "src\n"); break;
	case 14: case 16: make_file(H("src"), "src\n"); break;
	case 15: make_file(J("src"), "src\n"); break;
	case 17: make_file(H("a"), "a\n"); make_file(J("b"), "b\n"); break;
	case 18: case 21: case 22: case 23: case 24: case 25: case 26: case 27: case 28: case 29:
	case 31: case 32: case 33: case 34: case 35: case 36: case 37: case 39: case 41: case 42: case 43:
	case 44: case 46: case 47: case 48: case 52: case 54:
		make_file(J("f"), "content\n");
		break;
	case 19: case 20: case 45: make_dir(J("d")); break;
	case 30: make_file(H("src"), "clone me\n"); make_file(J("f"), ""); break;
	case 38:
		make_file(J("f"), "x\n");
		xattr_supported = setxattr(path_of(J("f")), "user.kab2", "v", 1, 0) == 0;
		break;
	case 40: {
		unsigned char blob[64];
		size_t len = acl_blob(blob);

		make_file(J("f"), "x\n");
		xattr_supported = setxattr(path_of(J("f")), "system.posix_acl_access", blob, len, 0) == 0;
		break;
	}
	case 50: prepare_overlay(op); break;
	case 51: make_dir(H("alias")); break;
	case 55: make_file(H("capf"), "cap\n"); break;
	default: break;
	}
}

static void run_op(int op)
{
	char detail[256] = "";
	int fd, rc;

	switch (op) {
	case 1:
		rc = open(path_of(J("f")), O_CREAT | O_WRONLY | O_EXCL, 0644);
		report(op, "creat", NULL, rc);
		break;
	case 2:
		rc = openat(dirfd_, J("f"), O_CREAT | O_RDWR | O_EXCL, 0644);
		report(op, "openat-creat", NULL, rc);
		break;
	case 3:
		rc = openat2_call(dirfd_, J("f"), O_CREAT | O_WRONLY | O_EXCL, 0644, RESOLVE_BENEATH);
		report(op, "openat2-creat-beneath", NULL, rc);
		break;
	case 4:
		rc = mknodat(dirfd_, J("f"), S_IFREG | 0644, 0);
		report(op, "mknod-regular", NULL, rc);
		break;
	case 5:
		rc = mknodat(dirfd_, J("fifo"), S_IFIFO | 0644, 0);
		report(op, "mkfifo", NULL, rc);
		break;
	case 6:
		rc = bind_socket(J("sock"));
		report(op, "bind-socket", NULL, rc);
		break;
	case 7:
		rc = mkdirat(dirfd_, J("d"), 0755);
		report(op, "mkdir", NULL, rc);
		break;
	case 8:
		rc = symlinkat("target", dirfd_, J("l"));
		report(op, "symlink", NULL, rc);
		break;
	case 9:
		rc = linkat(dirfd_, H("src"), dirfd_, J("l"), 0);
		report(op, "link-new-name", NULL, rc);
		break;
	case 10:
		rc = linkat(dirfd_, J("src"), dirfd_, H("l"), 0);
		report(op, "link-source", NULL, rc);
		break;
	case 11:
		fd = open_rd(H("src"));
		rc = linkat(fd, "", dirfd_, J("l"), AT_EMPTY_PATH);
		report(op, "linkat-empty-path", NULL, rc);
		close(fd);
		break;
	case 12: {
		char proc[64];

		fd = open_rd(H("src"));
		snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
		rc = linkat(AT_FDCWD, proc, dirfd_, J("l"), AT_SYMLINK_FOLLOW);
		report(op, "link-proc-fd", NULL, rc);
		close(fd);
		break;
	}
	case 13: {
		char proc[64];

		fd = open(dir, O_TMPFILE | O_WRONLY, 0644);
		if (fd < 0) {
			report(op, "tmpfile-link", "tmpfile=failed", fd);
			break;
		}
		snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
		rc = linkat(AT_FDCWD, proc, dirfd_, J("l"), AT_SYMLINK_FOLLOW);
		report(op, "tmpfile-link", "tmpfile=ok", rc);
		close(fd);
		break;
	}
	case 14:
		rc = renameat2(dirfd_, H("src"), dirfd_, J("dst"), 0);
		report(op, "rename-new-name", NULL, rc);
		break;
	case 15:
		rc = renameat2(dirfd_, J("src"), dirfd_, H("dst"), 0);
		report(op, "rename-source", NULL, rc);
		break;
	case 16:
		rc = renameat2(dirfd_, H("src"), dirfd_, J("dst"), RENAME_WHITEOUT);
		report(op, "rename-whiteout", NULL, rc);
		break;
	case 17:
		rc = renameat2(dirfd_, H("a"), dirfd_, J("b"), RENAME_EXCHANGE);
		report(op, "rename-exchange", NULL, rc);
		break;
	case 18:
		rc = unlinkat(dirfd_, J("f"), 0);
		report(op, "unlink", NULL, rc);
		break;
	case 19:
		rc = rmdir(path_of(J("d")));
		report(op, "rmdir", NULL, rc);
		break;
	case 20:
		rc = unlinkat(dirfd_, J("d"), AT_REMOVEDIR);
		report(op, "unlinkat-removedir", NULL, rc);
		break;
	case 21:
		rc = open(path_of(J("f")), O_WRONLY);
		report(op, "open-wronly", NULL, rc);
		if (rc >= 0) close(rc);
		break;
	case 22:
		rc = open(path_of(J("f")), O_RDWR);
		report(op, "open-rdwr", NULL, rc);
		if (rc >= 0) close(rc);
		break;
	case 23:
		rc = open(path_of(J("f")), O_RDONLY);
		report(op, "open-rdonly", NULL, rc);
		if (rc >= 0) close(rc);
		break;
	case 24:
		rc = open(path_of(J("f")), O_RDONLY | O_TRUNC);
		report(op, "open-rdonly-trunc", NULL, rc);
		if (rc >= 0) close(rc);
		break;
	case 25:
		rc = open(path_of(J("f")), O_WRONLY | O_TRUNC);
		report(op, "open-wronly-trunc", NULL, rc);
		if (rc >= 0) close(rc);
		break;
	case 26:
		fd = open(path_of(J("f")), O_RDWR);
		if (fd < 0) {
			report(op, "write", "open=failed", fd);
			break;
		}
		rc = write(fd, "w", 1);
		report(op, "write", "open=ok", rc);
		close(fd);
		break;
	case 27: {
		void *map;

		fd = open(path_of(J("f")), O_RDWR);
		if (fd < 0) {
			report(op, "mmap-shared-write", "open=failed", fd);
			break;
		}
		map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (map == MAP_FAILED) {
			report(op, "mmap-shared-write", "open=ok", -1);
		} else {
			((char *)map)[0] = 'm';
			rc = msync(map, 4096, MS_SYNC);
			report(op, "mmap-shared-write", "open=ok mmap=ok", rc);
			munmap(map, 4096);
		}
		close(fd);
		break;
	}
	case 28: {
		void *map;

		fd = open(path_of(J("f")), O_RDONLY);
		if (fd < 0) {
			report(op, "mprotect-private", "open=failed", fd);
			break;
		}
		map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
		if (map == MAP_FAILED) {
			report(op, "mprotect-private", "open=ok", -1);
		} else {
			rc = mprotect(map, 4096, PROT_READ | PROT_WRITE);
			report(op, "mprotect-private", "open=ok mmap=ok", rc);
			munmap(map, 4096);
		}
		close(fd);
		break;
	}
	case 29:
		fd = open(path_of(J("f")), O_RDWR);
		if (fd < 0) {
			report(op, "fallocate", "open=failed", fd);
			break;
		}
		rc = fallocate(fd, 0, 0, 4096);
		report(op, "fallocate", "open=ok", rc);
		close(fd);
		break;
	case 30: {
		int src = open_rd(H("src"));

		fd = open(path_of(J("f")), O_RDWR);
		if (fd < 0) {
			report(op, "ficlone", "open=failed", fd);
		} else {
			rc = ioctl(fd, FICLONE, src);
			report(op, "ficlone", "open=ok", rc);
			close(fd);
		}
		close(src);
		break;
	}
	case 31:
		rc = chmod(path_of(J("f")), 0600);
		report(op, "chmod", NULL, rc);
		break;
	case 32:
		rc = fchownat(dirfd_, J("f"), -1, getgid(), 0);
		report(op, "chown-same-gid", NULL, rc);
		break;
	case 33:
		rc = truncate(path_of(J("f")), 0);
		report(op, "truncate", NULL, rc);
		break;
	case 34:
		rc = utimensat(dirfd_, J("f"), NULL, 0);
		report(op, "utimensat", NULL, rc);
		break;
	case 35:
		rc = fchmodat(dirfd_, J("f"), 0640, 0);
		report(op, "fchmodat", NULL, rc);
		break;
	case 36:
		fd = open(path_of(J("f")), O_RDWR);
		if (fd < 0) {
			report(op, "ftruncate", "open=failed", fd);
			break;
		}
		rc = ftruncate(fd, 1);
		report(op, "ftruncate", "open=ok", rc);
		close(fd);
		break;
	case 37:
		rc = setxattr(path_of(J("f")), "user.kab2", "v", 1, 0);
		report(op, "setxattr-user", NULL, rc);
		break;
	case 38:
		snprintf(detail, sizeof(detail), "prepared=%s", xattr_supported ? "ok" : "unsupported");
		rc = removexattr(path_of(J("f")), "user.kab2");
		report(op, "removexattr-user", detail, rc);
		break;
	case 39: {
		unsigned char blob[64];
		size_t len = acl_blob(blob);

		rc = setxattr(path_of(J("f")), "system.posix_acl_access", blob, len, 0);
		report(op, "setfacl", NULL, rc);
		break;
	}
	case 40:
		snprintf(detail, sizeof(detail), "prepared=%s", xattr_supported ? "ok" : "unsupported");
		rc = removexattr(path_of(J("f")), "system.posix_acl_access");
		report(op, "removeacl", detail, rc);
		break;
	case 41: {
		long flags = 0;

		fd = open_judged(op, "ioctl-setflags-rdonly-fd", J("f"));
		if (fd < 0)
			break;
		rc = ioctl(fd, FS_IOC_GETFLAGS, &flags);
		snprintf(detail, sizeof(detail), "getflags=%s", rc ? result(rc) : "ok");
		rc = ioctl(fd, FS_IOC_SETFLAGS, &flags);
		report(op, "ioctl-setflags-rdonly-fd", detail, rc);
		close(fd);
		break;
	}
	case 42: {
		struct fsxattr fsx = {};

		fd = open_judged(op, "ioctl-fssetxattr-rdonly-fd", J("f"));
		if (fd < 0)
			break;
		rc = ioctl(fd, FS_IOC_FSGETXATTR, &fsx);
		snprintf(detail, sizeof(detail), "fsgetxattr=%s", rc ? result(rc) : "ok");
		rc = ioctl(fd, FS_IOC_FSSETXATTR, &fsx);
		report(op, "ioctl-fssetxattr-rdonly-fd", detail, rc);
		close(fd);
		break;
	}
	case 43: {
		struct probe_file_attr attr = {};

		rc = syscall(__NR_file_setattr, dirfd_, J("f"), &attr, sizeof(attr), 0);
		report(op, "file_setattr-syscall", NULL, rc);
		break;
	}
	case 44: {
		long version = 1;

		fd = open_judged(op, "ioctl-ext4-setversion", J("f"));
		if (fd < 0)
			break;
		rc = ioctl(fd, EXT4_IOC_SETVERSION, &version);
		report(op, "ioctl-ext4-setversion", NULL, rc);
		close(fd);
		break;
	}
	case 45: {
		struct fscrypt_policy_v1 policy = {.version = 0, .contents_encryption_mode = 1,
						   .filenames_encryption_mode = 4};

		fd = open_judged(op, "ioctl-set-encryption-policy", J("d"));
		if (fd < 0)
			break;
		rc = ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy);
		report(op, "ioctl-set-encryption-policy", NULL, rc);
		close(fd);
		break;
	}
	case 46: {
		struct fsverity_enable_arg arg = {.version = 1, .hash_algorithm = 1, .block_size = 4096};

		fd = open_judged(op, "ioctl-enable-verity", J("f"));
		if (fd < 0)
			break;
		rc = ioctl(fd, FS_IOC_ENABLE_VERITY, &arg);
		report(op, "ioctl-enable-verity", NULL, rc);
		close(fd);
		break;
	}
	case 47: {
		// The command with a bit above 32 set: the kernel reads `cmd` as unsigned int, so the
		// hook and the filesystem see FS_IOC_SETFLAGS, which seccomp comparing 64 bits would not.
		long flags = 0;
		unsigned long cmd = (unsigned long)FS_IOC_SETFLAGS | (1UL << 40);

		fd = open_judged(op, "ioctl-setflags-high-bits", J("f"));
		if (fd < 0)
			break;
		ioctl(fd, FS_IOC_GETFLAGS, &flags);
		rc = ioctl(fd, cmd, &flags);
		snprintf(detail, sizeof(detail), "cmd=0x%lx", cmd);
		report(op, "ioctl-setflags-high-bits", detail, rc);
		close(fd);
		break;
	}
	case 48: {
		long flags = 0;

		fd = open_judged(op, "ioctl-getflags", J("f"));
		if (fd < 0)
			break;
		rc = ioctl(fd, FS_IOC_GETFLAGS, &flags);
		report(op, "ioctl-getflags", NULL, rc);
		close(fd);
		break;
	}
	case 49:
		rc = open(dir, O_TMPFILE | O_RDWR, 0644);
		report(op, "tmpfile", NULL, rc);
		if (rc >= 0) close(rc);
		break;
	case 50:
		overlay_op = op;
		snprintf(overlay_merged, sizeof(overlay_merged), "%s/%s", dir, H("merged"));
		snprintf(overlay_opts, sizeof(overlay_opts), "lowerdir=%s/%s,upperdir=%s/%s,workdir=%s/%s,userxattr",
			 dir, H("lower"), dir, H("upper"), dir, H("work"));
		// The file is created at merged/<name>; its upper-layer dentry carries the same name.
		snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir), "/%s", H("merged"));
		rc = in_userns(overlay_body, 1);
		dir[strlen(dir) - strlen(H("merged")) - 1] = 0;
		printf("op=%02d label=overlay-upper-create result=%s\n", op, userns_result(rc));
		break;
	case 51:
		rc = in_userns(alias_body, 1);
		printf("op=%02d label=bind-alias-create result=%s\n", op, userns_result(rc));
		break;
	case 52: {
		unsigned char buf[sizeof(struct file_handle) + 128];
		struct file_handle *handle = (struct file_handle *)buf;
		int mount_id;

		handle->handle_bytes = 128;
		rc = name_to_handle_at(dirfd_, J("f"), handle, &mount_id, 0);
		if (rc) {
			report(op, "open-by-handle", "name_to_handle=failed", rc);
			break;
		}
		rc = open_by_handle_at(dirfd_, handle, O_WRONLY);
		report(op, "open-by-handle", "name_to_handle=ok", rc);
		if (rc >= 0) close(rc);
		break;
	}
	case 53: {
		unsigned char params[120] = {};

		rc = syscall(__NR_io_uring_setup, 4, params);
		report(op, "io-uring-setup", NULL, rc);
		if (rc >= 0) close(rc);
		break;
	}
	case 54: {
		// A descriptor of the judged file passed over a socket pair to this process: the
		// receive hook runs at recvmsg, and a refused descriptor is dropped with MSG_CTRUNC.
		int pair[2], received = -1;
		struct msghdr msg = {};
		char byte = 'x';
		struct iovec iov = {.iov_base = &byte, .iov_len = 1};
		union {
			struct cmsghdr header;
			unsigned char bytes[CMSG_SPACE(sizeof(int))];
		} control = {};
		struct cmsghdr *cmsg;

		fd = open_judged(op, "receive-fd", J("f"));
		if (fd < 0)
			break;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
			report(op, "receive-fd", "socketpair=failed", -1);
			break;
		}
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = &control;
		msg.msg_controllen = sizeof(control);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
		if (sendmsg(pair[0], &msg, 0) < 0) {
			report(op, "receive-fd", "sendmsg=failed", -1);
			break;
		}
		memset(&control, 0, sizeof(control));
		msg.msg_controllen = sizeof(control);
		msg.msg_flags = 0;
		rc = recvmsg(pair[1], &msg, 0);
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
				memcpy(&received, CMSG_DATA(cmsg), sizeof(int));
		snprintf(detail, sizeof(detail), "received=%s ctrunc=%d", received >= 0 ? "yes" : "no",
			 (msg.msg_flags & MSG_CTRUNC) != 0);
		report(op, "receive-fd", detail, rc);
		close(fd);
		close(pair[0]);
		close(pair[1]);
		if (received >= 0)
			close(received);
		break;
	}
	case 55: {
		// security.capability from a user namespace the process makes, then read from outside
		// it and removed from inside: what a share stores of it ("Phases", 2).
		unsigned char value[64];
		char read_outside[32];
		int set, removed;

		snprintf(capability_path, sizeof(capability_path), "%s/%s", dir, H("capf"));
		set = in_userns(capability_set_body, 0);
		if (getxattr(capability_path, "security.capability", value, sizeof(value)) >= 0)
			snprintf(read_outside, sizeof(read_outside), "present");
		else
			snprintf(read_outside, sizeof(read_outside), "%s", result(-1));
		removed = in_userns(capability_remove_body, 0);
		printf("op=%02d label=userns-security-capability set=%s read-outside=%s removed=%s\n", op,
		       userns_result(set), read_outside, userns_result(removed));
		break;
	}
	default:
		break;
	}
}

#define OP_COUNT 55

static void open_inventory_dir(const char *mode, int create)
{
	snprintf(dir, sizeof(dir), "%s/inv-%s", tree, mode);
	if (create && mkdir(dir, 0755) && errno != EEXIST)
		die("mkdir %s: %s", dir, strerror(errno));
	dirfd_ = open(dir, O_RDONLY | O_DIRECTORY);
	if (dirfd_ < 0)
		die("open %s: %s", dir, strerror(errno));
}

static int cmd_prepare(const char *mode)
{
	open_inventory_dir(mode, 1);
	for (int op = 1; op <= OP_COUNT; op++)
		prepare_op(op);
	printf("prepared dir=%s xattr=%d\n", dir, xattr_supported);
	return 0;
}

static const char *op_filter;   // `only=N,N` or `skip=N,N`, or NULL for every operation

static int op_selected(int op)
{
	char token[16], list[256];
	int only;

	if (!op_filter)
		return 1;
	only = !strncmp(op_filter, "only=", 5);
	if (!only && strncmp(op_filter, "skip=", 5))
		die("inventory: the filter is only=N,N or skip=N,N, not %s", op_filter);
	snprintf(token, sizeof(token), ",%d,", op);
	snprintf(list, sizeof(list), ",%s,", op_filter + 5);
	return (strstr(list, token) != NULL) == only;
}

static int cmd_inventory(const char *mode)
{
	open_inventory_dir(mode, 0);
	// `prepare` learned whether the share stores xattrs; the rows that need one re-check.
	xattr_supported = getxattr(path_of(helper(38, deny ? "deny-f" : "f")), "user.kab2", NULL, 0) >= 0;
	for (int op = 1; op <= OP_COUNT; op++)
		if (op_selected(op))
			run_op(op);
	return 0;
}

// ---------------------------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------------------------

static void tree_file(const char *rel, const char *content)
{
	char path[4096];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", tree, rel);
	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0)
		die("create %s: %s", path, strerror(errno));
	if (content && write(fd, content, strlen(content)) < 0)
		die("write %s: %s", path, strerror(errno));
	close(fd);
}

static void tree_dir(const char *rel)
{
	char path[4096], *slash;

	snprintf(path, sizeof(path), "%s/%s", tree, rel);
	for (slash = path + strlen(tree) + 1; *slash; slash++)
		if (*slash == '/') {
			*slash = 0;
			if (mkdir(path, 0755) && errno != EEXIST)
				die("mkdir %s: %s", path, strerror(errno));
			*slash = '/';
		}
	if (mkdir(path, 0755) && errno != EEXIST)
		die("mkdir %s: %s", path, strerror(errno));
}

static const char *deep_path(int depth)
{
	static char path[1024];
	size_t len = 0;

	for (int i = 0; i < depth; i++)
		len += snprintf(path + len, sizeof(path) - len, "%sd", i ? "/" : "");
	return path;
}

// The fixture: a workspace with a gitdir, a nested gitdir under modules, a module namespace, the
// launcher's directory, the defaults' names, a writable region, a session-made `.git`, and a
// chain deeper than the walk's bound.
static int cmd_make_tree(void)
{
	char deep[1100];

	if (mkdir(tree, 0755) && errno != EEXIST)
		die("mkdir %s: %s", tree, strerror(errno));
	tree_dir(".git/hooks");
	tree_dir(".git/objects/info");
	tree_dir(".git/objects/pack");
	tree_dir(".git/objects/x/.ko-agent-sandbox");
	tree_dir(".git/refs/heads");
	tree_dir(".git/rebase-merge");
	tree_dir(".git/modules/sub/refs/heads");
	tree_dir(".git/modules/sub/objects");
	tree_dir(".git/modules/sub/worktrees/wt");
	tree_dir(".git/worktrees/feature");
	tree_dir(".git/modules/other");
	tree_file(".git/HEAD", "ref: refs/heads/main\n");
	tree_file(".git/HEAD.lock", "ref: refs/heads/main\n");
	tree_file(".git/config", "[core]\n");
	tree_file(".git/hooks/pre-commit", "#!/bin/sh\n");
	tree_file(".git/refs/heads/main", "0000000000000000000000000000000000000000\n");
	tree_file(".git/modules/sub/HEAD", "ref: refs/heads/main\n");
	tree_file(".git/modules/sub/config", "[core]\n");
	tree_file(".git/modules/other/x", "");
	tree_dir(".ko-agent-sandbox/file");
	tree_file(".ko-agent-sandbox/file/rule", "");
	tree_dir(".vscode");
	tree_file(".vscode/tasks.json", "{}\n");
	tree_dir(".claude");
	tree_file(".claude/settings.json", "{}\n");
	tree_dir("node_modules/x/.vscode");
	tree_file("node_modules/x/.vscode/tasks.json", "{}\n");
	tree_dir("apps");
	tree_dir("sub/.git");
	tree_file("sub/.git/HEAD.lock", "ref: refs/heads/main\n");
	tree_file("README.md", "readme\n");
	tree_file("README2.md", "readme\n");
	snprintf(deep, sizeof(deep), "deep/%s", deep_path(70));
	tree_dir(deep);
	printf("made tree=%s\n", tree);
	return 0;
}

enum action { A_WRITE, A_CREAT, A_UNLINK, A_RENAME, A_MKDIR, A_MKFIFO, A_BIND, A_CHMOD, A_SYMLINK, A_LINK };

struct corpus_case {
	const char *label;
	enum action action;
	const char *a;
	const char *b;
	int expect_allow;
};

static const struct corpus_case corpus[] = {
	{"write-git-config", A_WRITE, ".git/config", NULL, 0},
	{"write-git-head", A_WRITE, ".git/HEAD", NULL, 1},
	{"creat-git-ref", A_CREAT, ".git/refs/heads/x", NULL, 1},
	{"creat-git-hook", A_CREAT, ".git/hooks/x", NULL, 0},
	{"creat-alternates", A_CREAT, ".git/objects/info/alternates", NULL, 0},
	{"creat-commit-graph", A_CREAT, ".git/objects/info/commit-graph", NULL, 1},
	{"creat-under-read-only-line", A_CREAT, ".vscode/tasks2.json", NULL, 0},
	{"creat-in-writable-region", A_CREAT, "node_modules/x/.vscode/t2.json", NULL, 1},
	{"creat-in-sandbox-config", A_CREAT, ".ko-agent-sandbox/file/x", NULL, 0},
	{"mkdir-dotgit", A_MKDIR, "sub2/.git", NULL, 1},
	{"creat-head-in-made-dotgit", A_CREAT, "sub/.git/HEAD", NULL, 0},
	{"rename-lock-onto-missing-head", A_RENAME, "sub/.git/HEAD.lock", "sub/.git/HEAD", 0},
	{"rename-lock-onto-head", A_RENAME, ".git/HEAD.lock", ".git/HEAD", 1},
	// Under a directory without a `.git`: a case-insensitive host answers the spelling of an
	// existing name with EEXIST before any hook.
	{"creat-dotgit-folded-case", A_CREAT, "apps/.GiT", NULL, 0},
	// U+200B inside the name, ignorable; U+0131, dotless i, folded to `i`.
	{"creat-dotgit-ignorable", A_CREAT, "apps/.g\xe2\x80\x8bit", NULL, 0},
	{"creat-dotgit-folded-letter", A_CREAT, "apps/.g\xc4\xb1t", NULL, 0},
	{"creat-dotgit-trailing-dot", A_CREAT, "sub/.git.", NULL, 0},
	{"creat-dotgitx", A_CREAT, "sub/.gitx", NULL, 1},
	{"creat-sandbox-name", A_CREAT, "sub/.ko-agent-sandbox", NULL, 0},
	{"write-readme", A_WRITE, "README.md", NULL, 1},
	{"creat-beyond-walk-bound", A_CREAT, "deep/DEEP70/f", NULL, 0},
	{"creat-at-depth-60", A_CREAT, "deep/DEEP58/f", NULL, 1},
	{"bind-socket", A_BIND, "sub/s", NULL, 0},
	{"mkfifo", A_MKFIFO, "sub/fifo", NULL, 1},
	{"creat-nested-gitdir-protected", A_CREAT, ".git/modules/sub/config2", NULL, 0},
	{"creat-nested-gitdir-ref", A_CREAT, ".git/modules/sub/refs/heads/x", NULL, 1},
	// A linked worktree's gitdir re-roots the classification at its name (policy.rs,
	// child_context): HEAD there is operational, the redirection files are protected.
	{"creat-worktree-head", A_CREAT, ".git/worktrees/feature/HEAD", NULL, 1},
	{"creat-worktree-gitdir-file", A_CREAT, ".git/worktrees/feature/gitdir", NULL, 0},
	{"creat-nested-gitdir-worktree-head", A_CREAT, ".git/modules/sub/worktrees/wt/HEAD", NULL, 1},
	{"creat-in-module-namespace", A_CREAT, ".git/modules/other/y", NULL, 0},
	{"creat-sandbox-in-git-state", A_CREAT, ".git/objects/x/.ko-agent-sandbox/f", NULL, 0},
	{"creat-pattern-name", A_CREAT, "sub/lefthook.yml", NULL, 0},
	{"write-claude-settings", A_WRITE, ".claude/settings.json", NULL, 0},
	{"creat-beside-claude-settings", A_CREAT, ".claude/notes.md", NULL, 1},
	{"chmod-git-config", A_CHMOD, ".git/config", NULL, 0},
	{"chmod-readme", A_CHMOD, "README.md", NULL, 1},
	{"symlink-in-hooks", A_SYMLINK, ".git/hooks/y", NULL, 0},
	{"link-into-hooks", A_LINK, "README.md", ".git/hooks/z", 0},
	{"link-from-config", A_LINK, ".git/config", "sub/cfg", 0},
	{"unlink-readme2", A_UNLINK, "README2.md", NULL, 1},
	{"creat-index-lock", A_CREAT, ".git/index.lock", NULL, 1},
	{"creat-config-lock", A_CREAT, ".git/config.lock", NULL, 0},
	{"creat-rebase-todo", A_CREAT, ".git/rebase-merge/todo", NULL, 0},
	{"rename-ref", A_RENAME, ".git/refs/heads/main", ".git/refs/heads/renamed", 1},
	{"creat-pack", A_CREAT, ".git/objects/pack/p.pack", NULL, 1},
	{"mkfifo-in-objects", A_MKFIFO, ".git/objects/pack/fifo", NULL, 1},
	// Last, the cases whose success, when the program lets them through, takes away what the cases
	// above act on.
	{"rename-dir-out-of-region", A_RENAME, "node_modules/x", "apps/x", 0},
	{"rename-pinned-component", A_RENAME, ".claude", "saved", 0},
	{"unlink-hook", A_UNLINK, ".git/hooks/pre-commit", NULL, 0},
	{"rename-hooks-dir", A_RENAME, ".git/hooks", ".git/hooks2", 0},
	{"rename-git-objects", A_RENAME, ".git/objects", ".git/objects2", 0},
};
#define CORPUS (sizeof(corpus) / sizeof(corpus[0]))

static const char *tree_path(const char *rel)
{
	static char path[2][8192];
	static int slot;
	char *out = path[slot++ & 1];
	const char *deep = strstr(rel, "DEEP");

	if (deep) {
		int depth = atoi(deep + 4);
		const char *rest = deep + 4;

		while (*rest >= '0' && *rest <= '9')
			rest++;
		snprintf(out, 8192, "%s/%.*s%s%s", tree, (int)(deep - rel), rel, deep_path(depth), rest);
	} else {
		snprintf(out, 8192, "%s/%s", tree, rel);
	}
	return out;
}

static int run_case(const struct corpus_case *item)
{
	int rc = -1, fd;

	switch (item->action) {
	case A_WRITE:
		fd = open(tree_path(item->a), O_WRONLY);
		rc = fd;
		if (fd >= 0)
			close(fd);
		break;
	case A_CREAT:
		fd = open(tree_path(item->a), O_CREAT | O_WRONLY | O_EXCL, 0644);
		rc = fd;
		if (fd >= 0)
			close(fd);
		break;
	case A_UNLINK:
		rc = unlink(tree_path(item->a));
		break;
	case A_RENAME:
		rc = rename(tree_path(item->a), tree_path(item->b));
		break;
	case A_MKDIR: {
		const char *path = tree_path(item->a);
		char parent[8192];
		char *slash;

		snprintf(parent, sizeof(parent), "%s", path);
		slash = strrchr(parent, '/');
		if (slash)
			*slash = 0;
		mkdir(parent, 0755);
		rc = mkdir(path, 0755);
		break;
	}
	case A_MKFIFO:
		rc = mknod(tree_path(item->a), S_IFIFO | 0644, 0);
		break;
	case A_BIND: {
		struct sockaddr_un addr = {.sun_family = AF_UNIX};
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		char cwd[4096], sub[8192];
		int saved;

		snprintf(sub, sizeof(sub), "%s/sub", tree);
		if (sock < 0 || !getcwd(cwd, sizeof(cwd)) || chdir(sub))
			break;
		snprintf(addr.sun_path, sizeof(addr.sun_path), "s");
		rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
		saved = errno;
		if (chdir(cwd))
			die("chdir: %s", strerror(errno));
		close(sock);
		errno = saved;
		break;
	}
	case A_CHMOD:
		rc = chmod(tree_path(item->a), 0644);
		break;
	case A_SYMLINK:
		rc = symlink("target", tree_path(item->a));
		break;
	case A_LINK:
		rc = link(tree_path(item->a), tree_path(item->b));
		break;
	}
	return rc;
}

// EACCES or EOPNOTSUPP on a FIFO case is the share's answer (virtiofs refuses a FIFO with EACCES,
// 9p with EOPNOTSUPP), counted as unsupported apart from the mismatches; any other failure but
// EPERM is a mismatch, since the program answers EPERM alone and the fixture is laid out so that
// no case meets a prior object (a case-insensitive host would answer a folded spelling of an
// existing name with EEXIST).
static int cmd_corpus(void)
{
	int unsupported = 0;

	for (size_t i = 0; i < CORPUS; i++) {
		const struct corpus_case *item = &corpus[i];
		int rc = run_case(item);
		int err = errno;
		int allowed = rc >= 0;
		int decided = allowed || err == EPERM;
		int unsupported_here = !decided && item->action == A_MKFIFO && (err == EACCES || err == EOPNOTSUPP);
		const char *got = allowed ? "allow" : err == EPERM ? "deny" : "error";
		int match = decided && allowed == item->expect_allow;
		const char *verdict = match ? "MATCH" : unsupported_here ? "UNSUPPORTED" : "MISMATCH";

		printf("case=%s expect=%s got=%s%s%s %s\n", item->label, item->expect_allow ? "allow" : "deny", got,
		       allowed ? "" : ":", allowed ? "" : (errno = err, result(-1)), verdict);
		if (unsupported_here)
			unsupported++;
		else if (!match)
			mismatches++;
	}
	printf("corpus cases=%zu mismatches=%d unsupported=%d\n", CORPUS, mismatches, unsupported);
	return mismatches ? 1 : 0;
}

// ---------------------------------------------------------------------------------------------
// The walk's cost
// ---------------------------------------------------------------------------------------------

static long ns_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static int cmd_walk_cost(const char *path, int count)
{
	long start, rdwr, rdonly, lstat_ns;
	struct stat st;
	int failed = 0;

	start = ns_now();
	for (int i = 0; i < count; i++) {
		int fd = open(path, O_RDWR);

		if (fd < 0)
			failed++;
		else
			close(fd);
	}
	rdwr = (ns_now() - start) / count;
	start = ns_now();
	for (int i = 0; i < count; i++) {
		int fd = open(path, O_RDONLY);

		if (fd < 0)
			failed++;
		else
			close(fd);
	}
	rdonly = (ns_now() - start) / count;
	start = ns_now();
	for (int i = 0; i < count; i++)
		if (lstat(path, &st))
			failed++;
	lstat_ns = (ns_now() - start) / count;
	printf("walk-cost path=%s n=%d open_rdwr_ns=%ld open_rdonly_ns=%ld lstat_ns=%ld failed=%d\n", path, count,
	       rdwr, rdonly, lstat_ns, failed);
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 3)
		die("usage: see the header of mutate.c");
	tree = argv[2];
	if (!strcmp(argv[1], "prepare") && argc == 4) {
		deny = !strcmp(argv[3], "deny");
		return cmd_prepare(argv[3]);
	}
	if (!strcmp(argv[1], "inventory") && (argc == 4 || argc == 5)) {
		deny = !strcmp(argv[3], "deny");
		op_filter = argc == 5 ? argv[4] : NULL;
		return cmd_inventory(argv[3]);
	}
	if (!strcmp(argv[1], "make-tree") && argc == 3)
		return cmd_make_tree();
	if (!strcmp(argv[1], "corpus") && argc == 3)
		return cmd_corpus();
	if (!strcmp(argv[1], "walk-cost") && argc == 4)
		return cmd_walk_cost(argv[2], atoi(argv[3]));
	die("unknown subcommand %s", argv[1]);
}
