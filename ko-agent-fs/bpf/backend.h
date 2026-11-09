// The BPF cgroup-LSM backend of ko-agent-fs/bpf/doc/architecture.md: what the controller, the
// read-back and the fixture share. That is the formats, and the readings each side takes for itself.
//
// - policy.bpf.c takes the records' layout from records.h, as this file does, and defines the other
//   map values the controller fills itself: struct ident, root and policy_config. Those layouts here
//   must equal the program's, and the read-back compares the kernel's map info with this table.
// - No action of the controller's is here: the read-back learns what is attached from the kernel
//   alone. loader.h holds what the programs that call libbpf share.
// - The launcher installs the three binaries built from this directory (Containerfile) into the
//   podman machine (KoAgentBpf.scala). The policy, lifecycle and benchmark suites build the same
//   sources (their sources.txt).
#ifndef BACKEND_H
#define BACKEND_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/openat2.h>
#include <linux/types.h>

#include "records.h"

// Debian trixie's libelf-dev ships libelf.a without libeu.a, but libelf.a calls four tree helpers
// from libeu.a (elfutils, lib/eu-search.c). These stand in for them in the static link of the binaries
// that link libelf; the others compile them unused. Each binary is single-threaded, so the lock the
// originals take is left out.
#include <search.h>
struct eu_search_tree {
	void *root;
};

void *eu_tsearch(const void *key, struct eu_search_tree *tree, int (*compare)(const void *, const void *))
{
	return tsearch(key, &tree->root, compare);
}

void *eu_tfind(const void *key, struct eu_search_tree *tree, int (*compare)(const void *, const void *))
{
	return tfind(key, &tree->root, compare);
}

void *eu_tdelete(const void *key, struct eu_search_tree *tree, int (*compare)(const void *, const void *))
{
	return tdelete(key, &tree->root, compare);
}

void eu_search_tree_init(struct eu_search_tree *tree)
{
	tree->root = NULL;
}

void eu_search_tree_fini(struct eu_search_tree *tree, void (*free_fn)(void *))
{
	tdestroy(tree->root, free_fn);
	tree->root = NULL;
}

#define FS_TYPE_BYTES 16
#define FLAG_SHORT_NAMES 1u
#define FLAG_UNIX_SOCKETS 2u
#define SCRATCH_SLOTS 4
#define PIN_FS "/sys/fs/bpf"

struct ident {
	__u64 s_dev;
	__u64 i_ino;
};

struct root {
	__u32 kind;
	__u32 pad;
};

struct policy_config {
	__u32 rule_count;
	__u32 flags;
	char fs_type[FS_TYPE_BYTES];
	char vol_fs_type[FS_TYPE_BYTES];
	__u32 runtime_mnt_ns;
	__u32 pad;
	struct ident host_root;
};

// The policy's hooks in the program's enum order; the stats map has one entry per hook.
static const char *const policy_hooks[] = {
	"file_open", "inode_create", "inode_mknod", "inode_symlink", "inode_link", "inode_rename", "inode_unlink",
	"inode_setattr", "file_receive",
};
#define POLICY_HOOKS (sizeof(policy_hooks) / sizeof(policy_hooks[0]))

static const char *const root_kinds[] = {"none", "workspace", "gitdir", "volume", "guarded-git", "guarded-sandbox"};
#define ROOT_KINDS (sizeof(root_kinds) / sizeof(root_kinds[0]))

// The program's maps: name, type, key and value sizes, entries, and whether the map holds the
// session's records (the controller freezes those once filled). A value size of 0 marks the
// program's own scratch, which is not compared. The object also has one read-only map for its
// string literals.
struct map_shape {
	const char *name;
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	bool records;
};
static const struct map_shape policy_maps[] = {
	{"roots", BPF_MAP_TYPE_HASH, sizeof(struct ident), sizeof(struct root), ROOTS, true},
	{"rules", BPF_MAP_TYPE_ARRAY, 4, sizeof(struct rule_line), RULE_LINES, true},
	{"aliases", BPF_MAP_TYPE_ARRAY, 4, sizeof(struct alias_context), ALIASES, true},
	{"policy_config", BPF_MAP_TYPE_ARRAY, 4, sizeof(struct policy_config), 1, true},
	{"scratch", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 0, SCRATCH_SLOTS, false},
	{"guard", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 1, false},
	{"stats", BPF_MAP_TYPE_ARRAY, 4, 0, POLICY_HOOKS, false},
	{"last_decision", BPF_MAP_TYPE_ARRAY, 4, 0, 1, false},
};
#define POLICY_MAPS (sizeof(policy_maps) / sizeof(policy_maps[0]))

__attribute__((noreturn, format(printf, 1, 2))) static inline void die(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "%s: ", PROGRAM_NAME);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(2);
}

// snprintf that ends the run where the text does not fit `size`: a path cut to fit names another file,
// which the controller would pin, open or record as a root. A path buffer is PATH_MAX, 4096 bytes: the
// kernel refuses a path argument of 4096 bytes or more with ENAMETOOLONG, so a larger buffer would only
// move the failure to the syscall.
__attribute__((format(printf, 3, 4))) static inline void format_or_die(char *out, size_t size, const char *format,
								 ...)
{
	va_list args;
	int len;

	va_start(args, format);
	len = vsnprintf(out, size, format, args);
	va_end(args);
	if (len < 0 || (size_t)len >= size)
		die("%d bytes do not fit in %zu: %s...", len, size, out);
}

// A refusal of the launch, kept distinct from a failure. The launcher prints the reason and binds
// nothing writable.
__attribute__((noreturn, format(printf, 2, 3))) static inline void refuse(const char *reason, const char *format,
									   ...)
{
	va_list args;

	printf("refused reason=%s ", reason);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
	exit(3);
}

static inline double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

// What the controller records for a root: statx's major, minor and inode number, with the device
// laid out as the kernel's MKDEV lays out s_dev ("The policy").
static inline void ident_of(const char *path, struct ident *id)
{
	struct statx stx;

	if (statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_INO, &stx))
		die("statx %s: %s", path, strerror(errno));
	id->s_dev = ((__u64)stx.stx_dev_major << 20) | stx.stx_dev_minor;
	id->i_ino = stx.stx_ino;
}

static inline bool same_ident(const struct ident *a, const struct ident *b)
{
	return a->s_dev == b->s_dev && a->i_ino == b->i_ino;
}

// A mount namespace's inode number, as /proc/PID/ns/mnt names it: `mnt:[4026531841]`.
static inline __u32 mnt_ns_inum(const char *pid)
{
	char path[64], link[64];
	ssize_t len;
	unsigned long inum;

	format_or_die(path, sizeof(path), "/proc/%s/ns/mnt", pid);
	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0)
		die("readlink %s: %s", path, strerror(errno));
	link[len] = 0;
	if (sscanf(link, "mnt:[%lu]", &inum) != 1)
		die("%s: unexpected %s", path, link);
	return inum;
}

// --- Mounts ----------------------------------------------------------------------------------

struct mount_entry {
	char mountpoint[PATH_MAX];
	char fstype[64];
};

// /proc/self/mountinfo unescapes its octal escapes (`\040` for a space in a mountpoint).
static inline void unescape(char *text)
{
	char *out = text;

	for (char *in = text; *in; in++) {
		if (*in == '\\' && in[1] >= '0' && in[1] <= '7' && in[2] >= '0' && in[2] <= '7' && in[3] >= '0' &&
		    in[3] <= '7') {
			*out++ = (in[1] - '0') * 64 + (in[2] - '0') * 8 + (in[3] - '0');
			in += 3;
		} else {
			*out++ = *in;
		}
	}
	*out = 0;
}

// The mounts of this process's namespace, read once.
static inline int read_mounts(struct mount_entry **out)
{
	static struct mount_entry *mounts;
	static int count = -1;
	FILE *file;
	char *line = NULL;
	size_t capacity = 0;

	if (count >= 0) {
		*out = mounts;
		return count;
	}
	file = fopen("/proc/self/mountinfo", "r");
	if (!file)
		die("open /proc/self/mountinfo: %s", strerror(errno));
	count = 0;
	// getline reads each line whole: a mountpoint escaped to four bytes per character outgrows any fixed
	// line, and a cut line would be read as a mount of its own.
	while (getline(&line, &capacity, file) >= 0) {
		char *save = NULL, *field, *dash;
		int index = 0;
		struct mount_entry entry = {};

		dash = strstr(line, " - ");
		if (!dash)
			continue;
		*dash = 0;
		for (field = strtok_r(line, " ", &save); field; field = strtok_r(NULL, " ", &save), index++)
			if (index == 4) {
				unescape(field);
				format_or_die(entry.mountpoint, sizeof(entry.mountpoint), "%s", field);
			}
		save = NULL;
		field = strtok_r(dash + 3, " ", &save);
		if (!field || !entry.mountpoint[0])
			continue;
		format_or_die(entry.fstype, sizeof(entry.fstype), "%s", field);
		mounts = realloc(mounts, (count + 1) * sizeof(*mounts));
		if (!mounts)
			die("out of memory");
		mounts[count++] = entry;
	}
	free(line);
	fclose(file);
	*out = mounts;
	return count;
}

// Whether `path` is `prefix` or lies below it, by components.
static inline bool is_beneath(const char *prefix, const char *path)
{
	size_t len = strlen(prefix);

	if (!strcmp(prefix, "/"))
		return path[0] == '/';
	return !strncmp(prefix, path, len) && (path[len] == 0 || path[len] == '/');
}

// The type of the filesystem holding `path`: the mount with the longest mountpoint above it.
static inline void fs_type_of(const char *path, char *out, size_t size)
{
	struct mount_entry *mounts;
	int count = read_mounts(&mounts), best = -1;
	size_t best_len = 0;
	char resolved[PATH_MAX];

	if (!realpath(path, resolved))
		die("realpath %s: %s", path, strerror(errno));
	for (int i = 0; i < count; i++)
		if (is_beneath(mounts[i].mountpoint, resolved) && strlen(mounts[i].mountpoint) >= best_len) {
			best = i;
			best_len = strlen(mounts[i].mountpoint);
		}
	if (best < 0)
		die("no mount holds %s", path);
	if (strlen(mounts[best].fstype) >= size)
		die("filesystem type %s is longer than %zu bytes", mounts[best].fstype, size - 1);
	strcpy(out, mounts[best].fstype);
}

// The mountpoints strictly below `path`; `first` receives one of them.
static inline int mounts_below(const char *path, char *first, size_t size)
{
	struct mount_entry *mounts;
	int count = read_mounts(&mounts), below = 0;
	char resolved[PATH_MAX];

	if (!realpath(path, resolved))
		die("realpath %s: %s", path, strerror(errno));
	for (int i = 0; i < count; i++)
		if (strcmp(mounts[i].mountpoint, resolved) && is_beneath(resolved, mounts[i].mountpoint)) {
			if (!below)
				format_or_die(first, size, "%s", mounts[i].mountpoint);
			below++;
		}
	return below;
}

// --- Paths the controller and the read-back open ----------------------------------------------

// Whether `rel` is a non-empty relative path of plain components: no leading `/`, and no empty, `.` or
// `..` component.
static inline bool plain_relative(const char *rel)
{
	if (!*rel)
		return false;
	for (const char *at = rel; *at;) {
		const char *end = strchr(at, '/');
		size_t clen = end ? (size_t)(end - at) : strlen(at);

		if (clen == 0 || (clen == 1 && at[0] == '.') || (clen == 2 && at[0] == '.' && at[1] == '.'))
			return false;
		at += clen + (end ? 1 : 0);
	}
	return true;
}

// `path` below `root` as a relative path. NULL when it is not below `root`, or not plain_relative.
static const char *relative_beneath(const char *root, const char *path)
{
	size_t len = strlen(root);

	if (strncmp(root, path, len) || path[len] != '/' || !plain_relative(path + len + 1))
		return NULL;
	return path + len + 1;
}

// Opens `rel` below `root_fd` without following a symlink, crossing a mount or climbing above
// `root_fd`. A symlink in place of a directory fails with ELOOP, a mount on one with EXDEV, and a `..`
// that climbs out with EXDEV too. With O_PATH | O_NOFOLLOW, a symlink as the last component opens as
// itself.
static inline int open_beneath(int root_fd, const char *rel, int flags)
{
	struct open_how how = {
		.flags = flags,
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS,
	};

	return syscall(SYS_openat2, root_fd, rel, &how, sizeof(how));
}

// The invoking user's slice, from SUDO_UID. It is the only place where the controller attaches
// and the reconcile removes ("Native Linux").
static const char *slice_root(void)
{
	static char root[PATH_MAX];
	const char *uid = getenv("SUDO_UID");

	if (!uid || !*uid)
		die("SUDO_UID is unset: run under sudo");
	// A value such as `0.slice/..` would move the root, and the reconcile removes cgroups below it.
	if (strspn(uid, "0123456789") != strlen(uid))
		die("SUDO_UID is not a number: %s", uid);
	format_or_die(root, sizeof(root), "/sys/fs/cgroup/user.slice/user-%s.slice", uid);
	return root;
}

// bpffs refuses a name containing a `.` with EPERM at the lookup, since it reserves such names for
// its own special files (kernel/bpf/inode.c, bpf_lookup). So a pin path below the mount must not
// contain one.
static inline void require_pin_dir(const char *pindir)
{
	const char *rel = relative_beneath(PIN_FS, pindir);

	if (!rel)
		refuse("pindir-outside-bpffs", "pindir=%s", pindir);
	if (strchr(rel, '.'))
		refuse("pindir-dotted", "pindir=%s", pindir);
}

// Opens an attach cgroup below the user's slice, refusing any other.
static inline int open_cgroup(const char *path)
{
	const char *root = slice_root();
	const char *rel = relative_beneath(root, path);
	int root_fd, fd;

	if (!rel)
		refuse("cgroup-outside-slice", "cgroup=%s slice=%s", path, root);
	root_fd = open(root, O_RDONLY | O_DIRECTORY);
	if (root_fd < 0)
		die("open %s: %s", root, strerror(errno));
	fd = open_beneath(root_fd, rel, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		refuse("cgroup-open", "cgroup=%s error=%s", path, strerror(errno));
	close(root_fd);
	return fd;
}

// --- The guard's records, and the policy they expect in the maps -------------------------------

struct records {
	struct records_header header;
	struct rule_line rules[RULE_LINES];
	struct alias_context aliases[ALIASES];
	struct guarded_path guarded[ROOTS];
};

static inline void read_records(const char *path, struct records *out)
{
	FILE *file = fopen(path, "rb");

	memset(out, 0, sizeof(*out));
	if (!file)
		die("open %s: %s", path, strerror(errno));
	if (fread(&out->header, sizeof(out->header), 1, file) != 1 || memcmp(out->header.magic, RECORDS_MAGIC, 8))
		die("%s: not a records file", path);
	if (out->header.layout != RECORDS_LAYOUT)
		die("%s: layout %08x, this build reads %08x", path, out->header.layout, RECORDS_LAYOUT);
	if (out->header.rule_count > RULE_LINES || out->header.alias_count > ALIASES ||
	    out->header.root_count > GUARDED_PATHS)
		die("%s: counts %u/%u/%u exceed the policy's bounds", path, out->header.rule_count,
		    out->header.alias_count, out->header.root_count);
	if (fread(out->rules, sizeof(struct rule_line), out->header.rule_count, file) != out->header.rule_count ||
	    fread(out->aliases, sizeof(struct alias_context), out->header.alias_count, file) !=
		    out->header.alias_count ||
	    fread(out->guarded, sizeof(struct guarded_path), out->header.root_count, file) != out->header.root_count ||
	    fgetc(file) != EOF)
		die("%s: its size does not match its counts", path);
	fclose(file);
	// The volume's root is the controller's own (`--volume`), never a record's. A path is the
	// workspace root itself, or plain components below it.
	for (__u32 i = 0; i < out->header.root_count; i++)
		if (out->guarded[i].len >= PATH_BYTES || out->guarded[i].path[out->guarded[i].len] != 0 ||
		    out->guarded[i].kind == 0 || out->guarded[i].kind >= ROOT_KINDS ||
		    out->guarded[i].kind == ROOT_VOLUME ||
		    (out->guarded[i].len && !plain_relative(out->guarded[i].path)))
			die("%s: guarded path %u is malformed", path, i);
}

// The policy a launch loads: the records, the roots by identity and the configuration. Each caller
// reads them for itself.
//
// - The fixture root is a second workspace root ("Lifecycle", 3). It must be on the workspace's
//   filesystem type, or every refusal expected there would fail.
// - `no_root` is a `--workspace=read-only` session's policy ("The policy"). The share's type and
//   the volume's root are recorded, but no workspace, gitdir or fixture root, so every mutation on
//   the share's type is refused. `records` may then be NULL.
struct policy {
	struct records rec;
	struct ident idents[ROOTS];
	struct root roots[ROOTS];
	char root_paths[ROOTS][PATH_MAX];
	int root_count;
	struct policy_config cfg;
};

// Records a root whose identity is in `policy->idents[policy->root_count]` already.
static inline void add_root_ident(struct policy *policy, __u32 kind, const char *path)
{
	int index = policy->root_count;

	for (int i = 0; i < index; i++)
		if (same_ident(&policy->idents[i], &policy->idents[index]))
			die("two roots share an identity: %s and %s", policy->root_paths[i], path);
	policy->roots[index].kind = kind;
	format_or_die(policy->root_paths[index], PATH_MAX, "%s", path);
	policy->root_count++;
}

// A root the launcher names by path: the fixture's or the volume's.
static inline void add_root(struct policy *policy, __u32 kind, const char *path)
{
	if (policy->root_count >= ROOTS)
		die("more than %d roots", ROOTS);
	ident_of(path, &policy->idents[policy->root_count]);
	add_root_ident(policy, kind, path);
}

// A guarded object of the records, resolved below the workspace's descriptor rather than by path: the
// workspace is shared live, and a directory swapped for a symlink between the guard's resolve and this
// one would otherwise record another object's identity. Any symlink or mount on the way refuses the
// launch; the last component is taken as itself, as statx's AT_SYMLINK_NOFOLLOW takes it.
static inline void add_guarded_root(struct policy *policy, int workspace_fd, const char *workspace,
				    const struct guarded_path *guarded)
{
	struct statx stx;
	char path[PATH_MAX];
	int fd = workspace_fd;

	if (policy->root_count >= ROOTS)
		die("more than %d roots", ROOTS);
	format_or_die(path, sizeof(path), "%s%s%s", workspace, guarded->len ? "/" : "", guarded->path);
	if (guarded->len) {
		fd = open_beneath(workspace_fd, guarded->path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0)
			refuse("guarded-path", "path=%s error=%s", path, strerror(errno));
	}
	if (statx(fd, "", AT_EMPTY_PATH, STATX_INO, &stx))
		die("statx %s: %s", path, strerror(errno));
	if (fd != workspace_fd)
		close(fd);
	policy->idents[policy->root_count].s_dev = ((__u64)stx.stx_dev_major << 20) | stx.stx_dev_minor;
	policy->idents[policy->root_count].i_ino = stx.stx_ino;
	add_root_ident(policy, guarded->kind, path);
}

static inline void expect_policy(struct policy *policy, const char *records, const char *workspace, const char *fixture,
			  const char *volume, __u32 flags, bool no_root)
{
	memset(policy, 0, sizeof(*policy));
	if (records)
		read_records(records, &policy->rec);
	else if (!no_root)
		die("a policy with roots needs the records file");
	if (!no_root && policy->rec.header.root_count) {
		int workspace_fd = open(workspace, O_PATH | O_DIRECTORY | O_CLOEXEC);

		if (workspace_fd < 0)
			die("open %s: %s", workspace, strerror(errno));
		for (__u32 i = 0; i < policy->rec.header.root_count; i++)
			add_guarded_root(policy, workspace_fd, workspace, &policy->rec.guarded[i]);
		close(workspace_fd);
	}
	fs_type_of(workspace, policy->cfg.fs_type, sizeof(policy->cfg.fs_type));
	if (fixture) {
		char type[FS_TYPE_BYTES];

		fs_type_of(fixture, type, sizeof(type));
		if (strcmp(type, policy->cfg.fs_type))
			refuse("fixture-fs-type", "fixture=%s type=%s workspace_type=%s", fixture, type,
			       policy->cfg.fs_type);
		if (!no_root)
			add_root(policy, ROOT_WORKSPACE, fixture);
	}
	if (volume) {
		fs_type_of(volume, policy->cfg.vol_fs_type, sizeof(policy->cfg.vol_fs_type));
		add_root(policy, ROOT_VOLUME, volume);
	}
	policy->cfg.rule_count = no_root ? 0 : policy->rec.header.rule_count;
	policy->cfg.flags = flags;
	// The runtime's mount namespace is the controller's own ("Policy on WSL"): podman and the
	// runtime run in the same place where the launcher runs the controller and the read-back.
	policy->cfg.runtime_mnt_ns = mnt_ns_inum("self");
	ident_of("/", &policy->cfg.host_root);
}

static inline __u32 parse_flags(const char *text)
{
	char copy[256], *save = NULL, *token;
	__u32 flags = 0;

	format_or_die(copy, sizeof(copy), "%s", text);
	for (token = strtok_r(copy, ",", &save); token; token = strtok_r(NULL, ",", &save)) {
		if (!strcmp(token, "short-names"))
			flags |= FLAG_SHORT_NAMES;
		else if (!strcmp(token, "unix-socket"))
			flags |= FLAG_UNIX_SOCKETS;
		else
			die("--flags: unknown flag %s", token);
	}
	return flags;
}

// The expectation shared by the controller's attach and the read-back's verify and check-pins: the
// options after the positional operands, then the hooks. `--no-root` marks the read-only session's.
struct expectation {
	const char *tags_path;
	const char *records;
	const char *workspace;
	const char *fixture;
	const char *volume;
	const char *object;
	const char *bind_source;
	const char *preloaded;
	__u32 flags;
	bool no_root;
	const char **hooks;
	int hook_count;
};

static inline int hook_index(const char *name);

static inline void parse_expectation(int argc, char **argv, struct expectation *exp, const char *usage)
{
	int first = 0;

	memset(exp, 0, sizeof(*exp));
	exp->object = "policy.bpf.o";
	while (first < argc && argv[first][0] == '-') {
		const char *option = argv[first++];

		if (!strcmp(option, "--no-root")) {
			exp->no_root = true;
			continue;
		}
		if (first >= argc)
			die("%s: %s takes a value", usage, option);
		if (!strcmp(option, "--tags"))
			exp->tags_path = argv[first++];
		else if (!strcmp(option, "--records"))
			exp->records = argv[first++];
		else if (!strcmp(option, "--workspace"))
			exp->workspace = argv[first++];
		else if (!strcmp(option, "--fixture"))
			exp->fixture = argv[first++];
		else if (!strcmp(option, "--volume"))
			exp->volume = argv[first++];
		else if (!strcmp(option, "--flags"))
			exp->flags = parse_flags(argv[first++]);
		else if (!strcmp(option, "--object"))
			exp->object = argv[first++];
		else if (!strcmp(option, "--bind-source"))
			exp->bind_source = argv[first++];
		else if (!strcmp(option, "--preloaded"))
			exp->preloaded = argv[first++];
		else
			die("%s: unknown option %s", usage, option);
	}
	if (first >= argc)
		die("%s: no hook named", usage);
	exp->hooks = (const char **)argv + first;
	exp->hook_count = argc - first;
	// The callers size their arrays by the hook table, and a hook named twice would attach twice.
	if (exp->hook_count > (int)POLICY_HOOKS)
		die("%s: %d hooks named, the policy has %zu", usage, exp->hook_count, POLICY_HOOKS);
	for (int i = 0; i < exp->hook_count; i++) {
		hook_index(exp->hooks[i]);
		for (int k = 0; k < i; k++)
			if (!strcmp(exp->hooks[k], exp->hooks[i]))
				die("%s: hook %s named twice", usage, exp->hooks[i]);
	}
}

static inline int hook_index(const char *name)
{
	for (unsigned i = 0; i < POLICY_HOOKS; i++)
		if (!strcmp(policy_hooks[i], name))
			return i;
	die("no hook %s in the policy", name);
}

static inline void print_tag(const __u8 *tag)
{
	for (int i = 0; i < BPF_TAG_SIZE; i++)
		printf("%02x", tag[i]);
}

#endif
