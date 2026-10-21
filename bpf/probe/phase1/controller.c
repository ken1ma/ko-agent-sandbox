// Phase 1 of doc/plan-bpf-lsm-cgroup.md: the privileged side of the probe. It loads
// lsm_probe.bpf.o, installed beside this binary, attaches its programs to a cgroup by link, pins
// the links, and reads back what the kernel holds; phase1.sh drives it through `podman machine
// ssh` under sudo. Each subcommand prints lines phase1.sh greps, `key=value` on one line.
//
//   controller load                      verify every program one at a time and all together, timed
//   controller attach CGROUP PINDIR [--keep-going] [--fail-after-attach] PROG...
//                                        attach PROG... to CGROUP, pin each link at PINDIR/PROG;
//                                        --fail-after-attach then exits 1, as a failed read-back would
//   controller query CGROUP              the programs attached to CGROUP, and every lsm_cgroup link
//   controller link-info PIN             a pinned link's id, program and cgroup id (0 once detached)
//   controller last-open PIN             the identity file_open recorded, read through PIN's program
//   controller stats PIN                 the per-hook counters, read through PIN's program
//   controller jited PIN OUT             PIN's program as jited bytes into OUT, with a barrier scan
//   controller statx PATH                PATH's identity as the plan's controller records it
//   controller unpin PINDIR              remove every pin under PINDIR
//
// The object is found beside the binary (/proc/self/exe) and never taken as an argument, as the
// plan's controller does ("Native Linux").
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#define OBJECT_NAME "lsm_probe.bpf.o"
#define LOG_BYTES (16u << 20)

// Debian trixie's libelf-dev 0.192-4 ships libelf.a without libeu.a, whose four tree helpers
// libelf.a calls (elfutils, lib/eu-search.c). These stand in for a static link; the controller is
// single-threaded, so the lock the originals take is left out, and only the tree's root, the
// struct's first member, is touched.
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

// Must match lsm_probe.bpf.c.
struct hook_stats {
	__u64 calls;
	__u64 walks;
	__u64 retries;
	__u64 gave_up;
	__u64 max_depth;
	__u64 barrier_sum;
};

struct last_open {
	__u64 s_dev;
	__u64 i_ino;
	__u64 count;
	__u32 f_mode;
	__u32 denied;
	__u32 depth;
	__u32 seq;
	char fs_type[16];
};

static const char *const hook_names[] = {
	"file_open", "inode_create", "inode_mknod", "inode_symlink", "inode_link", "inode_rename",
	"inode_unlink", "inode_setattr", "file_receive", "inode_mkdir", "inode_rmdir",
};
#define HOOK_COUNT (sizeof(hook_names) / sizeof(hook_names[0]))

static void die(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "controller: ");
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(1);
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void object_path(char *out, size_t size)
{
	char exe[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

	if (len < 0)
		die("readlink /proc/self/exe: %s", strerror(errno));
	exe[len] = 0;
	snprintf(out, size, "%s/%s", dirname(exe), OBJECT_NAME);
}

static struct bpf_object *open_object(void)
{
	char path[PATH_MAX];
	struct bpf_object *obj;

	object_path(path, sizeof(path));
	obj = bpf_object__open_file(path, NULL);
	if (!obj)
		die("open %s: %s", path, strerror(errno));
	return obj;
}

// The verifier's stats line is its last line at log level 4 (BPF_LOG_STATS).
static const char *last_line(const char *log)
{
	const char *end = log + strlen(log);
	const char *line;

	while (end > log && end[-1] == '\n')
		end--;
	line = end;
	while (line > log && line[-1] != '\n')
		line--;
	return line;
}

static void print_prog_info(struct bpf_program *prog, const char *prefix)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int fd = bpf_program__fd(prog);

	if (bpf_prog_get_info_by_fd(fd, &info, &len))
		die("prog info: %s", strerror(errno));
	printf("%s name=%s verified_insns=%u xlated_bytes=%u jited_bytes=%u attach_btf_id=%u tag=",
	       prefix, bpf_program__name(prog), info.verified_insns, info.xlated_prog_len,
	       info.jited_prog_len, info.attach_btf_id);
	for (int i = 0; i < BPF_TAG_SIZE; i++)
		printf("%02x", info.tag[i]);
	printf("\n");
}

// Load with one program selected, or all when `only` is NULL; print the verifier's stats per
// program and the wall time of the load.
static int load_selected(const char *only, bool print_log_on_failure)
{
	struct bpf_object *obj = open_object();
	struct bpf_program *prog;
	char *logs[HOOK_COUNT] = {};
	int index = 0, err;
	double start;

	bpf_object__for_each_program(prog, obj) {
		bool selected = !only || !strcmp(bpf_program__name(prog), only);

		bpf_program__set_autoload(prog, selected);
		if (!selected || index >= (int)HOOK_COUNT)
			continue;
		logs[index] = calloc(1, LOG_BYTES);
		bpf_program__set_log_buf(prog, logs[index], LOG_BYTES);
		bpf_program__set_log_level(prog, print_log_on_failure ? 1 : 4);
		index++;
	}
	start = now_ms();
	err = bpf_object__load(obj);
	printf("load only=%s ok=%d ms=%.1f\n", only ? only : "all", err == 0, now_ms() - start);
	index = 0;
	bpf_object__for_each_program(prog, obj) {
		if (!bpf_program__autoload(prog))
			continue;
		if (index < (int)HOOK_COUNT && logs[index]) {
			if (err == 0)
				printf("verifier name=%s %s\n", bpf_program__name(prog), last_line(logs[index]));
			else if (print_log_on_failure) {
				const char *log = logs[index];
				size_t len = strlen(log);
				const char *tail = len > 6000 ? log + len - 6000 : log;

				printf("verifier-log name=%s\n%s\n", bpf_program__name(prog), tail);
			}
			free(logs[index]);
		}
		if (err == 0)
			print_prog_info(prog, "prog");
		index++;
	}
	bpf_object__close(obj);
	return err;
}

static int cmd_load(void)
{
	int failed = 0;

	for (size_t i = 0; i < HOOK_COUNT; i++)
		if (load_selected(hook_names[i], false)) {
			failed++;
			load_selected(hook_names[i], true);
		}
	if (load_selected(NULL, false))
		failed++;
	return failed ? 1 : 0;
}

static int cmd_attach(int argc, char **argv)
{
	const char *cgroup, *pindir;
	bool keep_going = false, fail_after_attach = false;
	struct bpf_object *obj;
	struct bpf_program *prog;
	int cgroup_fd, first = 0, failed = 0, attached = 0;

	if (argc < 3)
		die("usage: attach CGROUP PINDIR [--keep-going] PROG...");
	cgroup = argv[0];
	pindir = argv[1];
	first = 2;
	while (first < argc && argv[first][0] == '-') {
		if (!strcmp(argv[first], "--keep-going"))
			keep_going = true;
		else if (!strcmp(argv[first], "--fail-after-attach"))
			fail_after_attach = true;
		else
			die("attach: unknown option %s", argv[first]);
		first++;
	}
	if (first >= argc)
		die("attach: no program named");
	for (int i = first; i < argc; i++) {
		bool known = false;

		for (size_t h = 0; h < HOOK_COUNT; h++)
			known |= !strcmp(argv[i], hook_names[h]);
		if (!known)
			die("attach: no program %s in %s", argv[i], OBJECT_NAME);
	}
	cgroup_fd = open(cgroup, O_RDONLY | O_DIRECTORY);
	if (cgroup_fd < 0)
		die("open cgroup %s: %s", cgroup, strerror(errno));
	if (mkdir(pindir, 0700) && errno != EEXIST)
		die("mkdir %s: %s", pindir, strerror(errno));
	obj = open_object();
	bpf_object__for_each_program(prog, obj) {
		bool selected = false;

		for (int i = first; i < argc; i++)
			selected |= !strcmp(bpf_program__name(prog), argv[i]);
		bpf_program__set_autoload(prog, selected);
	}
	if (bpf_object__load(obj))
		die("load: %s", strerror(errno));
	for (int i = first; i < argc; i++) {
		struct bpf_link *link;
		char pin[PATH_MAX];

		prog = bpf_object__find_program_by_name(obj, argv[i]);
		link = bpf_program__attach_cgroup(prog, cgroup_fd);
		if (!link) {
			int err = errno;

			printf("attach name=%s ok=0 errno=%d error=%s\n", argv[i], err, strerror(err));
			failed++;
			if (keep_going)
				continue;
			break;
		}
		snprintf(pin, sizeof(pin), "%s/%s", pindir, argv[i]);
		if (bpf_link__pin(link, pin))
			die("pin %s: %s", pin, strerror(errno));
		printf("attach name=%s ok=1 link_id=", argv[i]);
		{
			struct bpf_link_info info = {};
			__u32 len = sizeof(info);

			if (bpf_link_get_info_by_fd(bpf_link__fd(link), &info, &len))
				die("link info: %s", strerror(errno));
			printf("%u prog_id=%u cgroup_id=%llu\n", info.id, info.prog_id,
			       (unsigned long long)info.cgroup.cgroup_id);
		}
		attached++;
	}
	printf("attached count=%d failed=%d\n", attached, failed);
	if (failed && !keep_going)
		return 1;
	if (fail_after_attach) {
		fprintf(stderr, "controller: injected failure after the attach\n");
		return 1;
	}
	return 0;
}

static struct btf *vmlinux_btf(void)
{
	static struct btf *btf;

	if (!btf) {
		btf = btf__load_vmlinux_btf();
		if (!btf)
			die("vmlinux BTF: %s", strerror(errno));
	}
	return btf;
}

static const char *btf_func_name(__u32 id)
{
	const struct btf_type *type = btf__type_by_id(vmlinux_btf(), id);

	return type ? btf__name_by_offset(vmlinux_btf(), type->name_off) : "?";
}

static void print_prog_by_id(__u32 id, const char *prefix)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int fd = bpf_prog_get_fd_by_id(id);

	if (fd < 0)
		die("prog %u: %s", id, strerror(errno));
	if (bpf_prog_get_info_by_fd(fd, &info, &len))
		die("prog info %u: %s", id, strerror(errno));
	printf("%s prog_id=%u name=%s hook=%s attach_btf_id=%u tag=", prefix, id, info.name,
	       btf_func_name(info.attach_btf_id), info.attach_btf_id);
	for (int i = 0; i < BPF_TAG_SIZE; i++)
		printf("%02x", info.tag[i]);
	printf("\n");
	close(fd);
}

// Every cgroup link of attach type BPF_LSM_CGROUP in the kernel, and the distinct hooks they hold:
// the slots in use, which the plan's controller reads before attaching ("The mechanism").
static void print_all_lsm_cgroup_links(void)
{
	__u32 id = 0, hooks[64], hook_count = 0, links = 0;

	while (!bpf_link_get_next_id(id, &id)) {
		struct bpf_link_info info = {};
		__u32 len = sizeof(info);
		int fd = bpf_link_get_fd_by_id(id);

		if (fd < 0)
			continue;
		if (!bpf_link_get_info_by_fd(fd, &info, &len) && info.type == BPF_LINK_TYPE_CGROUP &&
		    info.cgroup.attach_type == BPF_LSM_CGROUP) {
			struct bpf_prog_info pinfo = {};
			__u32 plen = sizeof(pinfo);
			int pfd = bpf_prog_get_fd_by_id(info.prog_id);
			bool seen = false;

			if (pfd >= 0 && !bpf_prog_get_info_by_fd(pfd, &pinfo, &plen)) {
				for (__u32 i = 0; i < hook_count; i++)
					seen |= hooks[i] == pinfo.attach_btf_id;
				if (!seen && hook_count < 64)
					hooks[hook_count++] = pinfo.attach_btf_id;
				printf("link id=%u prog_id=%u cgroup_id=%llu hook=%s\n", info.id, info.prog_id,
				       (unsigned long long)info.cgroup.cgroup_id,
				       btf_func_name(pinfo.attach_btf_id));
			}
			if (pfd >= 0)
				close(pfd);
			links++;
		}
		close(fd);
	}
	printf("slots links=%u hooks_in_use=%u\n", links, hook_count);
}

static int cmd_query(const char *cgroup)
{
	LIBBPF_OPTS(bpf_prog_query_opts, opts);
	__u32 ids[64], flags[64];
	int cgroup_fd = open(cgroup, O_RDONLY | O_DIRECTORY);

	if (cgroup_fd < 0)
		die("open cgroup %s: %s", cgroup, strerror(errno));
	if (bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &opts))
		die("prog query: %s", strerror(errno));
	printf("query cgroup=%s prog_cnt=%u\n", cgroup, opts.prog_cnt);
	if (opts.prog_cnt > 64)
		die("more than 64 programs");
	// A BPF_LSM_CGROUP query that asks for ids must take the attach flags too, or it is EINVAL
	// (kernel/bpf/cgroup.c, __cgroup_bpf_query).
	opts.prog_ids = ids;
	opts.prog_attach_flags = flags;
	if (opts.prog_cnt && bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &opts))
		die("prog query: %s", strerror(errno));
	for (__u32 i = 0; i < opts.prog_cnt; i++)
		print_prog_by_id(ids[i], "attached");
	print_all_lsm_cgroup_links();
	return 0;
}

static int link_fd_of_pin(const char *pin, struct bpf_link_info *info)
{
	__u32 len = sizeof(*info);
	int fd = bpf_obj_get(pin);

	if (fd < 0)
		die("open pin %s: %s", pin, strerror(errno));
	memset(info, 0, sizeof(*info));
	if (bpf_link_get_info_by_fd(fd, info, &len))
		die("link info %s: %s", pin, strerror(errno));
	return fd;
}

static int cmd_link_info(const char *pin)
{
	struct bpf_link_info info;
	int fd = link_fd_of_pin(pin, &info);

	printf("link-info pin=%s id=%u type=%u prog_id=%u cgroup_id=%llu attach_type=%u\n", pin,
	       info.id, info.type, info.prog_id, (unsigned long long)info.cgroup.cgroup_id,
	       info.cgroup.attach_type);
	close(fd);
	return 0;
}

// The map a pinned link's program uses, found as the plan's read-back finds it: the program's
// map ids from BPF_OBJ_GET_INFO_BY_FD, each opened by id, selected by name.
static int map_fd_of_pin(const char *pin, const char *map_name)
{
	struct bpf_link_info linfo;
	struct bpf_prog_info pinfo = {};
	__u32 map_ids[16], plen = sizeof(pinfo);
	int link_fd = link_fd_of_pin(pin, &linfo);
	int prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);

	close(link_fd);
	if (prog_fd < 0)
		die("prog %u: %s", linfo.prog_id, strerror(errno));
	pinfo.nr_map_ids = 16;
	pinfo.map_ids = (__u64)(uintptr_t)map_ids;
	if (bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen))
		die("prog info: %s", strerror(errno));
	close(prog_fd);
	for (__u32 i = 0; i < pinfo.nr_map_ids && i < 16; i++) {
		struct bpf_map_info minfo = {};
		__u32 mlen = sizeof(minfo);
		int fd = bpf_map_get_fd_by_id(map_ids[i]);

		if (fd < 0)
			die("map %u: %s", map_ids[i], strerror(errno));
		if (bpf_map_get_info_by_fd(fd, &minfo, &mlen))
			die("map info: %s", strerror(errno));
		if (!strcmp(minfo.name, map_name)) {
			printf("map name=%s id=%u type=%u key_size=%u value_size=%u max_entries=%u\n",
			       minfo.name, minfo.id, minfo.type, minfo.key_size, minfo.value_size,
			       minfo.max_entries);
			return fd;
		}
		close(fd);
	}
	die("program of %s uses no map %s", pin, map_name);
	return -1;
}

static int cmd_last_open(const char *pin)
{
	int fd = map_fd_of_pin(pin, "last_open");
	struct last_open rec = {};
	__u32 key = 0;

	if (bpf_map_lookup_elem(fd, &key, &rec))
		die("lookup: %s", strerror(errno));
	printf("last-open s_dev=%llu major=%u minor=%u i_ino=%llu count=%llu f_mode=0x%x denied=%u "
	       "depth=%u seq=%u fs_type=%s\n",
	       (unsigned long long)rec.s_dev, (unsigned)(rec.s_dev >> 20), (unsigned)(rec.s_dev & 0xfffff),
	       (unsigned long long)rec.i_ino, (unsigned long long)rec.count, rec.f_mode, rec.denied,
	       rec.depth, rec.seq, rec.fs_type);
	return 0;
}

static int cmd_stats(const char *pin)
{
	int fd = map_fd_of_pin(pin, "stats");

	for (__u32 key = 0; key < HOOK_COUNT; key++) {
		struct hook_stats st = {};

		if (bpf_map_lookup_elem(fd, &key, &st))
			die("lookup: %s", strerror(errno));
		printf("stats hook=%s calls=%llu walks=%llu retries=%llu gave_up=%llu max_depth=%llu "
		       "barrier_sum=%llu\n",
		       hook_names[key], (unsigned long long)st.calls, (unsigned long long)st.walks,
		       (unsigned long long)st.retries, (unsigned long long)st.gave_up,
		       (unsigned long long)st.max_depth, (unsigned long long)st.barrier_sum);
	}
	return 0;
}

// The jited program's bytes, scanned for the barrier instruction the plan expects per
// architecture: arm64 `ldaddal` (LSE; 64-bit 0xf8e0xxxx, 32-bit 0xb8e0xxxx) or `dmb ish`
// (0xd5033bbf) on the LL/SC path; x86-64 `lock xadd` (f0 [48] 0f c1). The xlated program is
// scanned for the atomic fetch-add instruction itself (BPF_STX|BPF_DW|BPF_ATOMIC, imm
// BPF_ADD|BPF_FETCH).
static int cmd_jited(const char *pin, const char *out)
{
	struct bpf_link_info linfo;
	struct bpf_prog_info sizes = {}, info = {};
	__u32 len = sizeof(sizes);
	int link_fd = link_fd_of_pin(pin, &linfo);
	int prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);
	unsigned char *jited, *xlated;
	unsigned ldaddal = 0, dmb = 0, lock_xadd = 0, fetch_add = 0;
	FILE *file;

	close(link_fd);
	if (prog_fd < 0)
		die("prog %u: %s", linfo.prog_id, strerror(errno));
	// The first call reports the lengths; the second, given buffers of those lengths, fills them.
	if (bpf_prog_get_info_by_fd(prog_fd, &sizes, &len))
		die("prog info: %s", strerror(errno));
	jited = calloc(1, sizes.jited_prog_len + 1);
	xlated = calloc(1, sizes.xlated_prog_len + 1);
	info.jited_prog_insns = (__u64)(uintptr_t)jited;
	info.jited_prog_len = sizes.jited_prog_len;
	info.xlated_prog_insns = (__u64)(uintptr_t)xlated;
	info.xlated_prog_len = sizes.xlated_prog_len;
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len))
		die("prog dump: %s", strerror(errno));
	for (__u32 i = 0; i + 4 <= info.jited_prog_len; i += 4) {
		__u32 word = jited[i] | jited[i + 1] << 8 | jited[i + 2] << 16 | (__u32)jited[i + 3] << 24;

		if ((word & 0xffe0fc00u) == 0xf8e00000u || (word & 0xffe0fc00u) == 0xb8e00000u)
			ldaddal++;
		if (word == 0xd5033bbfu)
			dmb++;
	}
	for (__u32 i = 0; i + 4 <= info.jited_prog_len; i++)
		if (jited[i] == 0xf0 &&
		    ((jited[i + 1] == 0x48 && jited[i + 2] == 0x0f && jited[i + 3] == 0xc1) ||
		     (jited[i + 1] == 0x0f && jited[i + 2] == 0xc1)))
			lock_xadd++;
	for (__u32 i = 0; i + 8 <= info.xlated_prog_len; i += 8) {
		__u8 code = xlated[i];
		__s32 imm = (__s32)(xlated[i + 4] | xlated[i + 5] << 8 | xlated[i + 6] << 16 |
				    (__u32)xlated[i + 7] << 24);

		if ((code == 0xdb || code == 0xc3) && imm == 0x01)
			fetch_add++;
	}
	printf("jited pin=%s jited_bytes=%u xlated_bytes=%u fetch_add_insns=%u ldaddal=%u dmb_ish=%u "
	       "lock_xadd=%u\n",
	       pin, info.jited_prog_len, info.xlated_prog_len, fetch_add, ldaddal, dmb, lock_xadd);
	file = fopen(out, "w");
	if (!file || fwrite(jited, 1, info.jited_prog_len, file) != info.jited_prog_len)
		die("write %s: %s", out, strerror(errno));
	fclose(file);
	return 0;
}

// What the plan's controller records for a root: statx's major, minor and inode number, laid out
// as the kernel's MKDEV lays s_dev out, with the filesystem type from statfs.
static int cmd_statx(const char *path)
{
	struct statx stx;
	struct statfs sfs;

	if (statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_INO | STATX_TYPE, &stx))
		die("statx %s: %s", path, strerror(errno));
	if (statfs(path, &sfs))
		die("statfs %s: %s", path, strerror(errno));
	printf("statx path=%s major=%u minor=%u mkdev=%llu ino=%llu mode=0%o fs_magic=0x%lx\n", path,
	       stx.stx_dev_major, stx.stx_dev_minor,
	       ((unsigned long long)stx.stx_dev_major << 20) | stx.stx_dev_minor,
	       (unsigned long long)stx.stx_ino, stx.stx_mode & S_IFMT, (unsigned long)sfs.f_type);
	return 0;
}

static int cmd_unpin(const char *pindir)
{
	DIR *dir = opendir(pindir);
	struct dirent *entry;

	if (!dir) {
		if (errno == ENOENT)
			return 0;
		die("opendir %s: %s", pindir, strerror(errno));
	}
	while ((entry = readdir(dir))) {
		char path[PATH_MAX];

		if (entry->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", pindir, entry->d_name);
		if (unlink(path))
			die("unlink %s: %s", path, strerror(errno));
		printf("unpinned %s\n", path);
	}
	closedir(dir);
	if (rmdir(pindir))
		die("rmdir %s: %s", pindir, strerror(errno));
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (argc < 2)
		die("usage: see the header of controller.c");
	if (!strcmp(argv[1], "load") && argc == 2)
		return cmd_load();
	if (!strcmp(argv[1], "attach"))
		return cmd_attach(argc - 2, argv + 2);
	if (!strcmp(argv[1], "query") && argc == 3)
		return cmd_query(argv[2]);
	if (!strcmp(argv[1], "link-info") && argc == 3)
		return cmd_link_info(argv[2]);
	if (!strcmp(argv[1], "last-open") && argc == 3)
		return cmd_last_open(argv[2]);
	if (!strcmp(argv[1], "stats") && argc == 3)
		return cmd_stats(argv[2]);
	if (!strcmp(argv[1], "jited") && argc == 4)
		return cmd_jited(argv[2], argv[3]);
	if (!strcmp(argv[1], "statx") && argc == 3)
		return cmd_statx(argv[2]);
	if (!strcmp(argv[1], "unpin") && argc == 3)
		return cmd_unpin(argv[2]);
	die("unknown subcommand %s", argv[1]);
}
