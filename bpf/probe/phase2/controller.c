// Phase 2 of doc/plan-bpf-lsm-cgroup.md: the privileged side of the probe, Phase 1's controller
// with two objects and their maps. It loads inventory.bpf.o or classify.bpf.o, installed beside
// this binary, attaches programs to a cgroup by link, pins the links, fills the policy's maps
// before the attach, and reads back what the kernel holds; phase2.sh drives it through
// `podman machine ssh` under sudo. Each subcommand prints lines phase2.sh greps, `key=value`.
//
//   controller load OBJ                  verify every program of OBJ alone, then all together, timed
//   controller verifier-log OBJ PROG OUT load PROG alone with the verifier's full log written to OUT
//   controller attach OBJ CGROUP PINDIR [--keep-going] [--pin-maps DIR] [--deny-all]
//                    [--fs-type NAME] [--root KIND=PATH]... [--rules FILE] PROG...
//                                        attach PROG... to CGROUP, pin each link at PINDIR/PROG;
//                                        --pin-maps shares the maps with the next attach of OBJ;
//                                        --root and --rules fill classify's maps before the attach
//   controller query CGROUP              the programs attached to CGROUP, and every lsm_cgroup link
//   controller link-info PIN             a pinned link's id, program and cgroup id (0 once detached)
//   controller hits PIN                  inventory: every (hook, operation) with calls, through PIN, a link or
//                                        the --pin-maps directory (also totals, reset and deny-all)
//   controller totals PIN                inventory: every hook's calls, marker names or not
//   controller reset PIN                 inventory: zero the hits and totals
//   controller deny-all PIN 0|1          inventory: refuse every call of the attached hooks, or not
//   controller stats PIN                 classify: the per-hook counters and times
//   controller last-decision PIN         classify: the last decision taken
//   controller jited PIN OUT             PIN's program as jited bytes into OUT, with a barrier scan
//   controller statx PATH                PATH's identity as the plan's controller records it
//   controller unpin PINDIR              remove every pin under PINDIR
#define _GNU_SOURCE
#include <ctype.h>
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

#define LOG_BYTES (64u << 20)
#define MAX_PROGS 64

// Debian trixie's libelf-dev ships libelf.a without libeu.a, whose four tree helpers libelf.a
// calls (elfutils, lib/eu-search.c). These stand in for a static link; the controller is
// single-threaded, so the lock the originals take is left out.
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

// --- Must match inventory.bpf.c ---------------------------------------------------------------

#define INV_OPS 100
#define INV_NAME_BYTES 32

struct op_hit {
	__u64 calls;
	__u64 denied;
	__u64 last_arg;
	char last_name[INV_NAME_BYTES];
};

struct hook_total {
	__u64 calls;
	__u64 denied;
	__u64 last_arg;
	char last_name[INV_NAME_BYTES];
};

struct inv_config {
	__u32 deny_all;
};

static const char *const inventory_hooks[] = {
	"path_mknod", "inode_create", "inode_mknod", "path_mkdir", "inode_mkdir", "path_symlink",
	"inode_symlink", "path_link", "inode_link", "path_rename", "inode_rename", "path_unlink",
	"inode_unlink", "path_rmdir", "inode_rmdir", "file_open", "inode_setattr", "inode_setxattr",
	"inode_removexattr", "inode_set_acl", "inode_remove_acl", "inode_file_setattr", "file_ioctl",
	"file_ioctl_compat", "file_receive", "file_permission", "path_truncate", "file_truncate",
	"path_chmod", "path_chown", "mmap_file", "file_mprotect", "inode_permission",
};
#define INVENTORY_HOOKS (sizeof(inventory_hooks) / sizeof(inventory_hooks[0]))

// --- Must match classify.bpf.c ----------------------------------------------------------------

#define RULE_LINES 128
#define RULE_COMPS 4
#define COMP_BYTES 32
#define FS_TYPE_BYTES 16

struct ident {
	__u64 s_dev;
	__u64 i_ino;
};

struct root {
	__u32 kind;
	__u32 pad;
};

struct rule_line {
	__u8 word;
	__u8 anchored;
	__u8 ncomp;
	__u8 pad;
	char comp[RULE_COMPS][COMP_BYTES];
};

struct policy_config {
	__u32 rule_count;
	__u32 flags;
	char fs_type[FS_TYPE_BYTES];
};

struct hook_stats {
	__u64 calls;
	__u64 allowed;
	__u64 denied;
	__u64 outside;
	__u64 walks;
	__u64 retries;
	__u64 gave_up;
	__u64 max_depth;
	__u64 ns_sum;
	__u64 ns_max;
};

struct last_decision {
	__u64 count;
	__u32 hook;
	__u32 reason;
	__u32 depth;
	__u32 root_kind;
	char name[32];
};

static const char *const classify_hooks[] = {
	"file_open", "inode_create", "inode_mknod", "inode_symlink", "inode_link", "inode_rename",
	"inode_unlink", "inode_setattr",
};
#define CLASSIFY_HOOKS (sizeof(classify_hooks) / sizeof(classify_hooks[0]))

static const char *const reasons[] = {
	"allow", "outside", "walk-noroot", "walk-bound", "walk-torn", "name-too-long", "git-protected",
	"git-pinned", "git-name", "sandbox-name", "head", "rule-read-only", "rule-pinned", "region",
	"socket", "internal",
};
#define REASONS (sizeof(reasons) / sizeof(reasons[0]))

static const char *const root_kinds[] = {"none", "workspace", "gitdir", "volume"};

// ----------------------------------------------------------------------------------------------

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

// The object is found beside the binary (/proc/self/exe) and never taken as a path, as the plan's
// controller does ("Native Linux"); OBJ is its file name.
static void object_path(const char *name, char *out, size_t size)
{
	char exe[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

	if (len < 0)
		die("readlink /proc/self/exe: %s", strerror(errno));
	exe[len] = 0;
	if (strchr(name, '/'))
		die("the object is named, not pathed: %s", name);
	snprintf(out, size, "%s/%s", dirname(exe), name);
}

static struct bpf_object *open_object(const char *name)
{
	char path[PATH_MAX];
	struct bpf_object *obj;

	object_path(name, path, sizeof(path));
	obj = bpf_object__open_file(path, NULL);
	if (!obj)
		die("open %s: %s", path, strerror(errno));
	return obj;
}

// The verifier's three stats lines are its last lines at log level 4 (BPF_LOG_STATS): the time,
// the stack depth and the instructions processed.
static void print_stats_lines(const char *prefix, const char *log)
{
	const char *end = log + strlen(log);
	const char *lines[3] = {NULL, NULL, NULL};
	int count = 0;

	while (end > log && end[-1] == '\n')
		end--;
	while (count < 3 && end > log) {
		const char *line = end;

		while (line > log && line[-1] != '\n')
			line--;
		lines[count++] = line;
		end = line;
		while (end > log && end[-1] == '\n')
			end--;
	}
	printf("%s", prefix);
	for (int i = count - 1; i >= 0; i--) {
		const char *line = lines[i];
		const char *stop = strchr(line, '\n');

		printf(" %.*s;", (int)(stop ? stop - line : (int)strlen(line)), line);
	}
	printf("\n");
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
// program and the wall time of the load. At `log_level` 1 or 2 the log of `only` goes to
// `log_out`.
static int load_selected(const char *object, const char *only, int log_level, const char *log_out)
{
	struct bpf_object *obj = open_object(object);
	struct bpf_program *prog;
	char *logs[MAX_PROGS] = {};
	int index = 0, err;
	double start;

	bpf_object__for_each_program(prog, obj) {
		bool selected = !only || !strcmp(bpf_program__name(prog), only);

		bpf_program__set_autoload(prog, selected);
		if (!selected || index >= MAX_PROGS)
			continue;
		logs[index] = calloc(1, LOG_BYTES);
		bpf_program__set_log_buf(prog, logs[index], LOG_BYTES);
		bpf_program__set_log_level(prog, log_level ? log_level : 4);
		index++;
	}
	start = now_ms();
	err = bpf_object__load(obj);
	printf("load object=%s only=%s ok=%d ms=%.1f\n", object, only ? only : "all", err == 0, now_ms() - start);
	index = 0;
	bpf_object__for_each_program(prog, obj) {
		if (!bpf_program__autoload(prog))
			continue;
		if (index < MAX_PROGS && logs[index]) {
			char prefix[128];

			snprintf(prefix, sizeof(prefix), "verifier name=%s", bpf_program__name(prog));
			if (err == 0 && !log_level)
				print_stats_lines(prefix, logs[index]);
			if (log_out) {
				FILE *file = fopen(log_out, "w");

				if (!file || fputs(logs[index], file) == EOF)
					die("write %s: %s", log_out, strerror(errno));
				fclose(file);
				print_stats_lines(prefix, logs[index]);
			} else if (err) {
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

static int cmd_load(const char *object)
{
	struct bpf_object *obj = open_object(object);
	struct bpf_program *prog;
	char names[MAX_PROGS][64];
	int count = 0, failed = 0;

	bpf_object__for_each_program(prog, obj) {
		if (count < MAX_PROGS)
			snprintf(names[count++], sizeof(names[0]), "%s", bpf_program__name(prog));
	}
	bpf_object__close(obj);
	for (int i = 0; i < count; i++)
		if (load_selected(object, names[i], 0, NULL)) {
			failed++;
			load_selected(object, names[i], 1, NULL);
		}
	if (load_selected(object, NULL, 0, NULL))
		failed++;
	return failed ? 1 : 0;
}

static int cmd_verifier_log(const char *object, const char *prog, const char *out)
{
	return load_selected(object, prog, 1, out) ? 1 : 0;
}

// What the plan's controller records for a root: statx's major, minor and inode number, laid out
// as the kernel's MKDEV lays s_dev out.
static void ident_of(const char *path, struct ident *id, unsigned *mode)
{
	struct statx stx;

	if (statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_INO | STATX_TYPE, &stx))
		die("statx %s: %s", path, strerror(errno));
	id->s_dev = ((__u64)stx.stx_dev_major << 20) | stx.stx_dev_minor;
	id->i_ino = stx.stx_ino;
	if (mode)
		*mode = stx.stx_mode & S_IFMT;
}

// A rule file for the probe: `word comp/comp[/comp...] [anchored]` per line, the components
// already folded, `#` comments and blank lines ignored. Fills `rules` and the count.
static __u32 read_rules(const char *path, int rules_fd)
{
	FILE *file = fopen(path, "r");
	char line[512];
	__u32 count = 0;

	if (!file)
		die("open %s: %s", path, strerror(errno));
	while (fgets(line, sizeof(line), file)) {
		struct rule_line rule = {};
		char *word, *name, *flag, *save = NULL, *comp;
		char *hash = strchr(line, '#');

		if (hash)
			*hash = 0;
		word = strtok_r(line, " \t\r\n", &save);
		if (!word)
			continue;
		name = strtok_r(NULL, " \t\r\n", &save);
		flag = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			die("%s: a line without a name", path);
		if (!strcmp(word, "read-only"))
			rule.word = 1;
		else if (!strcmp(word, "writable"))
			rule.word = 2;
		else if (!strcmp(word, "pinned-path"))
			rule.word = 3;
		else
			die("%s: unknown word %s", path, word);
		rule.anchored = flag && !strcmp(flag, "anchored");
		for (comp = strtok_r(name, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
			if (rule.ncomp >= RULE_COMPS)
				die("%s: more than %d components: %s", path, RULE_COMPS, name);
			if (strlen(comp) >= COMP_BYTES)
				die("%s: a component of %zu bytes", path, strlen(comp));
			strcpy(rule.comp[rule.ncomp++], comp);
		}
		if (count >= RULE_LINES)
			die("%s: more than %d lines", path, RULE_LINES);
		if (bpf_map_update_elem(rules_fd, &count, &rule, BPF_ANY))
			die("rules update: %s", strerror(errno));
		count++;
	}
	fclose(file);
	return count;
}

static int map_fd_by_name(struct bpf_object *obj, const char *name)
{
	int fd = bpf_object__find_map_fd_by_name(obj, name);

	if (fd < 0)
		die("no map %s in the object", name);
	return fd;
}

static int cmd_attach(int argc, char **argv)
{
	const char *object, *cgroup, *pindir, *pin_maps = NULL, *rules_path = NULL, *fs_type = NULL;
	const char *root_args[64];
	int root_count = 0;
	bool keep_going = false, deny_all = false;
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	int cgroup_fd, first, failed = 0, attached = 0;

	if (argc < 4)
		die("usage: attach OBJ CGROUP PINDIR [options] PROG...");
	object = argv[0];
	cgroup = argv[1];
	pindir = argv[2];
	first = 3;
	while (first < argc && argv[first][0] == '-') {
		const char *option = argv[first++];

		if (!strcmp(option, "--keep-going"))
			keep_going = true;
		else if (!strcmp(option, "--deny-all"))
			deny_all = true;
		else if (!strcmp(option, "--pin-maps") && first < argc)
			pin_maps = argv[first++];
		else if (!strcmp(option, "--rules") && first < argc)
			rules_path = argv[first++];
		else if (!strcmp(option, "--fs-type") && first < argc)
			fs_type = argv[first++];
		else if (!strcmp(option, "--root") && first < argc && root_count < 64)
			root_args[root_count++] = argv[first++];
		else
			die("attach: unknown option %s", option);
	}
	if (first >= argc)
		die("attach: no program named");
	cgroup_fd = open(cgroup, O_RDONLY | O_DIRECTORY);
	if (cgroup_fd < 0)
		die("open cgroup %s: %s", cgroup, strerror(errno));
	if (mkdir(pindir, 0700) && errno != EEXIST)
		die("mkdir %s: %s", pindir, strerror(errno));
	obj = open_object(object);
	for (int i = first; i < argc; i++)
		if (!bpf_object__find_program_by_name(obj, argv[i]))
			die("attach: no program %s in %s", argv[i], object);
	bpf_object__for_each_program(prog, obj) {
		bool selected = false;

		for (int i = first; i < argc; i++)
			selected |= !strcmp(bpf_program__name(prog), argv[i]);
		bpf_program__set_autoload(prog, selected);
	}
	if (pin_maps) {
		// A map pinned there from an earlier attach is reused, so the batches of inventory
		// programs count into one table.
		if (mkdir(pin_maps, 0700) && errno != EEXIST)
			die("mkdir %s: %s", pin_maps, strerror(errno));
		bpf_object__for_each_map(map, obj) {
			char path[PATH_MAX];

			if (bpf_map__is_internal(map))
				continue;
			snprintf(path, sizeof(path), "%s/%s", pin_maps, bpf_map__name(map));
			if (bpf_map__set_pin_path(map, path))
				die("pin path %s: %s", path, strerror(errno));
		}
	}
	if (bpf_object__load(obj))
		die("load: %s", strerror(errno));
	if (deny_all) {
		struct inv_config cfg = {.deny_all = 1};
		__u32 zero = 0;

		if (bpf_map_update_elem(map_fd_by_name(obj, "probe_config"), &zero, &cfg, BPF_ANY))
			die("config update: %s", strerror(errno));
	}
	if (root_count || rules_path || fs_type) {
		// The policy's records, written before the attach and never after ("The policy").
		struct policy_config cfg = {};
		__u32 zero = 0;
		int roots_fd = map_fd_by_name(obj, "roots");

		for (int i = 0; i < root_count; i++) {
			char spec[PATH_MAX];
			char *eq;
			struct ident id;
			struct root root = {};

			snprintf(spec, sizeof(spec), "%s", root_args[i]);
			eq = strchr(spec, '=');
			if (!eq)
				die("--root takes KIND=PATH: %s", spec);
			*eq = 0;
			if (!strcmp(spec, "workspace"))
				root.kind = 1;
			else if (!strcmp(spec, "gitdir"))
				root.kind = 2;
			else if (!strcmp(spec, "volume"))
				root.kind = 3;
			else
				die("--root kind: %s", spec);
			ident_of(eq + 1, &id, NULL);
			if (bpf_map_update_elem(roots_fd, &id, &root, BPF_ANY))
				die("roots update: %s", strerror(errno));
			printf("root kind=%s path=%s mkdev=%llu ino=%llu\n", spec, eq + 1,
			       (unsigned long long)id.s_dev, (unsigned long long)id.i_ino);
		}
		if (rules_path)
			cfg.rule_count = read_rules(rules_path, map_fd_by_name(obj, "rules"));
		if (fs_type) {
			if (strlen(fs_type) >= FS_TYPE_BYTES)
				die("--fs-type: too long");
			strcpy(cfg.fs_type, fs_type);
		}
		if (bpf_map_update_elem(map_fd_by_name(obj, "policy_config"), &zero, &cfg, BPF_ANY))
			die("config update: %s", strerror(errno));
		printf("policy rule_count=%u fs_type=%s roots=%d\n", cfg.rule_count, cfg.fs_type, root_count);
	}
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
	return failed && !keep_going ? 1 : 0;
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
// the slots in use.
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
// map ids from BPF_OBJ_GET_INFO_BY_FD, each opened by id, selected by name. When `pin` is a
// directory, the one `attach --pin-maps` filled, the map is its entry of that name.
static int map_fd_of_pin(const char *pin, const char *map_name)
{
	struct bpf_link_info linfo;
	struct bpf_prog_info pinfo = {};
	__u32 map_ids[16], plen = sizeof(pinfo);
	struct stat st;
	int link_fd, prog_fd;

	if (!stat(pin, &st) && S_ISDIR(st.st_mode)) {
		char path[PATH_MAX];
		int fd;

		snprintf(path, sizeof(path), "%s/%s", pin, map_name);
		fd = bpf_obj_get(path);
		if (fd < 0)
			die("open pinned map %s: %s", path, strerror(errno));
		return fd;
	}
	link_fd = link_fd_of_pin(pin, &linfo);
	prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);
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
		if (!strcmp(minfo.name, map_name))
			return fd;
		close(fd);
	}
	die("program of %s uses no map %s", pin, map_name);
	return -1;
}

static void print_name(const char *name, size_t size)
{
	for (size_t i = 0; i < size && name[i]; i++)
		putchar(isprint((unsigned char)name[i]) && name[i] != ' ' ? name[i] : '?');
}

static int cmd_hits(const char *pin)
{
	int fd = map_fd_of_pin(pin, "hits");

	for (__u32 hook = 0; hook < INVENTORY_HOOKS; hook++)
		for (__u32 op = 0; op < INV_OPS; op++) {
			__u32 key = hook * INV_OPS + op;
			struct op_hit hit = {};

			if (bpf_map_lookup_elem(fd, &key, &hit))
				die("lookup: %s", strerror(errno));
			if (!hit.calls)
				continue;
			printf("hit op=%02u hook=%s calls=%llu denied=%llu arg=0x%llx name=", op,
			       inventory_hooks[hook], (unsigned long long)hit.calls,
			       (unsigned long long)hit.denied, (unsigned long long)hit.last_arg);
			print_name(hit.last_name, sizeof(hit.last_name));
			printf("\n");
		}
	return 0;
}

static int cmd_totals(const char *pin)
{
	int fd = map_fd_of_pin(pin, "totals");

	for (__u32 hook = 0; hook < INVENTORY_HOOKS; hook++) {
		struct hook_total total = {};

		if (bpf_map_lookup_elem(fd, &hook, &total))
			die("lookup: %s", strerror(errno));
		printf("total hook=%s calls=%llu denied=%llu arg=0x%llx name=", inventory_hooks[hook],
		       (unsigned long long)total.calls, (unsigned long long)total.denied,
		       (unsigned long long)total.last_arg);
		print_name(total.last_name, sizeof(total.last_name));
		printf("\n");
	}
	return 0;
}

static int cmd_reset(const char *pin)
{
	int hits_fd = map_fd_of_pin(pin, "hits");
	int totals_fd = map_fd_of_pin(pin, "totals");
	struct op_hit hit = {};
	struct hook_total total = {};

	for (__u32 key = 0; key < INVENTORY_HOOKS * INV_OPS; key++)
		if (bpf_map_update_elem(hits_fd, &key, &hit, BPF_ANY))
			die("update: %s", strerror(errno));
	for (__u32 key = 0; key < INVENTORY_HOOKS; key++)
		if (bpf_map_update_elem(totals_fd, &key, &total, BPF_ANY))
			die("update: %s", strerror(errno));
	printf("reset ok=1\n");
	return 0;
}

static int cmd_deny_all(const char *pin, const char *value)
{
	int fd = map_fd_of_pin(pin, "probe_config");
	struct inv_config cfg = {.deny_all = atoi(value) != 0};
	__u32 zero = 0;

	if (bpf_map_update_elem(fd, &zero, &cfg, BPF_ANY))
		die("update: %s", strerror(errno));
	printf("deny-all value=%u\n", cfg.deny_all);
	return 0;
}

static int cmd_stats(const char *pin)
{
	int fd = map_fd_of_pin(pin, "stats");

	for (__u32 key = 0; key < CLASSIFY_HOOKS; key++) {
		struct hook_stats st = {};

		if (bpf_map_lookup_elem(fd, &key, &st))
			die("lookup: %s", strerror(errno));
		// ns_mean and ns_max are over the judged calls: those not ending at the superblock check.
		printf("stats hook=%s calls=%llu allowed=%llu denied=%llu outside=%llu walks=%llu retries=%llu "
		       "gave_up=%llu max_depth=%llu ns_mean=%llu ns_max=%llu\n",
		       classify_hooks[key], (unsigned long long)st.calls, (unsigned long long)st.allowed,
		       (unsigned long long)st.denied, (unsigned long long)st.outside, (unsigned long long)st.walks,
		       (unsigned long long)st.retries, (unsigned long long)st.gave_up,
		       (unsigned long long)st.max_depth,
		       (unsigned long long)(st.calls > st.outside ? st.ns_sum / (st.calls - st.outside) : 0),
		       (unsigned long long)st.ns_max);
	}
	return 0;
}

static int cmd_last_decision(const char *pin)
{
	int fd = map_fd_of_pin(pin, "last_decision");
	struct last_decision last = {};
	__u32 zero = 0;

	if (bpf_map_lookup_elem(fd, &zero, &last))
		die("lookup: %s", strerror(errno));
	printf("last-decision count=%llu hook=%s reason=%s depth=%u root=%s name=",
	       (unsigned long long)last.count, last.hook < CLASSIFY_HOOKS ? classify_hooks[last.hook] : "?",
	       last.reason < REASONS ? reasons[last.reason] : "?", last.depth,
	       last.root_kind < 4 ? root_kinds[last.root_kind] : "?");
	print_name(last.name, sizeof(last.name));
	printf("\n");
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

static int cmd_statx(const char *path)
{
	struct ident id;
	unsigned mode;
	struct statfs sfs;

	ident_of(path, &id, &mode);
	if (statfs(path, &sfs))
		die("statfs %s: %s", path, strerror(errno));
	printf("statx path=%s major=%u minor=%u mkdev=%llu ino=%llu mode=0%o fs_magic=0x%lx\n", path,
	       (unsigned)(id.s_dev >> 20), (unsigned)(id.s_dev & 0xfffff), (unsigned long long)id.s_dev,
	       (unsigned long long)id.i_ino, mode, (unsigned long)sfs.f_type);
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
		struct stat st;

		if (entry->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", pindir, entry->d_name);
		if (!lstat(path, &st) && S_ISDIR(st.st_mode)) {
			cmd_unpin(path);
			continue;
		}
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
	if (!strcmp(argv[1], "load") && argc == 3)
		return cmd_load(argv[2]);
	if (!strcmp(argv[1], "verifier-log") && argc == 5)
		return cmd_verifier_log(argv[2], argv[3], argv[4]);
	if (!strcmp(argv[1], "attach"))
		return cmd_attach(argc - 2, argv + 2);
	if (!strcmp(argv[1], "query") && argc == 3)
		return cmd_query(argv[2]);
	if (!strcmp(argv[1], "link-info") && argc == 3)
		return cmd_link_info(argv[2]);
	if (!strcmp(argv[1], "hits") && argc == 3)
		return cmd_hits(argv[2]);
	if (!strcmp(argv[1], "totals") && argc == 3)
		return cmd_totals(argv[2]);
	if (!strcmp(argv[1], "reset") && argc == 3)
		return cmd_reset(argv[2]);
	if (!strcmp(argv[1], "deny-all") && argc == 4)
		return cmd_deny_all(argv[2], argv[3]);
	if (!strcmp(argv[1], "stats") && argc == 3)
		return cmd_stats(argv[2]);
	if (!strcmp(argv[1], "last-decision") && argc == 3)
		return cmd_last_decision(argv[2]);
	if (!strcmp(argv[1], "jited") && argc == 4)
		return cmd_jited(argv[2], argv[3]);
	if (!strcmp(argv[1], "statx") && argc == 3)
		return cmd_statx(argv[2]);
	if (!strcmp(argv[1], "unpin") && argc == 3)
		return cmd_unpin(argv[2]);
	die("unknown subcommand %s", argv[1]);
}
