// Phase 3 of doc/plan-bpf-lsm-cgroup.md: the privileged side of the probe, Phase 2's controller
// for policy.bpf.o. It loads the object, installed beside this binary, fills the policy's maps,
// attaches the programs to a cgroup by link, pins the links, and reads back what the kernel holds;
// phase3.sh drives it through `podman machine ssh` under sudo. Each subcommand prints lines
// phase3.sh greps, `key=value`.
//
//   controller load OBJ                  verify every program of OBJ alone, then all together, timed
//   controller verifier-log OBJ PROG OUT load PROG alone with the verifier's full log written to OUT
//   controller attach OBJ CGROUP PINDIR [--keep-going] [--fs-type NAME] [--vol-fs-type NAME]
//                    [--flags F,F] [--root KIND=PATH]... [--rules FILE] PROG...
//                                        attach PROG... to CGROUP, pin each link at PINDIR/PROG, the
//                                        maps filled before the attach: the types are the share's and
//                                        the volume's; KIND is workspace, gitdir, volume, guarded-git
//                                        or guarded-sandbox; F is short-names or unix-sockets; FILE
//                                        is the rules file read_rules describes
//   controller query CGROUP              the programs attached to CGROUP, and every lsm_cgroup link
//   controller link-info PIN             a pinned link's id, program and cgroup id (0 once detached)
//   controller stats PIN                 the per-hook counters and times
//   controller guard PIN MASK            mark the scratch slots of MASK (bits 0 to 3) taken on every CPU, for
//                                        the slot-exhaustion rows; 0 frees them
//   controller reset-stats PIN           zero them
//   controller last-decision PIN         the last decision taken
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

// --- Must match policy.bpf.c ------------------------------------------------------------------

#define RULE_LINES 128
#define RULE_COMPS 7
#define COMP_BYTES 64
#define FS_TYPE_BYTES 16
#define ALIASES 16

#define FLAG_SHORT_NAMES 1u
#define FLAG_UNIX_SOCKETS 2u

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
	__u8 alias;
	char comp[RULE_COMPS][COMP_BYTES];
};

#define WORD_READ_ONLY 1
#define WORD_WRITABLE 2
#define WORD_PINNED 3

struct alias_context {
	__u8 partial[RULE_LINES];
	__s32 deciding;
	__u32 pinned_path;
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
	__u64 reentry;
	__u64 nested_max;
};

struct last_decision {
	__u64 count;
	__u32 hook;
	__u32 reason;
	__u32 depth;
	__u32 root_kind;
	char name[32];
	__u64 ns_inum;
	__u64 ns_anon;
	__u64 ns_root_dev;
	__u64 ns_root_ino;
	char comm[16];
	char ns_root[32];
	char my_root[32];
};

static const char *const policy_hooks[] = {
	"file_open", "inode_create", "inode_mknod", "inode_symlink", "inode_link", "inode_rename",
	"inode_unlink", "inode_setattr", "file_receive",
};
#define POLICY_HOOKS (sizeof(policy_hooks) / sizeof(policy_hooks[0]))

static const char *const reasons[] = {
	"allow", "outside", "walk-noroot", "walk-bound", "walk-torn", "name-too-long", "git-protected",
	"git-pinned", "git-name", "sandbox-name", "head", "rule-read-only", "rule-pinned", "region",
	"socket", "internal", "reentry", "short-name", "alias-overflow", "symlink-syntax", "symlink-short",
	"symlink-gitdir", "symlink-region", "socket-gitdir", "receive-ns", "receive-dir", "fifo",
};
#define REASONS (sizeof(reasons) / sizeof(reasons[0]))

static const char *const root_kinds[] = {"none", "workspace", "gitdir", "volume", "guarded-git", "guarded-sandbox"};
#define ROOT_KINDS (sizeof(root_kinds) / sizeof(root_kinds[0]))

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

// --- The rules file and the alias contexts -----------------------------------------------------

// policy.rs, `component_matches`, in user space: the iterative glob with one backtrack point.
static bool glob_matches(const char *pattern, const char *name)
{
	size_t p = 0, n = 0, star_p = 0, star_n = 0;
	bool have_star = false;
	size_t plen = strlen(pattern), nlen = strlen(name);

	while (n < nlen) {
		if (p < plen && pattern[p] == '*') {
			star_p = p;
			star_n = n;
			have_star = true;
			p++;
		} else if (p < plen && pattern[p] == name[n]) {
			p++;
			n++;
		} else if (have_star) {
			p = star_p + 1;
			star_n++;
			n = star_n;
		} else {
			return false;
		}
	}
	while (p < plen && pattern[p] == '*')
		p++;
	return p == plen;
}

// policy.rs, `child_rule_context`, in user space, over the lines a context is computed against:
// the alias context of a symlink's position, which the guard computes in production.
// The lines are the rules map's, by their indices; the guard's own anchored lines, which the
// filter computes a symlink's context without, never match here.
static void child_rule_context(const struct rule_line *lines, __u32 count, struct alias_context *ctx,
			       bool parent_is_root, const char *folded)
{
	__u8 next[RULE_LINES] = {};
	__s32 deciding = ctx->deciding;
	__u32 pinned = 0;

	for (__u32 line = 0; line < count; line++) {
		const struct rule_line *rule = &lines[line];
		__u8 was = ctx->partial[line];
		__u8 reached = 0;

		if (rule->anchored)
			continue;
		for (int k = 0; k < rule->ncomp; k++) {
			bool can_start = k == 0 ? (!rule->anchored || parent_is_root) : (was >> k) & 1;
			bool matched;

			if (!can_start)
				continue;
			matched = rule->anchored ? !strcmp(rule->comp[k], folded) : glob_matches(rule->comp[k], folded);
			if (matched)
				reached |= 1u << (k + 1);
		}
		if (reached & (1u << rule->ncomp)) {
			if (rule->word == WORD_PINNED)
				pinned = 1;
			else if ((__s32)line > deciding)
				deciding = line;
			reached &= ~(1u << rule->ncomp);
		}
		next[line] = reached;
	}
	for (__u32 line = 0; line < count; line++)
		if (next[line] && lines[line].word != WORD_PINNED && (__s32)line <= deciding)
			next[line] = 0;
	memcpy(ctx->partial, next, sizeof(next));
	ctx->deciding = deciding;
	ctx->pinned_path = pinned;
}

static void fold_ascii(char *text)
{
	for (char *at = text; *at; at++)
		if (*at >= 'A' && *at <= 'Z')
			*at += 'a' - 'A';
}

// A rule file for the probe: `word comp/comp[/comp...] [anchored] [alias=PATH]` per line, `#`
// comments and blank lines ignored. `alias=PATH` on an anchored `pinned-path` line names the
// workspace-relative entry whose rule context the line's end carries (the symlink the guard
// followed), computed here over the lines above it by their own indices, the anchored ones
// among them never matching, as the guard computes it over the launcher's lines. Fills `rules`,
// `aliases` and the count.
static __u32 read_rules(const char *path, int rules_fd, int aliases_fd)
{
	FILE *file = fopen(path, "r");
	static struct rule_line lines[RULE_LINES];
	char line[1024];
	__u32 count = 0, alias_count = 0;

	if (!file)
		die("open %s: %s", path, strerror(errno));
	while (fgets(line, sizeof(line), file)) {
		struct rule_line *rule;
		char *word, *name, *token, *save = NULL, *comp, *alias_path = NULL;
		char *hash = strchr(line, '#');
		bool anchored = false;

		if (hash)
			*hash = 0;
		word = strtok_r(line, " \t\r\n", &save);
		if (!word)
			continue;
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			die("%s: a line without a name", path);
		while ((token = strtok_r(NULL, " \t\r\n", &save))) {
			if (!strcmp(token, "anchored"))
				anchored = true;
			else if (!strncmp(token, "alias=", 6))
				alias_path = token + 6;
			else
				die("%s: unknown token %s", path, token);
		}
		if (count >= RULE_LINES)
			die("%s: more than %d lines", path, RULE_LINES);
		rule = &lines[count];
		memset(rule, 0, sizeof(*rule));
		if (!strcmp(word, "read-only"))
			rule->word = WORD_READ_ONLY;
		else if (!strcmp(word, "writable"))
			rule->word = WORD_WRITABLE;
		else if (!strcmp(word, "pinned-path"))
			rule->word = WORD_PINNED;
		else
			die("%s: unknown word %s", path, word);
		rule->anchored = anchored;
		fold_ascii(name);
		for (comp = strtok_r(name, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
			if (rule->ncomp >= RULE_COMPS)
				die("%s: more than %d components: %s", path, RULE_COMPS, name);
			if (strlen(comp) >= COMP_BYTES)
				die("%s: a component of %zu bytes", path, strlen(comp));
			strcpy(rule->comp[rule->ncomp++], comp);
		}
		if (alias_path) {
			struct alias_context ctx = {.deciding = -1};
			char spelled[1024];
			bool first = true;

			if (rule->word != WORD_PINNED || !anchored)
				die("%s: alias= belongs to an anchored pinned-path line", path);
			if (alias_count >= ALIASES)
				die("%s: more than %d aliases", path, ALIASES);
			snprintf(spelled, sizeof(spelled), "%s", alias_path);
			fold_ascii(spelled);
			for (comp = strtok_r(spelled, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
				child_rule_context(lines, count, &ctx, first, comp);
				first = false;
			}
			if (bpf_map_update_elem(aliases_fd, &alias_count, &ctx, BPF_ANY))
				die("aliases update: %s", strerror(errno));
			printf("alias index=%u path=%s deciding=%d pinned_path=%u partial_lines=", alias_count,
			       alias_path, ctx.deciding, ctx.pinned_path);
			for (__u32 i = 0; i < count; i++)
				if (ctx.partial[i])
					printf("%u:%x,", i, ctx.partial[i]);
			printf("\n");
			rule->alias = ++alias_count;
		}
		if (bpf_map_update_elem(rules_fd, &count, rule, BPF_ANY))
			die("rules update: %s", strerror(errno));
		count++;
	}
	fclose(file);
	return count;
}

// A mount namespace's inode number, as /proc/PID/ns/mnt names it: `mnt:[4026531841]`.
static __u32 mnt_ns_inum(const char *pid)
{
	char path[64], link[64];
	ssize_t len;
	unsigned long inum;

	snprintf(path, sizeof(path), "/proc/%s/ns/mnt", pid);
	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0)
		die("readlink %s: %s", path, strerror(errno));
	link[len] = 0;
	if (sscanf(link, "mnt:[%lu]", &inum) != 1)
		die("%s: unexpected %s", path, link);
	return inum;
}

static int map_fd_by_name(struct bpf_object *obj, const char *name)
{
	int fd = bpf_object__find_map_fd_by_name(obj, name);

	if (fd < 0)
		die("no map %s in the object", name);
	return fd;
}

static __u32 parse_flags(const char *text)
{
	char copy[256], *save = NULL, *token;
	__u32 flags = 0;

	snprintf(copy, sizeof(copy), "%s", text);
	for (token = strtok_r(copy, ",", &save); token; token = strtok_r(NULL, ",", &save)) {
		if (!strcmp(token, "short-names"))
			flags |= FLAG_SHORT_NAMES;
		else if (!strcmp(token, "unix-sockets"))
			flags |= FLAG_UNIX_SOCKETS;
		else
			die("--flags: unknown flag %s", token);
	}
	return flags;
}

static int cmd_attach(int argc, char **argv)
{
	const char *object, *cgroup, *pindir, *rules_path = NULL, *fs_type = NULL, *vol_fs_type = NULL;
	const char *root_args[64];
	int root_count = 0;
	__u32 flags = 0;
	bool keep_going = false;
	struct bpf_object *obj;
	struct bpf_program *prog;
	int cgroup_fd, first, failed = 0, attached = 0;
	struct policy_config cfg = {};
	__u32 zero = 0;
	int roots_fd;

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
		else if (!strcmp(option, "--rules") && first < argc)
			rules_path = argv[first++];
		else if (!strcmp(option, "--fs-type") && first < argc)
			fs_type = argv[first++];
		else if (!strcmp(option, "--vol-fs-type") && first < argc)
			vol_fs_type = argv[first++];
		else if (!strcmp(option, "--flags") && first < argc)
			flags = parse_flags(argv[first++]);
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
	if (bpf_object__load(obj))
		die("load: %s", strerror(errno));
	// The policy's records, written before the attach and never after ("The policy").
	roots_fd = map_fd_by_name(obj, "roots");
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
		for (__u32 kind = 1; kind < ROOT_KINDS; kind++)
			if (!strcmp(spec, root_kinds[kind]))
				root.kind = kind;
		if (!root.kind)
			die("--root kind: %s", spec);
		ident_of(eq + 1, &id, NULL);
		if (bpf_map_update_elem(roots_fd, &id, &root, BPF_ANY))
			die("roots update: %s", strerror(errno));
		printf("root kind=%s path=%s mkdev=%llu ino=%llu\n", spec, eq + 1,
		       (unsigned long long)id.s_dev, (unsigned long long)id.i_ino);
	}
	if (rules_path)
		cfg.rule_count = read_rules(rules_path, map_fd_by_name(obj, "rules"), map_fd_by_name(obj, "aliases"));
	if (fs_type) {
		if (strlen(fs_type) >= FS_TYPE_BYTES)
			die("--fs-type: too long");
		strcpy(cfg.fs_type, fs_type);
	}
	if (vol_fs_type) {
		if (strlen(vol_fs_type) >= FS_TYPE_BYTES)
			die("--vol-fs-type: too long");
		strcpy(cfg.vol_fs_type, vol_fs_type);
	}
	cfg.flags = flags;
	// The runtime's mount namespace is the controller's own: podman and the runtime run where
	// the launcher runs the controller. It is not pid 1's on every machine (measured on WSL,
	// "Phase 3 on WSL"). The host's root directory, by identity, names the runtime's namespaces
	// by their root where the number does not.
	cfg.runtime_mnt_ns = mnt_ns_inum("self");
	ident_of("/", &cfg.host_root, NULL);
	if (bpf_map_update_elem(map_fd_by_name(obj, "policy_config"), &zero, &cfg, BPF_ANY))
		die("config update: %s", strerror(errno));
	printf("policy rule_count=%u fs_type=%s vol_fs_type=%s roots=%d flags=%u runtime_mnt_ns=%u init_mnt_ns=%u "
	       "host_root=%llu:%llu\n",
	       cfg.rule_count, cfg.fs_type, cfg.vol_fs_type, root_count, cfg.flags, cfg.runtime_mnt_ns,
	       mnt_ns_inum("1"), (unsigned long long)cfg.host_root.s_dev, (unsigned long long)cfg.host_root.i_ino);
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
// map ids from BPF_OBJ_GET_INFO_BY_FD, each opened by id, selected by name.
static int map_fd_of_pin(const char *pin, const char *map_name)
{
	struct bpf_link_info linfo;
	struct bpf_prog_info pinfo = {};
	__u32 map_ids[16], plen = sizeof(pinfo);
	int link_fd, prog_fd;

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

static int cmd_stats(const char *pin)
{
	int fd = map_fd_of_pin(pin, "stats");

	for (__u32 key = 0; key < POLICY_HOOKS; key++) {
		struct hook_stats st = {};

		if (bpf_map_lookup_elem(fd, &key, &st))
			die("lookup: %s", strerror(errno));
		// ns_mean and ns_max are over the judged calls: those not ending at the superblock check.
		printf("stats hook=%s calls=%llu allowed=%llu denied=%llu outside=%llu walks=%llu retries=%llu "
		       "gave_up=%llu max_depth=%llu ns_mean=%llu ns_max=%llu reentry=%llu nested_max=%llu\n",
		       policy_hooks[key], (unsigned long long)st.calls, (unsigned long long)st.allowed,
		       (unsigned long long)st.denied, (unsigned long long)st.outside, (unsigned long long)st.walks,
		       (unsigned long long)st.retries, (unsigned long long)st.gave_up,
		       (unsigned long long)st.max_depth,
		       (unsigned long long)(st.calls > st.outside ? st.ns_sum / (st.calls - st.outside) : 0),
		       (unsigned long long)st.ns_max, (unsigned long long)st.reentry,
		       (unsigned long long)st.nested_max);
	}
	return 0;
}

// The per-CPU guard word on every CPU: a per-CPU map takes one value per possible CPU.
static int cmd_guard(const char *pin, const char *mask_text)
{
	int fd = map_fd_of_pin(pin, "guard");
	int cpus = libbpf_num_possible_cpus();
	__u64 *values;
	__u32 zero = 0;
	unsigned long mask = strtoul(mask_text, NULL, 0);

	if (cpus <= 0)
		die("possible cpus: %s", strerror(errno));
	values = calloc(cpus, sizeof(*values));
	for (int i = 0; i < cpus; i++)
		values[i] = mask;
	if (bpf_map_update_elem(fd, &zero, values, BPF_ANY))
		die("guard update: %s", strerror(errno));
	printf("guard mask=0x%lx cpus=%d\n", mask, cpus);
	return 0;
}

static int cmd_reset_stats(const char *pin)
{
	int fd = map_fd_of_pin(pin, "stats");
	struct hook_stats st = {};

	for (__u32 key = 0; key < POLICY_HOOKS; key++)
		if (bpf_map_update_elem(fd, &key, &st, BPF_ANY))
			die("update: %s", strerror(errno));
	printf("reset-stats ok=1\n");
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
	       (unsigned long long)last.count, last.hook < POLICY_HOOKS ? policy_hooks[last.hook] : "?",
	       last.reason < REASONS ? reasons[last.reason] : "?", last.depth,
	       last.root_kind < ROOT_KINDS ? root_kinds[last.root_kind] : "?");
	print_name(last.name, sizeof(last.name));
	if (last.hook == 8) {
		printf(" comm=");
		print_name(last.comm, sizeof(last.comm));
		printf(" ns_inum=%llu ns_anon=%llu ns_root=%llu:%llu:", (unsigned long long)last.ns_inum,
		       (unsigned long long)last.ns_anon, (unsigned long long)last.ns_root_dev,
		       (unsigned long long)last.ns_root_ino);
		print_name(last.ns_root, sizeof(last.ns_root));
		printf(" my_root=");
		print_name(last.my_root, sizeof(last.my_root));
	}
	printf("\n");
	return 0;
}

// The jited program's bytes, scanned for the barrier instruction the plan expects per
// architecture: arm64 `ldaddal` (LSE; 64-bit 0xf8e0xxxx, 32-bit 0xb8e0xxxx) or `dmb ish`
// (0xd5033bbf) on the LL/SC path; x86-64 `lock xadd` (f0 [4x] 0f c1, any REX prefix: a scan of
// the `REX.W` form alone counted one of three on WSL, "Phase 3 on WSL"). The xlated program is
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
		    (((jited[i + 1] & 0xf0) == 0x40 && jited[i + 2] == 0x0f && jited[i + 3] == 0xc1) ||
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
	if (!strcmp(argv[1], "stats") && argc == 3)
		return cmd_stats(argv[2]);
	if (!strcmp(argv[1], "reset-stats") && argc == 3)
		return cmd_reset_stats(argv[2]);
	if (!strcmp(argv[1], "guard") && argc == 4)
		return cmd_guard(argv[2], argv[3]);
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
