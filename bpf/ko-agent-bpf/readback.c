// The BPF cgroup-LSM backend of bpf/ko-agent-bpf/doc/architecture.md: the read-back ("Lifecycle", 3), a
// program with the controller's privileges and none of its code. It asks the kernel what is
// attached to the attach cgroup and compares it with what the launch meant: the hook set, each
// program's tag against the installed object's, and each map's shape and contents against the
// guard's records and the identities it reads for itself. A difference ends the launch. It also
// records the installed object's tags, once per installation and kernel, checks pinned programs
// before a restart reuses them ("Lifecycle", 5), and checks the preloaded set before a launch takes
// it. Exit status 1 is a difference, 2 a failure.
//
//   readback tags OBJ OUT             load OBJ, beside this binary, and write each program's name,
//                                     hook and tag, and the read-only data map's bytes, to OUT, under
//                                     the running kernel's release
//   readback verify CGROUP --tags FILE --records FILE --workspace PATH [--fixture PATH] [--volume PATH]
//                  [--flags F,F] [--no-root] HOOK...
//                                     the programs attached to CGROUP must be HOOK..., once each and
//                                     nothing else, with FILE's tags, sharing one map set whose
//                                     records are those the guard produced for this launch, frozen,
//                                     and whose read-only data is FILE's; --no-root expects a read-only
//                                     session's policy (backend.h), for which --records may be absent
//   readback check-pins PINDIR --tags FILE --records FILE --workspace PATH [--fixture PATH]
//                      [--volume PATH] [--flags F,F] [--no-root] HOOK...
//                                     the same of the programs pinned under PINDIR/progs
//   readback check-preloaded PINDIR --tags FILE HOOK...
//                                     the programs pinned under PINDIR/progs are HOOK... with FILE's
//                                     tags and read-only data, over one map set holding no record and
//                                     not frozen: the preloaded set a launch may take
#define _GNU_SOURCE
#include <libgen.h>
#include <sys/utsname.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define PROGRAM_NAME "readback"
#include "backend.h"

#define MAX_MAPS 32

struct tag_entry {
	char name[64];
	__u32 attach_btf_id;
	__u8 tag[BPF_TAG_SIZE];
};

#define RODATA_MAX 16384

struct tags {
	char kernel[128];
	struct tag_entry entries[POLICY_HOOKS];
	int count;
	// The string literals' read-only map: the tag covers instructions alone, so a build differing in
	// data alone keeps every tag and is told apart by these bytes.
	__u32 rodata_size;
	unsigned char rodata[RODATA_MAX];
};

static bool is_rodata(const struct bpf_map_info *info)
{
	return strstr(info->name, "rodata") && (info->map_flags & BPF_F_RDONLY_PROG);
}

// Reads the one value of a read-only data map into `out`; returns its size.
static __u32 read_rodata(int fd, const struct bpf_map_info *info, unsigned char *out)
{
	__u32 zero = 0;

	if (info->max_entries != 1 || info->value_size > RODATA_MAX)
		die("read-only map %s: %u entries of %u bytes", info->name, info->max_entries, info->value_size);
	if (bpf_map_lookup_elem(fd, &zero, out))
		die("read-only map %s: %s", info->name, strerror(errno));
	return info->value_size;
}

static const char *kernel_release(void)
{
	static struct utsname uts;

	if (!uts.release[0] && uname(&uts))
		die("uname: %s", strerror(errno));
	return uts.release;
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

// The BTF id of a hook's attach point, `bpf_lsm_<hook>`: what a program's attach_btf_id names.
static __u32 hook_btf_id(const char *hook)
{
	char name[128];
	__s32 id;

	snprintf(name, sizeof(name), "bpf_lsm_%s", hook);
	id = btf__find_by_name_kind(vmlinux_btf(), name, BTF_KIND_FUNC);
	if (id < 0)
		die("no %s in the kernel's BTF", name);
	return id;
}

// --- tags -----------------------------------------------------------------------------------------

static int cmd_tags(const char *name, const char *out_path)
{
	char exe[PATH_MAX], path[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	FILE *out;
	double start;
	int count = 0, rodata_maps = 0;

	if (len < 0)
		die("readlink /proc/self/exe: %s", strerror(errno));
	exe[len] = 0;
	if (strchr(name, '/'))
		die("the object is named, not pathed: %s", name);
	snprintf(path, sizeof(path), "%s/%s", dirname(exe), name);
	obj = bpf_object__open_file(path, NULL);
	if (!obj)
		die("open %s: %s", path, strerror(errno));
	start = now_ms();
	if (bpf_object__load(obj))
		die("load %s: %s", path, strerror(errno));
	out = fopen(out_path, "w");
	if (!out)
		die("open %s: %s", out_path, strerror(errno));
	fprintf(out, "kernel=%s object=%s\n", kernel_release(), name);
	bpf_object__for_each_map(map, obj) {
		struct bpf_map_info info = {};
		__u32 ilen = sizeof(info), size;
		unsigned char rodata[RODATA_MAX];

		if (bpf_map_get_info_by_fd(bpf_map__fd(map), &info, &ilen))
			die("map info: %s", strerror(errno));
		if (!is_rodata(&info))
			continue;
		size = read_rodata(bpf_map__fd(map), &info, rodata);
		fprintf(out, "rodata size=%u hex=", size);
		for (__u32 i = 0; i < size; i++)
			fprintf(out, "%02x", rodata[i]);
		fprintf(out, "\n");
		rodata_maps++;
	}
	if (rodata_maps != 1)
		die("%s holds %d read-only data maps, not one", name, rodata_maps);
	bpf_object__for_each_program(prog, obj) {
		struct bpf_prog_info info = {};
		__u32 ilen = sizeof(info);

		if (bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &ilen))
			die("prog info: %s", strerror(errno));
		fprintf(out, "prog=%s attach_btf_id=%u tag=", bpf_program__name(prog), info.attach_btf_id);
		for (int i = 0; i < BPF_TAG_SIZE; i++)
			fprintf(out, "%02x", info.tag[i]);
		fprintf(out, "\n");
		count++;
	}
	fclose(out);
	printf("tags object=%s programs=%d kernel=%s out=%s ms=%.1f\n", name, count, kernel_release(), out_path,
	       now_ms() - start);
	return 0;
}

static void read_tags(const char *path, struct tags *tags)
{
	FILE *file = fopen(path, "r");
	// The read-only data's line holds two hex digits per byte after its prefix.
	static char line[2 * RODATA_MAX + 128];

	memset(tags, 0, sizeof(*tags));
	if (!file)
		die("open %s: %s", path, strerror(errno));
	while (fgets(line, sizeof(line), file)) {
		struct tag_entry *entry;
		char hex[2 * BPF_TAG_SIZE + 1];

		if (sscanf(line, "kernel=%127s", tags->kernel) == 1)
			continue;
		if (!strncmp(line, "rodata size=", 12)) {
			const char *hex = strstr(line, "hex=");
			size_t digits;

			if (sscanf(line, "rodata size=%u", &tags->rodata_size) != 1 || !hex ||
			    tags->rodata_size > RODATA_MAX)
				die("%s: unexpected line %s", path, line);
			hex += 4;
			digits = strspn(hex, "0123456789abcdef");
			if (digits != 2 * (size_t)tags->rodata_size || (hex[digits] != '\n' && hex[digits] != 0))
				die("%s: the read-only data holds %zu hex digits, not %u", path, digits,
				    2 * tags->rodata_size);
			for (__u32 i = 0; i < tags->rodata_size; i++) {
				unsigned byte;

				if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
					die("%s: the read-only data is not hex", path);
				tags->rodata[i] = byte;
			}
			continue;
		}
		if (tags->count >= (int)POLICY_HOOKS)
			die("%s: more than %zu programs", path, POLICY_HOOKS);
		entry = &tags->entries[tags->count];
		if (sscanf(line, "prog=%63s attach_btf_id=%u tag=%16s", entry->name, &entry->attach_btf_id, hex) != 3)
			die("%s: unexpected line %s", path, line);
		for (int i = 0; i < BPF_TAG_SIZE; i++) {
			unsigned byte;

			if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
				die("%s: a tag is not hex: %s", path, hex);
			entry->tag[i] = byte;
		}
		tags->count++;
	}
	fclose(file);
	if (!tags->kernel[0] || !tags->count || !tags->rodata_size)
		die("%s: no kernel, no program or no read-only data recorded", path);
}

// --- verify -----------------------------------------------------------------------------------------

// A difference: printed, and the verdict.
static int differ(const char *what, const char *format, ...)
{
	va_list args;

	printf("verify ok=0 reason=%s ", what);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
	return 1;
}

static int compare_u32s(const void *a, const void *b)
{
	__u32 x = *(const __u32 *)a, y = *(const __u32 *)b;

	return x < y ? -1 : x > y;
}

// The maps every program of the set references, by id, sorted: one set for the sandbox.
static int map_ids_of(int prog_fd, __u32 *ids)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	info.nr_map_ids = MAX_MAPS;
	info.map_ids = (__u64)(uintptr_t)ids;
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len))
		die("prog info: %s", strerror(errno));
	if (info.nr_map_ids > MAX_MAPS)
		die("a program references more than %d maps", MAX_MAPS);
	qsort(ids, info.nr_map_ids, sizeof(*ids), compare_u32s);
	return info.nr_map_ids;
}

// Every record of the roots map, compared as a set with the expected identities.
static int compare_roots(int fd, const struct policy *policy)
{
	struct ident key, next;
	bool have = false;
	int count = 0;

	while (!bpf_map_get_next_key(fd, have ? &key : NULL, &next)) {
		struct root root;
		bool found = false;

		key = next;
		have = true;
		if (bpf_map_lookup_elem(fd, &key, &root))
			die("roots lookup: %s", strerror(errno));
		for (int i = 0; i < policy->root_count; i++)
			if (same_ident(&policy->idents[i], &key) && policy->roots[i].kind == root.kind)
				found = true;
		if (!found)
			return differ("map-contents", "map=roots unexpected mkdev=%llu ino=%llu kind=%u",
				      (unsigned long long)key.s_dev, (unsigned long long)key.i_ino, root.kind);
		count++;
	}
	if (count != policy->root_count)
		return differ("map-contents", "map=roots count=%d expected=%d", count, policy->root_count);
	return 0;
}

static int compare_array(int fd, const char *name, const void *expected, size_t record, __u32 filled, __u32 entries)
{
	char *value = calloc(1, record), *zero = calloc(1, record);

	if (!value || !zero)
		die("out of memory");
	for (__u32 i = 0; i < entries; i++) {
		const void *want = i < filled ? (const char *)expected + i * record : zero;

		if (bpf_map_lookup_elem(fd, &i, value))
			die("%s lookup %u: %s", name, i, strerror(errno));
		if (memcmp(value, want, record)) {
			free(value);
			free(zero);
			return differ("map-contents", "map=%s index=%u", name, i);
		}
	}
	free(value);
	free(zero);
	return 0;
}

static int compare_config(int fd, const struct policy_config *want)
{
	struct policy_config have;
	__u32 zero = 0;

	if (bpf_map_lookup_elem(fd, &zero, &have))
		die("policy_config lookup: %s", strerror(errno));
	if (have.rule_count != want->rule_count || have.flags != want->flags ||
	    strncmp(have.fs_type, want->fs_type, FS_TYPE_BYTES) ||
	    strncmp(have.vol_fs_type, want->vol_fs_type, FS_TYPE_BYTES) ||
	    have.runtime_mnt_ns != want->runtime_mnt_ns || !same_ident(&have.host_root, &want->host_root))
		return differ("map-contents",
			      "map=policy_config have rule_count=%u flags=%u fs_type=%.16s vol_fs_type=%.16s mnt_ns=%u "
			      "want rule_count=%u flags=%u fs_type=%.16s vol_fs_type=%.16s mnt_ns=%u",
			      have.rule_count, have.flags, have.fs_type, have.vol_fs_type, have.runtime_mnt_ns,
			      want->rule_count, want->flags, want->fs_type, want->vol_fs_type, want->runtime_mnt_ns);
	return 0;
}

// Whether the kernel holds the map frozen, which the descriptor's fdinfo says and struct
// bpf_map_info does not.
static bool map_frozen(int fd)
{
	char path[64], line[128];
	int frozen = -1;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	file = fopen(path, "r");
	if (!file)
		die("%s: %s", path, strerror(errno));
	while (frozen < 0 && fgets(line, sizeof(line), file))
		sscanf(line, "frozen: %d", &frozen);
	fclose(file);
	if (frozen < 0)
		die("%s names no frozen state", path);
	return frozen;
}

// The map set of one sandbox: the eight of the table by shape, one read-only map of string
// literals holding the installed object's bytes, nothing else; then the records in the four the
// launch filled, frozen as RECORDS_FROZEN says: an attached set's are, a preloaded set's not yet.
static int verify_maps(const __u32 *ids, int count, const struct policy *policy, const struct tags *tags,
		       bool records_frozen)
{
	bool seen[POLICY_MAPS] = {};
	int rodata = 0;

	for (int i = 0; i < count; i++) {
		struct bpf_map_info info = {};
		__u32 len = sizeof(info);
		int fd = bpf_map_get_fd_by_id(ids[i]);
		int shape = -1;

		if (fd < 0)
			die("map %u: %s", ids[i], strerror(errno));
		if (bpf_map_get_info_by_fd(fd, &info, &len))
			die("map info %u: %s", ids[i], strerror(errno));
		for (unsigned k = 0; k < POLICY_MAPS; k++)
			if (!strcmp(info.name, policy_maps[k].name))
				shape = k;
		if (shape < 0) {
			unsigned char bytes[RODATA_MAX];
			__u32 size;

			if (!is_rodata(&info) || rodata++) {
				close(fd);
				return differ("map-set", "unexpected map id=%u name=%s type=%u", ids[i], info.name,
					      info.type);
			}
			size = read_rodata(fd, &info, bytes);
			close(fd);
			if (size != tags->rodata_size || memcmp(bytes, tags->rodata, size))
				return differ("rodata", "map=%s size=%u installed_size=%u: the read-only data differs "
					      "from the installed object's", info.name, size, tags->rodata_size);
			continue;
		}
		if (seen[shape]) {
			close(fd);
			return differ("map-set", "map %s twice", info.name);
		}
		seen[shape] = true;
		if (info.type != policy_maps[shape].type || info.key_size != policy_maps[shape].key_size ||
		    (policy_maps[shape].value_size && info.value_size != policy_maps[shape].value_size) ||
		    info.max_entries != policy_maps[shape].max_entries) {
			close(fd);
			return differ("map-shape", "map=%s type=%u key=%u value=%u entries=%u expected type=%u key=%u "
				      "value=%u entries=%u", info.name, info.type, info.key_size, info.value_size,
				      info.max_entries, policy_maps[shape].type, policy_maps[shape].key_size,
				      policy_maps[shape].value_size, policy_maps[shape].max_entries);
		}
		if (policy_maps[shape].records && map_frozen(fd) != records_frozen) {
			close(fd);
			return differ("map-frozen", "map=%s frozen=%d expected=%d", info.name, !records_frozen,
				      records_frozen);
		}
		if (!strcmp(info.name, "roots") && compare_roots(fd, policy))
			return 1;
		if (!strcmp(info.name, "rules") &&
		    compare_array(fd, "rules", policy->rec.rules, sizeof(struct rule_line),
				  policy->rec.header.rule_count, RULE_LINES))
			return 1;
		if (!strcmp(info.name, "aliases") &&
		    compare_array(fd, "aliases", policy->rec.aliases, sizeof(struct alias_context),
				  policy->rec.header.alias_count, ALIASES))
			return 1;
		if (!strcmp(info.name, "policy_config") && compare_config(fd, &policy->cfg))
			return 1;
		close(fd);
	}
	for (unsigned k = 0; k < POLICY_MAPS; k++)
		if (!seen[k])
			return differ("map-set", "map %s missing", policy_maps[k].name);
	if (rodata != 1)
		return differ("map-set", "no read-only data map");
	return 0;
}

// The programs, by descriptor: the hook set exact, every tag the installed object's, one map set.
static int verify_programs(int *prog_fds, int count, const struct expectation *exp, const struct policy *policy,
			   const struct tags *tags, bool records_frozen, const char *what, double start)
{
	__u32 expected_ids[POLICY_HOOKS], first_maps[MAX_MAPS];
	bool matched[POLICY_HOOKS] = {};
	int first_count = -1;

	if (strcmp(tags->kernel, kernel_release()))
		return differ("tags-kernel", "tags recorded on %s, running %s", tags->kernel, kernel_release());
	for (int i = 0; i < exp->hook_count; i++)
		expected_ids[i] = hook_btf_id(exp->hooks[i]);
	if (count != exp->hook_count)
		return differ("hook-set", "attached=%d expected=%d", count, exp->hook_count);
	for (int i = 0; i < count; i++) {
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info), ids[MAX_MAPS];
		int hook = -1, map_count;
		const struct tag_entry *entry = NULL;

		if (bpf_prog_get_info_by_fd(prog_fds[i], &info, &len))
			die("prog info: %s", strerror(errno));
		if (info.type != BPF_PROG_TYPE_LSM)
			return differ("prog-type", "prog_id=%u type=%u", info.id, info.type);
		for (int k = 0; k < exp->hook_count; k++)
			if (expected_ids[k] == info.attach_btf_id)
				hook = k;
		if (hook < 0)
			return differ("hook-set", "prog_id=%u attach_btf_id=%u is no expected hook", info.id,
				      info.attach_btf_id);
		if (matched[hook])
			return differ("hook-set", "hook=%s attached twice", exp->hooks[hook]);
		matched[hook] = true;
		for (int k = 0; k < tags->count; k++)
			if (!strcmp(tags->entries[k].name, exp->hooks[hook]))
				entry = &tags->entries[k];
		if (!entry)
			return differ("tag", "hook=%s has no installed tag", exp->hooks[hook]);
		if (entry->attach_btf_id != info.attach_btf_id || memcmp(entry->tag, info.tag, BPF_TAG_SIZE)) {
			printf("verify ok=0 reason=tag hook=%s prog_id=%u tag=", exp->hooks[hook], info.id);
			print_tag(info.tag);
			printf(" installed=");
			print_tag(entry->tag);
			printf("\n");
			return 1;
		}
		map_count = map_ids_of(prog_fds[i], ids);
		if (first_count < 0) {
			first_count = map_count;
			memcpy(first_maps, ids, map_count * sizeof(*ids));
		} else if (map_count != first_count || memcmp(first_maps, ids, map_count * sizeof(*ids))) {
			return differ("map-set", "hook=%s references other maps than %s", exp->hooks[hook],
				      exp->hooks[0]);
		}
	}
	if (verify_maps(first_maps, first_count, policy, tags, records_frozen))
		return 1;
	printf("%s ok=1 programs=%d maps=%d roots=%d rule_count=%u aliases=%u fs_type=%s records_frozen=%d "
	       "ms=%.1f\n", what, count, first_count, policy->root_count, policy->rec.header.rule_count,
	       policy->rec.header.alias_count, policy->cfg.fs_type, records_frozen, now_ms() - start);
	return 0;
}

static int cmd_verify(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_prog_query_opts, opts);
	__u32 ids[64], flags[64];
	int prog_fds[64];
	struct expectation exp;
	struct policy policy;
	struct tags tags;
	int cgroup_fd, result;
	double start = now_ms();

	if (argc < 2)
		die("usage: verify CGROUP [options] HOOK...");
	parse_expectation(argc - 1, argv + 1, &exp, "verify");
	if (!exp.tags_path || !exp.workspace)
		die("verify: --tags and --workspace are required");
	read_tags(exp.tags_path, &tags);
	expect_policy(&policy, exp.records, exp.workspace, exp.fixture, exp.volume, exp.flags, exp.no_root);
	cgroup_fd = open_cgroup(argv[0]);
	// BPF_PROG_QUERY on the attach cgroup with BPF_LSM_CGROUP lists the programs of every hook
	// together; the ids need the attach-flags buffer beside them (kernel/bpf/cgroup.c,
	// __cgroup_bpf_query).
	if (bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &opts))
		die("prog query: %s", strerror(errno));
	if (opts.prog_cnt > 64)
		die("more than 64 programs");
	opts.prog_ids = ids;
	opts.prog_attach_flags = flags;
	if (opts.prog_cnt && bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &opts))
		die("prog query: %s", strerror(errno));
	for (__u32 i = 0; i < opts.prog_cnt; i++) {
		prog_fds[i] = bpf_prog_get_fd_by_id(ids[i]);
		if (prog_fds[i] < 0)
			die("prog %u: %s", ids[i], strerror(errno));
	}
	result = verify_programs(prog_fds, opts.prog_cnt, &exp, &policy, &tags, true, "verify", start);
	return result ? 1 : 0;
}

static int cmd_check_pins(int argc, char **argv)
{
	int prog_fds[POLICY_HOOKS];
	struct expectation exp;
	struct policy policy;
	struct tags tags;
	double start = now_ms();

	if (argc < 2)
		die("usage: check-pins PINDIR [options] HOOK...");
	parse_expectation(argc - 1, argv + 1, &exp, "check-pins");
	if (!exp.tags_path || !exp.workspace)
		die("check-pins: --tags and --workspace are required");
	if (!relative_beneath(PIN_FS, argv[0]))
		die("pindir %s is not under %s", argv[0], PIN_FS);
	read_tags(exp.tags_path, &tags);
	expect_policy(&policy, exp.records, exp.workspace, exp.fixture, exp.volume, exp.flags, exp.no_root);
	for (int i = 0; i < exp.hook_count; i++) {
		char pin[PATH_MAX];

		snprintf(pin, sizeof(pin), "%s/progs/%s", argv[0], exp.hooks[i]);
		prog_fds[i] = bpf_obj_get(pin);
		if (prog_fds[i] < 0) {
			printf("check-pins ok=0 reason=missing-pin pin=%s error=%s\n", pin, strerror(errno));
			return 1;
		}
	}
	return verify_programs(prog_fds, exp.hook_count, &exp, &policy, &tags, true, "check-pins", start) ? 1 : 0;
}

// The preloaded set ("Lifecycle"): the pinned programs of every hook, the installed object's, over
// maps holding no record and a zero configuration, which is what a zeroed policy expects.
static int cmd_check_preloaded(int argc, char **argv)
{
	int prog_fds[POLICY_HOOKS];
	struct expectation exp;
	struct policy policy;
	struct tags tags;
	double start = now_ms();

	if (argc < 2)
		die("usage: check-preloaded PINDIR --tags FILE HOOK...");
	parse_expectation(argc - 1, argv + 1, &exp, "check-preloaded");
	if (!exp.tags_path)
		die("check-preloaded: --tags is required");
	if (!relative_beneath(PIN_FS, argv[0]))
		die("pindir %s is not under %s", argv[0], PIN_FS);
	read_tags(exp.tags_path, &tags);
	memset(&policy, 0, sizeof(policy));
	for (int i = 0; i < exp.hook_count; i++) {
		char pin[PATH_MAX];

		snprintf(pin, sizeof(pin), "%s/progs/%s", argv[0], exp.hooks[i]);
		prog_fds[i] = bpf_obj_get(pin);
		if (prog_fds[i] < 0) {
			printf("check-preloaded ok=0 reason=missing-pin pin=%s error=%s\n", pin, strerror(errno));
			return 1;
		}
	}
	return verify_programs(prog_fds, exp.hook_count, &exp, &policy, &tags, false, "check-preloaded",
			       start) ? 1 : 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (argc < 2)
		die("usage: see the header of readback.c");
	if (!strcmp(argv[1], "tags") && argc == 4)
		return cmd_tags(argv[2], argv[3]);
	if (!strcmp(argv[1], "verify"))
		return cmd_verify(argc - 2, argv + 2);
	if (!strcmp(argv[1], "check-pins"))
		return cmd_check_pins(argc - 2, argv + 2);
	if (!strcmp(argv[1], "check-preloaded"))
		return cmd_check_preloaded(argc - 2, argv + 2);
	die("unknown subcommand %s", argv[1]);
}
