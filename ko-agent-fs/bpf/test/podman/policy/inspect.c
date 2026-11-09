// The policy suite of ko-agent-fs/bpf/doc/evidence.md: what the suite reads of the program beyond what
// a launch needs. The shipped controller attaches the policy (../../../controller.c), so the corpus runs
// against maps filled as a launch fills them; this tool verifies the object for the verifier's figures
// and reads the program's own maps through a pinned link. Policy.scala runs it through
// `podman machine ssh` under sudo. Each subcommand prints `key=value` lines, which Policy.scala reads.
//
//   inspect load OBJ                  verify every program of OBJ alone, then all together, timed
//   inspect verifier-log OBJ PROG OUT load PROG alone with the verifier's full log written to OUT
//   inspect stats PIN                 the per-hook counters and times
//   inspect reset-stats PIN           zero them
//   inspect guard PIN MASK            mark the scratch slots of MASK (bits 0 to 3) as taken on every
//                                     CPU, for the slot-exhaustion rows; 0 frees them
//   inspect last-decision PIN         the last decision taken
//   inspect jited PIN OUT             PIN's program as jited bytes into OUT, with a barrier scan
//
// PIN is a link the controller pinned, PINDIR/links/HOOK.
#define _GNU_SOURCE
#include <ctype.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define PROGRAM_NAME "inspect"
#include "backend.h"
#include "loader.h"

#define LOG_BYTES (64u << 20)
#define MAX_PROGS 64

// The program's own maps, which backend.h's table leaves uncompared: these copy policy.bpf.c's
// layouts, and map_fd_of_pin refuses a map whose value size differs, so a struct grown in the program
// fails here before a lookup could write past one of these.
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

// policy.bpf.c's `enum reason`, by name.
static const char *const reasons[] = {
	"allow", "outside", "walk-noroot", "walk-bound", "walk-torn", "name-too-long", "git-protected",
	"git-pinned", "git-name", "sandbox-name", "head", "rule-read-only", "rule-pinned", "region",
	"socket", "internal", "reentry", "short-name", "alias-overflow", "symlink-syntax", "symlink-short",
	"symlink-gitdir", "symlink-region", "socket-gitdir", "receive-ns", "receive-dir", "fifo",
};
#define REASONS (sizeof(reasons) / sizeof(reasons[0]))

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

// At log level 4 (BPF_LOG_STATS), the verifier's last three lines are its stats: the time, the
// stack depth and the instructions processed.
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
	print_tag(info.tag);
	printf("\n");
}

// Loads with one program selected, or all when `only` is NULL. Prints the verifier's stats per
// program and the wall time of the load. At `log_level` 1 or 2, the log of `only` goes to
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
		if (!logs[index])
			die("out of memory");
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

			format_or_die(prefix, sizeof(prefix), "verifier name=%s", bpf_program__name(prog));
			if (err == 0 && !log_level)
				print_stats_lines(prefix, logs[index]);
			if (log_out) {
				FILE *file = fopen(log_out, "w");

				if (!file || fputs(logs[index], file) == EOF || fclose(file))
					die("write %s: %s", log_out, strerror(errno));
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
			format_or_die(names[count++], sizeof(names[0]), "%s", bpf_program__name(prog));
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

// The program a pinned link holds, by descriptor.
static int prog_fd_of_pin(const char *pin)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	int link_fd = bpf_obj_get(pin), prog_fd;

	if (link_fd < 0)
		die("open pin %s: %s", pin, strerror(errno));
	if (bpf_link_get_info_by_fd(link_fd, &info, &len))
		die("link info %s: %s", pin, strerror(errno));
	close(link_fd);
	prog_fd = bpf_prog_get_fd_by_id(info.prog_id);
	if (prog_fd < 0)
		die("prog %u: %s", info.prog_id, strerror(errno));
	return prog_fd;
}

// The map a pinned link's program uses, found as the read-back finds it: take the program's map ids,
// open each by id, and select one by name. Its value must be `value_size` bytes.
static int map_fd_of_pin(const char *pin, const char *map_name, __u32 value_size)
{
	struct bpf_prog_info pinfo = {};
	__u32 map_ids[16], plen = sizeof(pinfo);
	int prog_fd = prog_fd_of_pin(pin);

	pinfo.nr_map_ids = 16;
	pinfo.map_ids = (__u64)(uintptr_t)map_ids;
	if (bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen))
		die("prog info: %s", strerror(errno));
	close(prog_fd);
	if (pinfo.nr_map_ids > 16)
		die("the program of %s references %u maps, more than 16", pin, pinfo.nr_map_ids);
	for (__u32 i = 0; i < pinfo.nr_map_ids; i++) {
		struct bpf_map_info minfo = {};
		__u32 mlen = sizeof(minfo);
		int fd = bpf_map_get_fd_by_id(map_ids[i]);

		if (fd < 0)
			die("map %u: %s", map_ids[i], strerror(errno));
		if (bpf_map_get_info_by_fd(fd, &minfo, &mlen))
			die("map info: %s", strerror(errno));
		if (!strcmp(minfo.name, map_name)) {
			if (minfo.value_size != value_size)
				die("map %s holds values of %u bytes, this tool reads %u", map_name, minfo.value_size,
				    value_size);
			return fd;
		}
		close(fd);
	}
	die("program of %s uses no map %s", pin, map_name);
}

static void print_name(const char *name, size_t size)
{
	for (size_t i = 0; i < size && name[i]; i++)
		putchar(isprint((unsigned char)name[i]) && name[i] != ' ' ? name[i] : '?');
}

static int cmd_stats(const char *pin)
{
	int fd = map_fd_of_pin(pin, "stats", sizeof(struct hook_stats));

	for (__u32 key = 0; key < POLICY_HOOKS; key++) {
		struct hook_stats st = {};

		if (bpf_map_lookup_elem(fd, &key, &st))
			die("lookup: %s", strerror(errno));
		// ns_mean and ns_max cover the judged calls: those that do not end at the superblock
		// check.
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

// Sets the per-CPU guard word on every CPU. A per-CPU map takes one value per possible CPU.
static int cmd_guard(const char *pin, const char *mask_text)
{
	int fd = map_fd_of_pin(pin, "guard", sizeof(__u64));
	int cpus = libbpf_num_possible_cpus();
	__u64 *values;
	__u32 zero = 0;
	char *end;
	unsigned long mask;

	errno = 0;
	mask = strtoul(mask_text, &end, 0);
	if (errno || end == mask_text || *end || mask > 0xf)
		die("guard: the mask %s is not a number from 0 to 0xf", mask_text);
	if (cpus <= 0)
		die("possible cpus: %s", strerror(-cpus));
	values = calloc(cpus, sizeof(*values));
	if (!values)
		die("out of memory");
	for (int i = 0; i < cpus; i++)
		values[i] = mask;
	if (bpf_map_update_elem(fd, &zero, values, BPF_ANY))
		die("guard update: %s", strerror(errno));
	free(values);
	printf("guard mask=0x%lx cpus=%d\n", mask, cpus);
	return 0;
}

static int cmd_reset_stats(const char *pin)
{
	int fd = map_fd_of_pin(pin, "stats", sizeof(struct hook_stats));
	struct hook_stats st = {};

	for (__u32 key = 0; key < POLICY_HOOKS; key++)
		if (bpf_map_update_elem(fd, &key, &st, BPF_ANY))
			die("update: %s", strerror(errno));
	printf("reset-stats ok=1\n");
	return 0;
}

static int cmd_last_decision(const char *pin)
{
	int fd = map_fd_of_pin(pin, "last_decision", sizeof(struct last_decision));
	struct last_decision last = {};
	__u32 zero = 0;

	if (bpf_map_lookup_elem(fd, &zero, &last))
		die("lookup: %s", strerror(errno));
	printf("last-decision count=%llu hook=%s reason=%s depth=%u root=%s name=",
	       (unsigned long long)last.count, last.hook < POLICY_HOOKS ? policy_hooks[last.hook] : "?",
	       last.reason < REASONS ? reasons[last.reason] : "?", last.depth,
	       last.root_kind < ROOT_KINDS ? root_kinds[last.root_kind] : "?");
	print_name(last.name, sizeof(last.name));
	if (last.hook < POLICY_HOOKS && !strcmp(policy_hooks[last.hook], "file_receive")) {
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

// Scans the jited program's bytes for the barrier instruction the design expects on each
// architecture (doc/bpf-lsm-cgroup.md, "What is gained and what is lost"):
//
// - arm64: `ldaddal` (LSE; 64-bit 0xf8e0xxxx, 32-bit 0xb8e0xxxx), or `dmb ish` (0xd5033bbf) on the
//   LL/SC path;
// - x86-64: `lock xadd` (f0 [4x] 0f c1, with any REX prefix; scanning for the `REX.W` form alone
//   found only one of three on WSL, "Policy on WSL").
//
// The xlated program is scanned for the atomic fetch-add instruction itself
// (BPF_STX|BPF_DW|BPF_ATOMIC, imm BPF_ADD|BPF_FETCH).
static int cmd_jited(const char *pin, const char *out)
{
	struct bpf_prog_info sizes = {}, info = {};
	__u32 len = sizeof(sizes);
	int prog_fd = prog_fd_of_pin(pin);
	unsigned char *jited, *xlated;
	unsigned ldaddal = 0, dmb = 0, lock_xadd = 0, fetch_add = 0;
	FILE *file;

	if (bpf_prog_get_info_by_fd(prog_fd, &sizes, &len))
		die("prog info: %s", strerror(errno));
	jited = calloc(1, sizes.jited_prog_len + 1);
	xlated = calloc(1, sizes.xlated_prog_len + 1);
	if (!jited || !xlated)
		die("out of memory");
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
	if (!file || fwrite(jited, 1, info.jited_prog_len, file) != info.jited_prog_len || fclose(file))
		die("write %s: %s", out, strerror(errno));
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (argc < 2)
		die("usage: see the header of inspect.c");
	if (!strcmp(argv[1], "load") && argc == 3)
		return cmd_load(argv[2]);
	if (!strcmp(argv[1], "verifier-log") && argc == 5)
		return cmd_verifier_log(argv[2], argv[3], argv[4]);
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
	die("unknown subcommand %s", argv[1]);
}
