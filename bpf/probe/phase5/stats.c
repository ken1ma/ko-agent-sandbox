// Phase 5 of doc/plan-bpf-lsm-cgroup.md: the program's own counters, read from the stats map the
// session's programs share, zeroed before each measured workload and read after it, so that each
// workload's figure comes with the number of calls each hook judged and the time the program took
// in them. Phase 3's controller has the same two commands; the launcher's
// (bpf/ko-agent-bpf/controller.c) has not, since no launch reads the counters.
//
//   stats read PIN     one line per hook: calls, decisions, walks, retries, the mean and maximum time
//                      from entry to decision over the judged calls (those not ending at the
//                      superblock check)
//   stats reset PIN    zero every hook's counters
//
// PIN is one pinned link of the session, PINDIR/links/file_open; the map is found through the
// program the link holds.

#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PROGRAM_NAME "stats"
#include "backend.h"

// policy.bpf.c's layout; backend.h's map table leaves this map's value size unchecked, so it is checked here.
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

static int stats_fd_of_pin(const char *pin)
{
	struct bpf_link_info linfo = {};
	struct bpf_prog_info pinfo = {};
	__u32 map_ids[16], llen = sizeof(linfo), plen = sizeof(pinfo);
	int link_fd, prog_fd;

	link_fd = bpf_obj_get(pin);
	if (link_fd < 0)
		die("open %s: %s", pin, strerror(errno));
	if (bpf_link_get_info_by_fd(link_fd, &linfo, &llen))
		die("link info: %s", strerror(errno));
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
		if (!strcmp(minfo.name, "stats") && minfo.value_size == sizeof(struct hook_stats))
			return fd;
		close(fd);
	}
	die("the program of %s uses no stats map of %zu bytes a value", pin, sizeof(struct hook_stats));
	return -1;
}

static int cmd_read(const char *pin)
{
	int fd = stats_fd_of_pin(pin);

	for (__u32 key = 0; key < POLICY_HOOKS; key++) {
		struct hook_stats st = {};

		if (bpf_map_lookup_elem(fd, &key, &st))
			die("lookup: %s", strerror(errno));
		printf("stats hook=%s calls=%llu allowed=%llu denied=%llu outside=%llu walks=%llu retries=%llu "
		       "gave_up=%llu max_depth=%llu ns_mean=%llu ns_max=%llu reentry=%llu nested_max=%llu\n",
		       policy_hooks[key], (unsigned long long)st.calls, (unsigned long long)st.allowed,
		       (unsigned long long)st.denied, (unsigned long long)st.outside, (unsigned long long)st.walks,
		       (unsigned long long)st.retries, (unsigned long long)st.gave_up, (unsigned long long)st.max_depth,
		       (unsigned long long)(st.calls > st.outside ? st.ns_sum / (st.calls - st.outside) : 0),
		       (unsigned long long)st.ns_max, (unsigned long long)st.reentry, (unsigned long long)st.nested_max);
	}
	return 0;
}

static int cmd_reset(const char *pin)
{
	int fd = stats_fd_of_pin(pin);
	struct hook_stats st = {};

	for (__u32 key = 0; key < POLICY_HOOKS; key++)
		if (bpf_map_update_elem(fd, &key, &st, BPF_ANY))
			die("update: %s", strerror(errno));
	printf("stats reset ok=1\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "read"))
		return cmd_read(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "reset"))
		return cmd_reset(argv[2]);
	die("usage: stats read|reset PIN");
}
