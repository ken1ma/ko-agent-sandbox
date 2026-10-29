// Phase 4 of doc/plan-bpf-lsm-cgroup.md: a write from user space to each record map of an attached
// session, as a stray tool of the machine's root would make one, and to `stats`, which stays
// writable, as the control. Each map's first entry is read and written back unchanged, so a write
// the kernel allows changes no decision either.
//
//   rewrite PIN    one line per map: `rewrite map=NAME result=ok`, or the errno's name
//
// PIN is one pinned program of the session, PINDIR/progs/file_open. The other maps are left out:
// the program writes them, and a write-back could replace its updates with an older value. For
// `stats`, which the program writes too, that discards the counts between the read and the write;
// no row reads them.

#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PROGRAM_NAME "rewrite"
#include "backend.h"

#define MAX_VALUE 65536

static void rewrite_first(int fd, const struct bpf_map_info *info)
{
	static unsigned char key[256], value[MAX_VALUE];
	int err = 0;

	if (info->key_size > sizeof(key) || info->value_size > sizeof(value))
		die("map %s: key %u or value %u too large", info->name, info->key_size, info->value_size);
	if (info->type == BPF_MAP_TYPE_HASH) {
		if (bpf_map_get_next_key(fd, NULL, key))
			die("map %s holds no entry: %s", info->name, strerror(errno));
	} else {
		memset(key, 0, info->key_size);
	}
	if (bpf_map_lookup_elem(fd, key, value))
		die("map %s lookup: %s", info->name, strerror(errno));
	if (bpf_map_update_elem(fd, key, value, BPF_EXIST))
		err = errno;
	printf("rewrite map=%s result=%s\n", info->name, err ? strerrorname_np(err) : "ok");
}

int main(int argc, char **argv)
{
	struct bpf_prog_info pinfo = {};
	__u32 map_ids[16], plen = sizeof(pinfo);
	int prog_fd;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc != 2)
		die("usage: see the header of rewrite.c");
	prog_fd = bpf_obj_get(argv[1]);
	if (prog_fd < 0)
		die("open %s: %s", argv[1], strerror(errno));
	pinfo.nr_map_ids = 16;
	pinfo.map_ids = (__u64)(uintptr_t)map_ids;
	if (bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen))
		die("prog info: %s", strerror(errno));
	if (pinfo.nr_map_ids > 16)
		die("the program references more than 16 maps");
	for (__u32 i = 0; i < pinfo.nr_map_ids; i++) {
		struct bpf_map_info info = {};
		__u32 len = sizeof(info);
		int fd = bpf_map_get_fd_by_id(map_ids[i]);

		if (fd < 0)
			die("map %u: %s", map_ids[i], strerror(errno));
		if (bpf_map_get_info_by_fd(fd, &info, &len))
			die("map info %u: %s", map_ids[i], strerror(errno));
		for (unsigned k = 0; k < POLICY_MAPS; k++)
			if (!strcmp(info.name, policy_maps[k].name) &&
			    (policy_maps[k].records || !strcmp(info.name, "stats")))
				rewrite_first(fd, &info);
		close(fd);
	}
	return 0;
}
