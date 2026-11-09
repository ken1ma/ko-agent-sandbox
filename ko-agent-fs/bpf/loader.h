// The BPF cgroup-LSM backend of ko-agent-fs/bpf/doc/architecture.md: what the programs that call
// libbpf share: the controller, the read-back and the policy suite's inspect.c. backend.h holds
// what the fixture shares too, which links no libbpf. Include this after backend.h and libbpf's
// headers.
#ifndef LOADER_H
#define LOADER_H

#include <libgen.h>

// The object's path, beside the binary (/proc/self/exe), never a given one ("Native Linux"). NAME is
// its file name; a name with a `/` refuses.
static inline void object_path(const char *name, char *out, size_t size)
{
	char exe[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

	if (len < 0)
		die("readlink /proc/self/exe: %s", strerror(errno));
	exe[len] = 0;
	if (strchr(name, '/'))
		refuse("object-path", "object=%s", name);
	format_or_die(out, size, "%s/%s", dirname(exe), name);
}

static inline struct btf *vmlinux_btf(void)
{
	static struct btf *btf;

	if (!btf) {
		btf = btf__load_vmlinux_btf();
		if (!btf)
			die("vmlinux BTF: %s", strerror(errno));
	}
	return btf;
}

// The ids of the programs attached to the cgroup at `cgroup_fd`, of every hook together, into `ids`
// of `max` entries; returns their count. BPF_PROG_QUERY with BPF_LSM_CGROUP needs the attach-flags
// buffer beside the ids, or it fails with EINVAL (kernel/bpf/cgroup.c, __cgroup_bpf_query).
static inline __u32 attached_programs(int cgroup_fd, __u32 *ids, __u32 max)
{
	LIBBPF_OPTS(bpf_prog_query_opts, opts);
	__u32 flags[64];

	if (max > 64)
		die("attached_programs: at most 64 ids");
	if (bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &opts))
		die("prog query: %s", strerror(errno));
	if (opts.prog_cnt > max)
		die("more than %u programs attached", max);
	if (!opts.prog_cnt)
		return 0;
	opts.prog_ids = ids;
	opts.prog_attach_flags = flags;
	opts.count = max;
	if (bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &opts))
		die("prog query: %s", strerror(errno));
	return opts.prog_cnt;
}

#endif
