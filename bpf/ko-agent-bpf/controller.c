// The BPF cgroup-LSM backend of doc/plan-bpf-lsm-cgroup.md: the privileged side, the launcher's
// controller ("Lifecycle", 2, 5, 6 and 7). It loads policy.bpf.o from beside itself and never from
// a path, fills the maps from the guard's records file and the identities it reads for itself,
// attaches by link below the invoking user's slice alone, pins the links and the programs, keeps a
// spare program set verified ahead of the launches, attaches pinned programs again for a restart,
// and reconciles pins and cgroups at a launcher's start. The launcher (KoAgentBpf.scala) and the
// Phase 4 and 5 probes drive it through `podman machine ssh` under sudo; each subcommand prints
// `key=value` lines. Exit status 3 is a refusal (`refused reason=...`), 2 a failure.
//
//   controller attach CGROUP PINDIR --records FILE --workspace PATH [--fixture PATH] [--volume PATH]
//                    [--flags F,F] [--object NAME] [--bind-source PATH] [--spare DIR] [--no-root] HOOK...
//                                        load the object, fill the maps from FILE (the guard's
//                                        `--bpf-records`; fixture.c writes one for the probes) with
//                                        the roots' identities, attach HOOK... to CGROUP by link, pin
//                                        each link at PINDIR/links/HOOK and each program at
//                                        PINDIR/progs/HOOK. --object names another object beside the
//                                        binary, the probe's defective controller; --bind-source
//                                        refuses the launch when a mount lies below PATH; --spare
//                                        takes the spare set pinned under DIR by renaming DIR to
//                                        PINDIR and fills its maps through the pinned programs,
//                                        loading nothing, and loads as without it when DIR is gone;
//                                        --no-root is a read-only session's policy (backend.h)
//   controller prepare-spare PINDIR      load the object with every program, maps empty, and pin the
//                                        programs at PINDIR/progs/HOOK: the spare a launch takes
//   controller attach-pinned CGROUP PINDIR HOOK...
//                                        attach the pinned programs to a new cgroup, loading nothing
//   controller query CGROUP              the programs attached to CGROUP, and every lsm_cgroup link
//   controller link-info PIN             a pinned link's id, program and cgroup id (0 once detached)
//   controller statx PATH                PATH's identity as the plan's controller records it
//   controller unpin PINDIR              remove every pin under PINDIR
//   controller reconcile PINROOT --manager systemd|cgroupfs [--listing-failed] [--named NAME]...
//                       [--hold NAME]... [--session NAME CGROUP ID]...
//                                        for each recorded session whose cgroup no container names
//                                        (--named) and whose identity no label contradicts (--hold):
//                                        remove its pins and its cgroup when the cgroup's identity is
//                                        ID, it reads populated 0 and every pin names it, checking all
//                                        of them before removing any; refuse anything else
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define PROGRAM_NAME "controller"
#include "backend.h"

#define MAX_SESSIONS 64

// The object is found beside the binary (/proc/self/exe) and never taken as a path ("Native
// Linux"); NAME is its file name.
static struct bpf_object *open_object(const char *name)
{
	char exe[PATH_MAX], path[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	struct bpf_object *obj;

	if (len < 0)
		die("readlink /proc/self/exe: %s", strerror(errno));
	exe[len] = 0;
	if (strchr(name, '/'))
		refuse("object-path", "object=%s", name);
	snprintf(path, sizeof(path), "%s/%s", dirname(exe), name);
	obj = bpf_object__open_file(path, NULL);
	if (!obj)
		die("open %s: %s", path, strerror(errno));
	return obj;
}

static int map_fd_by_name(struct bpf_object *obj, const char *name)
{
	int fd = bpf_object__find_map_fd_by_name(obj, name);

	if (fd < 0)
		die("no map %s in the object", name);
	return fd;
}

// bpffs refuses a name holding a `.` with EPERM at the lookup (kernel/bpf/inode.c, bpf_lookup:
// reserved for its own special files), so a pin path below the mount may hold none.
static void require_pin_dir(const char *pindir)
{
	const char *rel = relative_beneath(PIN_FS, pindir);

	if (!rel)
		refuse("pindir-outside-bpffs", "pindir=%s", pindir);
	if (strchr(rel, '.'))
		refuse("pindir-dotted", "pindir=%s", pindir);
}

static void print_link(const char *hook, int link_fd)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);

	if (bpf_link_get_info_by_fd(link_fd, &info, &len))
		die("link info: %s", strerror(errno));
	printf("link hook=%s link_id=%u prog_id=%u cgroup_id=%llu\n", hook, info.id, info.prog_id,
	       (unsigned long long)info.cgroup.cgroup_id);
}

// The pin directory with its `links` and `progs`, and the pin root above it, which a fresh
// install and every machine boot leave absent: bpffs holds nothing across a boot.
static void make_pin_dirs(const char *pindir)
{
	char path[PATH_MAX], parent[PATH_MAX];
	char *slash;

	snprintf(parent, sizeof(parent), "%s", pindir);
	slash = strrchr(parent, '/');
	if (slash && slash != parent) {
		*slash = 0;
		if (strcmp(parent, PIN_FS) && mkdir(parent, 0700) && errno != EEXIST)
			die("mkdir %s: %s", parent, strerror(errno));
	}
	if (mkdir(pindir, 0700) && errno != EEXIST)
		die("mkdir %s: %s", pindir, strerror(errno));
	snprintf(path, sizeof(path), "%s/links", pindir);
	if (mkdir(path, 0700) && errno != EEXIST)
		die("mkdir %s: %s", path, strerror(errno));
	snprintf(path, sizeof(path), "%s/progs", pindir);
	if (mkdir(path, 0700) && errno != EEXIST)
		die("mkdir %s: %s", path, strerror(errno));
}

// The map descriptors a fill writes: by name out of a loaded object, or out of the maps a pinned
// program references, for the spare.
struct fill_maps {
	int roots, rules, aliases, config;
};

static void fill_policy(const struct fill_maps *maps, const struct policy *policy)
{
	__u32 zero = 0;

	for (int i = 0; i < policy->root_count; i++) {
		if (bpf_map_update_elem(maps->roots, &policy->idents[i], &policy->roots[i], BPF_ANY))
			die("roots update: %s", strerror(errno));
		printf("root kind=%s path=%s mkdev=%llu ino=%llu\n", root_kinds[policy->roots[i].kind],
		       policy->root_paths[i], (unsigned long long)policy->idents[i].s_dev,
		       (unsigned long long)policy->idents[i].i_ino);
	}
	for (__u32 i = 0; i < policy->cfg.rule_count; i++)
		if (bpf_map_update_elem(maps->rules, &i, &policy->rec.rules[i], BPF_ANY))
			die("rules update: %s", strerror(errno));
	for (__u32 i = 0; policy->cfg.rule_count && i < policy->rec.header.alias_count; i++)
		if (bpf_map_update_elem(maps->aliases, &i, &policy->rec.aliases[i], BPF_ANY))
			die("aliases update: %s", strerror(errno));
	if (bpf_map_update_elem(maps->config, &zero, &policy->cfg, BPF_ANY))
		die("config update: %s", strerror(errno));
}

static void pin_link(struct bpf_link *link, const char *pindir, const char *hook)
{
	char pin[PATH_MAX];

	snprintf(pin, sizeof(pin), "%s/links/%s", pindir, hook);
	if (bpf_link__pin(link, pin))
		die("pin %s: %s", pin, strerror(errno));
	print_link(hook, bpf_link__fd(link));
}

// The maps the spare's pinned programs reference, by name through their ids: the fill writes the
// same objects the programs read ("Lifecycle", the spare set).
static void spare_maps(int prog_fd, struct fill_maps *maps)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info), ids[32];

	info.nr_map_ids = 32;
	info.map_ids = (__u64)(uintptr_t)ids;
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len))
		die("prog info: %s", strerror(errno));
	if (info.nr_map_ids > 32)
		die("a pinned program references more than 32 maps");
	maps->roots = maps->rules = maps->aliases = maps->config = -1;
	for (__u32 i = 0; i < info.nr_map_ids; i++) {
		struct bpf_map_info minfo = {};
		__u32 mlen = sizeof(minfo);
		int fd = bpf_map_get_fd_by_id(ids[i]);

		if (fd < 0)
			die("map %u: %s", ids[i], strerror(errno));
		if (bpf_map_get_info_by_fd(fd, &minfo, &mlen))
			die("map info %u: %s", ids[i], strerror(errno));
		if (!strcmp(minfo.name, "roots"))
			maps->roots = fd;
		else if (!strcmp(minfo.name, "rules"))
			maps->rules = fd;
		else if (!strcmp(minfo.name, "aliases"))
			maps->aliases = fd;
		else if (!strcmp(minfo.name, "policy_config"))
			maps->config = fd;
		else
			close(fd);
	}
	if (maps->roots < 0 || maps->rules < 0 || maps->aliases < 0 || maps->config < 0)
		die("the spare's programs reference no complete map set");
}

static int cmd_attach(int argc, char **argv)
{
	const char *cgroup, *pindir;
	struct expectation exp;
	int cgroup_fd;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct policy policy;
	struct fill_maps maps;
	double start, loaded, filled, attached;
	bool from_spare = false;

	if (argc < 3)
		die("usage: attach CGROUP PINDIR [options] HOOK...");
	cgroup = argv[0];
	pindir = argv[1];
	parse_expectation(argc - 2, argv + 2, &exp, "attach");
	if (!exp.workspace)
		die("attach: --workspace is required");
	require_pin_dir(pindir);
	// The refusals come before any load: the cgroup, the bind source's mounts, the fixture's type.
	cgroup_fd = open_cgroup(cgroup);
	if (exp.bind_source) {
		char mount[PATH_MAX];
		int below = mounts_below(exp.bind_source, mount, sizeof(mount));

		if (below)
			refuse("mount-under-bind-source", "bind_source=%s mounts=%d first=%s", exp.bind_source, below,
			       mount);
	}
	expect_policy(&policy, exp.records, exp.workspace, exp.fixture, exp.volume, exp.flags, exp.no_root);
	start = now_ms();
	// The spare, taken by one rename: of two launches racing for it, one finds it gone and loads.
	if (exp.spare) {
		require_pin_dir(exp.spare);
		if (!rename(exp.spare, pindir))
			from_spare = true;
		else if (errno != ENOENT)
			die("rename %s to %s: %s", exp.spare, pindir, strerror(errno));
		else
			printf("spare taken=0 reason=absent spare=%s\n", exp.spare);
	}
	if (from_spare) {
		char pin[PATH_MAX];
		int prog_fd;

		snprintf(pin, sizeof(pin), "%s/progs/%s", pindir, exp.hooks[0]);
		prog_fd = bpf_obj_get(pin);
		if (prog_fd < 0)
			die("no pinned program %s in the spare: %s", pin, strerror(errno));
		spare_maps(prog_fd, &maps);
		close(prog_fd);
		printf("spare taken=1 spare=%s\n", exp.spare);
	} else {
		obj = open_object(exp.object);
		for (int i = 0; i < exp.hook_count; i++)
			if (!bpf_object__find_program_by_name(obj, exp.hooks[i]))
				die("attach: no program %s in %s", exp.hooks[i], exp.object);
		bpf_object__for_each_program(prog, obj) {
			bool selected = false;

			for (int i = 0; i < exp.hook_count; i++)
				selected |= !strcmp(bpf_program__name(prog), exp.hooks[i]);
			bpf_program__set_autoload(prog, selected);
		}
		if (bpf_object__load(obj))
			die("load: %s", strerror(errno));
		maps.roots = map_fd_by_name(obj, "roots");
		maps.rules = map_fd_by_name(obj, "rules");
		maps.aliases = map_fd_by_name(obj, "aliases");
		maps.config = map_fd_by_name(obj, "policy_config");
	}
	loaded = now_ms();
	// The records, written before the attach and never after ("The policy").
	fill_policy(&maps, &policy);
	filled = now_ms();
	make_pin_dirs(pindir);
	for (int i = 0; i < exp.hook_count; i++) {
		struct bpf_link *link;
		char pin[PATH_MAX];

		if (from_spare) {
			int prog_fd, link_fd;

			snprintf(pin, sizeof(pin), "%s/progs/%s", pindir, exp.hooks[i]);
			prog_fd = bpf_obj_get(pin);
			if (prog_fd < 0)
				die("no pinned program %s in the spare: %s", pin, strerror(errno));
			link_fd = bpf_link_create(prog_fd, cgroup_fd, BPF_LSM_CGROUP, NULL);
			if (link_fd < 0)
				die("attach %s: %s", exp.hooks[i], strerror(errno));
			snprintf(pin, sizeof(pin), "%s/links/%s", pindir, exp.hooks[i]);
			if (bpf_obj_pin(link_fd, pin))
				die("pin %s: %s", pin, strerror(errno));
			print_link(exp.hooks[i], link_fd);
			close(link_fd);
			close(prog_fd);
			continue;
		}
		prog = bpf_object__find_program_by_name(obj, exp.hooks[i]);
		link = bpf_program__attach_cgroup(prog, cgroup_fd);
		if (!link)
			die("attach %s: %s", exp.hooks[i], strerror(errno));
		snprintf(pin, sizeof(pin), "%s/progs/%s", pindir, exp.hooks[i]);
		if (bpf_program__pin(prog, pin))
			die("pin %s: %s", pin, strerror(errno));
		pin_link(link, pindir, exp.hooks[i]);
	}
	attached = now_ms();
	printf("attach cgroup=%s pindir=%s object=%s spare=%d hooks=%d rule_count=%u aliases=%u roots=%d fs_type=%s "
	       "vol_fs_type=%s flags=%u no_root=%d runtime_mnt_ns=%u load_ms=%.1f fill_ms=%.1f attach_ms=%.1f "
	       "total_ms=%.1f\n",
	       cgroup, pindir, exp.object, from_spare, exp.hook_count, policy.cfg.rule_count,
	       policy.cfg.rule_count ? policy.rec.header.alias_count : 0, policy.root_count, policy.cfg.fs_type,
	       policy.cfg.vol_fs_type, policy.cfg.flags, exp.no_root, policy.cfg.runtime_mnt_ns, loaded - start,
	       filled - loaded, attached - filled, attached - start);
	return 0;
}

static int cmd_unpin(const char *pindir);

// The spare set ("Lifecycle"): every program of the object loaded and verified with empty maps,
// the programs pinned and attached to nothing, for a launch to take by renaming PINDIR. Pinned
// under a directory of this process's own, PINDIR-<pid>, and published whole by one rename, so no
// launch or reconcile sees a set with programs still missing; a spare already present wins, and
// this one is unpinned.
static int cmd_prepare_spare(const char *pindir)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	double start = now_ms();
	int count = 0;
	struct stat st;
	char staging[PATH_MAX];

	require_pin_dir(pindir);
	if (!lstat(pindir, &st))
		refuse("spare-present", "pindir=%s", pindir);
	snprintf(staging, sizeof(staging), "%s-%d", pindir, getpid());
	obj = open_object("policy.bpf.o");
	if (bpf_object__load(obj))
		die("load: %s", strerror(errno));
	make_pin_dirs(staging);
	bpf_object__for_each_program(prog, obj) {
		char pin[PATH_MAX];

		snprintf(pin, sizeof(pin), "%s/progs/%s", staging, bpf_program__name(prog));
		if (bpf_program__pin(prog, pin))
			die("pin %s: %s", pin, strerror(errno));
		count++;
	}
	if (rename(staging, pindir)) {
		int err = errno;

		cmd_unpin(staging);
		if (err == EEXIST || err == ENOTEMPTY)
			refuse("spare-present", "pindir=%s staging=%s", pindir, staging);
		die("rename %s to %s: %s", staging, pindir, strerror(err));
	}
	printf("spare pindir=%s programs=%d load_ms=%.1f\n", pindir, count, now_ms() - start);
	return 0;
}

// A restart or recreate ("Lifecycle", 5): the pinned programs, verified at the launch, attached to
// the new cgroup by new links; the old links, detached when their cgroup went, are unpinned.
static int cmd_attach_pinned(int argc, char **argv)
{
	const char *cgroup, *pindir;
	int cgroup_fd;
	double start;

	if (argc < 3)
		die("usage: attach-pinned CGROUP PINDIR HOOK...");
	cgroup = argv[0];
	pindir = argv[1];
	for (int i = 2; i < argc; i++)
		hook_index(argv[i]);
	require_pin_dir(pindir);
	cgroup_fd = open_cgroup(cgroup);
	start = now_ms();
	for (int i = 2; i < argc; i++) {
		char pin[PATH_MAX];
		int prog_fd, link_fd;

		snprintf(pin, sizeof(pin), "%s/progs/%s", pindir, argv[i]);
		prog_fd = bpf_obj_get(pin);
		if (prog_fd < 0)
			die("no pinned program %s: %s", pin, strerror(errno));
		link_fd = bpf_link_create(prog_fd, cgroup_fd, BPF_LSM_CGROUP, NULL);
		if (link_fd < 0)
			die("attach pinned %s: %s", argv[i], strerror(errno));
		snprintf(pin, sizeof(pin), "%s/links/%s", pindir, argv[i]);
		if (unlink(pin) && errno != ENOENT)
			die("unlink %s: %s", pin, strerror(errno));
		if (bpf_obj_pin(link_fd, pin))
			die("pin %s: %s", pin, strerror(errno));
		print_link(argv[i], link_fd);
		close(link_fd);
		close(prog_fd);
	}
	printf("attach-pinned cgroup=%s pindir=%s hooks=%d ms=%.1f\n", cgroup, pindir, argc - 2, now_ms() - start);
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
	print_tag(info.tag);
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
				       (unsigned long long)info.cgroup.cgroup_id, btf_func_name(pinfo.attach_btf_id));
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

static int cmd_link_info(const char *pin)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	int fd = bpf_obj_get(pin);

	if (fd < 0)
		die("open pin %s: %s", pin, strerror(errno));
	if (bpf_link_get_info_by_fd(fd, &info, &len))
		die("link info %s: %s", pin, strerror(errno));
	printf("link-info pin=%s id=%u type=%u prog_id=%u cgroup_id=%llu attach_type=%u\n", pin, info.id, info.type,
	       info.prog_id, (unsigned long long)info.cgroup.cgroup_id, info.cgroup.attach_type);
	close(fd);
	return 0;
}

static int cmd_statx(const char *path)
{
	struct ident id;
	struct statfs sfs;
	char type[FS_TYPE_BYTES];

	ident_of(path, &id);
	if (statfs(path, &sfs))
		die("statfs %s: %s", path, strerror(errno));
	fs_type_of(path, type, sizeof(type));
	printf("statx path=%s major=%u minor=%u mkdev=%llu ino=%llu fs_magic=0x%lx fs_type=%s\n", path,
	       (unsigned)(id.s_dev >> 20), (unsigned)(id.s_dev & 0xfffff), (unsigned long long)id.s_dev,
	       (unsigned long long)id.i_ino, (unsigned long)sfs.f_type, type);
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

// --- The reconcile ("Lifecycle", 7) ---------------------------------------------------------------

struct session {
	const char *name;
	const char *cgroup;
	unsigned long long cgroup_id;
};

// The session's pin directory under the pin root: bpffs refuses a dotted name (require_pin_dir),
// and a container name carries the workspace directory's, so the launcher and this map `.` to `_`
// (KoAgentBpf.pinDir); the record and the cgroup keep the name.
static void pin_name(const char *session, char *out, size_t size)
{
	snprintf(out, size, "%s", session);
	for (char *at = out; *at; at++)
		if (*at == '.')
			*at = '_';
}

static bool named_in(const char *name, const char **names, int count)
{
	for (int i = 0; i < count; i++)
		if (!strcmp(names[i], name))
			return true;
	return false;
}

static bool one_component(const char *name)
{
	return name[0] && !strchr(name, '/') && strcmp(name, ".") && strcmp(name, "..");
}

#define MAX_PINS 32

struct pin_dir {
	int fd;                         // -1 when the directory is absent
	char names[MAX_PINS][64];
	int count;
};

// Opens one directory of the session's pins (`links` or `progs`) through the pins directory's own
// descriptor and checks every entry, each link against the session's cgroup; removes nothing.
// Returns 0, or -1 after printing the refusal.
static int check_pins(int pins_fd, const char *sub, unsigned long long cgroup_id, const char *name,
		      struct pin_dir *dir)
{
	DIR *stream;
	struct dirent *entry;

	dir->count = 0;
	dir->fd = open_beneath(pins_fd, sub, O_RDONLY | O_DIRECTORY);
	if (dir->fd < 0) {
		if (errno == ENOENT)
			return 0;
		printf("reconcile session=%s action=refused reason=pins-open path=%s error=%s\n", name, sub,
		       strerror(errno));
		return -1;
	}
	stream = fdopendir(dup(dir->fd));
	if (!stream)
		die("fdopendir: %s", strerror(errno));
	while ((entry = readdir(stream))) {
		LIBBPF_OPTS(bpf_obj_get_opts, opts, .path_fd = dir->fd, .file_flags = BPF_F_PATH_FD);
		int fd;

		if (entry->d_name[0] == '.')
			continue;
		if (dir->count >= MAX_PINS || strlen(entry->d_name) >= sizeof(dir->names[0])) {
			printf("reconcile session=%s action=refused reason=pins-too-many path=%s\n", name, sub);
			closedir(stream);
			return -1;
		}
		fd = bpf_obj_get_opts(entry->d_name, &opts);
		if (fd < 0) {
			printf("reconcile session=%s action=refused reason=pin-open path=%s/%s error=%s\n", name, sub,
			       entry->d_name, strerror(errno));
			closedir(stream);
			return -1;
		}
		if (!strcmp(sub, "links")) {
			struct bpf_link_info info = {};
			__u32 len = sizeof(info);

			if (bpf_link_get_info_by_fd(fd, &info, &len))
				die("link info: %s", strerror(errno));
			// A detached link reads cgroup_id 0: its cgroup is gone already.
			if (info.cgroup.cgroup_id && info.cgroup.cgroup_id != cgroup_id) {
				printf("reconcile session=%s action=refused reason=pin-names-another-cgroup path=%s/%s "
				       "pin_cgroup_id=%llu recorded=%llu\n",
				       name, sub, entry->d_name, (unsigned long long)info.cgroup.cgroup_id, cgroup_id);
				close(fd);
				closedir(stream);
				return -1;
			}
		}
		close(fd);
		strcpy(dir->names[dir->count++], entry->d_name);
	}
	closedir(stream);
	return 0;
}

// Removes the checked pins of one directory and the directory; only after every directory of the
// session passed its check, so that a refusal removes nothing.
static void delete_pins(int pins_fd, const char *sub, const struct pin_dir *dir)
{
	if (dir->fd < 0)
		return;
	for (int i = 0; i < dir->count; i++)
		if (unlinkat(dir->fd, dir->names[i], 0))
			die("unlink %s/%s: %s", sub, dir->names[i], strerror(errno));
	if (unlinkat(pins_fd, sub, AT_REMOVEDIR))
		die("rmdir %s: %s", sub, strerror(errno));
}

static int cmd_reconcile(int argc, char **argv)
{
	const char *pinroot, *manager = NULL, *named[MAX_SESSIONS], *hold[MAX_SESSIONS];
	struct session sessions[MAX_SESSIONS];
	int named_count = 0, hold_count = 0, session_count = 0, removed = 0, kept = 0, refused = 0;
	bool listing_failed = false;
	int bpffs_fd, slice_fd;
	const char *pinroot_rel;

	if (argc < 1)
		die("usage: reconcile PINROOT --manager M [options]");
	pinroot = argv[0];
	for (int i = 1; i < argc;) {
		if (!strcmp(argv[i], "--manager") && i + 1 < argc) {
			manager = argv[i + 1];
			i += 2;
		} else if (!strcmp(argv[i], "--listing-failed")) {
			listing_failed = true;
			i++;
		} else if (!strcmp(argv[i], "--named") && i + 1 < argc && named_count < MAX_SESSIONS) {
			named[named_count++] = argv[i + 1];
			i += 2;
		} else if (!strcmp(argv[i], "--hold") && i + 1 < argc && hold_count < MAX_SESSIONS) {
			hold[hold_count++] = argv[i + 1];
			i += 2;
		} else if (!strcmp(argv[i], "--session") && i + 3 < argc && session_count < MAX_SESSIONS) {
			sessions[session_count].name = argv[i + 1];
			sessions[session_count].cgroup = argv[i + 2];
			sessions[session_count].cgroup_id = strtoull(argv[i + 3], NULL, 10);
			session_count++;
			i += 4;
		} else {
			die("reconcile: unknown or incomplete option %s", argv[i]);
		}
	}
	if (!manager || (strcmp(manager, "systemd") && strcmp(manager, "cgroupfs")))
		die("reconcile: --manager systemd|cgroupfs is required");
	pinroot_rel = relative_beneath(PIN_FS, pinroot);
	if (!pinroot_rel)
		refuse("pinroot-outside-bpffs", "pinroot=%s", pinroot);
	// A listing that failed leaves every pin in place ("Lifecycle", 7).
	if (listing_failed) {
		printf("reconcile listing=failed sessions=%d removed=0 kept=%d refused=0\n", session_count,
		       session_count);
		return 0;
	}
	bpffs_fd = open(PIN_FS, O_RDONLY | O_DIRECTORY);
	if (bpffs_fd < 0)
		die("open %s: %s", PIN_FS, strerror(errno));
	slice_fd = open(slice_root(), O_RDONLY | O_DIRECTORY);
	if (slice_fd < 0)
		die("open %s: %s", slice_root(), strerror(errno));
	for (int i = 0; i < session_count; i++) {
		const struct session *session = &sessions[i];
		const char *cgroup_rel;
		int pinroot_fd, cgroup_fd, pins_fd, links, progs;
		struct stat st;
		char events[256] = {}, pins_rel[PATH_MAX];
		int events_fd;
		ssize_t got;

		if (named_in(session->name, named, named_count)) {
			printf("reconcile session=%s action=kept reason=named-by-container\n", session->name);
			kept++;
			continue;
		}
		if (named_in(session->name, hold, hold_count)) {
			printf("reconcile session=%s action=kept reason=identity-contradicted\n", session->name);
			kept++;
			continue;
		}
		if (!one_component(session->name)) {
			printf("reconcile session=%s action=refused reason=name\n", session->name);
			refused++;
			continue;
		}
		cgroup_rel = relative_beneath(slice_root(), session->cgroup);
		if (!cgroup_rel) {
			printf("reconcile session=%s action=refused reason=cgroup-outside-slice cgroup=%s\n",
			       session->name, session->cgroup);
			refused++;
			continue;
		}
		cgroup_fd = open_beneath(slice_fd, cgroup_rel, O_RDONLY | O_DIRECTORY);
		if (cgroup_fd < 0) {
			printf("reconcile session=%s action=refused reason=cgroup-open cgroup=%s error=%s\n",
			       session->name, session->cgroup, strerror(errno));
			refused++;
			continue;
		}
		if (fstat(cgroup_fd, &st))
			die("fstat: %s", strerror(errno));
		// The cgroup's identity is its inode number, the id its links carry.
		if ((unsigned long long)st.st_ino != session->cgroup_id) {
			printf("reconcile session=%s action=refused reason=cgroup-identity cgroup=%s recorded=%llu "
			       "found=%llu\n", session->name, session->cgroup, session->cgroup_id,
			       (unsigned long long)st.st_ino);
			refused++;
			close(cgroup_fd);
			continue;
		}
		events_fd = openat(cgroup_fd, "cgroup.events", O_RDONLY);
		if (events_fd < 0)
			die("open cgroup.events: %s", strerror(errno));
		got = read(events_fd, events, sizeof(events) - 1);
		close(events_fd);
		if (got <= 0 || !strstr(events, "populated 0")) {
			printf("reconcile session=%s action=kept reason=populated cgroup=%s\n", session->name,
			       session->cgroup);
			kept++;
			close(cgroup_fd);
			continue;
		}
		// No pin root at all, as after a machine boot: the session has no pins, and its cgroup
		// alone is judged below.
		pinroot_fd = open_beneath(bpffs_fd, pinroot_rel, O_RDONLY | O_DIRECTORY);
		if (pinroot_fd < 0 && errno != ENOENT)
			die("open %s: %s", pinroot, strerror(errno));
		pin_name(session->name, pins_rel, sizeof(pins_rel));
		pins_fd = pinroot_fd < 0 ? -1 : open_beneath(pinroot_fd, pins_rel, O_RDONLY | O_DIRECTORY);
		if (pinroot_fd >= 0 && pins_fd < 0 && errno != ENOENT) {
			printf("reconcile session=%s action=refused reason=pins-open path=%s/%s error=%s\n",
			       session->name, pinroot, pins_rel, strerror(errno));
			refused++;
			close(cgroup_fd);
			close(pinroot_fd);
			continue;
		}
		links = progs = 0;
		if (pins_fd >= 0) {
			struct pin_dir link_dir = {.fd = -1}, prog_dir = {.fd = -1};
			bool checked = !check_pins(pins_fd, "links", session->cgroup_id, session->name, &link_dir) &&
				       !check_pins(pins_fd, "progs", session->cgroup_id, session->name, &prog_dir);

			if (checked) {
				delete_pins(pins_fd, "links", &link_dir);
				delete_pins(pins_fd, "progs", &prog_dir);
				links = link_dir.count;
				progs = prog_dir.count;
			}
			if (link_dir.fd >= 0)
				close(link_dir.fd);
			if (prog_dir.fd >= 0)
				close(prog_dir.fd);
			close(pins_fd);
			if (!checked) {
				refused++;
				close(cgroup_fd);
				close(pinroot_fd);
				continue;
			}
			if (unlinkat(pinroot_fd, pins_rel, AT_REMOVEDIR))
				die("rmdir %s/%s: %s", pinroot, pins_rel, strerror(errno));
		}
		if (pinroot_fd >= 0)
			close(pinroot_fd);
		close(cgroup_fd);
		// Under systemd the launcher stops the slice unit, which removes the cgroup; under
		// cgroupfs the directory is removed here, through the slice root's descriptor.
		if (!strcmp(manager, "cgroupfs")) {
			if (unlinkat(slice_fd, cgroup_rel, AT_REMOVEDIR))
				die("rmdir %s: %s", session->cgroup, strerror(errno));
			printf("reconcile session=%s action=removed links=%d progs=%d cgroup=removed\n", session->name,
			       links, progs);
		} else {
			printf("reconcile session=%s action=removed links=%d progs=%d cgroup=stop-slice slice=%s\n",
			       session->name, links, progs, strrchr(session->cgroup, '/') + 1);
		}
		removed++;
	}
	printf("reconcile sessions=%d removed=%d kept=%d refused=%d\n", session_count, removed, kept, refused);
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (argc < 2)
		die("usage: see the header of controller.c");
	if (!strcmp(argv[1], "attach"))
		return cmd_attach(argc - 2, argv + 2);
	if (!strcmp(argv[1], "attach-pinned"))
		return cmd_attach_pinned(argc - 2, argv + 2);
	if (!strcmp(argv[1], "prepare-spare") && argc == 3)
		return cmd_prepare_spare(argv[2]);
	if (!strcmp(argv[1], "query") && argc == 3)
		return cmd_query(argv[2]);
	if (!strcmp(argv[1], "link-info") && argc == 3)
		return cmd_link_info(argv[2]);
	if (!strcmp(argv[1], "statx") && argc == 3)
		return cmd_statx(argv[2]);
	if (!strcmp(argv[1], "unpin") && argc == 3)
		return cmd_unpin(argv[2]);
	if (!strcmp(argv[1], "reconcile"))
		return cmd_reconcile(argc - 2, argv + 2);
	die("unknown subcommand %s", argv[1]);
}
