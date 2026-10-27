// The host build of policy.bpf.c (doc/plan-bpf-lsm-cgroup.md, "What is gained and what is lost"):
// the classifier compiled against the stand-in headers beside this file, its maps as arrays and a
// chain of dentries built from each query's path, so that policy.rs's corpus runs through it
// (fuse/ko-agent-fs/tests/bpf_equivalence.rs). What it cannot show is the glue around the
// classifier: the CO-RE reads, the walk's bounds under the verifier and the hooks' arguments.
//
//   policy-host RECORDS FS_TYPE [FLAGS]
//
// loads the guard's records file, then reads queries on stdin, one per line, tab-separated:
//
//   write PATH | setattr PATH | unlink PATH | create PATH | symlink PATH TARGET |
//   rename KIND FROM TO [replace] | link FROM TO            KIND: file, dir or symlink
//
// and answers each with `allow` or `deny`, the reason's number and its name. Every directory on a
// path exists; the entry a query names exists for write, setattr, unlink and a rename's source,
// and does not for create, symlink, link's new name and a rename's destination unless `replace`.
// FLAGS is the policy_config flags word.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../policy.bpf.c"
#include "records_file.h"

#define HOST_S_IFREG 0100000
#define HOST_S_IFLNK S_IFLNK

// ---------------------------------------------------------------------------------------------
// The maps and the helpers
// ---------------------------------------------------------------------------------------------

static struct {
	struct ident key;
	struct root value;
} root_entries[64];
static int root_entry_count;
static struct rule_line rule_values[RULE_LINES];
static struct alias_context alias_values[ALIASES];
static struct policy_config config_value;
static struct scratch scratch_values[SCRATCH_SLOTS];
static struct cpu_guard guard_value;
static struct hook_stats stats_values[HOOK_COUNT];
static struct last_decision last_value;

static void *array_value(const void *key, void *values, size_t value_bytes, __u32 count)
{
	__u32 index;

	memcpy(&index, key, sizeof(index));
	return index < count ? (char *)values + (size_t)index * value_bytes : NULL;
}

void *bpf_map_lookup_elem(const void *map, const void *key)
{
	if (map == &roots) {
		for (int i = 0; i < root_entry_count; i++)
			if (memcmp(key, &root_entries[i].key, sizeof(struct ident)) == 0)
				return &root_entries[i].value;
		return NULL;
	}
	if (map == &rules)
		return array_value(key, rule_values, sizeof(rule_values[0]), RULE_LINES);
	if (map == &aliases)
		return array_value(key, alias_values, sizeof(alias_values[0]), ALIASES);
	if (map == &policy_config)
		return array_value(key, &config_value, sizeof(config_value), 1);
	if (map == &scratch)
		return array_value(key, scratch_values, sizeof(scratch_values[0]), SCRATCH_SLOTS);
	if (map == &guard)
		return array_value(key, &guard_value, sizeof(guard_value), 1);
	if (map == &stats)
		return array_value(key, stats_values, sizeof(stats_values[0]), HOOK_COUNT);
	if (map == &last_decision)
		return array_value(key, &last_value, sizeof(last_value), 1);
	fprintf(stderr, "policy-host: a lookup in a map this build does not hold\n");
	exit(2);
}

long bpf_probe_read_kernel(void *dst, __u32 size, const void *src)
{
	if (!src) {
		memset(dst, 0, size);
		return -EFAULT;
	}
	memcpy(dst, src, size);
	return 0;
}

// As the kernel's: the length copied with its terminator; `size` when the string was longer and
// was cut; -EFAULT and a zeroed destination for no source.
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *src)
{
	size_t len;

	if (!src || size == 0) {
		memset(dst, 0, size);
		return -EFAULT;
	}
	len = strnlen(src, size);
	if (len >= size) {
		memcpy(dst, src, size - 1);
		((char *)dst)[size - 1] = 0;
		return size;
	}
	memcpy(dst, src, len + 1);
	return (long)len + 1;
}

long bpf_strncmp(const char *s1, __u32 s1_sz, const char *s2)
{
	return strncmp(s1, s2, s1_sz);
}

__u64 bpf_ktime_get_ns(void)
{
	static __u64 ticks;

	return ++ticks;
}

static struct task_struct host_task;

struct task_struct *bpf_get_current_task_btf(void)
{
	return &host_task;
}

long bpf_get_current_comm(void *buf, __u32 size)
{
	snprintf(buf, size, "policy-host");
	return 0;
}

// ---------------------------------------------------------------------------------------------
// The tree: a chain of dentries for each path a query names, the workspace root above them and
// the filesystem's root above that. An entry's identity is the hash of its path, so the roots
// recorded at load meet the same identity in every query's chain.
// ---------------------------------------------------------------------------------------------

static struct file_system_type share_type;
static struct super_block share_sb = {.s_dev = 1, .s_type = &share_type};
static struct mount host_mount;

struct node {
	struct dentry dentry;
	struct inode inode;
	char name[NAME_BYTES];
};

#define CHAIN_NODES (WALK_BOUND + 2)

struct chain {
	struct node nodes[CHAIN_NODES];
	int count;
};

static __u64 ident_of_path(const char *path, size_t len)
{
	__u64 hash = 0xcbf29ce484222325ull;

	for (size_t i = 0; i < len; i++) {
		hash ^= (unsigned char)path[i];
		hash *= 0x100000001b3ull;
	}
	return hash | 2;	// never the filesystem root's 1
}

static void init_node(struct node *node, struct node *parent, const char *name, size_t name_len, __u64 ino, __u32 mode,
		      int exists)
{
	memset(node, 0, sizeof(*node));
	memcpy(node->name, name, name_len);
	node->dentry.d_parent = parent ? &parent->dentry : &node->dentry;
	node->dentry.d_name.len = name_len;
	node->dentry.d_name.name = (const unsigned char *)node->name;
	node->inode.i_sb = &share_sb;
	node->inode.i_ino = ino;
	node->inode.i_mode = mode;
	node->dentry.d_inode = exists ? &node->inode : NULL;
}

// The chain for `path`, whose last entry has `leaf_mode` and exists when `leaf_exists`; NULL for a
// path deeper than the chain holds or with an empty component.
static struct dentry *chain_for(struct chain *chain, const char *path, int leaf_exists, __u32 leaf_mode)
{
	const char *at = path;
	struct node *parent;

	init_node(&chain->nodes[0], NULL, "/", 1, 1, S_IFDIR, 1);
	init_node(&chain->nodes[1], &chain->nodes[0], "workspace", 9, ident_of_path("", 0), S_IFDIR, 1);
	chain->count = 2;
	parent = &chain->nodes[1];
	while (*at) {
		const char *end = strchr(at, '/');
		size_t len = end ? (size_t)(end - at) : strlen(at);
		int last = !end;

		if (len == 0 || len >= NAME_BYTES || chain->count >= CHAIN_NODES)
			return NULL;
		init_node(&chain->nodes[chain->count], parent, at, len, ident_of_path(path, (size_t)(at + len - path)),
			  last ? leaf_mode : S_IFDIR, last ? leaf_exists : 1);
		parent = &chain->nodes[chain->count++];
		at = end ? end + 1 : at + len;
	}
	return &parent->dentry;
}

static struct inode *parent_inode(struct dentry *dentry)
{
	return dentry->d_parent->d_inode;
}

// ---------------------------------------------------------------------------------------------
// The records into the maps
// ---------------------------------------------------------------------------------------------

static void load_records(const char *path)
{
	struct records_file file;
	char error[512];

	if (records_file_read(path, &file, error, sizeof(error)) < 0) {
		fprintf(stderr, "policy-host: %s\n", error);
		exit(2);
	}
	if (file.rule_bytes != sizeof(struct rule_line) || file.alias_bytes != sizeof(struct alias_context)) {
		fprintf(stderr, "policy-host: records.h and policy.bpf.c lay a record out differently\n");
		exit(2);
	}
	memcpy(rule_values, file.rules, file.rule_count * sizeof(struct rule_line));
	memcpy(alias_values, file.aliases, file.alias_count * sizeof(struct alias_context));
	for (unsigned i = 0; i < file.root_count; i++) {
		root_entries[i].key.s_dev = share_sb.s_dev;
		root_entries[i].key.i_ino = ident_of_path(file.roots[i].path, strlen(file.roots[i].path));
		root_entries[i].value.kind = file.roots[i].kind;
	}
	root_entry_count = file.root_count;
	config_value.rule_count = file.rule_count;
}

// ---------------------------------------------------------------------------------------------
// The queries
// ---------------------------------------------------------------------------------------------

static const char *const reason_names[R_COUNT] = {
	[R_ALLOW] = "allow",
	[R_OUTSIDE] = "outside",
	[R_WALK_NOROOT] = "walk-noroot",
	[R_WALK_BOUND] = "walk-bound",
	[R_WALK_TORN] = "walk-torn",
	[R_NAME_TOO_LONG] = "name-too-long",
	[R_GIT_PROTECTED] = "git-protected",
	[R_GIT_PINNED] = "git-pinned",
	[R_GIT_NAME] = "git-name",
	[R_SANDBOX_NAME] = "sandbox-name",
	[R_HEAD] = "head",
	[R_RULE_READ_ONLY] = "rule-read-only",
	[R_RULE_PINNED] = "rule-pinned",
	[R_REGION] = "region",
	[R_SOCKET] = "socket",
	[R_INTERNAL] = "internal",
	[R_REENTRY] = "reentry",
	[R_SHORT_NAME] = "short-name",
	[R_ALIAS_OVERFLOW] = "alias-overflow",
	[R_SYMLINK_SYNTAX] = "symlink-syntax",
	[R_SYMLINK_SHORT] = "symlink-short",
	[R_SYMLINK_GITDIR] = "symlink-gitdir",
	[R_SYMLINK_REGION] = "symlink-region",
	[R_SOCKET_GITDIR] = "socket-gitdir",
	[R_RECEIVE_NS] = "receive-ns",
	[R_RECEIVE_DIR] = "receive-dir",
	[R_FIFO] = "fifo",
};

static struct chain chain_a, chain_b;

static __u32 mode_of_kind(const char *kind)
{
	if (!strcmp(kind, "file"))
		return HOST_S_IFREG;
	if (!strcmp(kind, "dir"))
		return S_IFDIR;
	if (!strcmp(kind, "symlink"))
		return HOST_S_IFLNK;
	return 0;
}

// One query's fields, tab-separated; `fields` receives up to `max` pointers and the count returns.
static int split_fields(char *line, char **fields, int max)
{
	int count = 0;
	char *at = line;

	line[strcspn(line, "\n")] = 0;
	while (count < max) {
		char *tab = strchr(at, '\t');

		fields[count++] = at;
		if (!tab)
			break;
		*tab = 0;
		at = tab + 1;
	}
	return count;
}

// Runs one query and returns the hook's answer, 1 allowed; -1 for a query this build cannot form.
static int run_query(char **f, int n)
{
	struct dentry *a, *b;
	__u32 mode;

	if (n == 2 && (!strcmp(f[0], "write") || !strcmp(f[0], "setattr") || !strcmp(f[0], "unlink"))) {
		a = chain_for(&chain_a, f[1], 1, HOST_S_IFREG);
		if (!a)
			return -1;
		if (!strcmp(f[0], "write")) {
			struct file file = {.f_mode = FMODE_WRITE, .f_path = {.mnt = &host_mount.mnt, .dentry = a}};

			return file_open(&file);
		}
		if (!strcmp(f[0], "setattr"))
			return inode_setattr(NULL, a, NULL);
		return inode_unlink(parent_inode(a), a);
	}
	if (n == 2 && !strcmp(f[0], "create")) {
		a = chain_for(&chain_a, f[1], 0, 0);
		return a ? inode_create(parent_inode(a), a, 0644) : -1;
	}
	if (n == 3 && !strcmp(f[0], "symlink")) {
		a = chain_for(&chain_a, f[1], 0, 0);
		return a ? inode_symlink(parent_inode(a), a, f[2]) : -1;
	}
	if (n == 3 && !strcmp(f[0], "link")) {
		a = chain_for(&chain_a, f[1], 1, HOST_S_IFREG);
		b = chain_for(&chain_b, f[2], 0, 0);
		return a && b ? inode_link(a, parent_inode(b), b) : -1;
	}
	if ((n == 4 || (n == 5 && !strcmp(f[4], "replace"))) && !strcmp(f[0], "rename") &&
	    (mode = mode_of_kind(f[1]))) {
		a = chain_for(&chain_a, f[2], 1, mode);
		b = chain_for(&chain_b, f[3], n == 5, mode);
		return a && b ? inode_rename(parent_inode(a), a, parent_inode(b), b) : -1;
	}
	return -1;
}

int main(int argc, char **argv)
{
	char line[8192];
	char *fields[8];

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "usage: policy-host RECORDS FS_TYPE [FLAGS]\n");
		return 2;
	}
	if (strlen(argv[2]) >= FS_TYPE_BYTES) {
		fprintf(stderr, "policy-host: FS_TYPE is longer than %d bytes\n", FS_TYPE_BYTES - 1);
		return 2;
	}
	share_type.name = argv[2];
	strcpy(config_value.fs_type, argv[2]);
	config_value.flags = argc == 4 ? (__u32)strtoul(argv[3], NULL, 0) : 0;
	load_records(argv[1]);
	while (fgets(line, sizeof(line), stdin)) {
		int n = split_fields(line, fields, 8);
		__u64 before = last_value.count;
		int answer = run_query(fields, n);

		if (answer < 0) {
			fprintf(stderr, "policy-host: not a query: %s\n", fields[0]);
			return 2;
		}
		if (last_value.count == before)
			printf("%s %d %s\n", answer ? "allow" : "deny", R_OUTSIDE, reason_names[R_OUTSIDE]);
		else
			printf("%s %u %s\n", answer ? "allow" : "deny", last_value.reason,
			       reason_names[last_value.reason]);
		fflush(stdout);
	}
	return 0;
}
