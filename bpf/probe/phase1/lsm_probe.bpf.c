// Phase 1 of doc/plan-bpf-lsm-cgroup.md: eleven BPF_LSM_CGROUP programs, one of which denies.
//
// `file_open` refuses opening a file whose name begins with MARKER for writing and records the
// identity of every opened object so named, a directory included; the other ten allow
// everything. Every program runs the bounded
// `d_parent` walk under `rename_lock`'s sequence with the fetch-add barrier the plan names ("What is
// gained and what is lost"), so the verifier's answer for that walk is measured on each hook. The
// eleven are the plan's eight, `file_receive`, and `inode_mkdir` and `inode_rmdir`, two hooks the
// plan does not take, which the slot test attaches to reach the kernel's ten and fail at eleven.
//
// Return convention (kernel/bpf/cgroup.c, bpf_prog_run_array_cg): 1 allows, 0 becomes -EPERM.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MARKER "ko-agent-bpf-marker"
#define MARKER_LEN (sizeof(MARKER) - 1)
#define FMODE_WRITE 0x2u

// A walk reads at most this many components; a real tree's depth is Phase 2's number.
#define WALK_BOUND 64
// A walk that overlaps a rename is discarded and repeated this many times, then denied.
#define RETRY_BOUND 4
#define NAME_BYTES 32

enum hook {
	HOOK_FILE_OPEN,
	HOOK_INODE_CREATE,
	HOOK_INODE_MKNOD,
	HOOK_INODE_SYMLINK,
	HOOK_INODE_LINK,
	HOOK_INODE_RENAME,
	HOOK_INODE_UNLINK,
	HOOK_INODE_SETATTR,
	HOOK_FILE_RECEIVE,
	HOOK_INODE_MKDIR,
	HOOK_INODE_RMDIR,
	HOOK_COUNT,
};

struct hook_stats {
	__u64 calls;
	__u64 walks;          // walks that ended with the sequence unchanged
	__u64 retries;        // walks discarded for a changed or odd sequence
	__u64 gave_up;        // calls whose RETRY_BOUND walks all failed
	__u64 max_depth;
	__u64 barrier_sum;    // the fetch-add's returned values, summed, so the fetch is not dropped
};

// What the last open of a MARKER file saw, for the identity test ("The policy").
struct last_open {
	__u64 s_dev;          // inode->i_sb->s_dev, the kernel's MKDEV layout
	__u64 i_ino;
	__u64 count;
	__u32 f_mode;
	__u32 denied;
	__u32 depth;
	__u32 seq;
	char fs_type[16];     // i_sb->s_type->name
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HOOK_COUNT);
	__type(key, __u32);
	__type(value, struct hook_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct last_open);
} last_open SEC(".maps");

// fs/dcache.c's `rename_lock`, a seqlock_t whose first word is the sequence. A typeless ksym:
// libbpf fills the address from /proc/kallsyms at load, which needs the controller's privileges.
extern const void rename_lock __ksym;

struct walk {
	__u64 hash;
	__u32 depth;
	__u32 seq;
	__u32 retries;
	__u64 barrier_sum;
};

static __always_inline __u32 read_rename_seq(void)
{
	__u32 seq = 1;	// odd, so a failed read counts as a writer active

	bpf_probe_read_kernel(&seq, sizeof(seq), &rename_lock);
	return seq;
}

// The ordering between the sequence reads and the dentry reads. Clang emits no fence for BPF;
// an atomic fetch-add is jited to `ldaddal` (arm64, LSE) or a `lock`-prefixed `xadd` (x86).
static __always_inline __u64 fetch_add_barrier(__u64 *word)
{
	return __sync_fetch_and_add(word, 1);
}

static __always_inline __u64 fold_name(struct dentry *cur)
{
	const unsigned char *name = BPF_CORE_READ(cur, d_name.name);
	__u32 len = BPF_CORE_READ(cur, d_name.len);
	__u64 first8 = 0;

	// The first eight bytes stand in for the classifier's fold; Phase 2 ports the real one.
	bpf_probe_read_kernel(&first8, sizeof(first8), name);
	return (first8 ^ ((__u64)len << 56)) * 0x100000001b3ULL;
}

// One pass from `start` to the filesystem root, or WALK_BOUND components, whichever comes first.
// Returns 1 when `rename_lock`'s sequence was even before and unchanged after.
static __always_inline int walk_once(struct dentry *start, struct walk *out)
{
	__u64 word = 0;
	__u64 hash = 0;
	struct dentry *cur = start;
	__u32 seq0, seq1, depth = 0;
	int i;

	seq0 = read_rename_seq();
	if (seq0 & 1)
		return 0;
	out->barrier_sum += fetch_add_barrier(&word);
	for (i = 0; i < WALK_BOUND; i++) {
		struct dentry *parent;

		hash = (hash ^ fold_name(cur)) * 0x100000001b3ULL;
		parent = BPF_CORE_READ(cur, d_parent);
		if (!parent || parent == cur)
			break;
		cur = parent;
		depth++;
	}
	out->barrier_sum += fetch_add_barrier(&word);
	seq1 = read_rename_seq();
	if (seq1 != seq0)
		return 0;
	out->hash = hash;
	out->depth = depth;
	out->seq = seq0;
	return 1;
}

static __always_inline int walk(enum hook hook, struct dentry *start, struct walk *out)
{
	__u32 key = hook;
	struct hook_stats *st = bpf_map_lookup_elem(&stats, &key);
	int ok = 0, i;

	out->hash = 0;
	out->depth = 0;
	out->seq = 0;
	out->retries = 0;
	out->barrier_sum = 0;
	for (i = 0; i < RETRY_BOUND; i++) {
		if (walk_once(start, out)) {
			ok = 1;
			break;
		}
		out->retries++;
	}
	if (st) {
		__sync_fetch_and_add(&st->calls, 1);
		if (ok)
			__sync_fetch_and_add(&st->walks, 1);
		else
			__sync_fetch_and_add(&st->gave_up, 1);
		__sync_fetch_and_add(&st->retries, out->retries);
		__sync_fetch_and_add(&st->barrier_sum, out->barrier_sum);
		if (out->depth > st->max_depth)
			st->max_depth = out->depth;
	}
	return ok;
}

static __always_inline int is_marker(struct dentry *dentry)
{
	char name[NAME_BYTES] = {};
	const unsigned char *src = BPF_CORE_READ(dentry, d_name.name);
	__u32 len = BPF_CORE_READ(dentry, d_name.len);
	int i;

	if (len < MARKER_LEN)
		return 0;
	if (bpf_probe_read_kernel_str(name, sizeof(name), src) < 0)
		return 0;
	for (i = 0; i < MARKER_LEN; i++)
		if (name[i] != MARKER[i])
			return 0;
	return 1;
}

SEC("lsm_cgroup/file_open")
int BPF_PROG(file_open, struct file *file)
{
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	__u32 f_mode = BPF_CORE_READ(file, f_mode);
	struct walk w;
	int walked = walk(HOOK_FILE_OPEN, dentry, &w);

	if (!is_marker(dentry))
		return walked;	// a walk that never settled denies, as the plan's policy does
	{
		__u32 key = 0;
		struct last_open *rec = bpf_map_lookup_elem(&last_open, &key);
		struct inode *inode = BPF_CORE_READ(dentry, d_inode);

		if (rec) {
			const char *type_name = BPF_CORE_READ(inode, i_sb, s_type, name);

			rec->s_dev = BPF_CORE_READ(inode, i_sb, s_dev);
			rec->i_ino = BPF_CORE_READ(inode, i_ino);
			rec->f_mode = f_mode;
			rec->denied = (f_mode & FMODE_WRITE) != 0 || !walked;
			rec->depth = w.depth;
			rec->seq = w.seq;
			rec->count++;
			bpf_probe_read_kernel_str(rec->fs_type, sizeof(rec->fs_type), type_name);
		}
	}
	if (f_mode & FMODE_WRITE)
		return 0;
	return walked;
}

#define ALLOW_AFTER_WALK(hook, dentry)				\
	do {							\
		struct walk w;					\
		walk(hook, dentry, &w);				\
		return 1;					\
	} while (0)

SEC("lsm_cgroup/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	ALLOW_AFTER_WALK(HOOK_INODE_CREATE, dentry);
}

SEC("lsm_cgroup/inode_mknod")
int BPF_PROG(inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	ALLOW_AFTER_WALK(HOOK_INODE_MKNOD, dentry);
}

SEC("lsm_cgroup/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	ALLOW_AFTER_WALK(HOOK_INODE_SYMLINK, dentry);
}

SEC("lsm_cgroup/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	ALLOW_AFTER_WALK(HOOK_INODE_LINK, new_dentry);
}

SEC("lsm_cgroup/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	ALLOW_AFTER_WALK(HOOK_INODE_RENAME, new_dentry);
}

SEC("lsm_cgroup/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry)
{
	ALLOW_AFTER_WALK(HOOK_INODE_UNLINK, dentry);
}

SEC("lsm_cgroup/inode_setattr")
int BPF_PROG(inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
	ALLOW_AFTER_WALK(HOOK_INODE_SETATTR, dentry);
}

SEC("lsm_cgroup/file_receive")
int BPF_PROG(file_receive, struct file *file)
{
	ALLOW_AFTER_WALK(HOOK_FILE_RECEIVE, BPF_CORE_READ(file, f_path.dentry));
}

SEC("lsm_cgroup/inode_mkdir")
int BPF_PROG(inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	ALLOW_AFTER_WALK(HOOK_INODE_MKDIR, dentry);
}

SEC("lsm_cgroup/inode_rmdir")
int BPF_PROG(inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	ALLOW_AFTER_WALK(HOOK_INODE_RMDIR, dentry);
}
