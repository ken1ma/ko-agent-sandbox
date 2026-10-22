// Phase 2 of doc/plan-bpf-lsm-cgroup.md, "every hook": one BPF_LSM_CGROUP program per hook the
// plan's "Inventory" names, each recording which exerciser operation reached it.
//
// The exerciser (mutate.c) names every object it touches `kab2-NN-...`, NN its operation number,
// and `kab2-NN-deny-...` for the operations the attached hook must refuse. A program parses the
// name of each dentry its hook receives, counts the call under (hook, NN), and returns 0, which
// the kernel turns into -EPERM, for a deny name. Objects named otherwise are allowed and counted
// under the hook's total alone, which is what the nested-podman row reads.
//
// Return convention (kernel/bpf/cgroup.c, bpf_prog_run_array_cg): 1 allows, 0 becomes -EPERM.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define OPS 100
#define NAME_BYTES 32

// The hooks, in the order controller.c names them.
enum hook {
	H_PATH_MKNOD, H_INODE_CREATE, H_INODE_MKNOD, H_PATH_MKDIR, H_INODE_MKDIR, H_PATH_SYMLINK,
	H_INODE_SYMLINK, H_PATH_LINK, H_INODE_LINK, H_PATH_RENAME, H_INODE_RENAME, H_PATH_UNLINK,
	H_INODE_UNLINK, H_PATH_RMDIR, H_INODE_RMDIR, H_FILE_OPEN, H_INODE_SETATTR, H_INODE_SETXATTR,
	H_INODE_REMOVEXATTR, H_INODE_SET_ACL, H_INODE_REMOVE_ACL, H_INODE_FILE_SETATTR, H_FILE_IOCTL,
	H_FILE_IOCTL_COMPAT, H_FILE_RECEIVE, H_FILE_PERMISSION, H_PATH_TRUNCATE, H_FILE_TRUNCATE,
	H_PATH_CHMOD, H_PATH_CHOWN, H_MMAP_FILE, H_FILE_MPROTECT, H_INODE_PERMISSION,
	HOOK_COUNT,
};

// One exerciser operation seen by one hook.
struct op_hit {
	__u64 calls;
	__u64 denied;
	__u64 last_arg;           // the hook's scalar argument: ioctl cmd, open f_flags, iattr ia_valid, ...
	char last_name[NAME_BYTES];   // an xattr's or ACL's name, where the hook has one
};

// Every call of the hook, marker names or not, with the last name argument seen.
struct hook_total {
	__u64 calls;
	__u64 denied;
	__u64 last_arg;
	char last_name[NAME_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HOOK_COUNT * OPS);
	__type(key, __u32);
	__type(value, struct op_hit);
} hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HOOK_COUNT);
	__type(key, __u32);
	__type(value, struct hook_total);
} totals SEC(".maps");

// deny_all: every call of the hook is refused, marker or not, for the nested-podman row.
struct config {
	__u32 deny_all;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} probe_config SEC(".maps");

// The operation number of a `kab2-NN...` name, or -1; `deny` is set for `kab2-NN-deny`.
static __always_inline int op_of(struct dentry *dentry, int *deny)
{
	char name[16] = {};
	const unsigned char *src;
	int op;

	*deny = 0;
	if (!dentry)
		return -1;
	src = BPF_CORE_READ(dentry, d_name.name);
	if (bpf_probe_read_kernel_str(name, sizeof(name), src) < 0)
		return -1;
	if (name[0] != 'k' || name[1] != 'a' || name[2] != 'b' || name[3] != '2' || name[4] != '-')
		return -1;
	if (name[5] < '0' || name[5] > '9' || name[6] < '0' || name[6] > '9')
		return -1;
	op = (name[5] - '0') * 10 + (name[6] - '0');
	if (name[7] == '-' && name[8] == 'd' && name[9] == 'e' && name[10] == 'n' && name[11] == 'y')
		*deny = 1;
	return op;
}

// Count the call under its hook, and under (hook, op) for a marker name. Returns 1 to allow and
// 0 to deny.
static __always_inline int judge(enum hook hook, struct dentry *dentry, __u64 arg, const char *name_arg)
{
	__u32 zero = 0, key = hook;
	struct config *cfg = bpf_map_lookup_elem(&probe_config, &zero);
	struct hook_total *total = bpf_map_lookup_elem(&totals, &key);
	int deny = 0, op = op_of(dentry, &deny);
	int allow = 1;

	if (cfg && cfg->deny_all)
		allow = 0;
	if (deny)
		allow = 0;
	if (total) {
		__sync_fetch_and_add(&total->calls, 1);
		if (!allow)
			__sync_fetch_and_add(&total->denied, 1);
		total->last_arg = arg;
		if (name_arg)
			bpf_probe_read_kernel_str(total->last_name, sizeof(total->last_name), name_arg);
	}
	if (op >= 0 && op < OPS) {
		struct op_hit *hit;

		key = hook * OPS + op;
		hit = bpf_map_lookup_elem(&hits, &key);
		if (hit) {
			__sync_fetch_and_add(&hit->calls, 1);
			if (!allow)
				__sync_fetch_and_add(&hit->denied, 1);
			hit->last_arg = arg;
			if (name_arg)
				bpf_probe_read_kernel_str(hit->last_name, sizeof(hit->last_name), name_arg);
		}
	}
	return allow;
}

// A hook with two dentries, a source and a destination: both are counted, and either deny name
// denies.
static __always_inline int judge2(enum hook hook, struct dentry *first, struct dentry *second, __u64 arg)
{
	int allow = judge(hook, first, arg, NULL);

	if (!judge(hook, second, arg, NULL))
		allow = 0;
	return allow;
}

static __always_inline struct dentry *file_dentry_of(struct file *file)
{
	return BPF_CORE_READ(file, f_path.dentry);
}

SEC("lsm_cgroup/path_mknod")
int BPF_PROG(path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
	return judge(H_PATH_MKNOD, dentry, mode, NULL);
}

SEC("lsm_cgroup/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return judge(H_INODE_CREATE, dentry, mode, NULL);
}

SEC("lsm_cgroup/inode_mknod")
int BPF_PROG(inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return judge(H_INODE_MKNOD, dentry, mode, NULL);
}

SEC("lsm_cgroup/path_mkdir")
int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	return judge(H_PATH_MKDIR, dentry, mode, NULL);
}

SEC("lsm_cgroup/inode_mkdir")
int BPF_PROG(inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return judge(H_INODE_MKDIR, dentry, mode, NULL);
}

SEC("lsm_cgroup/path_symlink")
int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	return judge(H_PATH_SYMLINK, dentry, 0, old_name);
}

SEC("lsm_cgroup/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	return judge(H_INODE_SYMLINK, dentry, 0, old_name);
}

SEC("lsm_cgroup/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
	return judge2(H_PATH_LINK, old_dentry, new_dentry, 0);
}

SEC("lsm_cgroup/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	return judge2(H_INODE_LINK, old_dentry, new_dentry, 0);
}

SEC("lsm_cgroup/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	return judge2(H_PATH_RENAME, old_dentry, new_dentry, flags);
}

SEC("lsm_cgroup/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	return judge2(H_INODE_RENAME, old_dentry, new_dentry, 0);
}

SEC("lsm_cgroup/path_unlink")
int BPF_PROG(path_unlink, const struct path *dir, struct dentry *dentry)
{
	return judge(H_PATH_UNLINK, dentry, 0, NULL);
}

SEC("lsm_cgroup/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry)
{
	return judge(H_INODE_UNLINK, dentry, 0, NULL);
}

SEC("lsm_cgroup/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *dentry)
{
	return judge(H_PATH_RMDIR, dentry, 0, NULL);
}

SEC("lsm_cgroup/inode_rmdir")
int BPF_PROG(inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	return judge(H_INODE_RMDIR, dentry, 0, NULL);
}

SEC("lsm_cgroup/file_open")
int BPF_PROG(file_open, struct file *file)
{
	__u64 arg = ((__u64)BPF_CORE_READ(file, f_mode) << 32) | BPF_CORE_READ(file, f_flags);

	return judge(H_FILE_OPEN, file_dentry_of(file), arg, NULL);
}

SEC("lsm_cgroup/inode_setattr")
int BPF_PROG(inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
	return judge(H_INODE_SETATTR, dentry, BPF_CORE_READ(attr, ia_valid), NULL);
}

SEC("lsm_cgroup/inode_setxattr")
int BPF_PROG(inode_setxattr, struct mnt_idmap *idmap, struct dentry *dentry, const char *name, const void *value,
	     size_t size, int flags)
{
	return judge(H_INODE_SETXATTR, dentry, size, name);
}

SEC("lsm_cgroup/inode_removexattr")
int BPF_PROG(inode_removexattr, struct mnt_idmap *idmap, struct dentry *dentry, const char *name)
{
	return judge(H_INODE_REMOVEXATTR, dentry, 0, name);
}

SEC("lsm_cgroup/inode_set_acl")
int BPF_PROG(inode_set_acl, struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name,
	     struct posix_acl *kacl)
{
	return judge(H_INODE_SET_ACL, dentry, 0, acl_name);
}

SEC("lsm_cgroup/inode_remove_acl")
int BPF_PROG(inode_remove_acl, struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name)
{
	return judge(H_INODE_REMOVE_ACL, dentry, 0, acl_name);
}

SEC("lsm_cgroup/inode_file_setattr")
int BPF_PROG(inode_file_setattr, struct dentry *dentry, struct file_kattr *fa)
{
	return judge(H_INODE_FILE_SETATTR, dentry, BPF_CORE_READ(fa, flags), NULL);
}

SEC("lsm_cgroup/file_ioctl")
int BPF_PROG(file_ioctl, struct file *file, unsigned int cmd, unsigned long arg)
{
	return judge(H_FILE_IOCTL, file_dentry_of(file), cmd, NULL);
}

SEC("lsm_cgroup/file_ioctl_compat")
int BPF_PROG(file_ioctl_compat, struct file *file, unsigned int cmd, unsigned long arg)
{
	return judge(H_FILE_IOCTL_COMPAT, file_dentry_of(file), cmd, NULL);
}

SEC("lsm_cgroup/file_receive")
int BPF_PROG(file_receive, struct file *file)
{
	return judge(H_FILE_RECEIVE, file_dentry_of(file), BPF_CORE_READ(file, f_mode), NULL);
}

SEC("lsm_cgroup/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
	return judge(H_FILE_PERMISSION, file_dentry_of(file), mask, NULL);
}

SEC("lsm_cgroup/path_truncate")
int BPF_PROG(path_truncate, const struct path *path)
{
	return judge(H_PATH_TRUNCATE, BPF_CORE_READ(path, dentry), 0, NULL);
}

SEC("lsm_cgroup/file_truncate")
int BPF_PROG(file_truncate, struct file *file)
{
	return judge(H_FILE_TRUNCATE, file_dentry_of(file), 0, NULL);
}

SEC("lsm_cgroup/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode)
{
	return judge(H_PATH_CHMOD, BPF_CORE_READ(path, dentry), mode, NULL);
}

SEC("lsm_cgroup/path_chown")
int BPF_PROG(path_chown, const struct path *path, __u32 uid, __u32 gid)
{
	return judge(H_PATH_CHOWN, BPF_CORE_READ(path, dentry), 0, NULL);
}

SEC("lsm_cgroup/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	// An anonymous mapping has no file; nothing to judge.
	if (!file)
		return 1;
	return judge(H_MMAP_FILE, file_dentry_of(file), (prot << 32) | flags, NULL);
}

SEC("lsm_cgroup/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
	struct file *file = BPF_CORE_READ(vma, vm_file);

	if (!file)
		return 1;
	return judge(H_FILE_MPROTECT, file_dentry_of(file), prot, NULL);
}

SEC("lsm_cgroup/inode_permission")
int BPF_PROG(inode_permission, struct inode *inode, int mask)
{
	// The hook has an inode and no dentry: counted under the total alone, never denied.
	__u32 key = H_INODE_PERMISSION;
	struct hook_total *total = bpf_map_lookup_elem(&totals, &key);

	if (total) {
		__sync_fetch_and_add(&total->calls, 1);
		total->last_arg = mask;
	}
	return 1;
}
