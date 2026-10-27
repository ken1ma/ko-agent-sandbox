/* The kernel types policy.bpf.c reads, for its host build (policy_host.c): the fields the program
 * reads, laid out as the host driver fills them, not as the kernel lays them out. The object for
 * the kernel is built against the kernel's own vmlinux.h (../Containerfile). */
#ifndef HOST_VMLINUX_H
#define HOST_VMLINUX_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef _Bool bool;
typedef unsigned short umode_t;
/* The host's <sys/types.h> has its own dev_t; the program's one use is inode_mknod's unused argument. */
typedef unsigned int kernel_dev_t;
#define dev_t kernel_dev_t

struct qstr {
	__u32 len;
	const unsigned char *name;
};

struct seqcount {
	unsigned sequence;
};

struct seqcount_spinlock {
	struct seqcount seqcount;
};

struct file_system_type {
	const char *name;
};

struct super_block {
	__u64 s_dev;
	struct file_system_type *s_type;
};

struct inode {
	struct super_block *i_sb;
	__u64 i_ino;
	__u32 i_mode;
};

struct dentry {
	struct seqcount_spinlock d_seq;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
};

struct vfsmount {
	struct dentry *mnt_root;
};

struct ns_common {
	__u32 inum;
};

struct mount;

struct mnt_namespace {
	struct ns_common ns;
	struct mount *root;
};

struct mount {
	struct vfsmount mnt;
	struct mnt_namespace *mnt_ns;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	__u32 f_mode;
	__u32 f_flags;
	struct path f_path;
};

struct fs_struct {
	struct path root;
};

struct nsproxy {
	struct mnt_namespace *mnt_ns;
};

struct task_struct {
	struct fs_struct *fs;
	struct nsproxy *nsproxy;
};

struct mnt_idmap {
	int unused;
};

struct iattr {
	unsigned int ia_valid;
};

#endif
