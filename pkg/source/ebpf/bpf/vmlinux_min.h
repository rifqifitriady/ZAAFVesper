/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * The few kernel types zaaf.bpf.c reads, declared by hand instead of a
 * multi-megabyte generated vmlinux.h. Every struct carries
 * preserve_access_index, so field offsets are relocated against the running
 * kernel's BTF at load time (CO-RE): only the names and types below matter,
 * not their order. A suffix after "___" names an alternative layout of the
 * same kernel struct (libbpf and cilium/ebpf ignore the suffix when matching).
 */
#ifndef __ZAAF_VMLINUX_MIN_H__
#define __ZAAF_VMLINUX_MIN_H__

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef short __s16;
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __s32 s32;
typedef __u64 u64;
typedef __s64 s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
typedef unsigned long size_t;
typedef long long time64_t;
typedef unsigned int fmode_t;
typedef unsigned short umode_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef int pid_t;
typedef __u32 dev_t;

enum { false = 0, true = 1 };

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	uid_t val;
} kuid_t;

typedef struct {
	gid_t val;
} kgid_t;

struct timespec64 {
	time64_t tv_sec;
	long tv_nsec;
} __attribute__((preserve_access_index));

struct qstr {
	unsigned int len;
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct super_block {
	dev_t s_dev;
} __attribute__((preserve_access_index));

/* i_ctime moved twice: __i_ctime (6.6) then i_ctime_sec/nsec (6.11). */
struct inode {
	umode_t i_mode;
	unsigned long i_ino;
	struct super_block *i_sb;
	time64_t i_ctime_sec;
	u32 i_ctime_nsec;
	struct timespec64 __i_ctime;
} __attribute__((preserve_access_index));

struct inode___pre66 {
	struct timespec64 i_ctime;
} __attribute__((preserve_access_index));

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct dentry *mnt_root;
} __attribute__((preserve_access_index));

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	struct inode *f_inode;
	unsigned int f_flags;
	fmode_t f_mode;
} __attribute__((preserve_access_index));

struct fs_struct {
	struct path pwd;
} __attribute__((preserve_access_index));

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
	struct file *exe_file;
} __attribute__((preserve_access_index));

struct cred {
	kuid_t uid;
	kuid_t euid;
	kgid_t gid;
} __attribute__((preserve_access_index));

struct signal_struct {
	atomic_t live;
} __attribute__((preserve_access_index));

struct task_struct {
	unsigned int flags;
	pid_t pid;
	pid_t tgid;
	int exit_code;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	u64 start_boottime;
	const struct cred *real_cred;
	const struct cred *cred;
	struct mm_struct *mm;
	struct fs_struct *fs;
	struct signal_struct *signal;
	char comm[16];
} __attribute__((preserve_access_index));

struct module {
	char name[56];
} __attribute__((preserve_access_index));

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	u16 sk_protocol;
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

struct sockaddr {
	unsigned short sa_family;
};

struct iovec {
	void *iov_base;
	size_t iov_len;
} __attribute__((preserve_access_index));

/*
 * iov_iter: "iov" became "__iov" in 6.4, "ubuf" exists from 6.0, and the
 * iter_type enum was reordered in 6.4; zaaf.bpf.c checks each with
 * bpf_core_field_exists / bpf_core_enum_value.
 */
struct iov_iter {
	u8 iter_type;
	size_t iov_offset;
	size_t count;
	const struct iovec *__iov;
	void *ubuf;
} __attribute__((preserve_access_index));

struct iov_iter___pre64 {
	const struct iovec *iov;
} __attribute__((preserve_access_index));

enum iter_type {
	ITER_UBUF = 0,
	ITER_IOVEC = 1,
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
	struct iov_iter msg_iter;
} __attribute__((preserve_access_index));

/* *_MODULE_COMPRESSED: kernels that decompress modules themselves report a
 * compressed module file (finit_module with MODULE_INIT_COMPRESSED_FILE,
 * e.g. kmod 31 with .ko.zst) under its own id. Older kernels lack it;
 * the programs check that it exists. Values are relocated (CO-RE). */
enum kernel_read_file_id {
	READING_MODULE = 2,
	READING_MODULE_COMPRESSED = 7,
};

enum kernel_load_data_id {
	LOADING_MODULE = 2,
	LOADING_MODULE_COMPRESSED = 7,
};

/* Format of the syscalls:sys_enter_* and sys_exit_* tracepoints (stable). */
struct sys_enter_ctx {
	u64 common;
	s32 nr;
	u32 pad;
	u64 args[6];
};

struct sys_exit_ctx {
	u64 common;
	s32 nr;
	u32 pad;
	s64 ret;
};

#endif
