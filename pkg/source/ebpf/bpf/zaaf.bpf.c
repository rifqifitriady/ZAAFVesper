// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * ZAAFVesper's Linux event source: kernel programs that report process,
 * file, credential, process-access, kernel-module and network activity to
 * the sensor through one ring buffer. The Go side (pkg/source/ebpf) decodes
 * the records in wire.go; the record layouts below and there must match.
 *
 * Design rules:
 *  - Hooks are stable tracepoints, BTF tracepoints, fentry/fexit and the
 *    syscalls tracepoints only; no kprobes, so no architecture-specific
 *    register code.
 *  - Every loop is bounded (MAX_PATH_DEPTH); every copy length is masked.
 *  - A record that does not fit in the ring buffer is counted in "drops"
 *    (per CPU, per kind); the sensor turns a rising count into a
 *    SensorDegraded event. Nothing is lost without a count.
 *  - The sensor's own file activity is not reported (self_tgid).
 */
#include "vmlinux_min.h"
#include "libbpf/bpf_helpers.h"
#include "libbpf/bpf_core_read.h"
#include "libbpf/bpf_tracing.h"
#include "libbpf/bpf_endian.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Record kinds (wire.go: kind*). */
#define K_EXEC 1
#define K_EXIT 2
#define K_FORK 3
#define K_FILE 4
#define K_SETUID 5
#define K_PROCACC 6
#define K_MODULE 7
#define K_NET 8
#define K_DNS 9
#define K_MAX 10

/* File operations (K_FILE). */
#define F_OPEN 1
#define F_CREATE 2
#define F_UNLINK 3
#define F_RENAME 4

/* Flags in K_EXEC eflags / K_FILE fflags / K_PROCACC tflags. */
#define FL_ARGS_TRUNC 1    /* argv longer than ARGS_MAX */
#define FL_ARGS_ERR 2      /* argv could not be read */
#define FL_PATH_TRUNC 4    /* first path incomplete (too deep or too long) */
#define FL_PATH2_TRUNC 8   /* second path (cwd, rename destination) incomplete */
#define FL_TRUNCATED 16    /* K_FILE F_CREATE: existing file opened O_TRUNC */

/* Process-access syscalls (K_PROCACC). */
#define S_PTRACE 1
#define S_VM_READV 2
#define S_VM_WRITEV 3

#define PATH_MAX_LEN 4096 /* power of two */
#define PATH_MASK (PATH_MAX_LEN - 1)
#define MAX_PATH_DEPTH 64
#define NAME_MASK 255
#define ARGS_MAX 4096
#define DNS_MAX 512
#define MOD_PATH_MAX 512

/* Event assembly buffer: strings start below EV_STR_LIMIT and are at most
 * PATH_MAX_LEN long, so (pos & EV_MASK) + len always fits. */
#define EV_SIZE (16384 + PATH_MAX_LEN)
#define EV_MASK 16383

/* Linux constants (stable UAPI / fs.h). */
#define O_TRUNC 01000
#define FMODE_WRITE 0x2
#define FMODE_CREATED 0x100000
#define FMODE_EXEC_FLAG 0x20 /* __FMODE_EXEC in f_flags */
#define S_IFMT 00170000
#define S_IFREG 0100000
#define PF_KTHREAD 0x00200000
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define PTRACE_ATTACH 16
#define PTRACE_SEIZE 0x4206
#define PTRACE_MODE_ATTACH 0x02

/* Set by the loader before load (volatile const: .rodata). */
volatile const u32 self_tgid = 0;
volatile const u32 want_open = 0;

struct hdr {
	u32 kind;
	u32 size;
	u64 ktime; /* bpf_ktime_get_boot_ns */
	u32 pid;   /* thread-group id */
	u32 tid;
	u32 ppid;  /* real_parent's thread-group id */
	u32 uid;
	u32 euid;
	u32 pad;
	u64 start_ns;  /* group leader start_boottime */
	u64 pstart_ns; /* real_parent group leader start_boottime */
	char comm[16];
};

struct exec_body {
	u32 dev; /* kernel s_dev */
	u32 eflags;
	u64 ino;
	s64 ctime_ns;
	u32 exe_len;
	u32 args_len;
	u32 cwd_len;
	u32 pad;
};

struct exit_body {
	u32 exit_code;
	u32 pad;
};

struct file_body {
	u32 op;
	u32 f_flags;
	u32 f_mode;
	u32 path_len;
	u32 dest_len;
	u32 fflags;
};

struct setuid_body {
	u32 old_uid;
	u32 old_euid;
	u32 new_uid;
	u32 new_euid;
};

struct procacc_body {
	u32 syscall;
	u32 request;
	u32 target_pid;
	u32 tflags;
	u64 target_start;
	u32 texe_len;
	u32 pad;
};

struct module_body {
	u32 source; /* 1 file, 2 memory, 0 unknown */
	u32 path_len;
	char name[56];
};

struct net_body {
	u16 family;
	u16 proto;
	u8 dir; /* 1 outbound, 2 inbound */
	u8 pad[3];
	u16 sport;
	u16 dport;
	u32 payload_len; /* K_DNS only */
	u8 saddr[16];
	u8 daddr[16];
};

/* Layouts must match wire.go. */
_Static_assert(sizeof(struct hdr) == 72, "hdr");
_Static_assert(sizeof(struct exec_body) == 40, "exec_body");
_Static_assert(sizeof(struct exit_body) == 8, "exit_body");
_Static_assert(sizeof(struct file_body) == 24, "file_body");
_Static_assert(sizeof(struct setuid_body) == 16, "setuid_body");
_Static_assert(sizeof(struct procacc_body) == 32, "procacc_body");
_Static_assert(sizeof(struct module_body) == 64, "module_body");
_Static_assert(sizeof(struct net_body) == 48, "net_body");

struct evbuf {
	u8 data[EV_SIZE];
};

struct pathbuf {
	char data[PATH_MAX_LEN * 2];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20); /* the loader may resize */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, K_MAX);
	__type(key, u32);
	__type(value, u64);
} drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct evbuf);
} evscratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, struct pathbuf);
} pathscratch SEC(".maps");

/* Per-thread state carried from a syscall's entry to the hook that reports. */
struct procacc_stash {
	u32 syscall;
	u32 request;
	u32 target_pid;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct procacc_stash);
} procacc SEC(".maps");

struct module_stash {
	u32 source;
	u32 path_len;
	u32 flags;
	u32 pad;
	char path[MOD_PATH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, struct module_stash);
} modstash SEC(".maps");

static __always_inline void count_drop(u32 kind)
{
	u64 *n = bpf_map_lookup_elem(&drops, &kind);
	if (n)
		*n += 1;
}

static __always_inline struct evbuf *evbuf(void)
{
	u32 zero = 0;
	return bpf_map_lookup_elem(&evscratch, &zero);
}

static __always_inline struct pathbuf *pathbuf(u32 i)
{
	return bpf_map_lookup_elem(&pathscratch, &i);
}

static __always_inline u64 leader_start(struct task_struct *t)
{
	return BPF_CORE_READ(t, group_leader, start_boottime);
}

/* fill_hdr describes task t (the acting process, or a new child). */
static __always_inline void fill_hdr(struct hdr *h, u32 kind, struct task_struct *t)
{
	struct task_struct *parent = BPF_CORE_READ(t, real_parent);
	h->kind = kind;
	h->ktime = bpf_ktime_get_boot_ns();
	h->pid = BPF_CORE_READ(t, tgid);
	h->tid = BPF_CORE_READ(t, pid);
	h->ppid = BPF_CORE_READ(parent, tgid);
	h->uid = BPF_CORE_READ(t, real_cred, uid.val);
	h->euid = BPF_CORE_READ(t, real_cred, euid.val);
	h->pad = 0;
	h->start_ns = leader_start(t);
	h->pstart_ns = leader_start(parent);
	BPF_CORE_READ_STR_INTO(&h->comm, t, comm);
}

static __always_inline void submit(struct evbuf *eb, u32 kind, u32 size)
{
	struct hdr *h = (struct hdr *)eb->data;
	size &= EV_MASK;
	if (size < sizeof(struct hdr))
		return;
	h->size = size;
	if (bpf_ringbuf_output(&events, eb->data, size, 0) != 0)
		count_drop(kind);
}

/*
 * resolve writes the path of (dentry, vfsmnt) at the end of pb: the result is
 * pb->data[off .. PATH_MAX_LEN-1), and the return value is off. It walks at
 * most MAX_PATH_DEPTH components and crosses mount points; *complete is
 * false when the walk stopped early (too deep or too long), in which case
 * the path is the trailing part only. The walk runs under bpf_loop (5.17+),
 * so the verifier checks one step instead of every combination of steps.
 */
struct walk {
	struct pathbuf *pb;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	struct mount *mnt_parent;
	u32 off;
	u32 complete;
};

static long walk_step(u32 i, void *data)
{
	struct walk *w = data;
	struct pathbuf *pb = w->pb;
	/* Copy to locals: BPF_CORE_READ relocates every access in its argument,
	 * and struct walk is not a kernel type. */
	struct dentry *dentry = w->dentry;
	struct vfsmount *vfsmnt = w->vfsmnt;
	struct mount *mnt = w->mnt;
	struct mount *mnt_parent = w->mnt_parent;
	if (!pb)
		return 1;
	struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
	if (dentry == mnt_root || dentry == parent) {
		if (dentry == mnt_root && mnt != mnt_parent) {
			/* Cross into the parent mount. */
			w->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
			w->mnt = mnt_parent;
			w->mnt_parent = BPF_CORE_READ(mnt_parent, mnt_parent);
			w->vfsmnt = (struct vfsmount *)((void *)mnt_parent + bpf_core_field_offset(struct mount, mnt));
			return 0;
		}
		w->complete = 1;
		return 1;
	}
	u32 len = BPF_CORE_READ(dentry, d_name.len) & NAME_MASK;
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	u32 off = w->off & PATH_MASK;
	if (len + 1 >= off)
		return 1;
	off -= len;
	bpf_probe_read_kernel(&pb->data[off & PATH_MASK], len, name);
	off -= 1;
	pb->data[off & PATH_MASK] = '/';
	w->off = off;
	w->dentry = parent;
	return 0;
}

static __always_inline u32 resolve(struct pathbuf *pb, struct dentry *dentry, struct vfsmount *vfsmnt, bool *complete)
{
	/* container_of with the offset relocated for the running kernel. */
	struct mount *mnt = (struct mount *)((void *)vfsmnt - bpf_core_field_offset(struct mount, mnt));
	struct walk w = {
		.pb = pb,
		.dentry = dentry,
		.vfsmnt = vfsmnt,
		.mnt = mnt,
		.mnt_parent = BPF_CORE_READ(mnt, mnt_parent),
		.off = PATH_MAX_LEN - 1,
	};
	pb->data[PATH_MAX_LEN - 1] = 0;
	bpf_loop(MAX_PATH_DEPTH, walk_step, &w, 0);
	u32 off = w.off & PATH_MASK;
	if (off == PATH_MAX_LEN - 1) {
		/* The root itself. */
		off -= 1;
		pb->data[off & PATH_MASK] = '/';
	}
	*complete = w.complete;
	return off & PATH_MASK;
}

/* put_path copies a resolved path (without its NUL) to eb at pos. */
static __always_inline u32 put_path(struct evbuf *eb, u32 pos, struct pathbuf *pb, u32 off)
{
	u32 len = (PATH_MAX_LEN - 1 - off) & PATH_MASK;
	bpf_probe_read_kernel(&eb->data[pos & EV_MASK], len, &pb->data[off & PATH_MASK]);
	return len;
}

static __always_inline u32 put_file_path(struct evbuf *eb, u32 pos, struct file *f, u32 slot, u32 *flags, u32 trunc_flag)
{
	struct pathbuf *pb = pathbuf(slot);
	bool complete;
	if (!pb || !f)
		return 0;
	u32 off = resolve(pb, BPF_CORE_READ(f, f_path.dentry), BPF_CORE_READ(f, f_path.mnt), &complete);
	if (!complete)
		*flags |= trunc_flag;
	return put_path(eb, pos, pb, off);
}

static __always_inline s64 inode_ctime_ns(struct inode *ino)
{
	if (bpf_core_field_exists(ino->i_ctime_sec))
		return BPF_CORE_READ(ino, i_ctime_sec) * 1000000000LL + BPF_CORE_READ(ino, i_ctime_nsec);
	if (bpf_core_field_exists(ino->__i_ctime))
		return BPF_CORE_READ(ino, __i_ctime.tv_sec) * 1000000000LL + BPF_CORE_READ(ino, __i_ctime.tv_nsec);
	struct inode___pre66 *old = (void *)ino;
	if (bpf_core_field_exists(old->i_ctime))
		return BPF_CORE_READ(old, i_ctime.tv_sec) * 1000000000LL + BPF_CORE_READ(old, i_ctime.tv_nsec);
	return 0;
}

/* ---- process lifecycle ---- */

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p)
{
	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	struct hdr *h = (struct hdr *)eb->data;
	struct exec_body *b = (struct exec_body *)(eb->data + sizeof(struct hdr));
	fill_hdr(h, K_EXEC, p);
	__builtin_memset(b, 0, sizeof(*b));

	u32 pos = sizeof(struct hdr) + sizeof(struct exec_body);
	struct file *exe = BPF_CORE_READ(p, mm, exe_file);
	if (exe) {
		struct inode *ino = BPF_CORE_READ(exe, f_inode);
		b->dev = BPF_CORE_READ(ino, i_sb, s_dev);
		b->ino = BPF_CORE_READ(ino, i_ino);
		b->ctime_ns = inode_ctime_ns(ino);
		b->exe_len = put_file_path(eb, pos, exe, 0, &b->eflags, FL_PATH_TRUNC);
		pos += b->exe_len;
	}

	unsigned long as = BPF_CORE_READ(p, mm, arg_start);
	unsigned long ae = BPF_CORE_READ(p, mm, arg_end);
	if (ae > as) {
		u32 n = ae - as;
		if (n > ARGS_MAX - 1) {
			n = ARGS_MAX - 1;
			b->eflags |= FL_ARGS_TRUNC;
		}
		n &= (ARGS_MAX - 1);
		if (bpf_probe_read_user(&eb->data[pos & EV_MASK], n, (void *)as) == 0) {
			b->args_len = n;
			pos += n;
		} else {
			b->eflags |= FL_ARGS_ERR;
		}
	}

	struct pathbuf *pb = pathbuf(1);
	if (pb) {
		bool complete;
		u32 off = resolve(pb, BPF_CORE_READ(p, fs, pwd.dentry), BPF_CORE_READ(p, fs, pwd.mnt), &complete);
		if (!complete)
			b->eflags |= FL_PATH2_TRUNC;
		b->cwd_len = put_path(eb, pos, pb, off);
		pos += b->cwd_len;
	}
	submit(eb, K_EXEC, pos);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	/* One record per process: when the last thread exits. */
	if (BPF_CORE_READ(p, signal, live.counter) != 0)
		return 0;
	if (BPF_CORE_READ(p, flags) & PF_KTHREAD)
		return 0;
	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	struct hdr *h = (struct hdr *)eb->data;
	struct exit_body *b = (struct exit_body *)(eb->data + sizeof(struct hdr));
	fill_hdr(h, K_EXIT, p);
	b->exit_code = BPF_CORE_READ(p, exit_code);
	b->pad = 0;
	submit(eb, K_EXIT, sizeof(struct hdr) + sizeof(struct exit_body));
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	/* New processes only, not threads; and not kernel threads. */
	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return 0;
	if (BPF_CORE_READ(child, flags) & PF_KTHREAD)
		return 0;
	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	fill_hdr((struct hdr *)eb->data, K_FORK, child);
	submit(eb, K_FORK, sizeof(struct hdr));
	return 0;
}

/* ---- files ---- */

static __always_inline bool self(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == self_tgid;
}

SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *f)
{
	u32 flags = BPF_CORE_READ(f, f_flags);
	u32 fmode = BPF_CORE_READ(f, f_mode);
	if (flags & FMODE_EXEC_FLAG)
		return 0; /* exec is reported by on_exec */
	u32 op = F_OPEN, fl = 0;
	umode_t mode = BPF_CORE_READ(f, f_inode, i_mode);
	if ((mode & S_IFMT) == S_IFREG) {
		if (fmode & FMODE_CREATED) {
			op = F_CREATE;
		} else if ((flags & O_TRUNC) && (fmode & FMODE_WRITE)) {
			op = F_CREATE;
			fl = FL_TRUNCATED;
		}
	}
	if (op == F_OPEN && !want_open)
		return 0;
	if (self())
		return 0;
	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct file_body *b = (struct file_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_FILE, t);
	b->op = op;
	b->f_flags = flags;
	b->f_mode = fmode;
	b->fflags = fl;
	b->dest_len = 0;
	u32 pos = sizeof(struct hdr) + sizeof(struct file_body);
	b->path_len = put_file_path(eb, pos, f, 0, &b->fflags, FL_PATH_TRUNC);
	submit(eb, K_FILE, pos + b->path_len);
	return 0;
}

SEC("fentry/security_path_unlink")
int BPF_PROG(on_unlink, const struct path *dir, struct dentry *dentry)
{
	if (self())
		return 0;
	struct evbuf *eb = evbuf();
	struct pathbuf *pb = pathbuf(0);
	if (!eb || !pb)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct file_body *b = (struct file_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_FILE, t);
	__builtin_memset(b, 0, sizeof(*b));
	b->op = F_UNLINK;
	bool complete;
	u32 off = resolve(pb, dentry, BPF_CORE_READ(dir, mnt), &complete);
	if (!complete)
		b->fflags |= FL_PATH_TRUNC;
	u32 pos = sizeof(struct hdr) + sizeof(struct file_body);
	b->path_len = put_path(eb, pos, pb, off);
	submit(eb, K_FILE, pos + b->path_len);
	return 0;
}

SEC("fentry/security_path_rename")
int BPF_PROG(on_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (self())
		return 0;
	struct evbuf *eb = evbuf();
	struct pathbuf *pb = pathbuf(0);
	struct pathbuf *pb2 = pathbuf(1);
	if (!eb || !pb || !pb2)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct file_body *b = (struct file_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_FILE, t);
	__builtin_memset(b, 0, sizeof(*b));
	b->op = F_RENAME;
	bool complete;
	u32 off = resolve(pb, old_dentry, BPF_CORE_READ(old_dir, mnt), &complete);
	if (!complete)
		b->fflags |= FL_PATH_TRUNC;
	u32 pos = sizeof(struct hdr) + sizeof(struct file_body);
	b->path_len = put_path(eb, pos, pb, off);
	pos += b->path_len;
	off = resolve(pb2, new_dentry, BPF_CORE_READ(new_dir, mnt), &complete);
	if (!complete)
		b->fflags |= FL_PATH2_TRUNC;
	b->dest_len = put_path(eb, pos, pb2, off);
	submit(eb, K_FILE, pos + b->dest_len);
	return 0;
}

/* ---- credentials ---- */

SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, const struct cred *new)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	u32 old_uid = BPF_CORE_READ(t, real_cred, uid.val);
	u32 old_euid = BPF_CORE_READ(t, real_cred, euid.val);
	u32 new_uid = BPF_CORE_READ(new, uid.val);
	u32 new_euid = BPF_CORE_READ(new, euid.val);
	if (old_uid == new_uid && old_euid == new_euid)
		return 0;
	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	struct setuid_body *b = (struct setuid_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_SETUID, t);
	b->old_uid = old_uid;
	b->old_euid = old_euid;
	b->new_uid = new_uid;
	b->new_euid = new_euid;
	submit(eb, K_SETUID, sizeof(struct hdr) + sizeof(struct setuid_body));
	return 0;
}

/* ---- process access: ptrace attach/seize, process_vm_readv/writev ---- */

static __always_inline void stash_procacc(u32 sc, u32 request, u32 target)
{
	struct procacc_stash s = { .syscall = sc, .request = request, .target_pid = target };
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&procacc, &tid, &s, BPF_ANY);
}

static __always_inline void unstash_procacc(void)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&procacc, &tid);
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int on_enter_ptrace(struct sys_enter_ctx *ctx)
{
	u32 req = (u32)ctx->args[0];
	if (req == PTRACE_ATTACH || req == PTRACE_SEIZE)
		stash_procacc(S_PTRACE, req, (u32)ctx->args[1]);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int on_exit_ptrace(struct sys_exit_ctx *ctx)
{
	unstash_procacc();
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int on_enter_vm_readv(struct sys_enter_ctx *ctx)
{
	stash_procacc(S_VM_READV, 0, (u32)ctx->args[0]);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_process_vm_readv")
int on_exit_vm_readv(struct sys_exit_ctx *ctx)
{
	unstash_procacc();
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int on_enter_vm_writev(struct sys_enter_ctx *ctx)
{
	stash_procacc(S_VM_WRITEV, 0, (u32)ctx->args[0]);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_process_vm_writev")
int on_exit_vm_writev(struct sys_exit_ctx *ctx)
{
	unstash_procacc();
	return 0;
}

/*
 * The kernel calls this LSM hook after its own ptrace permission checks have
 * passed (Yama and other LSMs may still refuse). Reported only inside one of
 * the syscalls above, so ordinary /proc reads by ps and the like are not.
 */
SEC("fentry/security_ptrace_access_check")
int BPF_PROG(on_ptrace_check, struct task_struct *child, unsigned int mode)
{
	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct procacc_stash *s = bpf_map_lookup_elem(&procacc, &tid);
	if (!s)
		return 0;
	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct procacc_body *b = (struct procacc_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_PROCACC, t);
	b->syscall = s->syscall;
	b->request = s->request;
	b->target_pid = BPF_CORE_READ(child, tgid);
	b->tflags = 0;
	b->target_start = leader_start(child);
	b->texe_len = 0;
	b->pad = 0;
	bpf_map_delete_elem(&procacc, &tid); /* one record per syscall */
	u32 pos = sizeof(struct hdr) + sizeof(struct procacc_body);
	struct file *exe = BPF_CORE_READ(child, mm, exe_file);
	if (exe) {
		b->texe_len = put_file_path(eb, pos, exe, 0, &b->tflags, FL_PATH_TRUNC);
		pos += b->texe_len;
	}
	submit(eb, K_PROCACC, pos);
	return 0;
}

/* ---- kernel modules ---- */

static __always_inline void modstash_reset(void)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&modstash, &tid);
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int on_enter_init_module(struct sys_enter_ctx *ctx)
{
	modstash_reset();
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int on_enter_finit_module(struct sys_enter_ctx *ctx)
{
	modstash_reset();
	return 0;
}

static struct module_stash empty_modstash;

SEC("fentry/security_kernel_read_file")
int BPF_PROG(on_kernel_read_file, struct file *f, enum kernel_read_file_id id)
{
	if (id != bpf_core_enum_value(enum kernel_read_file_id, READING_MODULE))
		return 0;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&modstash, &tid, &empty_modstash, BPF_ANY) != 0)
		return 0;
	struct module_stash *m = bpf_map_lookup_elem(&modstash, &tid);
	struct pathbuf *pb = pathbuf(0);
	if (!m || !pb)
		return 0;
	m->source = 1;
	bool complete;
	u32 off = resolve(pb, BPF_CORE_READ(f, f_path.dentry), BPF_CORE_READ(f, f_path.mnt), &complete);
	u32 len = (PATH_MAX_LEN - 1 - off) & PATH_MASK;
	if (!complete)
		m->flags |= FL_PATH_TRUNC;
	if (len > MOD_PATH_MAX - 1) {
		/* Keep the end of the path (file name). */
		off += len - (MOD_PATH_MAX - 1);
		len = MOD_PATH_MAX - 1;
		m->flags |= FL_PATH_TRUNC;
	}
	len &= (MOD_PATH_MAX - 1);
	bpf_probe_read_kernel(m->path, len, &pb->data[off & PATH_MASK]);
	m->path_len = len;
	return 0;
}

SEC("fentry/security_kernel_load_data")
int BPF_PROG(on_kernel_load_data, enum kernel_load_data_id id)
{
	if (id != bpf_core_enum_value(enum kernel_load_data_id, LOADING_MODULE))
		return 0;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&modstash, &tid, &empty_modstash, BPF_ANY) != 0)
		return 0;
	struct module_stash *m = bpf_map_lookup_elem(&modstash, &tid);
	if (m)
		m->source = 2;
	return 0;
}

SEC("tp_btf/module_load")
int BPF_PROG(on_module_load, struct module *mod)
{
	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct module_body *b = (struct module_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_MODULE, t);
	__builtin_memset(b, 0, sizeof(*b));
	BPF_CORE_READ_STR_INTO(&b->name, mod, name);
	u32 pos = sizeof(struct hdr) + sizeof(struct module_body);
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct module_stash *m = bpf_map_lookup_elem(&modstash, &tid);
	if (m) {
		b->source = m->source;
		u32 len = m->path_len & (MOD_PATH_MAX - 1);
		bpf_probe_read_kernel(&eb->data[pos & EV_MASK], len, m->path);
		b->path_len = len;
		pos += len;
		bpf_map_delete_elem(&modstash, &tid);
	}
	submit(eb, K_MODULE, pos);
	return 0;
}

/* ---- network ---- */

static __always_inline bool v4mapped(const u8 *a)
{
	for (int i = 0; i < 10; i++)
		if (a[i] != 0)
			return false;
	return a[10] == 0xff && a[11] == 0xff;
}

static __always_inline void net_from_sock(struct net_body *n, struct sock *sk)
{
	n->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	n->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	n->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (n->family == AF_INET) {
		__be32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(n->saddr, &s, 4);
		__builtin_memcpy(n->daddr, &d, 4);
	} else {
		BPF_CORE_READ_INTO(&n->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&n->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

static __always_inline int report_tcp(struct sock *sk, u8 dir)
{
	struct evbuf *eb = evbuf();
	if (!eb || !sk)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct net_body *n = (struct net_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_NET, t);
	__builtin_memset(n, 0, sizeof(*n));
	n->proto = IPPROTO_TCP;
	n->dir = dir;
	net_from_sock(n, sk);
	submit(eb, K_NET, sizeof(struct hdr) + sizeof(struct net_body));
	return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(on_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	if (ret != 0)
		return 0;
	return report_tcp(sk, 1);
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(on_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	if (ret != 0)
		return 0;
	/* A v4-mapped destination is handed to tcp_v4_connect and reported there. */
	u8 d[16];
	BPF_CORE_READ_INTO(&d, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	if (v4mapped(d))
		return 0;
	return report_tcp(sk, 1);
}

/* inet_csk_accept returns the accepted socket. Its argument list changed
 * in 6.10, so the return value is read with bpf_get_func_ret (5.17+),
 * which does not depend on the argument count. */
SEC("fexit/inet_csk_accept")
int BPF_PROG(on_inet_csk_accept)
{
	u64 ret = 0;
	if (bpf_get_func_ret(ctx, &ret) != 0 || ret == 0)
		return 0;
	struct sock *sk = (struct sock *)ret;
	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;
	return report_tcp(sk, 2);
}

/* DNS: the first DNS_MAX bytes of a UDP datagram sent to port 53. */
static __always_inline int report_dns(struct sock *sk, struct msghdr *msg, bool v6)
{
	struct net_body tmp = {};
	void *name = BPF_CORE_READ(msg, msg_name);
	tmp.family = v6 ? AF_INET6 : AF_INET;
	if (name) {
		if (v6) {
			struct sockaddr_in6 a;
			if (bpf_probe_read_kernel(&a, sizeof(a), name) != 0)
				return 0;
			if (a.sin6_family != AF_INET6)
				return 0;
			tmp.dport = bpf_ntohs(a.sin6_port);
			__builtin_memcpy(tmp.daddr, a.sin6_addr.in6_u.u6_addr8, 16);
		} else {
			struct sockaddr_in a;
			if (bpf_probe_read_kernel(&a, sizeof(a), name) != 0)
				return 0;
			tmp.dport = bpf_ntohs(a.sin_port);
			__builtin_memcpy(tmp.daddr, &a.sin_addr.s_addr, 4);
		}
	} else {
		tmp.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		if (v6) {
			BPF_CORE_READ_INTO(&tmp.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		} else {
			__be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
			__builtin_memcpy(tmp.daddr, &d, 4);
		}
	}
	if (tmp.dport != 53)
		return 0;
	if (v6 && v4mapped(tmp.daddr))
		return 0; /* udpv6_sendmsg hands it to udp_sendmsg */

	/* Locate the payload: a single user buffer (ITER_UBUF, 6.0+) or the
	 * first element of a user iovec array. Kernel-internal sends are not
	 * read. */
	struct iov_iter *it = &msg->msg_iter;
	u8 type = BPF_CORE_READ(it, iter_type);
	size_t ioff = BPF_CORE_READ(it, iov_offset);
	void *base = 0;
	u64 avail = 0;
	if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
	    type == bpf_core_enum_value(enum iter_type, ITER_UBUF) && bpf_core_field_exists(it->ubuf)) {
		base = BPF_CORE_READ(it, ubuf);
		avail = BPF_CORE_READ(it, count);
	} else if (type == bpf_core_enum_value(enum iter_type, ITER_IOVEC)) {
		const struct iovec *iov;
		if (bpf_core_field_exists(it->__iov)) {
			iov = BPF_CORE_READ(it, __iov);
		} else {
			struct iov_iter___pre64 *old = (void *)it;
			iov = BPF_CORE_READ(old, iov);
		}
		if (!iov)
			return 0;
		base = BPF_CORE_READ(iov, iov_base);
		avail = BPF_CORE_READ(iov, iov_len);
		if (ioff > avail)
			return 0;
		avail -= ioff;
	} else {
		return 0;
	}
	if (!base || avail < 12)
		return 0;

	struct evbuf *eb = evbuf();
	if (!eb)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct net_body *n = (struct net_body *)(eb->data + sizeof(struct hdr));
	fill_hdr((struct hdr *)eb->data, K_DNS, t);
	*n = tmp;
	n->proto = 17; /* UDP */
	n->dir = 1;
	n->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u32 len = avail > DNS_MAX ? DNS_MAX : (u32)avail;
	len &= (DNS_MAX * 2 - 1);
	if (len > DNS_MAX)
		len = DNS_MAX;
	u32 pos = sizeof(struct hdr) + sizeof(struct net_body);
	if (bpf_probe_read_user(&eb->data[pos & EV_MASK], len, base + ioff) != 0)
		return 0;
	n->payload_len = len;
	submit(eb, K_DNS, pos + len);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return report_dns(sk, msg, false);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return report_dns(sk, msg, true);
}
