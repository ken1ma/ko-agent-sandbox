// Phase 3 of doc/plan-bpf-lsm-cgroup.md, the policy program: Phase 2's representative program
// (../phase2/classify.bpf.c) with what that phase left to this one ("The policy"): the identities
// of guarded objects as second names, the guard's alias contexts (policy.rs, `RuleContext::also`),
// the NTFS short-name form, the symlink target rules (fs.rs, `target_has_portable_syntax` and
// `allow_symlink_target`), `file_receive` under `--unix-sockets`, and the walk's state guarded
// against reentry ("Phases", 3). The verifier's answer to it on both kernels and the corpus's
// decisions are what the phase measures.
//
// Every loop is a `bpf_for` over the kernel's numeric iterator (bpf_iter_num_*, Linux 6.4), which
// the verifier checks by convergence rather than by simulating every iteration, and every value a
// loop carries between iterations lives in map memory ("Phase 2 on macOS", convergence). The walk,
// the rule match and the symlink judgment are global functions, verified once per program ("Phase
// 2 on WSL", global function).
//
// Return convention (kernel/bpf/cgroup.c, bpf_prog_run_array_cg): 1 allows, 0 becomes -EPERM.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define WALK_BOUND 64         // components a walk reads before it denies; above any measured depth
#define RETRY_BOUND 8         // walks discarded for a move of a dentry seen in flight, then denied
#define NAME_BYTES 256        // a dentry name is at most 255 bytes and NUL-terminated
#define RULE_LINES 128
#define RULE_COMPS 7          // bit k of a partial byte: the line's first k components matched
#define COMP_BYTES 64
#define FS_TYPE_BYTES 16
#define ALIAS_SLOTS 2         // alias contexts live at one position; the guard refuses a deeper nesting
#define ALIASES 16            // alias contexts the guard records
#define SCRATCH_SLOTS 4       // tasks judged at once on one CPU; a fifth is denied (reentry)
#define TARGET_BYTES 1024     // a symlink target longer than this is denied
#define TARGET_COMPS 64

// policy_config.flags
#define FLAG_SHORT_NAMES 1u   // deny a mutation whose ancestry, or a symlink target, holds an NTFS short-name form
#define FLAG_UNIX_SOCKETS 2u  // allow a socket inode beneath a root outside a gitdir; file_receive judges arrivals

// An index masked to its array, where the compiler cannot drop the mask as redundant: a bound the
// verifier takes from a check on a spilled or 32-bit value does not reach the pointer arithmetic
// on every kernel (measured: Linux 6.18 refused `sc->raw[index]` after `index >= WALK_BOUND`
// returned, "unbounded min value", where 7.2 took the bound).
#define BOUNDED(value, count) \
	({ __u32 bounded_ = (value); barrier_var(bounded_); bounded_ & ((count) - 1); })

#define FMODE_WRITE 0x2u
#define O_TRUNC_FLAG 01000
#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFLNK 0120000
#define S_IFSOCK 0140000
#define MAX_ERRNO 4095
#define MNT_NS_ANON_INO 0xEFFFFFF7u  // every anonymous mount namespace's inode number on Linux 6.18 (measured)

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
	HOOK_COUNT,
};

// Why a call was denied, recorded with the decision; 0 is allowed.
enum reason {
	R_ALLOW,
	R_OUTSIDE,            // allowed: a superblock of another type, before any walk
	R_WALK_NOROOT,        // the walk met the filesystem root and no recorded root
	R_WALK_BOUND,         // the walk read WALK_BOUND components
	R_WALK_TORN,          // RETRY_BOUND walks each overlapped a rename
	R_NAME_TOO_LONG,
	R_GIT_PROTECTED,      // the object is a protected gitdir entry
	R_GIT_PINNED,         // `objects` or `objects/info`, created by mkdir alone, never moved
	R_GIT_NAME,           // a new `.git` name
	R_SANDBOX_NAME,       // a new `.ko-agent-sandbox` name, or an entry below one
	R_HEAD,               // a non-directory HEAD coming to be in a `.git` ("Directories")
	R_RULE_READ_ONLY,
	R_RULE_PINNED,
	R_REGION,             // a directory or symlink leaving a writable region or a gitdir
	R_SOCKET,             // a socket inode coming to be beneath a recorded root
	R_INTERNAL,           // a map lookup failed
	R_REENTRY,            // every scratch slot of this CPU was in use
	R_SHORT_NAME,         // an ancestry component of the NTFS short-name form, under FLAG_SHORT_NAMES
	R_ALIAS_OVERFLOW,     // more alias contexts at one position than ALIAS_SLOTS
	R_SYMLINK_SYNTAX,     // an absolute target, or one climbing above the workspace root
	R_SYMLINK_SHORT,      // a target component of the NTFS short-name form
	R_SYMLINK_GITDIR,     // a target entering a gitdir from the workspace
	R_SYMLINK_REGION,     // a target into a writable region from outside it
	R_SOCKET_GITDIR,      // under FLAG_UNIX_SOCKETS, a socket inode coming to be in a gitdir
	R_RECEIVE_NS,         // a descriptor from another mount namespace, not a share file the receiver may open
	R_RECEIVE_DIR,        // such a descriptor of a directory
	R_COUNT,
};

struct ident {
	__u64 s_dev;
	__u64 i_ino;
};

enum root_kind {
	ROOT_WORKSPACE = 1,   // a workspace root, or the proof fixture's: the walk's position is NotGit
	ROOT_GITDIR = 2,      // a gitdir the guard resolved under `modules/`: the position is InGit([])
	ROOT_VOLUME = 3,      // the persistent volume's root: the socket rule alone
	ROOT_GUARDED_GIT = 4,     // the root's `.git` object: any name of it is the gitdir entry
	ROOT_GUARDED_SANDBOX = 5, // the root's `.ko-agent-sandbox` object: any name of it is the launcher's directory
};

struct root {
	__u32 kind;
	__u32 pad;
};

// One resolved rule line, folded by the guard. `alias` names the alias context (1-based) the
// line's end carries, for an anchored `pinned-path` line at the end of a symlink the guard
// followed; 0 is none.
struct rule_line {
	__u8 word;            // 1 read-only, 2 writable, 3 pinned-path
	__u8 anchored;
	__u8 ncomp;
	__u8 alias;
	char comp[RULE_COMPS][COMP_BYTES];
};

#define WORD_READ_ONLY 1
#define WORD_WRITABLE 2
#define WORD_PINNED 3

// The rule context of the symlink whose end a `pinned-path` line names: what every entry below
// that end also stands as (policy.rs, `FileRules::push_alias`).
struct alias_context {
	__u8 partial[RULE_LINES];
	__s32 deciding;
	__u32 pinned_path;
};

struct policy_config {
	__u32 rule_count;
	__u32 flags;
	char fs_type[FS_TYPE_BYTES];      // the share's type: what the walk judges
	char vol_fs_type[FS_TYPE_BYTES];  // the volume's type, for file_receive; empty when no volume is recorded
	__u32 runtime_mnt_ns;             // the runtime's mount namespace, the controller's own, by inode number
	__u32 pad;
	struct ident host_root;           // the host's root directory, the controller's `/`
};

// The field that marks an anonymous mount namespace, one `open_tree` with `OPEN_TREE_CLONE` makes
// (fs/namespace.c, `is_anon_ns`): `is_anon` on Linux 7.2, `seq` equal to 0 on 6.18. Each is a
// CO-RE flavor of `struct mnt_namespace`, resolved against the running kernel at load.
struct mnt_namespace___anon {
	bool is_anon;
} __attribute__((preserve_access_index));

struct mnt_namespace___seq {
	__u64 seq;
} __attribute__((preserve_access_index));

struct hook_stats {
	__u64 calls;
	__u64 allowed;
	__u64 denied;
	__u64 outside;        // allowed before any walk, another superblock type
	__u64 walks;          // walks that ended with the sequence unchanged
	__u64 retries;
	__u64 gave_up;
	__u64 max_depth;
	__u64 ns_sum;         // bpf_ktime_get_ns from entry to decision, over the calls not outside
	__u64 ns_max;
	__u64 reentry;        // calls denied for want of a scratch slot
	__u64 nested_max;     // the highest slot index a call took: how deep tasks nested on one CPU
};

struct last_decision {
	__u64 count;
	__u32 hook;
	__u32 reason;
	__u32 depth;
	__u32 root_kind;
	char name[32];
	// file_receive's refusal, for the record: the receiver and the file's namespace.
	__u64 ns_inum;
	__u64 ns_anon;
	__u64 ns_root_dev;
	__u64 ns_root_ino;
	char comm[16];
	char ns_root[32];
	char my_root[32];
};

enum git_kind {
	GIT_NOT,
	GIT_IN,               // inside a gitdir; rel_start is the index of rel[0]
	GIT_MODULE_NS,        // a directory under `modules` not known as a gitdir root
	GIT_SANDBOX,          // the `.ko-agent-sandbox` entry or anything below it
};

struct position {
	__u32 git_kind;
	__s32 rel_start;      // sc->raw index of the gitdir-relative path's first component, or -1
	__u32 rel_len;        // its length; 0 is the gitdir entry itself
	__u32 depth;
	__u32 root_kind;
	__u32 status;         // walk status
	__u8 protected_git;   // classify() == Protected
	__u8 pinned_git;      // `objects` or `objects/info` of a gitdir
	__u8 target_dotgit;   // the target's own folded name is `.git`
	__u8 target_sandbox;  // ... `.ko-agent-sandbox`
	__u8 target_head;     // ... `head`, directly in a `.git`-named directory
	__u8 rule_read_only;  // under any of the entry's names
	__u8 rule_pinned;
	__u8 short_name;      // an ancestry component of the NTFS short-name form, under FLAG_SHORT_NAMES
	__u8 alias_overflow;
	__u8 pad[3];
	__s16 region;         // the `writable` line whose region the entry is in, or -1
	__s16 deciding;
};

// The values a loop carries from one iteration to the next, written to the map and read again at
// every iteration: the verifier does not track a map's contents, so it sees an unknown scalar at
// each iteration and the loop's states converge. A counter it tracks exactly, a register or stack
// slot used as an index or in a branch it can decide, makes every iteration a new state (measured:
// the fold's output counter unrolled 204 iterations deep until the program was "too large").
struct loop_state {
	__u32 depth;          // walk_once: the components recorded so far, and the levels read
	__u32 levels;
	__s32 mark_level;     // walk_once: the level of a gitdir or guarded root met on the way, or -1
	__u32 mark_kind;
	__u32 fold_out;       // fold_component: bytes written, and the position read
	__u32 fold_pos;
	__u32 glob_p;         // component_matches: the pattern and name positions, the backtrack point
	__u32 glob_n;
	__u32 glob_star_p;
	__u32 glob_star_n;
	__u32 glob_have_star;
	__u32 reached;        // rule_child: the current line's matched components
	__s32 deciding;       // the rule state: the last line naming the entry or an ancestor, -1 for none
	__u32 pinned_path;    // a pinned-path line names the entry
	__u32 any_partial;    // some line is an interior match: the entry is pinned
	__u32 activate;       // rule_child: the alias contexts (bit a: aliases[a]) the entry activates
	__u32 git_kind;       // locate: the git context so far
	__s32 rel_start;
	__u32 rel_len;
	__u32 dot;            // has_short_name_shape: the last `.` seen, plus one
	__u32 tgt_pos;        // judge_symlink: the target's read position, the resolved level, the component's length
	__u32 tgt_level;
	__u32 tgt_clen;
	__u32 tgt_first;      // the first special component of the resolved prefix, plus one
	__u32 same;           // alias_activate: a live slot equals the candidate
	__u64 barrier;        // walk_once: the word the barrier's fetch-add counts on
	__u64 cur;            // walk_level: the dentry the level reads, then its parent
	__u32 status;         // walk_level: the walk's end, a walk_status, and the root's kind there
	__u32 root_kind;
};

// Where an entry stands under the rules, for the main context and each live alias context
// (policy.rs, `RuleContext`): the lines partially matched by the entry's ancestors, the deciding
// line, and whether a pinned-path line names the entry.
struct rule_state {
	__u8 partial[RULE_LINES];     // bit k: the line's first k components match this entry's ancestors
	__s32 deciding;
	__u8 pinned_path;
	__u8 any_partial;
	__u8 live;
	__u8 pad;
};

// The walk's names, leaf first, and the classifier's working state. Per CPU and per slot: 512
// bytes of stack hold none of it, and a task preempted inside the program leaves its slot taken
// for the task that then enters on the same CPU ("Phases", 3).
struct scratch {
	char raw[WALK_BOUND][NAME_BYTES];
	__u8 raw_len[WALK_BOUND];
	__u64 dentries[WALK_BOUND];   // walk_once: each level's dentry and the sequence it was read under
	__u32 seqs[WALK_BOUND];
	char fold[NAME_BYTES];
	__u32 fold_len;
	char comp[NAME_BYTES];        // judge_symlink: the target component being judged
	struct rule_state ctx[1 + ALIAS_SLOTS];
	__u8 partial_next[RULE_LINES];
	__u8 level_partial[WALK_BOUND][RULE_LINES];   // the main context after each level below the root
	__s32 level_deciding[WALK_BOUND];
	__u8 tgt_special[WALK_BOUND];                 // judge_symlink: 1 a `.git`, 2 a `.ko-agent-sandbox`, per level
	char target[TARGET_BYTES];
	struct loop_state loop;
	char base[64];                // lock_base_is_operational: the name before `.lock`
	struct position pos[2];       // the hook's positions: the object's, and a destination's
};

// The slots in use on this CPU, one bit each.
struct cpu_guard {
	__u64 in_use;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct ident);
	__type(value, struct root);
} roots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RULE_LINES);
	__type(key, __u32);
	__type(value, struct rule_line);
} rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ALIASES);
	__type(key, __u32);
	__type(value, struct alias_context);
} aliases SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_config);
} policy_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, SCRATCH_SLOTS);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cpu_guard);
} guard SEC(".maps");

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
	__type(value, struct last_decision);
} last_decision SEC(".maps");

// ---------------------------------------------------------------------------------------------
// The scratch slots
// ---------------------------------------------------------------------------------------------

static __always_inline struct scratch *get_scratch(__u32 slot)
{
	__u32 key = slot & (SCRATCH_SLOTS - 1);

	return bpf_map_lookup_elem(&scratch, &key);
}

static __always_inline struct policy_config *get_config(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&policy_config, &zero);
}

// The lowest free slot of this CPU, taken by an atomic or; -1 when every slot is in use. The
// kernel runs a cgroup's programs under migrate_disable, so the slot is released on the CPU that
// took it.
static __always_inline int acquire_slot(void)
{
	__u32 zero = 0;
	struct cpu_guard *g = bpf_map_lookup_elem(&guard, &zero);
	int k;

	if (!g)
		return -1;
	bpf_for(k, 0, SCRATCH_SLOTS) {
		__u64 bit = 1ull << k;
		__u64 old = __sync_fetch_and_or(&g->in_use, bit);

		if (!(old & bit))
			return k;
	}
	return -1;
}

static __always_inline void release_slot(int slot)
{
	__u32 zero = 0;
	struct cpu_guard *g = bpf_map_lookup_elem(&guard, &zero);
	__u64 old;

	if (!g || slot < 0)
		return;
	old = __sync_fetch_and_and(&g->in_use, ~(1ull << (slot & (SCRATCH_SLOTS - 1))));
	barrier_var(old);
}

// ---------------------------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------------------------

enum walk_status {
	WALK_OK,              // a recorded root was met
	WALK_NOROOT,
	WALK_BOUND_HIT,
	WALK_TORN,
	WALK_TOO_LONG,
};

struct walk {
	__u32 depth;          // components read, the target's name first
	__u32 root_kind;
	__u32 status;
	__u32 retries;
	__s32 mark_level;     // the level of a gitdir or guarded root below the walk's root, or -1
	__u32 mark_kind;
};

// The ordering between a dentry's sequence reads and its field reads: an atomic fetch-add, which
// the JITs emit with a barrier ("What is gained and what is lost"). The fetched value is kept live
// and the word is map memory: an add whose result is unused compiles to the plain atomic add
// (no BPF_FETCH), which the arm64 JIT emits without ordering (measured: `stadd`, no `ldaddal`).
static __always_inline void barrier_fetch_add(struct scratch *sc)
{
	__u64 old = __sync_fetch_and_add(&sc->loop.barrier, 1);

	barrier_var(old);
}

// One level of the walk, from the dentry `ls->cur`: its name into `sc->raw[level]`, its inode
// looked up among the roots, its parent into `ls->cur`. Returns 1 to go on to the parent, 0 at the
// walk's end with `ls->status` and `ls->root_kind` set, or -1 for a dentry seen mid-move, which
// discards the walk. A global function, as the walk's two loops' bodies are: the verifier checks a
// global function once for any arguments, where it checks a loop's inlined body at every iteration
// until the states converge, which for this body took 919,220 instructions of the 1,000,000 limit
// on 6.18 ("Phase 3 on WSL") and 33,135 on 7.2.5.
__noinline int walk_level(__u64 slot, __u64 level)
{
	struct scratch *sc = get_scratch(slot);
	volatile struct loop_state *ls;
	struct dentry *cur, *parent;
	struct inode *inode;
	const unsigned char *name;
	__u32 i, seq0, seq1, len;
	long copied;

	if (!sc || level >= WALK_BOUND)
		return -1;
	ls = &sc->loop;
	i = level;
	cur = (struct dentry *)ls->cur;
	seq0 = BPF_CORE_READ(cur, d_seq.seqcount.sequence);
	ls->depth = i;
	if (seq0 & 1)
		return -1;
	sc->dentries[BOUNDED(i, WALK_BOUND)] = (__u64)cur;
	sc->seqs[BOUNDED(i, WALK_BOUND)] = seq0;
	ls->levels = i + 1;
	barrier_fetch_add(sc);
	inode = BPF_CORE_READ(cur, d_inode);
	len = BPF_CORE_READ(cur, d_name.len);
	name = BPF_CORE_READ(cur, d_name.name);
	parent = BPF_CORE_READ(cur, d_parent);
	copied = len < NAME_BYTES ? bpf_probe_read_kernel_str(sc->raw[BOUNDED(i, WALK_BOUND)], NAME_BYTES, name) : -1;
	barrier_fetch_add(sc);
	seq1 = BPF_CORE_READ(cur, d_seq.seqcount.sequence);
	if (seq1 != seq0)
		return -1;
	if (inode) {
		struct ident id;
		struct root *root;

		id.s_dev = BPF_CORE_READ(inode, i_sb, s_dev);
		id.i_ino = BPF_CORE_READ(inode, i_ino);
		root = bpf_map_lookup_elem(&roots, &id);
		if (root) {
			__u32 kind = root->kind;

			if (kind == ROOT_WORKSPACE || kind == ROOT_VOLUME) {
				ls->root_kind = kind;
				ls->status = WALK_OK;
				return 0;
			}
			if (ls->mark_level < 0) {
				ls->mark_level = i;
				ls->mark_kind = kind;
			}
		}
	}
	if (copied < 0) {
		ls->status = WALK_TOO_LONG;
		return 0;
	}
	sc->raw_len[BOUNDED(i, WALK_BOUND)] = len;
	ls->depth = i + 1;
	if (!parent || parent == cur) {
		ls->status = WALK_NOROOT;
		return 0;
	}
	ls->cur = (__u64)parent;
	return 1;
}

// One level of the snapshot: whether the dentry read at `level`, through the address it was read
// at, is still at the sequence it was read under. Returns 1 so, 0 moved, -1 for a bad slot.
__noinline int walk_recheck(__u64 slot, __u64 level)
{
	struct scratch *sc = get_scratch(slot);
	struct dentry *seen;
	__u32 i;

	if (!sc || level >= WALK_BOUND)
		return -1;
	i = level;
	seen = (struct dentry *)sc->dentries[BOUNDED(i, WALK_BOUND)];
	return BPF_CORE_READ(seen, d_seq.seqcount.sequence) == sc->seqs[BOUNDED(i, WALK_BOUND)];
}

// One pass from `start` toward the root: each component's name into `sc->raw`, until a dentry
// whose inode is a workspace or volume root, the filesystem root, or the bound. A gitdir root or
// a guarded object met on the way is marked and the walk goes on, so that the rules and the
// symlink depth keep the workspace's ancestry; it is the walk's root only where no workspace root
// lies above it. Each dentry's fields are
// read under its own sequence count, `d_seq`, which `__d_move` and `d_exchange` hold odd across
// the parent and name change (fs/dcache.c), and every level's count is read again after the last
// level, through the address each level was read at: a dentry seen mid-move, or moved at any
// time before that last read, discards the walk, so the chain is the object's position over one
// interval of the walk and not a composition of two moments, as the RCU path walk's revalidation
// makes a lookup's (fs/namei.c, `lookup_fast`). The addresses are scalars, read through the
// probe helper, and the program runs under the caller's RCU read lock, which keeps a dentry's
// memory a dentry (fs/dcache.c, `__d_free`). A rename elsewhere in the VM discards nothing
// (measured: a global `rename_lock` check retried at every rename of sixteen processes and gave
// up, "Phase 3 on macOS").
static __always_inline int walk_once(__u64 slot, struct dentry *start, struct scratch *sc, struct walk *out)
{
	volatile struct loop_state *ls = &sc->loop;
	int i, k;

	ls->depth = 0;
	ls->levels = 0;
	ls->mark_level = -1;
	ls->mark_kind = 0;
	ls->cur = (__u64)start;
	ls->status = WALK_BOUND_HIT;
	ls->root_kind = 0;
	bpf_for(i, 0, WALK_BOUND) {
		int next = walk_level(slot, i);

		if (next < 0)
			return 0;
		if (next == 0)
			break;
	}
	// The snapshot: no level moved while the levels above it were read.
	barrier_fetch_add(sc);
	bpf_for(k, 0, WALK_BOUND) {
		if (k >= ls->levels)
			break;
		if (walk_recheck(slot, k) != 1)
			return 0;
	}
	out->depth = ls->depth;
	out->root_kind = ls->root_kind;
	out->status = ls->status;
	out->mark_level = ls->mark_level;
	out->mark_kind = ls->mark_kind;
	if (ls->status == WALK_NOROOT && ls->mark_level >= 0) {
		// The filesystem root reached with no workspace root above the marked root: it is the
		// walk's root, and the names below it are the position. A walk that reached the bound
		// or a name too long keeps its status and denies, whatever it marked.
		out->depth = ls->mark_level;
		out->root_kind = ls->mark_kind;
		out->status = WALK_OK;
		out->mark_level = -1;
	}
	return 1;
}

static __always_inline void walk(enum hook hook, __u64 slot, struct dentry *start, struct scratch *sc,
				 struct walk *out)
{
	__u32 key = hook;
	struct hook_stats *st = bpf_map_lookup_elem(&stats, &key);
	int ok = 0, i;

	out->depth = 0;
	out->root_kind = 0;
	out->status = WALK_TORN;
	out->retries = RETRY_BOUND;
	out->mark_level = -1;
	out->mark_kind = 0;
	bpf_for(i, 0, RETRY_BOUND) {
		if (walk_once(slot, start, sc, out)) {
			ok = 1;
			out->retries = i;
			break;
		}
	}
	if (st) {
		if (ok)
			__sync_fetch_and_add(&st->walks, 1);
		else
			__sync_fetch_and_add(&st->gave_up, 1);
		__sync_fetch_and_add(&st->retries, out->retries);
		if (out->depth > st->max_depth)
			st->max_depth = out->depth;
	}
}

// ---------------------------------------------------------------------------------------------
// The fold: policy.rs, `fold`
// ---------------------------------------------------------------------------------------------

// The sequences `fold` treats specially, matched without a loop: a byte at or above 0x80 starts
// one of the code points a filesystem may ignore when comparing names (git's next_hfs_char:
// U+00AD, U+200B to U+200F, U+202A to U+202E, U+2060, U+206A to U+206F and U+FEFF, dropped) or
// one it may compare equal to an ASCII letter (U+0130 and U+0131 to `i`, U+212A to `k`,
// U+017F to `s`), or is copied as it is. Straight-line code: a loop over a table here is
// verified at every iteration of the fold's loop, and that loop at every component's.
static __always_inline int special_sequence(const char *src, __u32 pos, __u32 len, __u32 *step, __u8 *ascii)
{
	__u8 b0 = src[BOUNDED(pos, NAME_BYTES)];
	__u8 b1 = pos + 1 < len ? src[BOUNDED(pos + 1, NAME_BYTES)] : 0;
	__u8 b2 = pos + 2 < len ? src[BOUNDED(pos + 2, NAME_BYTES)] : 0;

	*ascii = 0;
	*step = 0;
	switch (b0) {
	case 0xc2:
		if (b1 == 0xad)
			*step = 2;
		break;
	case 0xc4:
		if (b1 == 0xb0 || b1 == 0xb1) {
			*step = 2;
			*ascii = 'i';
		}
		break;
	case 0xc5:
		if (b1 == 0xbf) {
			*step = 2;
			*ascii = 's';
		}
		break;
	case 0xe2:
		if (b1 == 0x80 && ((b2 >= 0x8b && b2 <= 0x8f) || (b2 >= 0xaa && b2 <= 0xae)))
			*step = 3;
		else if (b1 == 0x81 && (b2 == 0xa0 || (b2 >= 0xaa && b2 <= 0xaf)))
			*step = 3;
		else if (b1 == 0x84 && b2 == 0xaa) {
			*step = 3;
			*ascii = 'k';
		}
		break;
	case 0xef:
		if (b1 == 0xbb && b2 == 0xbf)
			*step = 3;
		break;
	}
	return *step != 0;
}

// `src`, a NAME_BYTES buffer of the scratch holding `len` bytes, folded into `sc->fold`: the
// special sequences dropped or folded, trailing `.` and space stripped, ASCII lowercased.
static __always_inline void fold_bytes(struct scratch *sc, const char *src, __u32 len)
{
	volatile struct loop_state *ls = &sc->loop;
	__u32 out;
	int i;

	ls->fold_out = 0;
	ls->fold_pos = 0;
	bpf_for(i, 0, NAME_BYTES) {
		__u32 pos = ls->fold_pos, out = ls->fold_out, step;
		__u8 byte, ascii;

		if (pos >= len || out >= NAME_BYTES - 1)
			break;
		byte = src[BOUNDED(pos, NAME_BYTES)];
		if (byte >= 0x80 && special_sequence(src, pos, len, &step, &ascii)) {
			if (ascii) {
				sc->fold[BOUNDED(out, NAME_BYTES)] = ascii;
				ls->fold_out = out + 1;
			}
			ls->fold_pos = pos + step;
			continue;
		}
		if (byte >= 'A' && byte <= 'Z')
			byte += 'a' - 'A';
		sc->fold[BOUNDED(out, NAME_BYTES)] = byte;
		ls->fold_out = out + 1;
		ls->fold_pos = pos + 1;
	}
	bpf_for(i, 0, NAME_BYTES) {
		__u32 out = ls->fold_out;
		__u8 last;

		if (out == 0 || out >= NAME_BYTES)
			break;
		last = sc->fold[BOUNDED(out - 1, NAME_BYTES)];
		if (last != '.' && last != ' ')
			break;
		ls->fold_out = out - 1;
	}
	out = BOUNDED(ls->fold_out, NAME_BYTES);
	sc->fold[out] = 0;
	sc->fold_len = out;
}

// `sc->raw[index]` folded into `sc->fold`. Returns 0 when the index is out of range.
static __always_inline int fold_component(struct scratch *sc, __u32 index)
{
	__u32 len;

	if (index >= WALK_BOUND)
		return 0;
	len = sc->raw_len[BOUNDED(index, WALK_BOUND)];
	if (len >= NAME_BYTES)
		return 0;
	fold_bytes(sc, sc->raw[BOUNDED(index, WALK_BOUND)], len);
	return 1;
}

// Whether `sc->fold` equals a literal.
#define FOLD_IS(sc, lit) ((sc)->fold_len == sizeof(lit) - 1 && bpf_strncmp((sc)->fold, sizeof(lit), lit) == 0)
// Whether a raw component equals a literal, byte for byte.
#define RAW_IS(sc, index, lit) \
	((sc)->raw_len[BOUNDED(index, WALK_BOUND)] == sizeof(lit) - 1 && \
	 bpf_strncmp((sc)->raw[BOUNDED(index, WALK_BOUND)], sizeof(lit), lit) == 0)

// Whether `src`, a NAME_BYTES buffer holding `len` bytes, has the shape of an NTFS 8.3 short name
// (fs.rs, `has_short_name_shape`): a base of at most eight bytes ending in `~` and digits, and an
// extension of at most three.
static __always_inline int has_short_name_shape(struct scratch *sc, const char *src, __u32 len)
{
	volatile struct loop_state *ls = &sc->loop;
	__u32 dot, base_len, ext_len, digits = 0;
	int k;

	if (len == 0 || len >= NAME_BYTES)
		return 0;
	ls->dot = 0;
	bpf_for(k, 0, NAME_BYTES) {
		if (k >= len)
			break;
		if (src[BOUNDED(k, NAME_BYTES)] == '.')
			ls->dot = k + 1;
	}
	dot = ls->dot;
	base_len = dot ? dot - 1 : len;
	ext_len = dot ? len - dot : 0;
	if (base_len > 8 || ext_len > 3 || base_len < 2)
		return 0;
	bpf_for(k, 0, 8) {
		__u8 byte;

		if (k >= base_len)
			break;
		byte = src[BOUNDED(base_len - 1 - k, NAME_BYTES)];
		if (byte < '0' || byte > '9')
			break;
		digits = k + 1;
	}
	if (digits == 0 || digits >= base_len)
		return 0;
	return src[BOUNDED(base_len - digits - 1, NAME_BYTES)] == '~';
}

// ---------------------------------------------------------------------------------------------
// The rule match: policy.rs, `component_matches` and `child_rule_context`
// ---------------------------------------------------------------------------------------------

// Whether the folded name matches one folded pattern component, `*` matching any run of bytes:
// the iterative matcher with one backtrack point, so a pattern of many stars stays polynomial.
static __always_inline int component_matches(struct scratch *sc, const char *pattern)
{
	volatile struct loop_state *ls = &sc->loop;
	const char *name = sc->fold;
	__u32 name_len = sc->fold_len;
	int i;

	ls->glob_p = 0;
	ls->glob_n = 0;
	ls->glob_star_p = 0;
	ls->glob_star_n = 0;
	ls->glob_have_star = 0;
	bpf_for(i, 0, COMP_BYTES * NAME_BYTES) {
		__u32 p = ls->glob_p, n = ls->glob_n;
		__u8 pc;

		if (n >= name_len)
			break;
		pc = p < COMP_BYTES ? pattern[BOUNDED(p, COMP_BYTES)] : 0;
		if (pc == '*') {
			ls->glob_star_p = p;
			ls->glob_star_n = n;
			ls->glob_have_star = 1;
			ls->glob_p = p + 1;
		} else if (pc != 0 && pc == (__u8)name[BOUNDED(n, NAME_BYTES)]) {
			ls->glob_p = p + 1;
			ls->glob_n = n + 1;
		} else if (ls->glob_have_star) {
			__u32 star_n = ls->glob_star_n + 1;

			ls->glob_p = ls->glob_star_p + 1;
			ls->glob_star_n = star_n;
			ls->glob_n = star_n;
		} else {
			return 0;
		}
	}
	bpf_for(i, 0, COMP_BYTES) {
		__u32 p = ls->glob_p;

		if (p >= COMP_BYTES)
			break;
		if (pattern[BOUNDED(p, COMP_BYTES)] == 0)
			return 1;
		if (pattern[BOUNDED(p, COMP_BYTES)] != '*')
			return 0;
		ls->glob_p = p + 1;
	}
	return 1;
}

// Whether the folded name equals an anchored line's component, byte for byte: the guard spelled
// a name it found, where `*` is a byte of the name.
static __always_inline int component_equals(struct scratch *sc, const char *pattern)
{
	__u32 name_len = sc->fold_len;
	int k;

	if (name_len >= COMP_BYTES)
		return 0;
	bpf_for(k, 0, COMP_BYTES) {
		__u8 pc = pattern[BOUNDED(k, COMP_BYTES)];

		if (k >= name_len)
			return pc == 0;
		if (pc != (__u8)sc->fold[BOUNDED(k, NAME_BYTES)])
			return 0;
	}
	return 0;
}

static __always_inline __u8 rule_word(__s32 line)
{
	__u32 key = line;
	struct rule_line *rule;

	if (line < 0)
		return 0;
	rule = bpf_map_lookup_elem(&rules, &key);
	return rule ? rule->word : 0;
}

// Where an ordinary entry stands under the rules, computed from its parent's state and its folded
// name, `sc->fold`: the child's state replaces the parent's in `sc->ctx[ctx_index]`. Returns the
// alias contexts (bit a: aliases[a]) the entry activates, by the pinned-path lines ending here,
// or -1 for an error. `anchored_ok` is set for a child of a workspace root. A global function: the
// verifier checks it once per program, where the main context and each alias context call it at
// every level.
__noinline int rule_child(__u64 slot, __u64 ctx_index, __u64 anchored_ok)
{
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch(slot);
	volatile struct loop_state *ls;
	struct rule_state *st;
	__u32 count;
	int line;

	if (!cfg || !sc || ctx_index > ALIAS_SLOTS)
		return -1;
	ls = &sc->loop;
	st = &sc->ctx[BOUNDED(ctx_index, 4)];
	count = cfg->rule_count;
	if (count > RULE_LINES)
		count = RULE_LINES;
	ls->deciding = st->deciding;
	ls->pinned_path = 0;
	ls->any_partial = 0;
	ls->activate = 0;
	bpf_for(line, 0, RULE_LINES) {
		__u32 key = line;
		struct rule_line *rule;
		__u8 was = st->partial[BOUNDED(line, RULE_LINES)];
		__u32 reached, ncomp;
		int k;

		if (line >= count)
			break;
		rule = bpf_map_lookup_elem(&rules, &key);
		if (!rule)
			break;
		// Continuations of the parent's interior matches, and a fresh match of the first
		// component where the line may start here.
		ls->reached = 0;
		bpf_for(k, 0, RULE_COMPS) {
			const char *comp = rule->comp[BOUNDED(k, RULE_COMPS + 1)];
			__u8 can_start = k == 0 ? (!rule->anchored || anchored_ok) : ((was >> k) & 1);
			int matched;

			if (k >= rule->ncomp)
				break;
			if (!can_start)
				continue;
			if (comp[0] != '*' && comp[0] != sc->fold[0])
				continue;
			matched = rule->anchored ? component_equals(sc, comp) : component_matches(sc, comp);
			if (matched)
				ls->reached |= 1u << ((k + 1) & 7);
		}
		reached = ls->reached;
		ncomp = rule->ncomp & 7;
		if (reached & (1u << ncomp)) {
			if (rule->word == WORD_PINNED) {
				ls->pinned_path = 1;
				if (rule->alias)
					ls->activate |= 1u << ((rule->alias - 1) & 15);
			} else if (line > ls->deciding) {
				ls->deciding = line;
			}
			reached &= ~(1u << ncomp);
		}
		sc->partial_next[BOUNDED(line, RULE_LINES)] = reached;
	}
	// A line earlier than the deciding one decides nothing below it; a pinned-path line pins
	// regardless of what decides.
	bpf_for(line, 0, RULE_LINES) {
		__u32 key = line;
		struct rule_line *rule;
		__u8 next;

		if (line >= count)
			break;
		next = sc->partial_next[BOUNDED(line, RULE_LINES)];
		rule = bpf_map_lookup_elem(&rules, &key);
		if (!rule)
			break;
		if (next && rule->word != WORD_PINNED && line <= ls->deciding)
			next = 0;
		st->partial[BOUNDED(line, RULE_LINES)] = next;
		if (next)
			ls->any_partial = 1;
	}
	st->deciding = ls->deciding;
	st->pinned_path = ls->pinned_path;
	st->any_partial = ls->any_partial;
	return ls->activate;
}

// Whether a rule state can still make the entry or one below it read-only or pinned
// (policy.rs, `decides_anything`): an alias context that cannot is dropped.
static __always_inline int state_decides(const struct rule_state *st)
{
	return rule_word(st->deciding) == WORD_READ_ONLY || st->pinned_path || st->any_partial;
}

// The alias contexts `mask` names (bit a: aliases[a]) copied into free alias slots, each unless a
// live slot already holds its equal. Returns 0, or -1 when no slot is free.
__noinline int alias_activate(__u64 slot, __u64 mask)
{
	struct scratch *sc = get_scratch(slot);
	volatile struct loop_state *ls;
	int a;

	if (!sc)
		return -1;
	ls = &sc->loop;
	bpf_for(a, 0, ALIASES) {
		__u32 key = a;
		struct alias_context *alias;
		int s, free_slot = -1;

		if (!((mask >> a) & 1))
			continue;
		alias = bpf_map_lookup_elem(&aliases, &key);
		if (!alias)
			return -1;
		ls->same = 0;
		bpf_for(s, 0, ALIAS_SLOTS) {
			struct rule_state *st = &sc->ctx[BOUNDED(1 + s, 4)];
			int k;

			if (!st->live) {
				if (free_slot < 0)
					free_slot = s;
				continue;
			}
			if (st->deciding != alias->deciding || st->pinned_path != (alias->pinned_path != 0))
				continue;
			ls->same = 1;
			bpf_for(k, 0, RULE_LINES) {
				if (st->partial[BOUNDED(k, RULE_LINES)] != alias->partial[BOUNDED(k, RULE_LINES)]) {
					ls->same = 0;
					break;
				}
			}
			if (ls->same)
				break;
		}
		if (ls->same)
			continue;
		if (free_slot < 0)
			return -1;
		{
			struct rule_state *st = &sc->ctx[BOUNDED(1 + free_slot, 4)];
			int k;

			bpf_for(k, 0, RULE_LINES)
				st->partial[BOUNDED(k, RULE_LINES)] = alias->partial[BOUNDED(k, RULE_LINES)];
			st->deciding = alias->deciding;
			st->pinned_path = alias->pinned_path != 0;
			st->any_partial = 0;
			bpf_for(k, 0, RULE_LINES)
				if (st->partial[BOUNDED(k, RULE_LINES)])
					st->any_partial = 1;
			st->live = 1;
		}
	}
	return 0;
}

// ---------------------------------------------------------------------------------------------
// The position: policy.rs, `child_context` and `classify`, with "Directories"
// ---------------------------------------------------------------------------------------------

// policy.rs, `classify_within_gitdir` and `classify_within_object_info`, over the gitdir-relative
// components, rel[k] being sc->raw[pos->rel_start - k].
static __always_inline __u8 is_scratch_name(struct scratch *sc, __u32 index);

static __always_inline int lock_base_is_operational(struct scratch *sc, __u32 index)
{
	// `<name>.lock` inherits its target's class, for the one-component names policy.rs enumerates.
	__u32 len = sc->raw_len[BOUNDED(index, WALK_BOUND)];
	const char *raw = sc->raw[BOUNDED(index, WALK_BOUND)];
	char *base = sc->base;
	__u32 lock_at = len - 5;
	int k;

	if (len < 6 || len > sizeof(sc->base) + 4)
		return 0;
	// The compiler drops a mask the range check above makes redundant, and the verifier, which
	// does not follow that check's arithmetic, then sees an unbounded offset: the barrier hides
	// the range from the compiler so the mask stays.
	barrier_var(lock_at);
	lock_at &= NAME_BYTES - 1;
	if (bpf_strncmp(raw + lock_at, 6, ".lock") != 0)
		return 0;
	__builtin_memset(sc->base, 0, sizeof(sc->base));
	bpf_for(k, 0, sizeof(sc->base) - 1) {
		if (k >= len - 5)
			break;
		base[BOUNDED(k, sizeof(sc->base))] = raw[BOUNDED(k, NAME_BYTES)];
	}
#define BASE_IS(lit) (bpf_strncmp(base, sizeof(sc->base), lit) == 0)
	return BASE_IS("objects") || BASE_IS("refs") || BASE_IS("logs") || BASE_IS("info") || BASE_IS("reftable") ||
	       BASE_IS("NOTES_MERGE_WORKTREE") || BASE_IS("lost-found") || BASE_IS("HEAD") || BASE_IS("ORIG_HEAD") ||
	       BASE_IS("FETCH_HEAD") || BASE_IS("MERGE_HEAD") || BASE_IS("CHERRY_PICK_HEAD") ||
	       BASE_IS("REVERT_HEAD") || BASE_IS("REBASE_HEAD") || BASE_IS("AUTO_MERGE") ||
	       BASE_IS("MERGE_AUTOSTASH") || BASE_IS("NOTES_MERGE_PARTIAL") || BASE_IS("NOTES_MERGE_REF") ||
	       BASE_IS("index") || BASE_IS("packed-refs") || BASE_IS("packed-refs.new") || BASE_IS("COMMIT_EDITMSG") ||
	       BASE_IS("MERGE_MSG") || BASE_IS("MERGE_MODE") || BASE_IS("SQUASH_MSG") || BASE_IS("TAG_EDITMSG") ||
	       BASE_IS("NOTES_EDITMSG") || BASE_IS("EDIT_DESCRIPTION") || BASE_IS("ADD_EDIT.patch") ||
	       BASE_IS("REPLACE_EDITOBJ") || BASE_IS("shallow") || BASE_IS("BISECT_HEAD") || BASE_IS("gc.pid") ||
	       BASE_IS("gc.log");
#undef BASE_IS
}

static __always_inline int all_digits(const char *raw, __u32 from, __u32 len)
{
	int k;

	if (from >= len)
		return 0;
	bpf_for(k, 0, NAME_BYTES) {
		__u8 byte;

		if (k < from)
			continue;
		if (k >= len)
			break;
		byte = raw[BOUNDED(k, NAME_BYTES)];
		if (byte < '0' || byte > '9')
			return 0;
	}
	return 1;
}

static __always_inline int all_hex(const char *raw, __u32 from, __u32 len)
{
	int k;

	if (from >= len)
		return 0;
	bpf_for(k, 0, NAME_BYTES) {
		__u8 byte;

		if (k < from)
			continue;
		if (k >= len)
			break;
		byte = raw[BOUNDED(k, NAME_BYTES)];
		if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f') || (byte >= 'A' && byte <= 'F')))
			return 0;
	}
	return 1;
}

static __always_inline int six_alnum(const char *raw, __u32 from, __u32 len)
{
	int k;

	if (len != from + 6)
		return 0;
	bpf_for(k, 0, 6) {
		__u8 byte = raw[BOUNDED(from + k, NAME_BYTES)];

		if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z')))
			return 0;
	}
	return 1;
}

// policy.rs, `is_operational_scratch_name`: `index.stash.<pid>`, `next-index-<pid>`,
// `sharedindex.<hash>`, `sharedindex_XXXXXX`, `shallow_XXXXXX`.
static __always_inline __u8 is_scratch_name(struct scratch *sc, __u32 index)
{
	const char *raw = sc->raw[BOUNDED(index, WALK_BOUND)];
	__u32 len = sc->raw_len[BOUNDED(index, WALK_BOUND)];

	if (len > 12 && bpf_strncmp(raw, 12, "index.stash.") == 0)
		return all_digits(raw, 12, len);
	if (len > 11 && bpf_strncmp(raw, 11, "next-index-") == 0)
		return all_digits(raw, 11, len);
	if (len > 12 && bpf_strncmp(raw, 12, "sharedindex.") == 0)
		return all_hex(raw, 12, len);
	if (len > 12 && bpf_strncmp(raw, 12, "sharedindex_") == 0)
		return six_alnum(raw, 12, len);
	if (len > 8 && bpf_strncmp(raw, 8, "shallow_") == 0)
		return six_alnum(raw, 8, len);
	return 0;
}

static __always_inline int classify_object_info(struct scratch *sc, __u32 index, __u32 remaining)
{
	// `objects/info/<name>...`: commit-graphs, commit-graph, packs, packs_XXXXXX and their locks.
	if (RAW_IS(sc, index, "commit-graphs"))
		return 0;
	if (remaining == 1) {
		const char *raw = sc->raw[BOUNDED(index, WALK_BOUND)];
		__u32 len = sc->raw_len[BOUNDED(index, WALK_BOUND)];

		if (RAW_IS(sc, index, "commit-graph") || RAW_IS(sc, index, "packs") ||
		    RAW_IS(sc, index, "commit-graph.lock") || RAW_IS(sc, index, "packs.lock"))
			return 0;
		if (len == 12 && bpf_strncmp(raw, 6, "packs_") == 0 && six_alnum(raw, 6, len))
			return 0;
	}
	return 1;
}

// Returns 1 for Protected, 0 for Operational.
static __always_inline int classify_in_gitdir(struct scratch *sc, struct position *pos)
{
	__u32 first;

	if (pos->rel_len == 0)
		return 1;
	first = pos->rel_start;
	if (first >= WALK_BOUND)
		return 1;
	if (RAW_IS(sc, first, "config") || RAW_IS(sc, first, "config.worktree") || RAW_IS(sc, first, "hooks") ||
	    RAW_IS(sc, first, "commondir") || RAW_IS(sc, first, "gitdir"))
		return 1;
	if (RAW_IS(sc, first, "objects") && pos->rel_len > 2) {
		__u32 second = first - 1;

		if (second >= WALK_BOUND)
			return 1;
		if (fold_component(sc, second) && FOLD_IS(sc, "info"))
			return classify_object_info(sc, second - 1, pos->rel_len - 2);
	}
	if (RAW_IS(sc, first, "objects") || RAW_IS(sc, first, "refs") || RAW_IS(sc, first, "logs") ||
	    RAW_IS(sc, first, "info") || RAW_IS(sc, first, "reftable") || RAW_IS(sc, first, "NOTES_MERGE_WORKTREE") ||
	    RAW_IS(sc, first, "lost-found"))
		return 0;
	if (pos->rel_len == 1) {
		if (RAW_IS(sc, first, "HEAD") || RAW_IS(sc, first, "ORIG_HEAD") ||
		    RAW_IS(sc, first, "FETCH_HEAD") || RAW_IS(sc, first, "MERGE_HEAD") ||
		    RAW_IS(sc, first, "CHERRY_PICK_HEAD") || RAW_IS(sc, first, "REVERT_HEAD") ||
		    RAW_IS(sc, first, "REBASE_HEAD") || RAW_IS(sc, first, "AUTO_MERGE") ||
		    RAW_IS(sc, first, "MERGE_AUTOSTASH") || RAW_IS(sc, first, "NOTES_MERGE_PARTIAL") ||
		    RAW_IS(sc, first, "NOTES_MERGE_REF") || RAW_IS(sc, first, "index") ||
		    RAW_IS(sc, first, "packed-refs") || RAW_IS(sc, first, "packed-refs.new") ||
		    RAW_IS(sc, first, "COMMIT_EDITMSG") || RAW_IS(sc, first, "MERGE_MSG") ||
		    RAW_IS(sc, first, "MERGE_MODE") || RAW_IS(sc, first, "SQUASH_MSG") ||
		    RAW_IS(sc, first, "TAG_EDITMSG") || RAW_IS(sc, first, "NOTES_EDITMSG") ||
		    RAW_IS(sc, first, "EDIT_DESCRIPTION") || RAW_IS(sc, first, "ADD_EDIT.patch") ||
		    RAW_IS(sc, first, "REPLACE_EDITOBJ") || RAW_IS(sc, first, "shallow") ||
		    RAW_IS(sc, first, "BISECT_HEAD") || RAW_IS(sc, first, "gc.pid") || RAW_IS(sc, first, "gc.log"))
			return 0;
		if (is_scratch_name(sc, first))
			return 0;
		if (lock_base_is_operational(sc, first))
			return 0;
	}
	return 1;
}

// The rules at one level of the walk: the main context's child state, recorded per level for the
// symlink judgment, then each live alias context's, dropped once it decides nothing, and the alias
// contexts the level activates. Returns 0 on an alias overflow or an error.
static __always_inline int rules_at_level(struct scratch *sc, __u64 slot, __u32 level, int anchored_ok)
{
	int mask = rule_child(slot, 0, anchored_ok), a, k;

	if (mask < 0)
		return 0;
	bpf_for(k, 0, RULE_LINES)
		sc->level_partial[BOUNDED(level, WALK_BOUND)][BOUNDED(k, RULE_LINES)] =
			sc->ctx[0].partial[BOUNDED(k, RULE_LINES)];
	sc->level_deciding[BOUNDED(level, WALK_BOUND)] = sc->ctx[0].deciding;
	bpf_for(a, 0, ALIAS_SLOTS) {
		struct rule_state *st = &sc->ctx[BOUNDED(1 + a, 4)];
		int more;

		if (!st->live)
			continue;
		more = rule_child(slot, 1 + a, 0);
		if (more < 0)
			return 0;
		mask |= more;
		if (!state_decides(st))
			st->live = 0;
	}
	if (mask && alias_activate(slot, mask) < 0)
		return 0;
	return 1;
}

// The position of the walked object: the git context from the root down, the rule context
// beside it, the "Directories" names and the short-name form at every component.
static __always_inline int locate(struct scratch *sc, __u64 slot, const struct policy_config *cfg, struct walk *w,
				  struct position *pos)
{
	volatile struct loop_state *ls = &sc->loop;
	__u32 git_kind;
	__s32 rel_start;
	__u32 rel_len;
	int i, k, a;

	pos->depth = w->depth;
	pos->root_kind = w->root_kind;
	pos->status = w->status;
	pos->protected_git = 0;
	pos->pinned_git = 0;
	pos->target_dotgit = 0;
	pos->target_sandbox = 0;
	pos->target_head = 0;
	pos->rule_read_only = 0;
	pos->rule_pinned = 0;
	pos->short_name = 0;
	pos->alias_overflow = 0;
	pos->region = -1;
	pos->deciding = -1;
	if (w->status != WALK_OK)
		return 0;
	ls->git_kind = GIT_NOT;
	ls->rel_start = -1;
	ls->rel_len = 0;
	if (w->root_kind == ROOT_GITDIR || w->root_kind == ROOT_GUARDED_GIT) {
		ls->git_kind = GIT_IN;
		ls->rel_start = w->depth;	// the root is the gitdir entry, one above the root child
	} else if (w->root_kind == ROOT_GUARDED_SANDBOX) {
		// The object itself, or a name below the guarded `.ko-agent-sandbox`.
		ls->git_kind = GIT_SANDBOX;
	}
	for (a = 0; a < 1 + ALIAS_SLOTS; a++) {
		struct rule_state *st = &sc->ctx[a];

		bpf_for(k, 0, RULE_LINES)
			st->partial[BOUNDED(k, RULE_LINES)] = 0;
		st->deciding = -1;
		st->pinned_path = 0;
		st->any_partial = 0;
		st->live = a == 0;
	}
	bpf_for(k, 0, RULE_LINES)
		sc->level_partial[0][BOUNDED(k, RULE_LINES)] = 0;
	sc->level_deciding[0] = -1;
	bpf_for(i, 0, WALK_BOUND) {
		__u32 index = w->depth - 1 - i;
		int at_root_child = i == 0;

		if (i >= w->depth || index >= WALK_BOUND)
			break;
		if (!fold_component(sc, index))
			return 0;
		if ((cfg->flags & FLAG_SHORT_NAMES) &&
		    has_short_name_shape(sc, sc->raw[BOUNDED(index, WALK_BOUND)],
					 sc->raw_len[BOUNDED(index, WALK_BOUND)]))
			pos->short_name = 1;
		// The rules, computed at every position: a `read-only` line keeps applying below a
		// `.git` entry ("Directories"), and a line may start inside one, the stricter reading.
		if (cfg->rule_count &&
		    !rules_at_level(sc, slot, i + 1, at_root_child && w->root_kind == ROOT_WORKSPACE)) {
			pos->alias_overflow = 1;
			return 0;
		}
		// policy.rs, child_context.
		git_kind = ls->git_kind;
		rel_start = ls->rel_start;
		rel_len = ls->rel_len;
		switch (git_kind) {
		case GIT_NOT:
			if (FOLD_IS(sc, ".git")) {
				ls->git_kind = GIT_IN;
				ls->rel_start = index;
				ls->rel_len = 0;
			} else if (FOLD_IS(sc, ".ko-agent-sandbox")) {
				ls->git_kind = GIT_SANDBOX;
			}
			break;
		case GIT_SANDBOX:
			break;
		case GIT_MODULE_NS:
			// A recorded gitdir root ends the walk before this; what remains is the namespace.
			if (FOLD_IS(sc, ".ko-agent-sandbox"))
				ls->git_kind = GIT_SANDBOX;
			break;
		case GIT_IN:
			if (FOLD_IS(sc, ".ko-agent-sandbox")) {
				// Protected in git state too ("Directories").
				ls->git_kind = GIT_SANDBOX;
			} else if (rel_len == 1 && rel_start >= 1 && rel_start <= WALK_BOUND &&
				   RAW_IS(sc, (__u32)(rel_start - 1), "worktrees")) {
				// rel_start is the gitdir entry; rel[0], the slot below it, is the
				// component being judged when rel_len is 1.
				ls->rel_start = index;	// re-rooted: this component is the gitdir entry
				ls->rel_len = 0;
			} else if (rel_len == 1 && rel_start >= 1 && rel_start <= WALK_BOUND &&
				   RAW_IS(sc, (__u32)(rel_start - 1), "modules")) {
				ls->git_kind = GIT_MODULE_NS;
			} else {
				ls->rel_len = rel_len + 1;
			}
			break;
		}
		if (w->mark_level >= 0 && index == (__u32)w->mark_level) {
			// The recorded gitdir root or guarded object, whatever its name: the gitdir
			// entry, or the launcher's directory.
			if (w->mark_kind == ROOT_GUARDED_SANDBOX) {
				ls->git_kind = GIT_SANDBOX;
			} else {
				ls->git_kind = GIT_IN;
				ls->rel_start = index;
				ls->rel_len = 0;
			}
		}
		if (index == 0) {
			pos->target_dotgit = FOLD_IS(sc, ".git");
			pos->target_sandbox = FOLD_IS(sc, ".ko-agent-sandbox");
			if (FOLD_IS(sc, "head") && w->depth >= 2 && fold_component(sc, 1) &&
			    FOLD_IS(sc, ".git"))
				pos->target_head = 1;
		}
	}
	git_kind = ls->git_kind;
	rel_start = ls->rel_start;
	rel_len = ls->rel_len;
	if (git_kind == GIT_IN && rel_start >= 0) {
		// rel_len counts the components after the gitdir entry; the entry itself is rel_len 0.
		pos->rel_start = rel_start == (__s32)w->depth ? (__s32)w->depth - 1 : rel_start - 1;
		pos->rel_len = rel_start == (__s32)w->depth ? w->depth : rel_len;
		if (pos->rel_len == 0)
			pos->rel_start = -1;
	} else {
		pos->rel_start = -1;
		pos->rel_len = 0;
	}
	pos->git_kind = git_kind;
	switch (git_kind) {
	case GIT_NOT:
		pos->protected_git = 0;
		break;
	case GIT_SANDBOX:
	case GIT_MODULE_NS:
		pos->protected_git = 1;
		break;
	case GIT_IN:
		pos->protected_git = classify_in_gitdir(sc, pos);
		if (pos->rel_len == 1 && pos->rel_start >= 0 && RAW_IS(sc, (__u32)pos->rel_start, "objects"))
			pos->pinned_git = 1;
		if (pos->rel_len == 2 && pos->rel_start >= 1 && RAW_IS(sc, (__u32)pos->rel_start, "objects") &&
		    fold_component(sc, pos->rel_start - 1) && FOLD_IS(sc, "info"))
			pos->pinned_git = 1;
		break;
	}
	pos->deciding = sc->ctx[0].deciding;
	pos->rule_read_only = rule_word(sc->ctx[0].deciding) == WORD_READ_ONLY;
	pos->rule_pinned = sc->ctx[0].pinned_path || sc->ctx[0].any_partial;
	pos->region = rule_word(sc->ctx[0].deciding) == WORD_WRITABLE ? sc->ctx[0].deciding : -1;
	// Under any of the entry's other names (policy.rs, `RuleContext::read_only` and `pinned`).
	bpf_for(a, 0, ALIAS_SLOTS) {
		struct rule_state *st = &sc->ctx[BOUNDED(1 + a, 4)];

		if (!st->live)
			continue;
		if (rule_word(st->deciding) == WORD_READ_ONLY)
			pos->rule_read_only = 1;
		if (st->pinned_path || st->any_partial)
			pos->rule_pinned = 1;
	}
	return 1;
}

// ---------------------------------------------------------------------------------------------
// The decisions: policy.rs, `authorize`, `authorize_create`, `authorize_rule`,
// `authorize_rule_create`, `authorize_region_move`, and "Directories"
// ---------------------------------------------------------------------------------------------

static __always_inline __u32 walk_reason(const struct position *pos)
{
	switch (pos->status) {
	case WALK_OK:
		return pos->alias_overflow ? R_ALIAS_OVERFLOW : R_INTERNAL;
	case WALK_NOROOT:
		return R_WALK_NOROOT;
	case WALK_BOUND_HIT:
		return R_WALK_BOUND;
	case WALK_TOO_LONG:
		return R_NAME_TOO_LONG;
	default:
		return R_WALK_TORN;
	}
}

// Mutation::Write and Mutation::SetAttr of an existing entry.
static __always_inline __u32 decide_modify(const struct position *pos)
{
	if (pos->short_name)
		return R_SHORT_NAME;
	if (pos->git_kind == GIT_SANDBOX)
		return R_SANDBOX_NAME;
	if (pos->protected_git)
		return R_GIT_PROTECTED;
	if (pos->rule_read_only)
		return R_RULE_READ_ONLY;
	return R_ALLOW;
}

// Mutation::Unlink and Mutation::RenameFrom.
static __always_inline __u32 decide_remove(const struct position *pos)
{
	__u32 reason = decide_modify(pos);

	if (reason)
		return reason;
	if (pos->pinned_git)
		return R_GIT_PINNED;
	if (pos->rule_pinned)
		return R_RULE_PINNED;
	return R_ALLOW;
}

// A name coming to be, by create, mknod, symlink, link or rename: the position is the new
// entry's own.
static __always_inline __u32 decide_create(const struct position *pos)
{
	if (pos->short_name)
		return R_SHORT_NAME;
	if (pos->target_dotgit)
		return R_GIT_NAME;
	if (pos->target_sandbox || pos->git_kind == GIT_SANDBOX)
		return R_SANDBOX_NAME;
	if (pos->protected_git)
		return R_GIT_PROTECTED;
	if (pos->pinned_git)
		return R_GIT_PINNED;
	if (pos->rule_read_only)
		return R_RULE_READ_ONLY;
	if (pos->rule_pinned)
		return R_RULE_PINNED;
	return R_ALLOW;
}

// A directory or symlink moving: it must not leave a writable region, nor a gitdir for the
// workspace.
static __always_inline __u32 decide_region_move(const struct position *from, const struct position *to,
						__u32 rule_count)
{
	if (to->git_kind != GIT_NOT)
		return R_ALLOW;
	if (from->git_kind != GIT_NOT)
		return rule_count ? R_REGION : R_ALLOW;
	if (from->region >= 0 && to->deciding != from->region)
		return R_REGION;
	return R_ALLOW;
}

// Whether a superblock's type name is `want`, a FS_TYPE_BYTES field of the configuration. The
// name is compared as two words: bpf_strncmp takes only a string literal (the verifier wants its
// third argument in a read-only map).
static __always_inline int sb_type_is(struct super_block *sb, const char *want_field)
{
	__u64 type[2] = {};
	__u64 want[2];
	const char *name = BPF_CORE_READ(sb, s_type, name);

	if (bpf_probe_read_kernel_str(type, sizeof(type), name) < 0)
		return 0;
	__builtin_memcpy(want, want_field, sizeof(want));
	return type[0] == want[0] && type[1] == want[1];
}

// Whether the object's superblock is of the root's type: what the policy judges at all.
static __always_inline int on_root_type(struct super_block *sb, const struct policy_config *cfg)
{
	return sb_type_is(sb, cfg->fs_type);
}

static __always_inline int finish(enum hook hook, __u32 reason, const struct position *pos,
				  struct scratch *sc, __u64 start_ns, int slot)
{
	__u32 key = hook, zero = 0;
	struct hook_stats *st = bpf_map_lookup_elem(&stats, &key);
	struct last_decision *last = bpf_map_lookup_elem(&last_decision, &zero);
	__u64 ns = bpf_ktime_get_ns() - start_ns;
	int allow = reason == R_ALLOW || reason == R_OUTSIDE;

	if (st) {
		__sync_fetch_and_add(&st->calls, 1);
		if (reason == R_OUTSIDE)
			__sync_fetch_and_add(&st->outside, 1);
		else if (allow)
			__sync_fetch_and_add(&st->allowed, 1);
		else
			__sync_fetch_and_add(&st->denied, 1);
		if (reason == R_REENTRY)
			__sync_fetch_and_add(&st->reentry, 1);
		if (slot >= 0 && (__u64)slot > st->nested_max)
			st->nested_max = slot;
		// The time of the judged calls: a call ending at the superblock check costs no walk.
		if (reason != R_OUTSIDE) {
			__sync_fetch_and_add(&st->ns_sum, ns);
			if (ns > st->ns_max)
				st->ns_max = ns;
		}
	}
	if (last && reason != R_OUTSIDE) {
		last->count++;
		last->hook = hook;
		last->reason = reason;
		last->depth = pos ? pos->depth : 0;
		last->root_kind = pos ? pos->root_kind : 0;
		if (sc && pos && pos->depth)
			bpf_probe_read_kernel_str(last->name, sizeof(last->name), sc->raw[0]);
		else
			last->name[0] = 0;
	}
	release_slot(slot);
	return allow;
}

// The walk and the position into `sc->pos[pos_index]`, as a global function: the verifier checks a
// global function once per program, where it checks an inlined or static one at each call, and
// the two-walk hooks exceed its budget with the walk checked twice on Linux 6.18 (measured, "Phase
// 2 on WSL": 640,000 to 790,000 insns for one walk there against 14,500 on 7.2). The dentry
// arrives as a scalar, which the walk's probe reads take as they take a pointer: the verifier
// passes a global function a pointer only as a declared trusted argument (measured on 7.2: "R2 is
// not a scalar" for a hook's dentry), which `file_open`'s dentry, read through a probe, is not.
__noinline int judge_position(__u64 hook, __u64 dentry, __u64 slot, __u64 pos_index)
{
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch(slot);
	struct position *pos;
	struct walk w;

	if (!cfg || !sc || pos_index > 1)
		return R_INTERNAL;
	pos = &sc->pos[pos_index & 1];
	walk(hook, slot, (struct dentry *)dentry, sc, &w);
	if (!locate(sc, slot, cfg, &w, pos))
		return walk_reason(pos);
	return R_ALLOW;
}

// A symlink's target, judged after its name at `sc->pos[0]` was allowed: refused when absolute or
// climbing above the workspace root (fs.rs, `target_has_portable_syntax`), and, with rules, at
// each path it passes resolved lexically from the link's directory (policy.rs,
// `symlink_target_paths`), when the last component has the NTFS short-name form, when the path
// enters a gitdir from the workspace (`enters_gitdir`), or when it is in a writable region the link
// is not in (`authorize_symlink_target`). A link in git state keeps the syntax rule alone, as the
// filter does. The rule state of each level comes from `sc->level_partial`, which the walk filled
// for the link's ancestors and which this fills for the target's components.
__noinline int judge_symlink(__u64 slot, __u64 target)
{
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch(slot);
	volatile struct loop_state *ls;
	struct position *pos;
	__u32 parent_level, judge_paths;
	long len;
	int i, k;

	if (!cfg || !sc)
		return R_INTERNAL;
	ls = &sc->loop;
	pos = &sc->pos[0];
	if (pos->depth == 0)
		return R_INTERNAL;
	len = bpf_probe_read_kernel_str(sc->target, TARGET_BYTES, (const void *)target);
	if (len < 0 || len >= TARGET_BYTES)
		return R_NAME_TOO_LONG;
	if (sc->target[0] == '/')
		return R_SYMLINK_SYNTAX;
	parent_level = pos->depth - 1;
	judge_paths = cfg->rule_count && pos->git_kind == GIT_NOT;
	bpf_for(k, 0, WALK_BOUND)
		sc->tgt_special[BOUNDED(k, WALK_BOUND)] = 0;
	ls->tgt_pos = 0;
	ls->tgt_level = parent_level;
	bpf_for(i, 0, TARGET_COMPS + 1) {
		__u32 start = ls->tgt_pos, clen, level = ls->tgt_level, special, first;
		int j;

		if (start >= (__u32)len - 1)
			return R_ALLOW;	// the target is consumed
		if (i >= TARGET_COMPS)
			return R_NAME_TOO_LONG;
		ls->tgt_clen = NAME_BYTES;
		bpf_for(j, 0, NAME_BYTES) {
			__u8 byte = sc->target[BOUNDED(start + j, TARGET_BYTES)];

			if (byte == 0 || byte == '/') {
				ls->tgt_clen = j;
				break;
			}
			sc->comp[BOUNDED(j, NAME_BYTES)] = byte;
		}
		clen = ls->tgt_clen;
		if (clen >= NAME_BYTES)
			return R_NAME_TOO_LONG;
		ls->tgt_pos = start + clen + 1;
		if (clen == 0 || (clen == 1 && sc->comp[0] == '.'))
			continue;
		if (clen == 2 && sc->comp[0] == '.' && sc->comp[1] == '.') {
			if (level == 0)
				return R_SYMLINK_SYNTAX;
			ls->tgt_level = level - 1;
			continue;
		}
		level++;
		if (level >= WALK_BOUND)
			return R_WALK_BOUND;
		ls->tgt_level = level;
		if (!judge_paths)
			continue;
		if (has_short_name_shape(sc, sc->comp, clen))
			return R_SYMLINK_SHORT;
		fold_bytes(sc, sc->comp, clen);
		special = FOLD_IS(sc, ".git") ? 1 : FOLD_IS(sc, ".ko-agent-sandbox") ? 2 : 0;
		sc->tgt_special[BOUNDED(level, WALK_BOUND)] = special;
		// The first special component of the resolved prefix: the link's own ancestors hold
		// none, since the link is outside git state, so only the target's components count,
		// at whatever level `..` brought them to.
		ls->tgt_first = 0;
		bpf_for(k, 0, WALK_BOUND) {
			__u32 at = 1 + k;

			if (at > level)
				break;
			if (sc->tgt_special[BOUNDED(at, WALK_BOUND)]) {
				ls->tgt_first = sc->tgt_special[BOUNDED(at, WALK_BOUND)];
				break;
			}
		}
		first = ls->tgt_first;
		if (first == 1)
			return R_SYMLINK_GITDIR;
		if (first)
			continue;	// in `.ko-agent-sandbox` state: no rule decides
		// The rule state at this level from the level below: the main context alone decides
		// a region (policy.rs, `RuleContext::region`).
		bpf_for(k, 0, RULE_LINES)
			sc->ctx[0].partial[BOUNDED(k, RULE_LINES)] =
				sc->level_partial[BOUNDED(level - 1, WALK_BOUND)][BOUNDED(k, RULE_LINES)];
		sc->ctx[0].deciding = sc->level_deciding[BOUNDED(level - 1, WALK_BOUND)];
		if (rule_child(slot, 0, level == 1 && pos->root_kind == ROOT_WORKSPACE) < 0)
			return R_INTERNAL;
		bpf_for(k, 0, RULE_LINES)
			sc->level_partial[BOUNDED(level, WALK_BOUND)][BOUNDED(k, RULE_LINES)] =
				sc->ctx[0].partial[BOUNDED(k, RULE_LINES)];
		sc->level_deciding[BOUNDED(level, WALK_BOUND)] = sc->ctx[0].deciding;
		if (rule_word(sc->ctx[0].deciding) == WORD_WRITABLE && pos->deciding != sc->ctx[0].deciding)
			return R_SYMLINK_REGION;
	}
	return R_NAME_TOO_LONG;
}

// A pointer's value as a scalar the verifier no longer types: read from its own stack slot
// through the probe helper, whose destination it marks as plain memory.
static __always_inline __u64 as_scalar(const void *ptr)
{
	__u64 value = 0;

	bpf_probe_read_kernel(&value, sizeof(value), &ptr);
	return value;
}

// The common prologue: the superblock check, the walk and the position. Returns the reason that
// ends the call, or R_ALLOW to go on. `sb` is the object's superblock, or the parent's for a name
// that does not exist yet; `judge_any_type` skips the type check, for the socket rule.
static __always_inline __u32 prologue(enum hook hook, struct dentry *dentry, struct super_block *sb,
				      const struct policy_config *cfg, int slot, int pos_index, int judge_any_type)
{
	if (!judge_any_type && !on_root_type(sb, cfg))
		return R_OUTSIDE;
	return judge_position(hook, as_scalar(dentry), slot, pos_index);
}

static __always_inline struct super_block *sb_of_inode(struct inode *inode)
{
	return BPF_CORE_READ(inode, i_sb);
}

// The prologue of every hook: the configuration, then, unless `sb_` is a superblock of another
// type, which ends the call as outside before any slot is taken, a scratch slot, or the reason
// the hook ends. A slot taken only for an object of the share's type keeps an exhaustion of the
// slots, a fifth task at once on one CPU, from denying what the policy never judges.
#define ENTER(hook_, cfg_, sc_, slot_, start_, sb_)                                      \
	do {                                                                                 \
		(cfg_) = get_config();                                                       \
		(slot_) = -1;                                                                \
		if (!(cfg_))                                                                 \
			return finish(hook_, R_INTERNAL, NULL, NULL, start_, -1);            \
		if ((sb_) && !on_root_type(sb_, cfg_))                                       \
			return finish(hook_, R_OUTSIDE, NULL, NULL, start_, -1);             \
		(slot_) = acquire_slot();                                                    \
		(sc_) = (slot_) >= 0 ? get_scratch(slot_) : NULL;                            \
		if (!(sc_))                                                                  \
			return finish(hook_, (slot_) < 0 ? R_REENTRY : R_INTERNAL, NULL, NULL, \
				      start_, slot_);                                        \
	} while (0)

SEC("lsm_cgroup/file_open")
int BPF_PROG(file_open, struct file *file)
{
	__u64 start = bpf_ktime_get_ns();
	__u32 f_mode = BPF_CORE_READ(file, f_mode);
	__u32 f_flags = BPF_CORE_READ(file, f_flags);
	struct dentry *dentry;
	struct inode *inode;
	struct policy_config *cfg;
	struct scratch *sc;
	__u32 reason;
	int slot;

	// A read-only open changes nothing; `O_TRUNC` without `FMODE_WRITE` is row 11's truncate.
	if (!(f_mode & FMODE_WRITE) && !(f_flags & O_TRUNC_FLAG))
		return 1;
	dentry = BPF_CORE_READ(file, f_path.dentry);
	inode = BPF_CORE_READ(dentry, d_inode);
	ENTER(HOOK_FILE_OPEN, cfg, sc, slot, start, sb_of_inode(inode));
	reason = prologue(HOOK_FILE_OPEN, dentry, sb_of_inode(inode), cfg, slot, 0, 0);
	if (reason == R_ALLOW)
		reason = decide_modify(&sc->pos[0]);
	return finish(HOOK_FILE_OPEN, reason, &sc->pos[0], sc, start, slot);
}

SEC("lsm_cgroup/inode_setattr")
int BPF_PROG(inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
	__u64 start = bpf_ktime_get_ns();
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct policy_config *cfg;
	struct scratch *sc;
	__u32 reason;
	int slot;

	ENTER(HOOK_INODE_SETATTR, cfg, sc, slot, start, sb_of_inode(inode));
	reason = prologue(HOOK_INODE_SETATTR, dentry, sb_of_inode(inode), cfg, slot, 0, 0);
	if (reason == R_ALLOW)
		reason = decide_modify(&sc->pos[0]);
	return finish(HOOK_INODE_SETATTR, reason, &sc->pos[0], sc, start, slot);
}

SEC("lsm_cgroup/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry)
{
	__u64 start = bpf_ktime_get_ns();
	struct policy_config *cfg;
	struct scratch *sc;
	__u32 reason;
	int slot;

	ENTER(HOOK_INODE_UNLINK, cfg, sc, slot, start, sb_of_inode(dir));
	reason = prologue(HOOK_INODE_UNLINK, dentry, sb_of_inode(dir), cfg, slot, 0, 0);
	if (reason == R_ALLOW)
		reason = decide_remove(&sc->pos[0]);
	return finish(HOOK_INODE_UNLINK, reason, &sc->pos[0], sc, start, slot);
}

// The socket rule on a name coming to be, judged at `pos`, whose prologue skipped the type
// check. By default a socket is refused beneath any recorded root and allowed elsewhere; under
// FLAG_UNIX_SOCKETS it is judged as an ordinary name and refused anywhere in a gitdir.
static __always_inline __u32 decide_socket(const struct policy_config *cfg, struct super_block *sb, __u32 reason,
					   const struct position *pos)
{
	if (cfg->flags & FLAG_UNIX_SOCKETS) {
		if (reason == R_ALLOW) {
			reason = decide_create(pos);
			if (reason == R_ALLOW && pos->git_kind != GIT_NOT)
				reason = R_SOCKET_GITDIR;
			return reason;
		}
	} else if (reason == R_ALLOW) {
		return R_SOCKET;
	}
	if (reason != R_OUTSIDE && pos->status == WALK_NOROOT)
		return on_root_type(sb, cfg) ? R_WALK_NOROOT : R_OUTSIDE;
	return reason;
}

// A new non-directory name: create, mknod and symlink share it; `is_socket` adds the socket rule,
// which holds beneath a recorded root of any superblock type; `target` is a symlink's.
static __always_inline int new_name(enum hook hook, struct inode *dir, struct dentry *dentry, int is_socket,
				    const char *target)
{
	__u64 start = bpf_ktime_get_ns();
	struct policy_config *cfg;
	struct scratch *sc;
	struct position *pos;
	__u32 reason;
	int slot;

	// A socket is judged on any superblock type, so its slot is taken whatever the type.
	ENTER(hook, cfg, sc, slot, start, is_socket ? NULL : sb_of_inode(dir));
	pos = &sc->pos[0];
	reason = prologue(hook, dentry, sb_of_inode(dir), cfg, slot, 0, is_socket);
	if (is_socket)
		return finish(hook, decide_socket(cfg, sb_of_inode(dir), reason, pos), pos, sc, start, slot);
	if (reason == R_ALLOW) {
		reason = decide_create(pos);
		if (reason == R_ALLOW && pos->target_head)
			reason = R_HEAD;
		if (reason == R_ALLOW && target)
			reason = judge_symlink(slot, as_scalar(target));
	}
	return finish(hook, reason, pos, sc, start, slot);
}

SEC("lsm_cgroup/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return new_name(HOOK_INODE_CREATE, dir, dentry, 0, NULL);
}

SEC("lsm_cgroup/inode_mknod")
int BPF_PROG(inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return new_name(HOOK_INODE_MKNOD, dir, dentry, (mode & S_IFMT) == S_IFSOCK, NULL);
}

SEC("lsm_cgroup/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	return new_name(HOOK_INODE_SYMLINK, dir, dentry, 0, old_name);
}

// A source object getting a second name, or moving: `old` positive, `new` a name.
static __always_inline int two_names(enum hook hook, struct dentry *old_dentry, struct inode *new_dir,
				     struct dentry *new_dentry)
{
	__u64 start = bpf_ktime_get_ns();
	struct policy_config *cfg;
	struct scratch *sc;
	struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
	struct inode *new_inode = BPF_CORE_READ(new_dentry, d_inode);
	__u32 old_mode = BPF_CORE_READ(old_inode, i_mode);
	struct position *from, *to;
	__u32 reason;
	int slot;

	// A socket source is judged on any superblock type; another source of another type is
	// outside, as the first prologue would find.
	ENTER(hook, cfg, sc, slot, start, (old_mode & S_IFMT) == S_IFSOCK ? NULL : sb_of_inode(old_inode));
	from = &sc->pos[0];
	to = &sc->pos[1];
	if ((old_mode & S_IFMT) == S_IFSOCK && !(cfg->flags & FLAG_UNIX_SOCKETS)) {
		// The socket rule on the destination, beneath any recorded root.
		reason = prologue(hook, new_dentry, sb_of_inode(new_dir), cfg, slot, 1, 1);
		return finish(hook, decide_socket(cfg, sb_of_inode(new_dir), reason, to), to, sc, start, slot);
	}
	reason = prologue(hook, old_dentry, sb_of_inode(old_inode), cfg, slot, 0, 0);
	if (reason == R_OUTSIDE)
		return finish(hook, R_OUTSIDE, NULL, NULL, start, slot);
	if (reason == R_ALLOW)
		reason = hook == HOOK_INODE_RENAME ? decide_remove(from) : decide_modify(from);
	if (reason != R_ALLOW)
		return finish(hook, reason, from, sc, start, slot);
	reason = prologue(hook, new_dentry, sb_of_inode(new_dir), cfg, slot, 1, 0);
	if (reason == R_OUTSIDE) {
		// A rename across superblocks is EXDEV before any hook; a link too. Not reached.
		return finish(hook, R_OUTSIDE, NULL, NULL, start, slot);
	}
	if (reason == R_ALLOW) {
		reason = decide_create(to);
		if (reason == R_ALLOW && new_inode) {
			// Replacing an existing entry removes it.
			reason = decide_remove(to);
		}
		if (reason == R_ALLOW && to->target_head) {
			// Allowed only as git's own update: a non-directory replacing a non-directory HEAD.
			__u32 new_mode = BPF_CORE_READ(new_inode, i_mode);

			if (!new_inode || (new_mode & S_IFMT) == S_IFDIR || (old_mode & S_IFMT) == S_IFDIR)
				reason = R_HEAD;
		}
		if (reason == R_ALLOW && (old_mode & S_IFMT) == S_IFSOCK && to->git_kind != GIT_NOT)
			reason = R_SOCKET_GITDIR;
		if (reason == R_ALLOW && ((old_mode & S_IFMT) == S_IFDIR || (old_mode & S_IFMT) == S_IFLNK))
			reason = decide_region_move(from, to, cfg->rule_count);
	}
	return finish(hook, reason, to, sc, start, slot);
}

SEC("lsm_cgroup/inode_link")
int BPF_PROG(inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	return two_names(HOOK_INODE_LINK, old_dentry, dir, new_dentry);
}

SEC("lsm_cgroup/inode_rename")
int BPF_PROG(inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	return two_names(HOOK_INODE_RENAME, old_dentry, new_dir, new_dentry);
}

// Whether a file's mount namespace is the runtime's and not another container's, for the task
// receiving it: a namespace whose root is the receiver's own root directory, which is the host's
// root for the runtime's processes, among them the container's init before it pivots into the
// container's root, and is a container's root for every session process, whose own namespace
// alone has it (fs/namespace.c, `pivot_root`; a session makes no namespace under the profile);
// the namespace the controller recorded as the runtime's; or an anonymous one holding a mount
// the runtime built and has not moved into place. The recorded namespace alone does not hold on
// WSL, where the runtime passes the volume mountpoint from a namespace that is neither the
// controller's nor pid 1's, which are one there ("Phase 3 on WSL").
static __always_inline int ns_is_runtime(struct mnt_namespace *ns, struct task_struct *task,
					 const struct policy_config *cfg)
{
	struct dentry *ns_root = BPF_CORE_READ(ns, root, mnt.mnt_root);
	struct dentry *my_root = BPF_CORE_READ(task, fs, root.dentry);
	struct ident root_id;

	if (ns_root && ns_root == my_root)
		return 1;
	root_id.s_dev = BPF_CORE_READ(ns_root, d_inode, i_sb, s_dev);
	root_id.i_ino = BPF_CORE_READ(ns_root, d_inode, i_ino);
	if (cfg->host_root.i_ino && root_id.s_dev == cfg->host_root.s_dev && root_id.i_ino == cfg->host_root.i_ino)
		return 1;
	if (BPF_CORE_READ(ns, ns.inum) == cfg->runtime_mnt_ns)
		return 1;
	// An anonymous namespace: by its flag on 7.2, by its sequence on kernels that keep one at 0
	// for it, and by the one inode number all of them share on 6.18, which has neither (measured,
	// "Phase 3 on WSL": crun passes the volume as an `open_tree` clone whose root is the volume
	// directory and whose number is 0xEFFFFFF7).
	if (BPF_CORE_READ(ns, ns.inum) == MNT_NS_ANON_INO)
		return 1;
	if (bpf_core_field_exists(((struct mnt_namespace___anon *)0)->is_anon))
		return BPF_CORE_READ((struct mnt_namespace___anon *)ns, is_anon);
	if (bpf_core_field_exists(((struct mnt_namespace___seq *)0)->seq))
		return BPF_CORE_READ((struct mnt_namespace___seq *)ns, seq) == 0;
	return 0;
}

// The refused object's name into the decision record, for a refusal taken before any walk.
static __always_inline struct position *note_dentry(struct scratch *sc, struct dentry *dentry)
{
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);

	bpf_probe_read_kernel_str(sc->raw[0], NAME_BYTES, name);
	sc->pos[0].depth = 1;
	sc->pos[0].root_kind = 0;
	return &sc->pos[0];
}

// What file_receive saw of a file's namespace and its receiver, into the decision record.
static __always_inline void note_receive(struct mnt_namespace *ns, struct task_struct *task)
{
	__u32 zero = 0;
	struct last_decision *last = bpf_map_lookup_elem(&last_decision, &zero);
	struct dentry *ns_root, *my_root;

	if (!last)
		return;
	ns_root = BPF_CORE_READ(ns, root, mnt.mnt_root);
	my_root = BPF_CORE_READ(task, fs, root.dentry);
	last->ns_inum = BPF_CORE_READ(ns, ns.inum);
	if (bpf_core_field_exists(((struct mnt_namespace___anon *)0)->is_anon))
		last->ns_anon = BPF_CORE_READ((struct mnt_namespace___anon *)ns, is_anon);
	else if (bpf_core_field_exists(((struct mnt_namespace___seq *)0)->seq))
		last->ns_anon = BPF_CORE_READ((struct mnt_namespace___seq *)ns, seq) == 0;
	last->ns_root_dev = BPF_CORE_READ(ns_root, d_inode, i_sb, s_dev);
	last->ns_root_ino = BPF_CORE_READ(ns_root, d_inode, i_ino);
	bpf_get_current_comm(last->comm, sizeof(last->comm));
	bpf_probe_read_kernel_str(last->ns_root, sizeof(last->ns_root), BPF_CORE_READ(ns_root, d_name.name));
	bpf_probe_read_kernel_str(last->my_root, sizeof(last->my_root), BPF_CORE_READ(my_root, d_name.name));
}

// A descriptor arriving by SCM_RIGHTS or pidfd_getfd, attached under FLAG_UNIX_SOCKETS ("The
// hooks", `file_receive`): a file of the receiver's own mount namespace, or of a kernel-internal
// mount (a pipe, a socket, an anonymous inode), passes, and so does one of the runtime's
// namespaces (`ns_is_runtime`), which pass the container's mount sources into it as it starts
// (measured: the volume's mountpoint directory, refused as a directory, failed crun's start,
// "Phase 3 on macOS"). Of another container's namespace, or of a mount that has left its
// namespace because the sender's container ended before the receiver read the message
// (fs/namespace.c, `umount_tree` clears `mnt_ns`), a directory is
// refused, whatever it names; a non-directory of the share's type passes only beneath a recorded
// root that the receiver's `file_open` would admit so, judged for writing when the descriptor has
// FMODE_WRITE; one of the volume's type passes only beneath the recorded volume root, so another
// workspace's volume file does not arrive; one of any other type passes, since it reaches no share
// and starts no lookup, which is what the runtime passes into the container's namespace while it
// starts (measured: with every other namespace's file refused, crun's start failed, "Phase 3 on
// macOS").
SEC("lsm_cgroup/file_receive")
int BPF_PROG(file_receive, struct file *file)
{
	__u64 start = bpf_ktime_get_ns();
	struct vfsmount *vfsmnt = BPF_CORE_READ(file, f_path.mnt);
	struct mount *mnt = (struct mount *)((char *)vfsmnt - bpf_core_field_offset(struct mount, mnt));
	struct mnt_namespace *ns = BPF_CORE_READ(mnt, mnt_ns);
	struct task_struct *task = bpf_get_current_task_btf();
	struct mnt_namespace *mine = BPF_CORE_READ(task, nsproxy, mnt_ns);
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct super_block *sb = sb_of_inode(inode);
	__u32 mode = BPF_CORE_READ(inode, i_mode);
	__u32 f_mode = BPF_CORE_READ(file, f_mode);
	struct policy_config *cfg;
	struct scratch *sc;
	__u32 reason;
	int slot;

	if (ns == mine || (unsigned long)ns >= (unsigned long)-MAX_ERRNO)
		return 1;
	ENTER(HOOK_FILE_RECEIVE, cfg, sc, slot, start, NULL);
	if (ns && ns_is_runtime(ns, task, cfg))
		return finish(HOOK_FILE_RECEIVE, R_OUTSIDE, note_dentry(sc, dentry), sc, start, slot);
	note_receive(ns, task);
	if ((mode & S_IFMT) == S_IFDIR)
		return finish(HOOK_FILE_RECEIVE, R_RECEIVE_DIR, note_dentry(sc, dentry), sc, start, slot);
	if (sb_type_is(sb, cfg->fs_type)) {
		reason = judge_position(HOOK_FILE_RECEIVE, as_scalar(dentry), slot, 0);
		if (reason == R_WALK_NOROOT)
			reason = R_RECEIVE_NS;
		if (reason == R_ALLOW && (f_mode & FMODE_WRITE))
			reason = decide_modify(&sc->pos[0]);
	} else if (cfg->vol_fs_type[0] && sb_type_is(sb, cfg->vol_fs_type)) {
		reason = judge_position(HOOK_FILE_RECEIVE, as_scalar(dentry), slot, 0);
		if (reason != R_ALLOW || sc->pos[0].root_kind != ROOT_VOLUME)
			reason = R_RECEIVE_NS;
	} else {
		return finish(HOOK_FILE_RECEIVE, R_OUTSIDE, note_dentry(sc, dentry), sc, start, slot);
	}
	return finish(HOOK_FILE_RECEIVE, reason, &sc->pos[0], sc, start, slot);
}
