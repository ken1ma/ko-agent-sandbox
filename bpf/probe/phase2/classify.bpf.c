// Phase 2 of doc/plan-bpf-lsm-cgroup.md, the representative program: the plan's eight hooks
// holding the bounded `d_parent` walk under `rename_lock`'s sequence, the fold, the git-context
// transitions and the ordered rule match of policy.rs, ported allocation-free with bounded loops,
// and deciding as "The policy" and "Directories" say. The verifier's answer to it, and its cost at
// a real tree's depth, are what the phase measures; what it leaves to Phase 3 is listed at the end.
//
// Every loop is a `bpf_for` over the kernel's numeric iterator (bpf_iter_num_*, Linux 6.4), which
// the verifier checks by convergence rather than by simulating every iteration: a 255-byte fold
// inside a 64-component walk would otherwise exceed its instruction budget.
//
// Return convention (kernel/bpf/cgroup.c, bpf_prog_run_array_cg): 1 allows, 0 becomes -EPERM.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define WALK_BOUND 64         // components a walk reads before it denies; above any measured depth
#define RETRY_BOUND 4         // walks discarded for a rename seen in flight, then denied
#define NAME_BYTES 256        // a dentry name is at most 255 bytes and NUL-terminated
#define RULE_LINES 128
#define RULE_COMPS 4
#define COMP_BYTES 32
#define FS_TYPE_BYTES 16

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

enum hook {
	HOOK_FILE_OPEN,
	HOOK_INODE_CREATE,
	HOOK_INODE_MKNOD,
	HOOK_INODE_SYMLINK,
	HOOK_INODE_LINK,
	HOOK_INODE_RENAME,
	HOOK_INODE_UNLINK,
	HOOK_INODE_SETATTR,
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
};

struct ident {
	__u64 s_dev;
	__u64 i_ino;
};

enum root_kind {
	ROOT_WORKSPACE = 1,   // a workspace root, or the proof fixture's: the walk's position is NotGit
	ROOT_GITDIR = 2,      // a gitdir the guard resolved under `modules/`: the position is InGit([])
	ROOT_VOLUME = 3,      // the persistent volume's root: the socket rule alone
};

struct root {
	__u32 kind;
	__u32 pad;
};

// One resolved rule line, folded by the guard. `first[k]` is comp[k]'s first byte, so a line
// whose first component cannot match a name is skipped by one compare.
struct rule_line {
	__u8 word;            // 1 read-only, 2 writable, 3 pinned-path
	__u8 anchored;
	__u8 ncomp;
	__u8 pad;
	char comp[RULE_COMPS][COMP_BYTES];
};

#define WORD_READ_ONLY 1
#define WORD_WRITABLE 2
#define WORD_PINNED 3

struct policy_config {
	__u32 rule_count;
	__u32 flags;
	char fs_type[FS_TYPE_BYTES];
};

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
};

struct last_decision {
	__u64 count;
	__u32 hook;
	__u32 reason;
	__u32 depth;
	__u32 root_kind;
	char name[32];
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
	__u8 rule_read_only;
	__u8 rule_pinned;
	__s16 region;         // the `writable` line whose region the entry is in, or -1
	__s16 deciding;
};

// The values a loop carries from one iteration to the next, written to the map and read again at
// every iteration: the verifier does not track a map's contents, so it sees an unknown scalar at
// each iteration and the loop's states converge. A counter it tracks exactly, a register or stack
// slot used as an index or in a branch it can decide, makes every iteration a new state (measured:
// the fold's output counter unrolled 204 iterations deep until the program was "too large").
struct loop_state {
	__u32 depth;          // walk_once: the components recorded so far
	__u32 fold_out;       // fold_component: bytes written, and the position read
	__u32 fold_pos;
	__u32 glob_p;         // component_matches: the pattern and name positions, the backtrack point
	__u32 glob_n;
	__u32 glob_star_p;
	__u32 glob_star_n;
	__u32 glob_have_star;
	__u32 reached;        // child_rule_state: the current line's matched components
	__s32 deciding;       // the rule state: the last line naming the entry or an ancestor, -1 for none
	__u32 pinned_path;    // a pinned-path line names the entry
	__u32 any_partial;    // some line is an interior match: the entry is pinned
	__u32 git_kind;       // locate: the git context so far
	__s32 rel_start;
	__u32 rel_len;
	__u64 barrier;        // walk_once: the word the barrier's fetch-add counts on
};

// The walk's names, leaf first, and the classifier's working state. Per CPU: 512 bytes of stack
// hold none of it.
struct scratch {
	char raw[WALK_BOUND][NAME_BYTES];
	__u8 raw_len[WALK_BOUND];
	char fold[NAME_BYTES];
	__u32 fold_len;
	__u8 partial[RULE_LINES];     // bit k: the line's first k components match this entry's ancestors
	__u8 partial_next[RULE_LINES];
	struct loop_state loop;
	char base[64];                // lock_base_is_operational: the name before `.lock`
	struct position pos[2];       // the hook's positions: the object's, and a destination's
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
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_config);
} policy_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch SEC(".maps");

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

extern const void rename_lock __ksym;

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
};

static __always_inline __u32 read_rename_seq(void)
{
	__u32 seq = 1;	// odd, so a failed read counts as a writer active

	bpf_probe_read_kernel(&seq, sizeof(seq), &rename_lock);
	return seq;
}

// The ordering between the sequence reads and the dentry reads: an atomic fetch-add, which the
// JITs emit with a barrier ("What is gained and what is lost"). The fetched value is kept live
// and the word is map memory: an add whose result is unused compiles to the plain atomic add
// (no BPF_FETCH), which the arm64 JIT emits without ordering (measured: `stadd`, no `ldaddal`).
static __always_inline void barrier_fetch_add(struct scratch *sc)
{
	__u64 old = __sync_fetch_and_add(&sc->loop.barrier, 1);

	barrier_var(old);
}

static __always_inline struct scratch *get_scratch(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&scratch, &zero);
}

// One pass from `start` toward the root: each component's name into `sc->raw`, until a dentry
// whose inode is a recorded root, the filesystem root, or the bound.
static __always_inline int walk_once(struct dentry *start, struct scratch *sc, struct walk *out)
{
	volatile struct loop_state *ls = &sc->loop;
	struct dentry *cur = start;
	__u32 seq0, seq1, status = WALK_BOUND_HIT, root_kind = 0;
	int i;

	seq0 = read_rename_seq();
	if (seq0 & 1)
		return 0;
	barrier_fetch_add(sc);
	ls->depth = 0;
	bpf_for(i, 0, WALK_BOUND) {
		struct inode *inode = BPF_CORE_READ(cur, d_inode);
		struct dentry *parent;
		const unsigned char *name;
		__u32 len;

		ls->depth = i;
		if (inode) {
			struct ident id;
			struct root *root;

			id.s_dev = BPF_CORE_READ(inode, i_sb, s_dev);
			id.i_ino = BPF_CORE_READ(inode, i_ino);
			root = bpf_map_lookup_elem(&roots, &id);
			if (root) {
				root_kind = root->kind;
				status = WALK_OK;
				break;
			}
		}
		len = BPF_CORE_READ(cur, d_name.len);
		if (len >= NAME_BYTES) {
			status = WALK_TOO_LONG;
			break;
		}
		name = BPF_CORE_READ(cur, d_name.name);
		if (bpf_probe_read_kernel_str(sc->raw[BOUNDED(i, WALK_BOUND)], NAME_BYTES, name) < 0) {
			status = WALK_TOO_LONG;
			break;
		}
		sc->raw_len[BOUNDED(i, WALK_BOUND)] = len;
		ls->depth = i + 1;
		parent = BPF_CORE_READ(cur, d_parent);
		if (!parent || parent == cur) {
			status = WALK_NOROOT;
			break;
		}
		cur = parent;
	}
	barrier_fetch_add(sc);
	seq1 = read_rename_seq();
	if (seq1 != seq0)
		return 0;
	out->depth = ls->depth;
	out->root_kind = root_kind;
	out->status = status;
	return 1;
}

static __always_inline void walk(enum hook hook, struct dentry *start, struct scratch *sc, struct walk *out)
{
	__u32 key = hook;
	struct hook_stats *st = bpf_map_lookup_elem(&stats, &key);
	int ok = 0, i;

	out->depth = 0;
	out->root_kind = 0;
	out->status = WALK_TORN;
	out->retries = RETRY_BOUND;
	bpf_for(i, 0, RETRY_BOUND) {
		if (walk_once(start, sc, out)) {
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

// `sc->raw[index]` folded into `sc->fold`: the special sequences dropped or folded, trailing `.`
// and space stripped, ASCII lowercased. Returns 0 when the index is out of range.
static __always_inline int fold_component(struct scratch *sc, __u32 index)
{
	volatile struct loop_state *ls = &sc->loop;
	const char *src;
	__u32 len, out;
	int i;

	if (index >= WALK_BOUND)
		return 0;
	src = sc->raw[BOUNDED(index, WALK_BOUND)];
	len = sc->raw_len[BOUNDED(index, WALK_BOUND)];
	if (len >= NAME_BYTES)
		return 0;
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
	return 1;
}

// Whether `sc->fold` equals a literal.
#define FOLD_IS(sc, lit) ((sc)->fold_len == sizeof(lit) - 1 && bpf_strncmp((sc)->fold, sizeof(lit), lit) == 0)
// Whether a raw component equals a literal, byte for byte.
#define RAW_IS(sc, index, lit) \
	((sc)->raw_len[BOUNDED(index, WALK_BOUND)] == sizeof(lit) - 1 && \
	 bpf_strncmp((sc)->raw[BOUNDED(index, WALK_BOUND)], sizeof(lit), lit) == 0)

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

// Where an ordinary entry stands under the rules, computed from its parent's and its folded name:
// `deciding`, `pinned_path` and `any_partial` of the loop state. The child's state from the
// parent's: `sc->partial` holds the parent's interior matches and receives the child's.
// `anchored_ok` is set for a child of a workspace root.
static __always_inline void child_rule_state(struct scratch *sc, const struct policy_config *cfg, int anchored_ok)
{
	volatile struct loop_state *ls = &sc->loop;
	__u32 count = cfg->rule_count;
	int line;

	ls->pinned_path = 0;
	ls->any_partial = 0;
	if (count > RULE_LINES)
		count = RULE_LINES;
	bpf_for(line, 0, RULE_LINES) {
		__u32 key = line;
		struct rule_line *rule;
		__u8 was = sc->partial[BOUNDED(line, RULE_LINES)];
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
			const char *comp = rule->comp[BOUNDED(k, RULE_COMPS)];
			__u8 can_start = k == 0 ? (!rule->anchored || anchored_ok) : ((was >> k) & 1);

			if (k >= rule->ncomp)
				break;
			if (!can_start)
				continue;
			if (comp[0] != '*' && comp[0] != sc->fold[0])
				continue;
			if (component_matches(sc, comp))
				ls->reached |= 1u << ((k + 1) & 7);
		}
		reached = ls->reached;
		ncomp = rule->ncomp & 7;
		if (reached & (1u << ncomp)) {
			if (rule->word == WORD_PINNED)
				ls->pinned_path = 1;
			else if (line > ls->deciding)
				ls->deciding = line;
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
		sc->partial[BOUNDED(line, RULE_LINES)] = next;
		if (next)
			ls->any_partial = 1;
	}
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

// The position of the walked object: the git context from the root down, the rule context
// beside it, the "Directories" names at the target.
static __always_inline int locate(struct scratch *sc, const struct policy_config *cfg, struct walk *w,
				  struct position *pos)
{
	volatile struct loop_state *ls = &sc->loop;
	__u32 git_kind;
	__s32 rel_start;
	__u32 rel_len;
	int i, k;

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
	pos->region = -1;
	pos->deciding = -1;
	if (w->status != WALK_OK)
		return 0;
	ls->deciding = -1;
	ls->pinned_path = 0;
	ls->any_partial = 0;
	ls->git_kind = GIT_NOT;
	ls->rel_start = -1;
	ls->rel_len = 0;
	if (w->root_kind == ROOT_GITDIR) {
		ls->git_kind = GIT_IN;
		ls->rel_start = w->depth;	// the root is the gitdir entry, one above the root child
	}
	bpf_for(k, 0, RULE_LINES)
		sc->partial[BOUNDED(k, RULE_LINES)] = 0;
	bpf_for(i, 0, WALK_BOUND) {
		__u32 index = w->depth - 1 - i;
		int at_root_child = i == 0;

		if (i >= w->depth || index >= WALK_BOUND)
			break;
		if (!fold_component(sc, index))
			return 0;
		// The rules, computed at every position: a `read-only` line keeps applying below a
		// `.git` entry ("Directories"), and a line may start inside one, the stricter reading.
		if (cfg->rule_count)
			child_rule_state(sc, cfg, at_root_child && w->root_kind == ROOT_WORKSPACE);
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
	pos->deciding = ls->deciding;
	pos->rule_read_only = rule_word(ls->deciding) == WORD_READ_ONLY;
	pos->rule_pinned = ls->pinned_path || ls->any_partial;
	pos->region = rule_word(ls->deciding) == WORD_WRITABLE ? ls->deciding : -1;
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
		return R_ALLOW;
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

static __always_inline struct policy_config *get_config(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&policy_config, &zero);
}

// Whether the object's superblock is of the root's type: what the policy judges at all. The
// configured name is compared as two words: bpf_strncmp takes only a string literal (the
// verifier wants its third argument in a read-only map).
static __always_inline int on_root_type(struct super_block *sb, const struct policy_config *cfg)
{
	__u64 type[2] = {};
	__u64 want[2];
	const char *name = BPF_CORE_READ(sb, s_type, name);

	if (bpf_probe_read_kernel_str(type, sizeof(type), name) < 0)
		return 0;
	__builtin_memcpy(want, cfg->fs_type, sizeof(want));
	return type[0] == want[0] && type[1] == want[1];
}

static __always_inline int finish(enum hook hook, __u32 reason, const struct position *pos,
				  struct scratch *sc, __u64 start_ns)
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
	return allow;
}

// The walk and the position into `sc->pos[slot]`, as a global function: the verifier checks a
// global function once per program, where it checks an inlined or static one at each call, and
// the two-walk hooks exceed its budget with the walk checked twice on Linux 6.18 (measured, "Phase
// 2 on WSL": 640,000 to 790,000 insns for one walk there against 14,500 on 7.2). The dentry
// arrives as a scalar, which the walk's probe reads take as they take a pointer: the verifier
// passes a global function a pointer only as a declared trusted argument (measured on 7.2: "R2 is
// not a scalar" for a hook's dentry), which `file_open`'s dentry, read through a probe, is not.
__noinline int judge_position(__u64 hook, __u64 dentry, __u64 slot)
{
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch();
	struct position *pos;
	struct walk w;

	if (!cfg || !sc || slot > 1)
		return R_INTERNAL;
	pos = &sc->pos[slot & 1];
	walk(hook, (struct dentry *)dentry, sc, &w);
	if (!locate(sc, cfg, &w, pos)) {
		if (pos->status == WALK_OK)
			return R_INTERNAL;
		return walk_reason(pos);
	}
	return R_ALLOW;
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
				      const struct policy_config *cfg, struct scratch *sc, struct position *pos,
				      int judge_any_type)
{
	if (!judge_any_type && !on_root_type(sb, cfg))
		return R_OUTSIDE;
	return judge_position(hook, as_scalar(dentry), pos == &sc->pos[1]);
}

static __always_inline struct super_block *sb_of_inode(struct inode *inode)
{
	return BPF_CORE_READ(inode, i_sb);
}

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
	struct position *pos;
	__u32 reason;

	// A read-only open changes nothing; `O_TRUNC` without `FMODE_WRITE` is row 11's truncate.
	if (!(f_mode & FMODE_WRITE) && !(f_flags & O_TRUNC_FLAG))
		return 1;
	dentry = BPF_CORE_READ(file, f_path.dentry);
	inode = BPF_CORE_READ(dentry, d_inode);
	cfg = get_config();
	sc = get_scratch();
	if (!cfg || !sc)
		return finish(HOOK_FILE_OPEN, R_INTERNAL, NULL, NULL, start);
	pos = &sc->pos[0];
	reason = prologue(HOOK_FILE_OPEN, dentry, sb_of_inode(inode), cfg, sc, pos, 0);
	if (reason == R_ALLOW)
		reason = decide_modify(pos);
	return finish(HOOK_FILE_OPEN, reason, pos, sc, start);
}

SEC("lsm_cgroup/inode_setattr")
int BPF_PROG(inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{
	__u64 start = bpf_ktime_get_ns();
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch();
	struct position *pos;
	__u32 reason;

	if (!cfg || !sc)
		return finish(HOOK_INODE_SETATTR, R_INTERNAL, NULL, NULL, start);
	pos = &sc->pos[0];
	reason = prologue(HOOK_INODE_SETATTR, dentry, sb_of_inode(inode), cfg, sc, pos, 0);
	if (reason == R_ALLOW)
		reason = decide_modify(pos);
	return finish(HOOK_INODE_SETATTR, reason, pos, sc, start);
}

SEC("lsm_cgroup/inode_unlink")
int BPF_PROG(inode_unlink, struct inode *dir, struct dentry *dentry)
{
	__u64 start = bpf_ktime_get_ns();
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch();
	struct position *pos;
	__u32 reason;

	if (!cfg || !sc)
		return finish(HOOK_INODE_UNLINK, R_INTERNAL, NULL, NULL, start);
	pos = &sc->pos[0];
	reason = prologue(HOOK_INODE_UNLINK, dentry, sb_of_inode(dir), cfg, sc, pos, 0);
	if (reason == R_ALLOW)
		reason = decide_remove(pos);
	return finish(HOOK_INODE_UNLINK, reason, pos, sc, start);
}

// A new non-directory name: create, mknod and symlink share it; `is_socket` adds the socket rule,
// which holds beneath a recorded root of any superblock type.
static __always_inline int new_name(enum hook hook, struct inode *dir, struct dentry *dentry, int is_socket)
{
	__u64 start = bpf_ktime_get_ns();
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch();
	struct position *pos;
	__u32 reason;

	if (!cfg || !sc)
		return finish(hook, R_INTERNAL, NULL, NULL, start);
	pos = &sc->pos[0];
	reason = prologue(hook, dentry, sb_of_inode(dir), cfg, sc, pos, is_socket);
	if (is_socket) {
		// Beneath any recorded root the socket is refused; outside every root, judged as an
		// ordinary name on the root's type, allowed elsewhere.
		if (reason == R_ALLOW)
			reason = R_SOCKET;
		else if (reason != R_OUTSIDE && pos->status == WALK_NOROOT)
			reason = on_root_type(sb_of_inode(dir), cfg) ? R_WALK_NOROOT : R_OUTSIDE;
		return finish(hook, reason, pos, sc, start);
	}
	if (reason == R_ALLOW) {
		reason = decide_create(pos);
		if (reason == R_ALLOW && pos->target_head)
			reason = R_HEAD;
	}
	return finish(hook, reason, pos, sc, start);
}

SEC("lsm_cgroup/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return new_name(HOOK_INODE_CREATE, dir, dentry, 0);
}

SEC("lsm_cgroup/inode_mknod")
int BPF_PROG(inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return new_name(HOOK_INODE_MKNOD, dir, dentry, (mode & S_IFMT) == S_IFSOCK);
}

SEC("lsm_cgroup/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
{
	return new_name(HOOK_INODE_SYMLINK, dir, dentry, 0);
}

// A source object getting a second name, or moving: `old` positive, `new` a name.
static __always_inline int two_names(enum hook hook, struct dentry *old_dentry, struct inode *new_dir,
				     struct dentry *new_dentry)
{
	__u64 start = bpf_ktime_get_ns();
	struct policy_config *cfg = get_config();
	struct scratch *sc = get_scratch();
	struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
	struct inode *new_inode = BPF_CORE_READ(new_dentry, d_inode);
	__u32 old_mode = BPF_CORE_READ(old_inode, i_mode);
	struct position *from, *to;
	__u32 reason;

	if (!cfg || !sc)
		return finish(hook, R_INTERNAL, NULL, NULL, start);
	from = &sc->pos[0];
	to = &sc->pos[1];
	if ((old_mode & S_IFMT) == S_IFSOCK) {
		// The socket rule on the destination, beneath any recorded root.
		reason = prologue(hook, new_dentry, sb_of_inode(new_dir), cfg, sc, to, 1);
		if (reason == R_ALLOW)
			return finish(hook, R_SOCKET, to, sc, start);
		if (to->status == WALK_NOROOT && !on_root_type(sb_of_inode(new_dir), cfg))
			return finish(hook, R_OUTSIDE, to, sc, start);
		return finish(hook, reason, to, sc, start);
	}
	reason = prologue(hook, old_dentry, sb_of_inode(old_inode), cfg, sc, from, 0);
	if (reason == R_OUTSIDE)
		return finish(hook, R_OUTSIDE, NULL, NULL, start);
	if (reason == R_ALLOW)
		reason = hook == HOOK_INODE_RENAME ? decide_remove(from) : decide_modify(from);
	if (reason != R_ALLOW)
		return finish(hook, reason, from, sc, start);
	reason = prologue(hook, new_dentry, sb_of_inode(new_dir), cfg, sc, to, 0);
	if (reason == R_OUTSIDE) {
		// A rename across superblocks is EXDEV before any hook; a link too. Not reached.
		return finish(hook, R_OUTSIDE, NULL, NULL, start);
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
		if (reason == R_ALLOW && ((old_mode & S_IFMT) == S_IFDIR || (old_mode & S_IFMT) == S_IFLNK))
			reason = decide_region_move(from, to, cfg->rule_count);
	}
	return finish(hook, reason, to, sc, start);
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

// Left to Phase 3 ("The policy"): the identities of the root's `.git` and `.ko-agent-sandbox` and
// of every resolved gitdir as second names; the guard's alias contexts (`RuleContext::also`); the
// NTFS short-name form; `file_receive`; the no-root policy's `fs_type` without roots, which this
// program gives by an empty roots map already.
