// The BPF cgroup-LSM backend of bpf/ko-agent-bpf/doc/architecture.md: the unprivileged side, the launcher's
// own process in the attach cgroup. It lays out the proof fixture and runs the proof ("Lifecycle",
// 3), deriving each expected answer from the whole ordered rule set as the filter decides it, makes
// the single syscalls the lifecycle rows need, and, for the suites, writes a records file from a
// rule file in place of the guard. Static, so it runs in the machine and in a container alike.
//
//   fixture records RULES OUT [--guarded KIND=RELPATH]...
//                                   the records file (records.h) of RULES, a rule file as the policy
//                                   suite reads one, and of the guarded objects by workspace-relative
//                                   path; KIND is workspace, gitdir, guarded-git or guarded-sandbox
//   fixture make ROOT RULES         the proof fixture: a tree laid out as a workspace with a .git
//                                   holding config and a hook, a .ko-agent-sandbox, ordinary files
//                                   and one entry per line of RULES, a rule file or the guard's
//                                   records file (the launcher passes the records)
//   fixture run ROOT RULES [--unix-socket] [--no-root]
//                                   the proof, from this process: one refused operation per hook,
//                                   one write per rule-line entry and per ordinary entry, each
//                                   printed with its expected and actual answer; --no-root is a
//                                   read-only session's policy, under which every write is refused
//   fixture join CGROUP CMD...      move this process into CGROUP, then run CMD
//   fixture write PATH              open PATH for writing, creating it, and write one byte
//   fixture rename FROM TO          rename(2), printing the errno name
//   fixture bind PATH               bind a socket at PATH and leave it
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/types.h>

#define PROGRAM_NAME "fixture"
#include "backend.h"

#define MAX_COMPS 64

static const char *errname(int err)
{
	switch (err) {
	case 0: return "ok";
	case EPERM: return "EPERM";
	case ENOENT: return "ENOENT";
	case EACCES: return "EACCES";
	case EEXIST: return "EEXIST";
	case EINVAL: return "EINVAL";
	case ENOSYS: return "ENOSYS";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case EXDEV: return "EXDEV";
	case EROFS: return "EROFS";
	case EISDIR: return "EISDIR";
	case ENOTDIR: return "ENOTDIR";
	case EBUSY: return "EBUSY";
	case ENOTEMPTY: return "ENOTEMPTY";
	case ENAMETOOLONG: return "ENAMETOOLONG";
	case EADDRINUSE: return "EADDRINUSE";
	default: return NULL;
	}
}

// `ok` or `<errno name or number>` of the last call.
static const char *result(int rc)
{
	static char text[32];
	int err = errno;

	if (rc >= 0)
		return "ok";
	if (errname(err))
		return errname(err);
	snprintf(text, sizeof(text), "errno%d", err);
	return text;
}

// --- The rule file ------------------------------------------------------------------------------------

struct rules {
	struct rule_line lines[RULE_LINES];
	struct alias_context aliases[ALIASES];
	char alias_paths[ALIASES][1024];
	__u32 count;
	__u32 alias_count;
};

static void fold_ascii(char *text)
{
	for (char *at = text; *at; at++)
		if (*at >= 'A' && *at <= 'Z')
			*at += 'a' - 'A';
}

// policy.rs, `component_matches`: the iterative glob with one backtrack point.
static bool glob_matches(const char *pattern, const char *name)
{
	size_t p = 0, n = 0, star_p = 0, star_n = 0;
	bool have_star = false;
	size_t plen = strlen(pattern), nlen = strlen(name);

	while (n < nlen) {
		if (p < plen && pattern[p] == '*') {
			star_p = p;
			star_n = n;
			have_star = true;
			p++;
		} else if (p < plen && pattern[p] == name[n]) {
			p++;
			n++;
		} else if (have_star) {
			p = star_p + 1;
			star_n++;
			n = star_n;
		} else {
			return false;
		}
	}
	while (p < plen && pattern[p] == '*')
		p++;
	return p == plen;
}

// policy.rs, `child_rule_context`, as the policy suite's controller computes it: the alias context
// of a symlink's position, over the lines above it by their own indices.
static void child_rule_context(const struct rule_line *lines, __u32 count, struct alias_context *ctx,
			       bool parent_is_root, const char *folded)
{
	__u8 next[RULE_LINES] = {};
	__s32 deciding = ctx->deciding;
	__u32 pinned = 0;

	for (__u32 line = 0; line < count; line++) {
		const struct rule_line *rule = &lines[line];
		__u8 was = ctx->partial[line];
		__u8 reached = 0;

		if (rule->anchored)
			continue;
		for (int k = 0; k < rule->ncomp; k++) {
			bool can_start = k == 0 ? (!rule->anchored || parent_is_root) : (was >> k) & 1;
			bool matched;

			if (!can_start)
				continue;
			matched = rule->anchored ? !strcmp(rule->comp[k], folded) : glob_matches(rule->comp[k], folded);
			if (matched)
				reached |= 1u << (k + 1);
		}
		if (reached & (1u << rule->ncomp)) {
			if (rule->word == WORD_PINNED)
				pinned = 1;
			else if ((__s32)line > deciding)
				deciding = line;
			reached &= ~(1u << rule->ncomp);
		}
		next[line] = reached;
	}
	for (__u32 line = 0; line < count; line++)
		if (next[line] && lines[line].word != WORD_PINNED && (__s32)line <= deciding)
			next[line] = 0;
	memcpy(ctx->partial, next, sizeof(next));
	ctx->deciding = deciding;
	ctx->pinned_path = pinned;
}

// The lines of a records file the guard wrote (`ko-agent-fs --resolve --bpf-records`), told from a
// rule file by its magic: the launcher's proof reads the records the controller loaded.
static bool read_records_as_rules(const char *path, struct rules *rules)
{
	static struct records rec;
	FILE *file = fopen(path, "rb");
	char magic[8];
	bool is_records;

	if (!file)
		die("open %s: %s", path, strerror(errno));
	is_records = fread(magic, 1, sizeof(magic), file) == sizeof(magic) && !memcmp(magic, RECORDS_MAGIC, 8);
	fclose(file);
	if (!is_records)
		return false;
	read_records(path, &rec);
	memset(rules, 0, sizeof(*rules));
	memcpy(rules->lines, rec.rules, sizeof(rules->lines));
	memcpy(rules->aliases, rec.aliases, sizeof(rules->aliases));
	rules->count = rec.header.rule_count;
	rules->alias_count = rec.header.alias_count;
	return true;
}

// A rule file: `word comp/comp[/comp...] [anchored] [alias=PATH]` per line, `#` comments and blank
// lines ignored, as the policy suite reads one (its controller.c, read_rules); or the guard's
// records file.
static void read_rules(const char *path, struct rules *rules)
{
	FILE *file;
	char line[1024];

	if (read_records_as_rules(path, rules))
		return;
	file = fopen(path, "r");
	memset(rules, 0, sizeof(*rules));
	if (!file)
		die("open %s: %s", path, strerror(errno));
	while (fgets(line, sizeof(line), file)) {
		struct rule_line *rule;
		char *word, *name, *token, *save = NULL, *comp, *alias_path = NULL;
		char *hash = strchr(line, '#');
		bool anchored = false;

		if (hash)
			*hash = 0;
		word = strtok_r(line, " \t\r\n", &save);
		if (!word)
			continue;
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			die("%s: a line without a name", path);
		while ((token = strtok_r(NULL, " \t\r\n", &save))) {
			if (!strcmp(token, "anchored"))
				anchored = true;
			else if (!strncmp(token, "alias=", 6))
				alias_path = token + 6;
			else
				die("%s: unknown token %s", path, token);
		}
		if (rules->count >= RULE_LINES)
			die("%s: more than %d lines", path, RULE_LINES);
		rule = &rules->lines[rules->count];
		if (!strcmp(word, "read-only"))
			rule->word = WORD_READ_ONLY;
		else if (!strcmp(word, "writable"))
			rule->word = WORD_WRITABLE;
		else if (!strcmp(word, "pinned-path"))
			rule->word = WORD_PINNED;
		else
			die("%s: unknown word %s", path, word);
		rule->anchored = anchored;
		fold_ascii(name);
		for (comp = strtok_r(name, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
			if (rule->ncomp >= RULE_COMPS)
				die("%s: more than %d components", path, RULE_COMPS);
			if (strlen(comp) >= COMP_BYTES)
				die("%s: a component of %zu bytes", path, strlen(comp));
			strcpy(rule->comp[rule->ncomp++], comp);
		}
		if (alias_path) {
			struct alias_context *ctx;
			char spelled[1024];
			bool first = true;

			if (rule->word != WORD_PINNED || !anchored)
				die("%s: alias= belongs to an anchored pinned-path line", path);
			if (rules->alias_count >= ALIASES)
				die("%s: more than %d aliases", path, ALIASES);
			ctx = &rules->aliases[rules->alias_count];
			ctx->deciding = -1;
			snprintf(rules->alias_paths[rules->alias_count], 1024, "%s", alias_path);
			snprintf(spelled, sizeof(spelled), "%s", alias_path);
			fold_ascii(spelled);
			for (comp = strtok_r(spelled, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
				child_rule_context(rules->lines, rules->count, ctx, first, comp);
				first = false;
			}
			rule->alias = ++rules->alias_count;
		}
		rules->count++;
	}
	fclose(file);
}

// --- records --------------------------------------------------------------------------------------------

static int cmd_records(int argc, char **argv)
{
	struct rules rules;
	struct records_header header = {.magic = RECORDS_MAGIC, .layout = RECORDS_LAYOUT};
	static struct guarded_path guarded[GUARDED_PATHS];
	__u32 guarded_count = 0;
	FILE *out;

	if (argc < 2)
		die("usage: records RULES OUT [--guarded KIND=RELPATH]...");
	read_rules(argv[0], &rules);
	for (int i = 2; i < argc; i += 2) {
		char *spec, *eq;
		static const char *const kinds[] = {"", "workspace", "gitdir", "", "guarded-git", "guarded-sandbox"};

		if (strcmp(argv[i], "--guarded") || i + 1 >= argc)
			die("records: unknown or incomplete option %s", argv[i]);
		if (guarded_count >= GUARDED_PATHS)
			die("more than %d guarded paths", GUARDED_PATHS);
		spec = argv[i + 1];
		eq = strchr(spec, '=');
		if (!eq)
			die("--guarded takes KIND=RELPATH: %s", spec);
		*eq = 0;
		for (unsigned kind = 1; kind < sizeof(kinds) / sizeof(kinds[0]); kind++)
			if (kinds[kind][0] && !strcmp(kinds[kind], spec))
				guarded[guarded_count].kind = kind;
		if (!guarded[guarded_count].kind)
			die("--guarded kind: %s", spec);
		if (strlen(eq + 1) >= PATH_BYTES)
			die("--guarded path too long");
		guarded[guarded_count].len = strlen(eq + 1);
		strcpy(guarded[guarded_count].path, eq + 1);
		guarded_count++;
	}
	header.rule_count = rules.count;
	header.alias_count = rules.alias_count;
	header.root_count = guarded_count;
	out = fopen(argv[1], "wb");
	if (!out)
		die("open %s: %s", argv[1], strerror(errno));
	if (fwrite(&header, sizeof(header), 1, out) != 1 ||
	    fwrite(rules.lines, sizeof(struct rule_line), rules.count, out) != rules.count ||
	    fwrite(rules.aliases, sizeof(struct alias_context), rules.alias_count, out) != rules.alias_count ||
	    fwrite(guarded, sizeof(struct guarded_path), guarded_count, out) != guarded_count)
		die("write %s: %s", argv[1], strerror(errno));
	fclose(out);
	printf("records out=%s rule_count=%u aliases=%u guarded=%u layout=%08x\n", argv[1], rules.count,
	       rules.alias_count, guarded_count, RECORDS_LAYOUT);
	return 0;
}

// --- The fixture ------------------------------------------------------------------------------------------

static char root[4096];
#define REL_BYTES 2048

// A path in the fixture; four buffers in turn, so a call with two operands gets two.
static const char *at(const char *rel)
{
	static char paths[4][4096 + REL_BYTES + 1];
	static int turn;
	char *path = paths[turn++ % 4];

	snprintf(path, sizeof(paths[0]), "%s/%s", root, rel);
	return path;
}

static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	(void)st;
	(void)ftw;
	if (type == FTW_DP || type == FTW_D ? rmdir(path) : unlink(path))
		die("remove %s: %s", path, strerror(errno));
	return 0;
}

// The fixture is laid out in place at a restart, so that its root keeps the identity the pinned
// programs hold ("Lifecycle", 5); an entry of the other kind, left by another rule file's layout, goes.
static void make_dir_at(const char *rel)
{
	struct stat st;

	if (!lstat(at(rel), &st) && !S_ISDIR(st.st_mode) && unlink(at(rel)))
		die("unlink %s: %s", at(rel), strerror(errno));
	if (mkdir(at(rel), 0755) && errno != EEXIST)
		die("mkdir %s: %s", at(rel), strerror(errno));
}

static void make_dirs(const char *rel)
{
	char copy[REL_BYTES];

	snprintf(copy, sizeof(copy), "%s", rel);
	for (char *slash = copy; *slash; slash++) {
		if (*slash != '/')
			continue;
		*slash = 0;
		make_dir_at(copy);
		*slash = '/';
	}
	make_dir_at(copy);
}

static void make_file(const char *rel, const char *content)
{
	char copy[REL_BYTES];
	char *slash;
	FILE *file;
	struct stat st;

	snprintf(copy, sizeof(copy), "%s", rel);
	slash = strrchr(copy, '/');
	if (slash) {
		*slash = 0;
		make_dirs(copy);
	}
	if (!lstat(at(rel), &st) && S_ISDIR(st.st_mode) && nftw(at(rel), remove_entry, 16, FTW_DEPTH | FTW_PHYS))
		die("remove %s: %s", at(rel), strerror(errno));
	file = fopen(at(rel), "w");
	if (!file || fputs(content, file) == EOF)
		die("write %s: %s", at(rel), strerror(errno));
	fclose(file);
}

// A line's concrete entry: its components with `x` for each `*`.
static void concrete_path(const struct rule_line *line, char *out, size_t size)
{
	out[0] = 0;
	for (int k = 0; k < line->ncomp; k++) {
		char comp[COMP_BYTES];

		snprintf(comp, sizeof(comp), "%s", line->comp[k]);
		for (char *star = comp; *star; star++)
			if (*star == '*')
				*star = 'x';
		snprintf(out + strlen(out), size - strlen(out), "%s%s", k ? "/" : "", comp);
	}
}

static bool is_below(const char *path, const char *other)
{
	size_t len = strlen(path);

	return !strncmp(other, path, len) && other[len] == '/';
}

// The proof's own names: the fixed entries the per-hook operations and the two ordinary writes
// need, and the names those operations create, which must not exist when the proof runs, or the
// kernel answers `EEXIST` before any hook. Each is chosen against every record (pick_name): a
// user's rule name cannot hold the `+` (FileRules.nameRefusal: a-z, 0-9, `.`, `_`, `-`, `*` and
// `/`), but the guard's anchored lines name whatever a relocated hook directory or a symlink's
// end is called, so a record equal to a base name or below it moves the name to `<base>.1`, `.2`
// and so on; `make` and `run` read the same records and choose the same names. A record above a
// name, such as `read-only sub`, keeps that directory a directory (has_entry_below).
struct names {
	char ordinary[REL_BYTES];
	char ordinary2[REL_BYTES];
	char sub[REL_BYTES];
	char sub_ordinary[REL_BYTES];
	char sub_git[REL_BYTES];
	char fifo[REL_BYTES];
	char sock[REL_BYTES];
	char git_new[REL_BYTES];
	char git_sock[REL_BYTES];
};

static bool record_at_or_below(const struct rules *rules, const char *path)
{
	for (__u32 i = 0; i < rules->count; i++) {
		char other[REL_BYTES];

		concrete_path(&rules->lines[i], other, sizeof(other));
		if (!strcmp(other, path) || is_below(path, other))
			return true;
	}
	return false;
}

// `base`, or `base.N` for the smallest N from 1 at which no record is the name or lies below it.
static void pick_name(const struct rules *rules, const char *base, char *out, size_t size)
{
	for (int n = 0;; n++) {
		if (n == 0)
			snprintf(out, size, "%s", base);
		else
			snprintf(out, size, "%s.%d", base, n);
		if (!record_at_or_below(rules, out))
			return;
		if (n == 999)
			die("no free name for %s among the records", base);
	}
}

static void pick_names(const struct rules *rules, struct names *names)
{
	pick_name(rules, "ko+ordinary", names->ordinary, sizeof(names->ordinary));
	pick_name(rules, "ko+ordinary2", names->ordinary2, sizeof(names->ordinary2));
	// The directory holding an ordinary file and the `.git` the per-hook operations try to make;
	// no record lies below it, so its own entries are free.
	pick_name(rules, "ko+sub", names->sub, sizeof(names->sub));
	snprintf(names->sub_ordinary, sizeof(names->sub_ordinary), "%s/ko+ordinary", names->sub);
	snprintf(names->sub_git, sizeof(names->sub_git), "%s/.git", names->sub);
	pick_name(rules, "ko+fifo", names->fifo, sizeof(names->fifo));
	pick_name(rules, "ko+sock", names->sock, sizeof(names->sock));
	pick_name(rules, ".git/ko+new", names->git_new, sizeof(names->git_new));
	pick_name(rules, ".git/ko+sock", names->git_sock, sizeof(names->git_sock));
}

// The fixed entries, laid out before the rule entries: a rule line naming a directory above one
// keeps the directory (has_entry_below).
#define FIXED_ENTRIES 7
static void fixed_entries(const struct names *names, const char *out[FIXED_ENTRIES])
{
	out[0] = ".git/HEAD";
	out[1] = ".git/config";
	out[2] = ".git/hooks/pre-commit";
	out[3] = ".ko-agent-sandbox/file/rule";
	out[4] = names->ordinary;
	out[5] = names->ordinary2;
	out[6] = names->sub_ordinary;
}

// Whether another line's entry or a fixed entry lies below this one's, which makes it a directory.
static bool has_entry_below(const struct rules *rules, const struct names *names, __u32 index, const char *path)
{
	const char *fixed[FIXED_ENTRIES];

	for (__u32 i = 0; i < rules->count; i++) {
		char other[REL_BYTES];

		if (i == index)
			continue;
		concrete_path(&rules->lines[i], other, sizeof(other));
		if (is_below(path, other))
			return true;
	}
	fixed_entries(names, fixed);
	for (unsigned i = 0; i < FIXED_ENTRIES; i++)
		if (is_below(path, fixed[i]))
			return true;
	return false;
}

static int split(const char *rel, char comps[][COMP_BYTES])
{
	char copy[REL_BYTES], *save = NULL, *comp;
	int count = 0;

	snprintf(copy, sizeof(copy), "%s", rel);
	for (comp = strtok_r(copy, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
		if (count >= MAX_COMPS)
			die("more than %d components: %s", MAX_COMPS, rel);
		snprintf(comps[count++], COMP_BYTES, "%s", comp);
	}
	return count;
}

// The last line naming the entry or one of its ancestors decides (file-rules.md, "The rule file"):
// a line matches where its components match a run of the path's, at any depth, or at the root
// alone when anchored. Returns the word, or 0 when no line applies.
static __u8 decide(const struct rules *rules, const char *rel)
{
	char comps[MAX_COMPS][COMP_BYTES];
	int count = split(rel, comps);
	__u8 word = 0;

	for (__u32 i = 0; i < rules->count; i++) {
		const struct rule_line *line = &rules->lines[i];

		for (int offset = 0; offset + line->ncomp <= count; offset++) {
			bool all = true;

			for (int k = 0; k < line->ncomp && all; k++)
				all = line->anchored ? !strcmp(line->comp[k], comps[offset + k])
						     : glob_matches(line->comp[k], comps[offset + k]);
			if (all)
				word = line->word;
			if (line->anchored)
				break;
		}
	}
	return word;
}

static int cmd_make(const char *rules_path)
{
	struct rules rules;
	struct names names;

	read_rules(rules_path, &rules);
	pick_names(&rules, &names);
	if (mkdir(root, 0755) && errno != EEXIST)
		die("mkdir %s: %s", root, strerror(errno));
	make_dirs(".git/hooks");
	make_dirs(".git/objects/info");
	make_file(".git/HEAD", "ref: refs/heads/main\n");
	make_file(".git/config", "[core]\n");
	make_file(".git/hooks/pre-commit", "#!/bin/sh\n");
	make_file(".ko-agent-sandbox/file/rule", "");
	make_file(names.ordinary, "x\n");
	make_file(names.ordinary2, "x\n");
	make_file(names.sub_ordinary, "x\n");
	for (__u32 i = 0; i < rules.count; i++) {
		char path[REL_BYTES];

		concrete_path(&rules.lines[i], path, sizeof(path));
		if (has_entry_below(&rules, &names, i, path))
			make_dirs(path);
		else
			make_file(path, "{}\n");
	}
	printf("make root=%s rule_entries=%u ordinary=%s sub=%s fifo=%s sock=%s\n", root, rules.count, names.ordinary,
	       names.sub, names.fifo, names.sock);
	return 0;
}

// --- The proof ----------------------------------------------------------------------------------------------

static int ops, mismatches, share_answered;

// One operation's answer against its expectation; an answer the share gives before any hook,
// EACCES or EOPNOTSUPP to a mkfifo, is counted apart.
static void record(const char *op, const char *rel, const char *expect, const char *got)
{
	const char *verdict = "match";

	ops++;
	if (strcmp(expect, got)) {
		if (!strcmp(op, "mkfifo") && (!strcmp(got, "EACCES") || !strcmp(got, "EOPNOTSUPP"))) {
			verdict = "share";
			share_answered++;
		} else {
			verdict = "mismatch";
			mismatches++;
		}
	}
	printf("fixture op=%s path=%s expect=%s got=%s verdict=%s\n", op, rel, expect, got, verdict);
}

static void try_write(const char *rel, const char *expect)
{
	int fd = open(at(rel), O_WRONLY | O_CREAT, 0644);
	int rc = fd;

	if (fd >= 0) {
		rc = write(fd, "x", 1) == 1 ? 0 : -1;
		close(fd);
	}
	record("write", rel, expect, result(rc));
}

static int bind_at(const char *path)
{
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	char dir[8192], cwd[4096];
	const char *base;
	char *slash;
	int sock, rc, saved;

	snprintf(dir, sizeof(dir), "%s", path);
	slash = strrchr(dir, '/');
	if (!slash)
		die("bind: %s has no directory", path);
	*slash = 0;
	base = slash + 1;
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
	// Bound relative to its directory: sun_path holds 108 bytes.
	if (!getcwd(cwd, sizeof(cwd)) || chdir(dir)) {
		saved = errno;
		close(sock);
		errno = saved;
		return -1;
	}
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", base);
	rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	saved = errno;
	if (chdir(cwd))
		die("chdir: %s", strerror(errno));
	if (rc < 0)
		close(sock);
	errno = saved;
	return rc < 0 ? -1 : sock;
}

// file_receive's refused operation: a child in a mount namespace of its own sends a directory
// descriptor of the fixture over a socket pair; the hook refuses it on arrival ("The hooks",
// file_receive), so nothing arrives and the message is truncated. Returns the answer's name:
// `refused`, `arrived`, or `unsupported` when the child could not make a namespace.
static const char *receive_dir(void)
{
	int pair[2], status;
	pid_t child;
	char data = 'd';
	struct msghdr msg = {};
	struct iovec iov = {.iov_base = &data, .iov_len = 1};
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair))
		die("socketpair: %s", strerror(errno));
	child = fork();
	if (child < 0)
		die("fork: %s", strerror(errno));
	if (child == 0) {
		int dir_fd;
		struct cmsghdr *cmsg;

		close(pair[0]);
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
			_exit(3);
		dir_fd = open(root, O_RDONLY | O_DIRECTORY);
		if (dir_fd < 0)
			_exit(4);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &dir_fd, sizeof(int));
		if (sendmsg(pair[1], &msg, 0) != 1)
			_exit(5);
		_exit(0);
	}
	close(pair[1]);
	if (waitpid(child, &status, 0) < 0)
		die("waitpid: %s", strerror(errno));
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		close(pair[0]);
		return WIFEXITED(status) && WEXITSTATUS(status) == 3 ? "unsupported" : "sender-failed";
	}
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	if (recvmsg(pair[0], &msg, 0) != 1)
		die("recvmsg: %s", strerror(errno));
	close(pair[0]);
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
			return "arrived";
	return (msg.msg_flags & MSG_CTRUNC) ? "refused" : "nothing";
}

static int cmd_run(const char *rules_path, bool unix_socket, bool no_root)
{
	struct rules rules;
	struct names names;
	double start = now_ms();
	int rc, sock;
	const char *absent[5];
	// Under a read-only session's policy every write on the share is refused, the ordinary ones
	// and the rule entries' alike ("The policy", a policy recording no root); under a live one the
	// fixed entries follow the rules as the rule entries do, since a line may name a directory
	// above them.
	const char *allowed = no_root ? "EPERM" : "ok";

	read_rules(rules_path, &rules);
	pick_names(&rules, &names);
	// A leftover at a name an operation creates, from a proof that ran without the policy, goes
	// first; refused, it stays, and the operation then answers `EEXIST`.
	absent[0] = names.fifo;
	absent[1] = names.sock;
	absent[2] = names.git_new;
	absent[3] = names.git_sock;
	absent[4] = names.sub_git;
	for (unsigned i = 0; i < 5; i++) {
		struct stat st;

		if (lstat(at(absent[i]), &st))
			continue;
		if (S_ISDIR(st.st_mode) ? rmdir(at(absent[i])) : unlink(at(absent[i])))
			printf("fixture op=remove path=%s got=%s verdict=leftover\n", absent[i], result(-1));
	}
	// One refused operation per hook, each a guarded name or object ("Lifecycle", 3).
	rc = open(at(names.git_new), O_WRONLY | O_CREAT | O_EXCL, 0644);
	record("creat", names.git_new, "EPERM", result(rc));
	if (rc >= 0)
		close(rc);
	// At an ordinary name: the FIFO rule refuses one anywhere on the share by type ("The policy"),
	// since one there can block the macOS virtiofs server (upstream-issues.md, "Setting a FIFO's
	// times blocks the macOS virtio-fs server").
	rc = mkfifo(at(names.fifo), 0644);
	record("mkfifo", names.fifo, "EPERM", result(rc));
	sock = bind_at(at(unix_socket ? names.git_sock : names.sock));
	record("bind", unix_socket ? names.git_sock : names.sock, "EPERM", result(sock));
	if (sock >= 0)
		close(sock);
	rc = symlink(names.ordinary, at(names.sub_git));
	record("symlink", names.sub_git, "EPERM", result(rc));
	rc = link(at(names.ordinary), at(names.sub_git));
	record("link", names.sub_git, "EPERM", result(rc));
	rc = rename(at(names.ordinary2), at(names.sub_git));
	record("rename", names.sub_git, "EPERM", result(rc));
	rc = unlink(at(".git/config"));
	record("unlink", ".git/config", "EPERM", result(rc));
	rc = open(at(".git/config"), O_WRONLY);
	record("open-write", ".git/config", "EPERM", result(rc));
	if (rc >= 0)
		close(rc);
	rc = chmod(at(".git/config"), 0600);
	record("chmod", ".git/config", "EPERM", result(rc));
	if (unix_socket)
		record("receive-dir", ".", "refused", receive_dir());
	// One write per rule-line entry, its answer from the whole ordered rule set, and the
	// ordinary entries.
	for (__u32 i = 0; i < rules.count; i++) {
		char path[REL_BYTES / 2], target[REL_BYTES];
		__u8 word;

		concrete_path(&rules.lines[i], path, sizeof(path));
		if (rules.lines[i].word == WORD_PINNED) {
			snprintf(target, sizeof(target), "%s.moved", path);
			rc = rename(at(path), at(target));
			record("rename-pinned", path, "EPERM", result(rc));
			continue;
		}
		if (has_entry_below(&rules, &names, i, path)) {
			char probe[REL_BYTES];

			snprintf(probe, sizeof(probe), "%s/ko+probe", path);
			pick_name(&rules, probe, target, sizeof(target));
		} else {
			snprintf(target, sizeof(target), "%s", path);
		}
		word = decide(&rules, target);
		try_write(target, word == WORD_WRITABLE ? allowed : "EPERM");
	}
	for (const char *const *fixed = (const char *const[]){names.ordinary, names.sub_ordinary, NULL}; *fixed;
	     fixed++) {
		__u8 word = decide(&rules, *fixed);

		try_write(*fixed, word == 0 || word == WORD_WRITABLE ? allowed : "EPERM");
	}
	try_write(".ko-agent-sandbox/file/rule", "EPERM");
	printf("fixture ops=%d mismatches=%d share_answered=%d ms=%.1f\n", ops, mismatches, share_answered,
	       now_ms() - start);
	return mismatches ? 1 : 0;
}

// --- Single calls ---------------------------------------------------------------------------------------------

static int cmd_join(int argc, char **argv)
{
	char path[4096], pid[32];
	int fd;

	if (argc < 2)
		die("usage: join CGROUP CMD...");
	snprintf(path, sizeof(path), "%s/cgroup.procs", argv[0]);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("open %s: %s", path, strerror(errno));
	snprintf(pid, sizeof(pid), "%d\n", getpid());
	if (write(fd, pid, strlen(pid)) != (ssize_t)strlen(pid))
		die("write %s: %s", path, strerror(errno));
	close(fd);
	execvp(argv[1], argv + 1);
	die("exec %s: %s", argv[1], strerror(errno));
	return 2;
}

static int cmd_write(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT, 0644), rc = fd;

	if (fd >= 0) {
		rc = write(fd, "x", 1) == 1 ? 0 : -1;
		close(fd);
	}
	printf("write path=%s result=%s\n", path, result(rc));
	return rc < 0 ? 1 : 0;
}

static int cmd_rename(const char *from, const char *to)
{
	int rc = rename(from, to);

	printf("rename from=%s to=%s result=%s\n", from, to, result(rc));
	return rc < 0 ? 1 : 0;
}

static int cmd_bind(const char *path)
{
	int sock = bind_at(path);

	printf("bind path=%s result=%s\n", path, result(sock));
	return sock < 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2)
		die("usage: see the header of fixture.c");
	if (!strcmp(argv[1], "records") && argc >= 4)
		return cmd_records(argc - 2, argv + 2);
	if ((!strcmp(argv[1], "make") || !strcmp(argv[1], "run")) && argc >= 4) {
		bool unix_socket = false, no_root = false, known = true;

		snprintf(root, sizeof(root), "%s", argv[2]);
		if (!strcmp(argv[1], "make") && argc == 4)
			return cmd_make(argv[3]);
		for (int i = 4; i < argc; i++) {
			if (!strcmp(argv[i], "--unix-socket"))
				unix_socket = true;
			else if (!strcmp(argv[i], "--no-root"))
				no_root = true;
			else
				known = false;
		}
		if (!strcmp(argv[1], "run") && known)
			return cmd_run(argv[3], unix_socket, no_root);
	}
	if (!strcmp(argv[1], "join") && argc >= 4)
		return cmd_join(argc - 2, argv + 2);
	if (!strcmp(argv[1], "write") && argc == 3)
		return cmd_write(argv[2]);
	if (!strcmp(argv[1], "rename") && argc == 4)
		return cmd_rename(argv[2], argv[3]);
	if (!strcmp(argv[1], "bind") && argc == 3)
		return cmd_bind(argv[2]);
	die("unknown subcommand or arguments: %s", argv[1]);
}
