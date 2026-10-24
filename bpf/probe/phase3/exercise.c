// Phase 3 of doc/plan-bpf-lsm-cgroup.md: the exerciser, run inside a container under the attach
// cgroup, against policy.bpf.c. It lays out the fixtures, decides the corpus, runs the torn-name
// race and the concurrency storm, and binds, passes and receives sockets and descriptors. Static,
// so the probe image's libc is not needed.
//
//   exercise make-tree TREE         the corpus fixture, laid out as a workspace; TREE-ptr beside it,
//                                   a workspace whose `.git` is a pointer file
//   exercise corpus TREE [GROUP]    the decisions, each printed as `case=... expect=... got=...`;
//                                   GROUP selects one group's cases (`exercise groups` lists them)
//   exercise check TREE             without the policy: the allowed cases run, and each refused
//                                   case's operands are looked up, so a fixture gap shows here
//   exercise race TREE SECONDS      two renamers, one per ancestor level, and a writer on torn
//                                   names by path and through held directory descriptors, counted
//   exercise storm TREE PROCS SECONDS
//                                   PROCS processes mixing permitted and refused operations, counted
//   exercise bind PATH              bind a socket at PATH and leave it
//   exercise serve SOCK SPEC...     bind SOCK, accept one peer, send one message holding one
//                                   descriptor per SPEC: ro:PATH, rw:PATH, dir:PATH, pipe, pair;
//                                   with the spec `then-exit`, exit right after sending instead
//                                   of waiting for the peer to finish
//   exercise receive SOCK [ACTION...]
//                                   connect to SOCK, receive the message, print what arrived, then
//                                   run each ACTION on a received descriptor by index: write:I,
//                                   openat:I:NAME, unlinkat:I:NAME, mkdirat:I:NAME, reopen:I; a
//                                   first ACTION `wait-for:PATH` waits between connecting and
//                                   receiving until PATH exists, which the driver creates once
//                                   the sender's container is gone
//   exercise namespaces             whether a user namespace and each mount syscall are refused
//   exercise fds                    the descriptors of this process and of the container's first
//                                   process beyond the standard three, which must be none
//   exercise walk-cost PATH N       N opens of PATH for writing, for reading, and N lstat, in ns each
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define V9FS_MAGIC 0x01021997

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif
#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif
#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif
#ifndef __NR_fspick
#define __NR_fspick 433
#endif
#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif

static const char *tree;
static int on_9p;             // the tree is on a 9p share, drvfs: what it refuses is counted apart

// Whether `path` is on a 9p share.
static int is_9p(const char *path)
{
	struct statfs sfs;

	return statfs(path, &sfs) == 0 && sfs.f_type == V9FS_MAGIC;
}

static void die(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "exercise: ");
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(2);
}

static const char *errname(int err)
{
	switch (err) {
	case EPERM: return "EPERM";
	case ENOENT: return "ENOENT";
	case EACCES: return "EACCES";
	case EEXIST: return "EEXIST";
	case ENOTTY: return "ENOTTY";
	case EINVAL: return "EINVAL";
	case ENOSYS: return "ENOSYS";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case EXDEV: return "EXDEV";
	case EBADF: return "EBADF";
	case EROFS: return "EROFS";
	case EISDIR: return "EISDIR";
	case ENOTDIR: return "ENOTDIR";
	case ELOOP: return "ELOOP";
	case EMLINK: return "EMLINK";
	case ESTALE: return "ESTALE";
	case EIO: return "EIO";
	case ENOTEMPTY: return "ENOTEMPTY";
	case EBUSY: return "EBUSY";
	case EAGAIN: return "EAGAIN";
	case ENAMETOOLONG: return "ENAMETOOLONG";
	case ECONNREFUSED: return "ECONNREFUSED";
	case EADDRINUSE: return "EADDRINUSE";
	default: return NULL;
	}
}

// `ok` or `<errno name or number>`.
static const char *result(int rc)
{
	static char text[32];
	int err = errno;

	if (rc >= 0)
		return "ok";
	if (errname(err))
		snprintf(text, sizeof(text), "%s", errname(err));
	else
		snprintf(text, sizeof(text), "errno%d", err);
	return text;
}

static long ns_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

// ---------------------------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------------------------

static const char *deep_path(int depth)
{
	static char path[1024];
	size_t len = 0;

	for (int i = 0; i < depth; i++)
		len += snprintf(path + len, sizeof(path) - len, "%sd", i ? "/" : "");
	return path;
}

// A workspace-relative path, with `DEEP<n>` standing for a chain of n directories named `d`.
static const char *tree_path(const char *rel)
{
	static char path[4][8192];
	static int slot;
	char *out = path[slot++ & 3];
	const char *deep = strstr(rel, "DEEP");

	if (deep) {
		int depth = atoi(deep + 4);
		const char *rest = deep + 4;

		while (*rest >= '0' && *rest <= '9')
			rest++;
		snprintf(out, 8192, "%s/%.*s%s%s", tree, (int)(deep - rel), rel, deep_path(depth), rest);
	} else {
		snprintf(out, 8192, "%s/%s", tree, rel);
	}
	return out;
}

static void tree_dirs(const char *rel)
{
	char path[8192];
	char *slash;

	snprintf(path, sizeof(path), "%s/%s", tree, rel);
	for (slash = path + strlen(tree) + 1; *slash; slash++)
		if (*slash == '/') {
			*slash = 0;
			if (mkdir(path, 0755) && errno != EEXIST)
				die("mkdir %s: %s", path, strerror(errno));
			*slash = '/';
		}
	if (mkdir(path, 0755) && errno != EEXIST)
		die("mkdir %s: %s", path, strerror(errno));
}

static void tree_file(const char *rel, const char *content)
{
	char path[8192], parent[8192];
	char *slash;
	int fd;

	snprintf(path, sizeof(path), "%s/%s", tree, rel);
	snprintf(parent, sizeof(parent), "%s", rel);
	slash = strrchr(parent, '/');
	if (slash) {
		*slash = 0;
		tree_dirs(parent);
	}
	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0)
		die("create %s: %s", path, strerror(errno));
	if (content && write(fd, content, strlen(content)) < 0)
		die("write %s: %s", path, strerror(errno));
	close(fd);
}

static void tree_symlink(const char *rel, const char *target)
{
	char path[8192];

	snprintf(path, sizeof(path), "%s/%s", tree, rel);
	if (symlink(target, path) && errno != EEXIST)
		die("symlink %s: %s", path, strerror(errno));
}

// The fixture: a workspace with a gitdir holding the operational and the protected names, a
// nested gitdir under modules, a module namespace, a linked worktree's gitdir, a gitdir whose
// `hooks` is a symlink, the launcher's directory, the defaults' names, a writable region, a
// symlinked `.claude` (the alias), session-made `.git` directories, directories of the NTFS
// short-name form, and a chain deeper than the walk's bound. Beside it, TREE-ptr: a workspace
// whose `.git` is a pointer file, for the guarded-object rows; the driver adds the host-made hard
// links there, outside the policy.
static int cmd_make_tree(void)
{
	char deep[1100];

	if (mkdir(tree, 0755) && errno != EEXIST)
		die("mkdir %s: %s", tree, strerror(errno));
	tree_dirs(".git/hooks");
	tree_dirs(".git/objects/info");
	tree_dirs(".git/objects/pack");
	tree_dirs(".git/objects/x/.ko-agent-sandbox");
	tree_dirs(".git/objects/x/.git");
	tree_dirs(".git/refs/heads");
	tree_dirs(".git/logs/refs/heads");
	tree_dirs(".git/rebase-merge");
	tree_dirs(".git/sequencer");
	tree_dirs(".git/rr-cache");
	tree_dirs(".git/filter-repo");
	tree_dirs(".git/lfs/objects/ab/cd");
	tree_dirs(".git/modules/sub/refs/heads");
	tree_dirs(".git/modules/sub/objects/info");
	tree_dirs(".git/modules/sub/hooks");
	tree_dirs(".git/modules/sub/worktrees/wt");
	tree_dirs(".git/worktrees/feature/hooks");
	tree_dirs(".git/modules/other");
	tree_file(".git/HEAD", "ref: refs/heads/main\n");
	tree_file(".git/HEAD.lock", "ref: refs/heads/main\n");
	tree_file(".git/ORIG_HEAD", "0000000000000000000000000000000000000000\n");
	tree_file(".git/config", "[core]\n");
	tree_file(".git/config.worktree", "[core]\n");
	tree_file(".git/hooks/pre-commit", "#!/bin/sh\n");
	tree_file(".git/hooks/post-commit", "#!/bin/sh\n");
	tree_file(".git/refs/heads/main", "0000000000000000000000000000000000000000\n");
	tree_file(".git/refs/heads/other", "0000000000000000000000000000000000000000\n");
	tree_file(".git/packed-refs", "# pack-refs\n");
	tree_file(".git/index", "");
	tree_file(".git/objects/info/packs", "");
	tree_file(".git/objects/pack/old.pack", "");
	tree_file(".git/rebase-merge/todo", "pick 0\n");
	tree_file(".git/modules/sub/HEAD", "ref: refs/heads/main\n");
	tree_file(".git/modules/sub/config", "[core]\n");
	tree_file(".git/modules/sub/hooks/pre-commit", "#!/bin/sh\n");
	tree_file(".git/modules/other/x", "");
	tree_file(".git/worktrees/feature/gitdir", "/x/.git\n");
	tree_file(".git/worktrees/feature/commondir", "../..\n");
	tree_file(".git/worktrees/feature/hooks/pre-commit", "#!/bin/sh\n");
	tree_file(".git/worktrees/feature/HEAD", "ref: refs/heads/feature\n");
	tree_dirs(".ko-agent-sandbox/file");
	tree_file(".ko-agent-sandbox/file/rule", "");
	tree_dirs(".vscode");
	tree_file(".vscode/tasks.json", "{}\n");
	tree_file(".vscode/settings.json", "{}\n");
	tree_dirs(".github/copilot");
	tree_file(".github/copilot/settings.json", "{}\n");
	tree_dirs("shared/claude");
	tree_file("shared/claude/notes.md", "");
	tree_symlink(".claude", "shared/claude");
	tree_dirs("node_modules/x/.vscode");
	tree_file("node_modules/x/.vscode/tasks.json", "{}\n");
	tree_file("node_modules/x/index.js", "");
	tree_dirs("node_modules/.bin");
	tree_dirs("apps");
	tree_dirs("src/sub");
	tree_file("src/main.rs", "");
	tree_file("src/evil", "evil\n");
	tree_dirs("sub/.git");
	tree_file("sub/.git/HEAD.lock", "ref: refs/heads/main\n");
	tree_file("sub/.git/objects-file", "");
	tree_dirs("sub2/.git/objects");
	tree_file("sub2/.git/objects/x", "");
	tree_dirs("filled/a");
	tree_file("filled/HEAD", "ref: refs/heads/main\n");
	tree_dirs("nested/.git/objects/x");
	tree_file("nested/.git/HEAD", "ref: refs/heads/main\n");
	tree_file("nested/.git/config", "[core]\n");
	tree_dirs("nested/.git/hooks");
	tree_file("nested/.git/hooks/pre-commit", "#!/bin/sh\n");
	tree_dirs("linked/.git/hooks-real");
	tree_file("linked/.git/hooks-real/pre-commit", "#!/bin/sh\n");
	tree_file("linked/.git/HEAD", "ref: refs/heads/main\n");
	tree_symlink("linked/.git/hooks", "hooks-real");
	tree_dirs("githooks");
	tree_file("githooks/pre-commit", "#!/bin/sh\n");
	tree_dirs("apps/githooks");
	tree_dirs("VSCODE~1");
	tree_dirs("shortish/NODE_M~1.JSO");
	tree_dirs("tilde/notes.md~");
	tree_file("README.md", "readme\n");
	tree_file("README2.md", "readme\n");
	tree_file("README3.md", "readme\n");
	tree_file("ordinary", "data\n");
	tree_dirs("storm");
	tree_dirs("race/outerAAAA/node_modAAAA/.vscode");
	tree_file("race/outerAAAA/node_modAAAA/.vscode/tasks.json", "{}\n");
	tree_dirs("race/outerAAAA/BBBBBBBBules/.vscode");
	tree_file("race/outerAAAA/BBBBBBBBules/.vscode/tasks.json", "{}\n");
	tree_dirs("race/BBBBouter");
	tree_file("submod/.git", "gitdir: ../.git/modules/sub\n");
	tree_file("submod/file", "");
	snprintf(deep, sizeof(deep), "deep/%s", deep_path(70));
	tree_dirs(deep);
	snprintf(deep, sizeof(deep), ".git/objects/deep/%s", deep_path(70));
	tree_dirs(deep);
	printf("made tree=%s\n", tree);
	{
		// The pointer-file workspace beside it.
		static char ptr[8192];
		const char *main_tree = tree;

		snprintf(ptr, sizeof(ptr), "%s-ptr", main_tree);
		tree = ptr;
		if (mkdir(tree, 0755) && errno != EEXIST)
			die("mkdir %s: %s", tree, strerror(errno));
		tree_file(".git", "gitdir: /host/real/.git\n");
		tree_file(".ko-agent-sandbox", "rule\n");
		tree_file("ordinary", "data\n");
		tree_file("ordinary2", "data\n");
		tree_dirs("sub");
		printf("made tree=%s\n", tree);
		tree = main_tree;
	}
	return 0;
}

// ---------------------------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------------------------

enum action {
	A_WRITE,              // open for writing
	A_APPEND,
	A_TRUNC,              // open O_RDONLY|O_TRUNC
	A_CREAT,              // open O_CREAT|O_EXCL
	A_CREAT_NOEXCL,       // open O_CREAT without O_EXCL: reopens an existing entry
	A_UNLINK,
	A_RMDIR,
	A_RENAME,
	A_EXCHANGE,           // renameat2 RENAME_EXCHANGE a with b
	A_MKDIR,
	A_MKFIFO,
	A_BIND,               // a socket bound at a
	A_CHMOD,
	A_CHOWN,              // to the caller's own ids
	A_UTIMES,
	A_TRUNCATE,           // truncate(2)
	A_SYMLINK,            // a symlink at a with target b
	A_LINK,               // a hard link of a at b
};

enum expect {
	E_ALLOW,
	E_DENY,               // EPERM
	E_FAIL,               // any error: the operation cannot succeed, the share's answer decides which
	E_ALLOW_POSIX,        // allowed; skipped on a 9p share, whose host cannot hold the name
};

struct corpus_case {
	const char *group;
	const char *label;
	enum action action;
	const char *a;
	const char *b;
	enum expect expect;
};

// Each case names the filter test it transcribes where one exists (`fuse/ko-agent-fs/tests`,
// `doc/git-metadata.md`, "Test list"). A FIFO case gets the share's own answer (virtiofs
// EACCES, 9p EOPNOTSUPP) where it is allowed; the `-ptr` group runs on TREE-ptr.
static const struct corpus_case corpus[] = {
	// name rule (mounted_mutate.rs, creating_a_dotgit_entry_is_refused_for_every_entry_type,
	// the_name_rule_covers_the_case_folded_and_collapsing_spellings, ordinary_dot_git_prefixed_names_are_allowed)
	{"name", "creat-dotgit", A_CREAT, "apps/.git", NULL, E_DENY},
	{"name", "creat-dotgit-upper", A_CREAT, "apps/.GIT", NULL, E_DENY},
	{"name", "creat-dotgit-mixed", A_CREAT, "apps/.Git", NULL, E_DENY},
	{"name", "creat-dotgit-trailing-dot", A_CREAT, "apps/.git.", NULL, E_DENY},
	{"name", "creat-dotgit-trailing-space", A_CREAT, "apps/.git ", NULL, E_DENY},
	{"name", "creat-dotgit-ignorable", A_CREAT, "apps/.g\xe2\x80\x8bit", NULL, E_DENY},
	{"name", "creat-dotgit-folded-letter", A_CREAT, "apps/.g\xc4\xb1t", NULL, E_DENY},
	{"name", "mkfifo-dotgit", A_MKFIFO, "apps/.git", NULL, E_DENY},
	{"name", "symlink-dotgit", A_SYMLINK, "apps/.git", "README.md", E_DENY},
	{"name", "link-dotgit", A_LINK, "README.md", "apps/.git", E_DENY},
	{"name", "rename-onto-dotgit", A_RENAME, "README3.md", "apps/.git", E_DENY},
	{"name", "exchange-onto-dotgit", A_EXCHANGE, "README3.md", "sub2/.git", E_DENY},
	{"name", "mkdir-dotgit", A_MKDIR, "apps/.git", NULL, E_ALLOW},
	{"name", "creat-dotgit-newline", A_CREAT, "apps/.git\n", NULL, E_ALLOW_POSIX},
	{"name", "creat-dotgitignore", A_CREAT, "apps/.gitignore", NULL, E_ALLOW},
	{"name", "creat-dotgithub", A_CREAT, "apps/.githubx", NULL, E_ALLOW},
	{"name", "creat-non-utf8", A_CREAT, "apps/\xff\xfe", NULL, E_ALLOW_POSIX},
	{"name", "creat-sandbox-name", A_CREAT, "apps/.ko-agent-sandbox", NULL, E_DENY},
	{"name", "creat-sandbox-folded", A_CREAT, "apps/.KO-AGENT-SANDBOX", NULL, E_DENY},
	{"name", "mkdir-sandbox-name", A_MKDIR, "apps/.ko-agent-sandbox", NULL, E_ALLOW},
	// the launcher's directory (the_launcher_configuration_directory_cannot_be_created_or_written)
	{"sandbox", "creat-in-sandbox-config", A_CREAT, ".ko-agent-sandbox/file/x", NULL, E_DENY},
	{"sandbox", "write-sandbox-rule", A_WRITE, ".ko-agent-sandbox/file/rule", NULL, E_DENY},
	{"sandbox", "unlink-sandbox-rule", A_UNLINK, ".ko-agent-sandbox/file/rule", NULL, E_DENY},
	{"sandbox", "rename-sandbox-dir", A_RENAME, ".ko-agent-sandbox", "saved-sandbox", E_DENY},
	{"sandbox", "mkdir-in-sandbox-config", A_MKDIR, ".ko-agent-sandbox/newdir", NULL, E_ALLOW},
	{"sandbox", "creat-sandbox-in-git-state", A_CREAT, ".git/objects/x/.ko-agent-sandbox/f", NULL, E_DENY},
	// hooks (existing_hooks_are_immutable_against_every_mutation), for the gitdir, a submodule's and a worktree's
	{"hooks", "write-hook", A_WRITE, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "append-hook", A_APPEND, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "trunc-hook", A_TRUNC, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "truncate-hook", A_TRUNCATE, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "chmod-hook", A_CHMOD, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "chown-hook", A_CHOWN, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "utimes-hook", A_UTIMES, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "unlink-hook", A_UNLINK, ".git/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "rename-hook-away", A_RENAME, ".git/hooks/pre-commit", "apps/hook", E_DENY},
	{"hooks", "rename-onto-hook", A_RENAME, "README3.md", ".git/hooks/pre-commit", E_DENY},
	{"hooks", "exchange-hook", A_EXCHANGE, "src/evil", ".git/hooks/pre-commit", E_DENY},
	{"hooks", "exchange-hook-reverse", A_EXCHANGE, ".git/hooks/pre-commit", "src/evil", E_DENY},
	{"hooks", "link-into-hooks", A_LINK, "README.md", ".git/hooks/z", E_DENY},
	{"hooks", "link-hook-out", A_LINK, ".git/hooks/pre-commit", "apps/hooklink", E_DENY},
	{"hooks", "symlink-in-hooks", A_SYMLINK, ".git/hooks/y", "../../README.md", E_DENY},
	{"hooks", "mkfifo-in-hooks", A_MKFIFO, ".git/hooks/fifo", NULL, E_DENY},
	{"hooks", "creat-hook", A_CREAT, ".git/hooks/x", NULL, E_DENY},
	{"hooks", "rmdir-hooks", A_RMDIR, ".git/hooks", NULL, E_FAIL},
	{"hooks", "rename-hooks-dir", A_RENAME, ".git/hooks", ".git/hooks2", E_DENY},
	{"hooks", "write-submodule-hook", A_WRITE, ".git/modules/sub/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "creat-submodule-hook", A_CREAT, ".git/modules/sub/hooks/x", NULL, E_DENY},
	{"hooks", "unlink-submodule-hook", A_UNLINK, ".git/modules/sub/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "write-worktree-hook", A_WRITE, ".git/worktrees/feature/hooks/pre-commit", NULL, E_DENY},
	{"hooks", "creat-worktree-hook", A_CREAT, ".git/worktrees/feature/hooks/x", NULL, E_DENY},
	{"hooks", "write-nested-repo-hook", A_WRITE, "nested/.git/hooks/pre-commit", NULL, E_DENY},
	// a `hooks` that is itself a symlink (a_symlinked_hooks_entry_cannot_be_re_aimed)
	{"hooks", "unlink-hooks-symlink", A_UNLINK, "linked/.git/hooks", NULL, E_DENY},
	{"hooks", "rename-hooks-symlink", A_RENAME, "linked/.git/hooks", "linked/.git/hooks-old", E_DENY},
	{"hooks", "write-through-hooks-symlink", A_WRITE, "linked/.git/hooks/pre-commit", NULL, E_DENY},
	// config and redirections (config_and_redirections_are_immutable)
	{"config", "write-config", A_WRITE, ".git/config", NULL, E_DENY},
	{"config", "append-config", A_APPEND, ".git/config", NULL, E_DENY},
	{"config", "write-config-worktree", A_WRITE, ".git/config.worktree", NULL, E_DENY},
	{"config", "write-commondir", A_WRITE, ".git/worktrees/feature/commondir", NULL, E_DENY},
	{"config", "creat-config-lock", A_CREAT, ".git/config.lock", NULL, E_DENY},
	{"config", "rename-onto-config", A_RENAME, "README3.md", ".git/config", E_DENY},
	{"config", "link-from-config", A_LINK, ".git/config", "apps/cfglink", E_DENY},
	{"config", "write-worktree-gitdir-file", A_WRITE, ".git/worktrees/feature/gitdir", NULL, E_DENY},
	{"config", "creat-worktree-gitdir-file", A_CREAT, ".git/worktrees/feature/config.worktree", NULL, E_DENY},
	{"config", "write-submodule-config", A_WRITE, ".git/modules/sub/config", NULL, E_DENY},
	{"config", "creat-nested-gitdir-protected", A_CREAT, ".git/modules/sub/config2", NULL, E_DENY},
	{"config", "write-nested-repo-config", A_WRITE, "nested/.git/config", NULL, E_DENY},
	// alternates (alternates_cannot_be_written_or_moved_into_place)
	{"alternates", "creat-alternates", A_CREAT, ".git/objects/info/alternates", NULL, E_DENY},
	{"alternates", "creat-http-alternates", A_CREAT, ".git/objects/info/http-alternates", NULL, E_DENY},
	{"alternates", "symlink-alternates", A_SYMLINK, ".git/objects/info/alternates", "../../../README.md", E_DENY},
	{"alternates", "creat-submodule-alternates", A_CREAT, ".git/modules/sub/objects/info/alternates", NULL, E_DENY},
	{"alternates", "rename-objects", A_RENAME, ".git/objects", ".git/objects2", E_DENY},
	{"alternates", "rename-objects-info", A_RENAME, ".git/objects/info", ".git/objects/info2", E_DENY},
	{"alternates", "rename-dir-onto-objects-info", A_RENAME, "filled", ".git/objects/info", E_DENY},
	{"alternates", "exchange-objects-info", A_EXCHANGE, "filled", ".git/objects/info", E_DENY},
	{"alternates", "creat-commit-graph", A_CREAT, ".git/objects/info/commit-graph", NULL, E_ALLOW},
	{"alternates", "write-objects-info-packs", A_WRITE, ".git/objects/info/packs", NULL, E_ALLOW},
	// operational state (operational_git_state_stays_writable, rebase_and_sequencer_todo_state_is_immutable)
	{"operational", "write-head", A_WRITE, ".git/HEAD", NULL, E_ALLOW},
	{"operational", "rename-lock-onto-head", A_RENAME, ".git/HEAD.lock", ".git/HEAD", E_ALLOW},
	{"operational", "write-orig-head", A_WRITE, ".git/ORIG_HEAD", NULL, E_ALLOW},
	{"operational", "creat-ref", A_CREAT, ".git/refs/heads/x", NULL, E_ALLOW},
	{"operational", "creat-ref-lock", A_CREAT, ".git/refs/heads/x.lock", NULL, E_ALLOW},
	{"operational", "rename-ref", A_RENAME, ".git/refs/heads/other", ".git/refs/heads/renamed", E_ALLOW},
	{"operational", "unlink-ref", A_UNLINK, ".git/refs/heads/renamed", NULL, E_ALLOW},
	{"operational", "creat-log", A_CREAT, ".git/logs/refs/heads/x", NULL, E_ALLOW},
	{"operational", "write-packed-refs", A_WRITE, ".git/packed-refs", NULL, E_ALLOW},
	{"operational", "creat-packed-refs-lock", A_CREAT, ".git/packed-refs.lock", NULL, E_ALLOW},
	{"operational", "creat-index-lock", A_CREAT, ".git/index.lock", NULL, E_ALLOW},
	{"operational", "write-index", A_WRITE, ".git/index", NULL, E_ALLOW},
	{"operational", "creat-pack", A_CREAT, ".git/objects/pack/p.pack", NULL, E_ALLOW},
	{"operational", "mkdir-object-dir", A_MKDIR, ".git/objects/ab", NULL, E_ALLOW},
	{"operational", "creat-object", A_CREAT, ".git/objects/ab/cdef", NULL, E_ALLOW},
	{"operational", "mkfifo-in-objects", A_MKFIFO, ".git/objects/pack/fifo", NULL, E_ALLOW},
	{"operational", "creat-commit-editmsg", A_CREAT, ".git/COMMIT_EDITMSG", NULL, E_ALLOW},
	{"operational", "creat-index-stash", A_CREAT, ".git/index.stash.1234", NULL, E_ALLOW},
	{"operational", "creat-index-stash-lock", A_CREAT, ".git/index.stash.1234.lock", NULL, E_ALLOW},
	{"operational", "creat-next-index-lock", A_CREAT, ".git/next-index-1234.lock", NULL, E_ALLOW},
	{"operational", "creat-bisect-log", A_CREAT, ".git/BISECT_LOG", NULL, E_ALLOW},
	{"operational", "creat-bisect-names", A_CREAT, ".git/BISECT_NAMES", NULL, E_ALLOW},
	{"operational", "creat-filter-repo-map", A_CREAT, ".git/filter-repo/commit-map", NULL, E_ALLOW},
	{"operational", "creat-lfs-object", A_CREAT, ".git/lfs/objects/ab/cd/abcdef", NULL, E_ALLOW},
	{"operational", "creat-sharedindex", A_CREAT, ".git/sharedindex.0123abcd", NULL, E_ALLOW},
	{"operational", "creat-rr-cache-entry", A_CREAT, ".git/rr-cache/x", NULL, E_DENY},
	{"operational", "creat-rebase-todo", A_CREAT, ".git/rebase-merge/done", NULL, E_DENY},
	{"operational", "write-rebase-todo", A_WRITE, ".git/rebase-merge/todo", NULL, E_DENY},
	{"operational", "creat-sequencer-todo", A_CREAT, ".git/sequencer/todo", NULL, E_DENY},
	{"operational", "creat-unknown-root-name", A_CREAT, ".git/notes-of-mine", NULL, E_DENY},
	{"operational", "creat-submodule-ref", A_CREAT, ".git/modules/sub/refs/heads/x", NULL, E_ALLOW},
	{"operational", "creat-worktree-head", A_CREAT, ".git/worktrees/feature/ORIG_HEAD", NULL, E_ALLOW},
	{"operational", "creat-nested-worktree-head", A_CREAT, ".git/modules/sub/worktrees/wt/HEAD", NULL, E_ALLOW},
	{"operational", "creat-in-module-namespace", A_CREAT, ".git/modules/other/y", NULL, E_DENY},
	{"operational", "write-nested-repo-head", A_WRITE, "nested/.git/HEAD", NULL, E_ALLOW},
	// the region rules of a gitdir (a_gitdir_keeps_the_listed_names_it_holds)
	{"operational", "rename-object-dir-out", A_RENAME, ".git/objects/x", "apps/x", E_DENY},
	{"operational", "symlink-into-gitdir", A_SYMLINK, "apps/objs", "../.git/objects/x", E_DENY},
	{"operational", "symlink-to-config", A_SYMLINK, "apps/cfg", "../.git/config", E_DENY},
	{"operational", "symlink-to-dotgit", A_SYMLINK, "apps/gitlink", "../.git", E_DENY},
	// the file rules (a_listed_file_cannot_be_written_created_or_replaced, ...)
	{"rules", "write-listed-file", A_WRITE, ".vscode/tasks.json", NULL, E_DENY},
	{"rules", "creat-under-read-only-line", A_CREAT, ".vscode/tasks2.json", NULL, E_DENY},
	{"rules", "unlink-listed-file", A_UNLINK, ".vscode/tasks.json", NULL, E_DENY},
	{"rules", "rename-onto-listed-file", A_RENAME, "README3.md", ".vscode/tasks.json", E_DENY},
	{"rules", "rename-listed-dir", A_RENAME, ".vscode", ".vscode-old", E_DENY},
	{"rules", "mkdir-listed-dir-name", A_MKDIR, "apps/.vscode", NULL, E_ALLOW},
	{"rules", "symlink-at-listed-name", A_SYMLINK, "apps/.idea", "../README.md", E_DENY},
	{"rules", "creat-pattern-name", A_CREAT, "apps/lefthook.yml", NULL, E_DENY},
	{"rules", "creat-pattern-name-folded", A_CREAT, "apps/LEFTHOOK.YML", NULL, E_DENY},
	{"rules", "creat-pattern-near-miss", A_CREAT, "apps/lefthookx.yml", NULL, E_ALLOW},
	{"rules", "creat-nested-listed-file", A_CREAT, ".github/copilot/mcp.json", NULL, E_ALLOW},
	{"rules", "write-nested-listed-file", A_WRITE, ".github/copilot/settings.json", NULL, E_DENY},
	// a directory a line names through (a_directory_a_line_names_through_cannot_be_swapped)
	{"rules", "rename-pinned-component", A_RENAME, ".github", "saved-github", E_DENY},
	{"rules", "exchange-pinned-component", A_EXCHANGE, ".github", "filled", E_DENY},
	{"rules", "mkdir-pinned-name", A_MKDIR, "apps/.github", NULL, E_ALLOW},
	{"rules", "creat-pinned-name", A_CREAT, "apps/.kiro", NULL, E_DENY},
	{"rules", "creat-beside-pinned", A_CREAT, ".github/notes.md", NULL, E_ALLOW},
	// the writable region (a_writable_region_keeps_the_listed_names_it_holds)
	{"rules", "creat-in-writable-region", A_CREAT, "node_modules/x/.vscode/t2.json", NULL, E_ALLOW},
	{"rules", "write-in-writable-region", A_WRITE, "node_modules/x/.vscode/tasks.json", NULL, E_ALLOW},
	{"rules", "rename-inside-region", A_RENAME, "node_modules/x/index.js", "node_modules/x/main.js", E_ALLOW},
	{"rules", "rename-dir-out-of-region", A_RENAME, "node_modules/x", "apps/x", E_DENY},
	{"rules", "rename-region-root", A_RENAME, "node_modules", "nm.bak", E_DENY},
	{"rules", "exchange-dir-out-of-region", A_EXCHANGE, "node_modules/x", "filled", E_DENY},
	{"rules", "rename-file-out-of-region", A_RENAME, "node_modules/x/main.js", "apps/main.js",
	 E_ALLOW},
	{"rules", "symlink-into-region", A_SYMLINK, "apps/x", "../node_modules/x", E_DENY},
	{"rules", "symlink-inside-region", A_SYMLINK, "node_modules/.bin/x", "../x/main.js", E_ALLOW},
	{"rules", "symlink-into-region-via-dotdot", A_SYMLINK, "src/sub/x",
	 "../../node_modules/../node_modules/x", E_DENY},
	{"rules", "symlink-out-of-region", A_SYMLINK, "node_modules/x/r", "../../README.md", E_ALLOW},
	// a writable line below a read-only directory (a_writable_line_frees_one_file_below_a_read_only_directory)
	{"rules", "write-freed-file", A_WRITE, ".vscode/settings.json", NULL, E_ALLOW},
	{"rules", "creat-beside-freed-file", A_CREAT, ".vscode/extensions.json", NULL,
	 E_DENY},
	// a relocated hook directory, an anchored `read-only-path` line (relocated_hooks_are_served_read_only)
	{"rules", "write-relocated-hook", A_WRITE, "githooks/pre-commit", NULL, E_DENY},
	{"rules", "creat-relocated-hook", A_CREAT, "githooks/new", NULL, E_DENY},
	{"rules", "rename-relocated-hooks-dir", A_RENAME, "githooks", "githooks-old", E_DENY},
	{"rules", "creat-under-same-name-elsewhere", A_CREAT, "apps/githooks/x", NULL, E_ALLOW},
	// the symlinked `.claude` (a_directory_a_symlinked_interior_reaches_keeps_the_line_s_rest)
	{"alias", "creat-listed-below-alias-end", A_CREAT, "shared/claude/settings.json", NULL, E_DENY},
	{"alias", "creat-listed-dir-below-alias-end", A_MKDIR, "shared/claude/skills", NULL, E_ALLOW},
	{"alias", "creat-in-listed-dir-below-alias-end", A_CREAT, "shared/claude/skills/x.md", NULL, E_DENY},
	{"alias", "creat-ordinary-below-alias-end", A_CREAT, "shared/claude/other.md", NULL, E_ALLOW},
	{"alias", "write-ordinary-below-alias-end", A_WRITE, "shared/claude/notes.md", NULL, E_ALLOW},
	{"alias", "rename-alias-end", A_RENAME, "shared/claude", "shared/claude-old", E_DENY},
	{"alias", "rename-alias-traversed", A_RENAME, "shared", "shared-old", E_DENY},
	{"alias", "unlink-alias-symlink", A_UNLINK, ".claude", NULL, E_DENY},
	{"alias", "creat-through-alias-symlink", A_CREAT, ".claude/settings.local.json", NULL, E_DENY},
	{"alias", "creat-ordinary-through-alias-symlink", A_CREAT, ".claude/scratch.md", NULL, E_ALLOW},
	// "Directories": the session-made `.git`
	{"directories", "creat-head-in-made-dotgit", A_CREAT, "sub/.git/HEAD", NULL, E_DENY},
	{"directories", "mkfifo-head-in-made-dotgit", A_MKFIFO, "sub/.git/HEAD", NULL, E_DENY},
	{"directories", "symlink-head-in-made-dotgit", A_SYMLINK, "sub/.git/HEAD", "../../README.md", E_DENY},
	{"directories", "link-head-in-made-dotgit", A_LINK, "README.md", "sub/.git/HEAD", E_DENY},
	{"directories", "rename-lock-onto-missing-head", A_RENAME, "sub/.git/HEAD.lock", "sub/.git/HEAD", E_DENY},
	{"directories", "mkdir-head-in-made-dotgit", A_MKDIR, "sub/.git/HEAD", NULL, E_ALLOW},
	{"directories", "exchange-lock-with-head-placeholder", A_EXCHANGE, "sub/.git/HEAD.lock", "sub/.git/HEAD",
	 E_DENY},
	{"directories", "creat-head-in-git-state-dotgit", A_CREAT, ".git/objects/x/.git/HEAD", NULL, E_DENY},
	{"directories", "creat-config-in-made-dotgit", A_CREAT, "sub/.git/config", NULL, E_DENY},
	{"directories", "creat-ref-in-made-dotgit", A_CREAT, "sub/.git/refs-file", NULL, E_DENY},
	{"directories", "exchange-filled-dir-with-made-dotgit", A_EXCHANGE, "filled", "sub2/.git", E_DENY},
	{"directories", "rename-made-dotgit-away", A_RENAME, "sub2/.git", "sub2/git-old", E_DENY},
	{"directories", "rmdir-made-dotgit-objects-nonempty", A_RMDIR, "sub2/.git/objects", NULL, E_FAIL},
	{"directories", "unlink-in-made-dotgit-objects", A_UNLINK, "sub2/.git/objects/x", NULL, E_ALLOW},
	{"directories", "rmdir-made-dotgit-objects", A_RMDIR, "sub2/.git/objects", NULL, E_ALLOW},
	{"directories", "rmdir-made-dotgit", A_RMDIR, "sub2/.git", NULL, E_ALLOW},
	{"directories", "mkdir-dotgit-under-read-only-line", A_MKDIR, ".vscode/.git", NULL, E_ALLOW},
	{"directories", "creat-below-dotgit-under-read-only-line", A_CREAT, ".vscode/.git/index.lock", NULL, E_DENY},
	{"directories", "mkdir-below-dotgit-under-read-only-line", A_MKDIR, ".vscode/.git/objects", NULL, E_ALLOW},
	// symlink syntax (a_symlink_target_with_nonportable_syntax_is_refused_and_an_ordinary_one_is_not)
	{"symlink", "symlink-absolute-outside", A_SYMLINK, "src/cached.o", "/home/nonroot/.cache/blob", E_DENY},
	{"symlink", "symlink-absolute-inside", A_SYMLINK, "src/self.rs", "/ABS/src/main.rs", E_DENY},
	{"symlink", "symlink-climbs-out", A_SYMLINK, "src/escape.rs", "../../elsewhere", E_DENY},
	{"symlink", "symlink-climbs-out-and-back", A_SYMLINK, "src/sub/passwd", "../../../etc/passwd", E_DENY},
	{"symlink", "symlink-sibling", A_SYMLINK, "src/sibling.rs", "main.rs", E_ALLOW},
	{"symlink", "symlink-up-and-across", A_SYMLINK, "src/sub/up.rs", "../main.rs", E_ALLOW},
	{"symlink", "symlink-to-root", A_SYMLINK, "src/sub/top", "../..", E_ALLOW},
	{"symlink", "symlink-dot-components", A_SYMLINK, "src/sub/dots", "./.././/main.rs", E_ALLOW},
	{"symlink", "symlink-short-name-target", A_SYMLINK, "src/pivot", "../VSCODE~1", E_DENY},
	{"symlink", "symlink-tilde-target", A_SYMLINK, "src/backup", "../tilde/notes.md~", E_ALLOW},
	{"symlink", "symlink-into-gitdir-then-out", A_SYMLINK, "src/weird", "../.git/../README.md", E_DENY},
	{"symlink", "symlink-into-sandbox-dir", A_SYMLINK, "src/sb", "../.ko-agent-sandbox/file", E_ALLOW},
	// the walk's bound and the deep chain
	{"walk", "creat-beyond-walk-bound", A_CREAT, "deep/DEEP70/f", NULL, E_DENY},
	{"walk", "creat-at-depth-60", A_CREAT, "deep/DEEP58/f", NULL, E_ALLOW},
	// The recorded `.git` met at the walk's last level, the workspace root one beyond the bound:
	// the mark must not stand in for the root. The chain below `.git` is 63 components: `f`,
	// 60 directories, `deep` and `objects`.
	{"walk", "creat-beyond-walk-bound-in-gitdir", A_CREAT, ".git/objects/deep/DEEP60/f", NULL, E_DENY},
	{"walk", "creat-in-gitdir-at-depth-60", A_CREAT, ".git/objects/deep/DEEP56/f", NULL, E_ALLOW},
	// sockets by default
	{"socket", "bind-socket-in-workspace", A_BIND, "apps/s", NULL, E_DENY},
	{"socket", "bind-socket-in-gitdir", A_BIND, ".git/objects/s", NULL, E_DENY},
	// a submodule worktree's pointer file, recorded as guarded, and the host's hard link to it at
	// apps/submod-pointer ("The policy", the second-name rule)
	{"nested", "write-submodule-pointer", A_WRITE, "submod/.git", NULL, E_DENY},
	{"nested", "write-through-submodule-pointer-link", A_WRITE, "apps/submod-pointer", NULL, E_DENY},
	{"nested", "unlink-submodule-pointer-link", A_UNLINK, "apps/submod-pointer", NULL, E_DENY},
	{"nested", "rename-onto-submodule-pointer-link", A_RENAME, "submod/file", "apps/submod-pointer", E_DENY},
	{"nested", "creat-beside-submodule-pointer", A_CREAT, "submod/other", NULL, E_ALLOW},
	// ordinary work (ordinary_workspace_work_is_unaffected)
	{"ordinary", "write-readme", A_WRITE, "README.md", NULL, E_ALLOW},
	{"ordinary", "creat-source", A_CREAT, "src/new.rs", NULL, E_ALLOW},
	{"ordinary", "mkdir-source-dir", A_MKDIR, "src/pkg", NULL, E_ALLOW},
	{"ordinary", "rename-source", A_RENAME, "src/new.rs", "src/pkg/new.rs", E_ALLOW},
	{"ordinary", "chmod-source", A_CHMOD, "src/pkg/new.rs", NULL, E_ALLOW},
	{"ordinary", "unlink-source", A_UNLINK, "src/pkg/new.rs", NULL, E_ALLOW},
	{"ordinary", "rmdir-source-dir", A_RMDIR, "src/pkg", NULL, E_ALLOW},
	{"ordinary", "unlink-readme2", A_UNLINK, "README2.md", NULL, E_ALLOW},
	{"ordinary", "mkfifo-ordinary", A_MKFIFO, "apps/fifo", NULL, E_ALLOW},
	{"ordinary", "link-ordinary", A_LINK, "README.md", "apps/readme-link", E_ALLOW},
	{"ordinary", "exchange-ordinary", A_EXCHANGE, "README.md", "ordinary", E_ALLOW},
	// the NTFS short-name form, under the flag (the `short` group runs with it set)
	{"short", "creat-under-short-name-dir", A_CREAT, "VSCODE~1/x", NULL, E_DENY},
	{"short", "creat-under-short-name-with-ext", A_CREAT, "shortish/NODE_M~1.JSO/x", NULL, E_DENY},
	{"short", "creat-under-tilde-dir", A_CREAT, "tilde/notes.md~/x", NULL, E_ALLOW},
	{"short", "creat-short-name", A_CREAT, "apps/AB12CD~1", NULL, E_DENY},
	{"short", "rename-short-name-dir", A_RENAME, "VSCODE~1", "vscode-long", E_DENY},
	{"short", "creat-ordinary-under-flag", A_CREAT, "apps/plain", NULL, E_ALLOW},
	// sockets under --unix-sockets (the `unix` group runs with the flag set)
	// A 9p share refuses the bind after the hook, so the cases on the bound socket are POSIX-only.
	{"unix", "bind-socket-in-workspace-allowed", A_BIND, "apps/s2", NULL, E_ALLOW_POSIX},
	{"unix", "bind-socket-in-gitdir-refused", A_BIND, ".git/objects/s2", NULL, E_DENY},
	{"unix", "bind-socket-at-gitdir-root", A_BIND, ".git/fsmonitor--daemon.ipc", NULL, E_DENY},
	{"unix", "bind-socket-under-read-only-line", A_BIND, ".vscode/s", NULL, E_DENY},
	{"unix", "rename-socket-into-gitdir", A_RENAME, "apps/s2", ".git/objects/s3", E_DENY},
	{"unix", "link-socket-into-gitdir", A_LINK, "apps/s2", ".git/objects/s4", E_DENY},
	{"unix", "rename-socket-in-workspace", A_RENAME, "apps/s2", "apps/s5", E_ALLOW_POSIX},
	{"unix", "symlink-into-gitdir-to-socket", A_SYMLINK, ".git/objects/slink", "../../apps/s5", E_ALLOW},
	// the pointer-file workspace (an_existing_dotgit_pointer_file_is_immutable,
	// a_second_name_of_a_guarded_entry_is_guarded_like_it): the guarded objects by their names and
	// by the host-made hard links GIT~1 and KO-AGE~1
	{"ptr", "write-pointer", A_WRITE, ".git", NULL, E_DENY},
	{"ptr", "append-pointer", A_APPEND, ".git", NULL, E_DENY},
	{"ptr", "creat-over-pointer", A_CREAT_NOEXCL, ".git", NULL, E_DENY},
	{"ptr", "unlink-pointer", A_UNLINK, ".git", NULL, E_DENY},
	{"ptr", "rename-pointer-away", A_RENAME, ".git", "moved", E_DENY},
	{"ptr", "rename-onto-pointer", A_RENAME, "ordinary", ".git", E_DENY},
	{"ptr", "link-pointer-out", A_LINK, ".git", "linked", E_DENY},
	{"ptr", "chmod-pointer", A_CHMOD, ".git", NULL, E_DENY},
	{"ptr", "append-through-git-alias", A_APPEND, "GIT~1", NULL, E_DENY},
	{"ptr", "creat-over-git-alias", A_CREAT_NOEXCL, "GIT~1", NULL, E_DENY},
	{"ptr", "unlink-git-alias", A_UNLINK, "GIT~1", NULL, E_DENY},
	{"ptr", "rename-git-alias-away", A_RENAME, "GIT~1", "moved", E_DENY},
	{"ptr", "rename-onto-git-alias", A_RENAME, "ordinary", "GIT~1", E_DENY},
	{"ptr", "link-git-alias-out", A_LINK, "GIT~1", "linked", E_DENY},
	{"ptr", "chmod-git-alias", A_CHMOD, "GIT~1", NULL, E_DENY},
	{"ptr", "truncate-git-alias", A_TRUNCATE, "GIT~1", NULL, E_DENY},
	{"ptr", "write-sandbox-file", A_WRITE, ".ko-agent-sandbox", NULL, E_DENY},
	{"ptr", "append-through-sandbox-alias", A_APPEND, "KO-AGE~1", NULL, E_DENY},
	{"ptr", "creat-over-sandbox-alias", A_CREAT_NOEXCL, "KO-AGE~1", NULL, E_DENY},
	{"ptr", "unlink-sandbox-alias", A_UNLINK, "KO-AGE~1", NULL, E_DENY},
	{"ptr", "rename-sandbox-alias-away", A_RENAME, "KO-AGE~1", "moved", E_DENY},
	{"ptr", "rename-onto-sandbox-alias", A_RENAME, "ordinary", "KO-AGE~1", E_DENY},
	{"ptr", "link-sandbox-alias-out", A_LINK, "KO-AGE~1", "linked", E_DENY},
	{"ptr", "write-ordinary-neighbour", A_WRITE, "ordinary", NULL, E_ALLOW},
	{"ptr", "creat-ordinary-neighbour", A_CREAT, "sub/x", NULL, E_ALLOW},
	{"ptr", "rename-ordinary-neighbour", A_RENAME, "ordinary2", "ordinary3", E_ALLOW},
};
#define CORPUS (sizeof(corpus) / sizeof(corpus[0]))

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

static int exchange(const char *a, const char *b)
{
	return syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE);
}

// The symlink corpus spells an absolute target inside the tree as `/ABS/...`.
static const char *symlink_target(const char *target)
{
	static char path[8192];

	if (strncmp(target, "/ABS/", 5))
		return target;
	snprintf(path, sizeof(path), "%s/%s", tree, target + 5);
	return path;
}

static int run_action(enum action action, const char *a, const char *b)
{
	int rc = -1, fd;

	switch (action) {
	case A_WRITE:
		fd = open(tree_path(a), O_WRONLY);
		rc = fd;
		if (fd >= 0)
			close(fd);
		break;
	case A_APPEND:
		fd = open(tree_path(a), O_WRONLY | O_APPEND);
		rc = fd;
		if (fd >= 0)
			close(fd);
		break;
	case A_TRUNC:
		fd = open(tree_path(a), O_RDONLY | O_TRUNC);
		rc = fd;
		if (fd >= 0)
			close(fd);
		break;
	case A_CREAT:
		fd = open(tree_path(a), O_CREAT | O_WRONLY | O_EXCL, 0644);
		rc = fd;
		if (fd >= 0)
			close(fd);
		break;
	case A_CREAT_NOEXCL:
		fd = open(tree_path(a), O_CREAT | O_WRONLY, 0644);
		rc = fd;
		if (fd >= 0)
			close(fd);
		break;
	case A_UNLINK:
		rc = unlink(tree_path(a));
		break;
	case A_RMDIR:
		rc = rmdir(tree_path(a));
		break;
	case A_RENAME:
		rc = rename(tree_path(a), tree_path(b));
		break;
	case A_EXCHANGE:
		rc = exchange(tree_path(a), tree_path(b));
		break;
	case A_MKDIR:
		rc = mkdir(tree_path(a), 0755);
		break;
	case A_MKFIFO:
		rc = mknod(tree_path(a), S_IFIFO | 0644, 0);
		break;
	case A_BIND:
		rc = bind_at(tree_path(a));
		if (rc >= 0)
			close(rc);
		break;
	case A_CHMOD:
		rc = chmod(tree_path(a), 0644);
		break;
	case A_CHOWN:
		rc = chown(tree_path(a), getuid(), getgid());
		break;
	case A_UTIMES: {
		struct timespec times[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};

		rc = utimensat(AT_FDCWD, tree_path(a), times, 0);
		break;
	}
	case A_TRUNCATE:
		rc = truncate(tree_path(a), 0);
		break;
	case A_SYMLINK:
		rc = symlink(symlink_target(b), tree_path(a));
		break;
	case A_LINK:
		rc = link(tree_path(a), tree_path(b));
		break;
	}
	return rc;
}

// Each case's answer against its expectation: `allow` and `deny` (EPERM) must match; `fail` takes
// any error. What the share answers instead of the hook is counted apart whatever the
// expectation: a FIFO's EACCES on virtiofs or EOPNOTSUPP on 9p, before any hook ("Phase 2 on
// macOS", FIFO), and, after the hook has allowed, a socket's EOPNOTSUPP and an exchange's EINVAL
// on 9p ("Phase 2 on WSL", share). A POSIX-only case is skipped on 9p, and a refused case whose
// operand a skipped case left missing with it. The `ptr` group runs on TREE-ptr.
static int cmd_corpus(const char *group)
{
	static char ptr[8192];
	const char *main_tree = tree;
	int mismatches = 0, unsupported = 0, run = 0, skipped = 0;

	snprintf(ptr, sizeof(ptr), "%s-ptr", main_tree);
	on_9p = is_9p(main_tree);
	for (size_t i = 0; i < CORPUS; i++) {
		const struct corpus_case *item = &corpus[i];
		int rc, err, allowed, decided, unsupported_here, match, expect_allow;
		const char *got, *verdict;

		if (group && strcmp(group, item->group))
			continue;
		if (!group && (!strcmp(item->group, "short") || !strcmp(item->group, "unix")))
			continue;
		if (on_9p && (item->expect == E_ALLOW_POSIX ||
			      (!strcmp(item->group, "unix") && item->action != A_BIND && item->action != A_SYMLINK))) {
			printf("case=%s/%s SKIPPED on 9p\n", item->group, item->label);
			skipped++;
			continue;
		}
		tree = !strcmp(item->group, "ptr") ? ptr : main_tree;
		expect_allow = item->expect == E_ALLOW || item->expect == E_ALLOW_POSIX;
		rc = run_action(item->action, item->a, item->b);
		err = errno;
		allowed = rc >= 0;
		decided = allowed || err == EPERM;
		unsupported_here = !allowed && err != EPERM &&
				   ((item->action == A_MKFIFO && (err == EACCES || err == EOPNOTSUPP)) ||
				    (on_9p && item->action == A_BIND && err == EOPNOTSUPP) ||
				    (on_9p && item->action == A_EXCHANGE && err == EINVAL));
		got = allowed ? "allow" : err == EPERM ? "deny" : "error";
		match = item->expect == E_FAIL ? !allowed : decided && allowed == expect_allow;
		verdict = match ? "MATCH" : unsupported_here ? "UNSUPPORTED" : "MISMATCH";
		errno = err;
		printf("case=%s/%s expect=%s got=%s%s%s %s\n", item->group, item->label,
		       expect_allow ? "allow" : item->expect == E_DENY ? "deny" : "fail", got,
		       allowed ? "" : ":", allowed ? "" : result(-1), verdict);
		run++;
		if (unsupported_here)
			unsupported++;
		else if (!match)
			mismatches++;
	}
	tree = main_tree;
	printf("corpus group=%s cases=%d mismatches=%d unsupported=%d skipped=%d\n", group ? group : "default", run,
	       mismatches, unsupported, skipped);
	return mismatches ? 1 : 0;
}

// Whether a path exists, without following a final symlink.
static int present(const char *path)
{
	struct stat st;

	return lstat(path, &st) == 0;
}

static int parent_present(const char *rel)
{
	char parent[8192];
	char *slash;

	snprintf(parent, sizeof(parent), "%s", tree_path(rel));
	slash = strrchr(parent, '/');
	if (slash)
		*slash = 0;
	return present(parent);
}

// The fixture against the corpus, without the policy: an allowed case runs and must succeed, and
// a refused case's operands must exist, the object for a mutation of an existing entry and the
// parent for a new name, so that under the policy its answer is the program's and not ENOENT.
static int cmd_check(void)
{
	static char ptr[8192];
	const char *main_tree = tree;
	int gaps = 0;

	snprintf(ptr, sizeof(ptr), "%s-ptr", main_tree);
	on_9p = is_9p(main_tree);
	for (size_t i = 0; i < CORPUS; i++) {
		const struct corpus_case *item = &corpus[i];
		int ok = 1, rc;

		tree = !strcmp(item->group, "ptr") ? ptr : main_tree;
		if (on_9p && (item->expect == E_ALLOW_POSIX ||
			      (!strcmp(item->group, "unix") && item->action != A_BIND && item->action != A_SYMLINK)))
			continue;
		if (item->expect == E_ALLOW || item->expect == E_ALLOW_POSIX) {
			rc = run_action(item->action, item->a, item->b);
			ok = rc >= 0 || (item->action == A_MKFIFO && (errno == EACCES || errno == EOPNOTSUPP)) ||
			     (on_9p && ((item->action == A_BIND && errno == EOPNOTSUPP) ||
					(item->action == A_EXCHANGE && errno == EINVAL)));
			if (rc >= 0 && item->action == A_BIND)
				close(rc);
			if (!ok)
				printf("check case=%s/%s allowed-case-failed=%s\n", item->group, item->label,
				       result(-1));
		} else {
			switch (item->action) {
			case A_CREAT: case A_CREAT_NOEXCL: case A_MKDIR: case A_MKFIFO: case A_BIND: case A_SYMLINK:
				ok = parent_present(item->a);
				break;
			case A_LINK:
				ok = present(tree_path(item->a)) && parent_present(item->b);
				break;
			case A_RENAME:
				ok = present(tree_path(item->a)) && parent_present(item->b);
				break;
			case A_EXCHANGE:
				ok = present(tree_path(item->a)) && present(tree_path(item->b));
				break;
			default:
				ok = present(tree_path(item->a));
			}
			if (!ok)
				printf("check case=%s/%s operand-missing\n", item->group, item->label);
		}
		if (!ok)
			gaps++;
	}
	tree = main_tree;
	printf("check cases=%zu gaps=%d\n", CORPUS, gaps);
	return gaps ? 1 : 0;
}

static int cmd_groups(void)
{
	const char *last = "";

	for (size_t i = 0; i < CORPUS; i++)
		if (strcmp(corpus[i].group, last)) {
			printf("%s\n", corpus[i].group);
			last = corpus[i].group;
		}
	return 0;
}

// ---------------------------------------------------------------------------------------------
// The torn-name race ("What is gained and what is lost")
// ---------------------------------------------------------------------------------------------

// Two ancestors move independently: one renamer moves `node_modAAAA` to `BBBBBBBBules` and back
// under the outer directory, by rename over a parked name and by exchange with the directory of
// the other name, while the other moves the outer directory `outerAAAA` to `BBBBouter` and back,
// by rename and by exchange. A writer opens `.vscode/tasks.json` for writing and creates beside
// it, by path under every combination of the names, and through directory descriptors of both
// `.vscode` directories held from the start, which follow the directories wherever they move.
// Every real position protects `.vscode`; only a torn name, `node_modules` out of either pair, or
// a chain composed of two moments would lift it. Every write must be refused: EPERM, or ENOENT
// when the name is away. Printed: the counts, and `succeeded`, which must be 0. On a 9p share no
// descriptor is held, since a directory with an open handle below it cannot be moved there, and
// each renamer prints the first error it met, so a share that refuses a move shows which.
static int race_write(const char *path, int create, long *writes, long *refused, long *absent, long *succeeded,
		      long *other)
{
	int fd = open(path, create ? O_CREAT | O_WRONLY | O_EXCL : O_WRONLY, 0644);

	(*writes)++;
	if (fd >= 0) {
		(*succeeded)++;
		close(fd);
		if (create)
			unlink(path);
		return 1;
	}
	if (errno == EPERM)
		(*refused)++;
	else if (errno == ENOENT || errno == ESTALE)
		(*absent)++;
	else
		(*other)++;
	return 0;
}

static int race_write_at(int dirfd, const char *name, int create, long *writes, long *refused, long *absent,
			 long *succeeded, long *other)
{
	int fd = openat(dirfd, name, create ? O_CREAT | O_WRONLY | O_EXCL : O_WRONLY, 0644);

	(*writes)++;
	if (fd >= 0) {
		(*succeeded)++;
		close(fd);
		if (create)
			unlinkat(dirfd, name, 0);
		return 1;
	}
	if (errno == EPERM)
		(*refused)++;
	else if (errno == ENOENT || errno == ESTALE)
		(*absent)++;
	else
		(*other)++;
	return 0;
}

static int cmd_race(int seconds)
{
	static const char *const outers[2] = {"outerAAAA", "BBBBouter"};
	static const char *const inners[2] = {"node_modAAAA", "BBBBBBBBules"};
	long deadline = ns_now() + seconds * 1000000000L;
	long writes = 0, refused = 0, absent = 0, succeeded = 0, other = 0;
	pid_t renamers[2];
	int held[2] = {-1, -1}, status;

	on_9p = is_9p(tree);
	for (int k = 0; k < 2 && !on_9p; k++) {
		char dir[8192];

		snprintf(dir, sizeof(dir), "%s/race/outerAAAA/%s/.vscode", tree, inners[k]);
		held[k] = open(dir, O_RDONLY | O_DIRECTORY);
		if (held[k] < 0)
			die("open %s: %s", dir, strerror(errno));
	}
	printf("race held_descriptors=%s\n", on_9p ? "no (9p)" : "yes");
	for (int which = 0; which < 2; which++) {
		renamers[which] = fork();
		if (renamers[which] < 0)
			die("fork: %s", strerror(errno));
		if (renamers[which] == 0) {
			long count = 0, first_error = 0, exchanges = 0;

			while (ns_now() < deadline) {
				char a[8192], b[8192], parked[8192];

				if (which == 0) {
					// The inner pair, under whichever outer name holds them now.
					for (int o = 0; o < 2; o++) {
						snprintf(a, sizeof(a), "%s/race/%s/%s", tree, outers[o], inners[0]);
						snprintf(b, sizeof(b), "%s/race/%s/%s", tree, outers[o], inners[1]);
						snprintf(parked, sizeof(parked), "%s/race/%s/parked", tree, outers[o]);
						if (!rename(a, parked))
							count++;
						else if (!first_error && errno != ENOENT)
							first_error = errno;
						if (!rename(parked, a))
							count++;
						if (!exchange(a, b))
							exchanges++;
						if (!exchange(a, b))
							exchanges++;
					}
				} else {
					// The outer directory, by rename over its empty placeholder and back,
					// and by exchange where the share has it.
					snprintf(a, sizeof(a), "%s/race/%s", tree, outers[0]);
					snprintf(b, sizeof(b), "%s/race/%s", tree, outers[1]);
					if (!rename(a, b))
						count++;
					else if (!first_error && errno != ENOENT)
						first_error = errno;
					if (!rename(b, a))
						count++;
					if (!exchange(a, b))
						exchanges++;
					if (!exchange(a, b))
						exchanges++;
				}
			}
			errno = first_error;
			printf("race renamer=%s renames=%ld exchanges=%ld first_error=%s\n",
			       which == 0 ? "inner" : "outer", count, exchanges, first_error ? result(-1) : "none");
			_exit(0);
		}
	}
	while (ns_now() < deadline) {
		for (int o = 0; o < 2; o++)
			for (int i = 0; i < 2; i++) {
				char path[8192];

				snprintf(path, sizeof(path), "%s/race/%s/%s/.vscode/tasks.json", tree, outers[o],
					 inners[i]);
				race_write(path, 0, &writes, &refused, &absent, &succeeded, &other);
				snprintf(path, sizeof(path), "%s/race/%s/%s/.vscode/new.json", tree, outers[o],
					 inners[i]);
				race_write(path, 1, &writes, &refused, &absent, &succeeded, &other);
			}
		for (int k = 0; k < 2 && held[k] >= 0; k++) {
			race_write_at(held[k], "tasks.json", 0, &writes, &refused, &absent, &succeeded, &other);
			race_write_at(held[k], "new.json", 1, &writes, &refused, &absent, &succeeded, &other);
		}
	}
	for (int which = 0; which < 2; which++)
		waitpid(renamers[which], &status, 0);
	printf("race writes=%ld refused=%ld absent=%ld other=%ld succeeded=%ld\n", writes, refused, absent, other,
	       succeeded);
	return succeeded ? 1 : 0;
}

// ---------------------------------------------------------------------------------------------
// The concurrency storm
// ---------------------------------------------------------------------------------------------

// Each process loops over operations whose answer is fixed: permitted ones in its own directory
// under `storm/`, refused ones on the guarded names. Printed per process: the decisions and the
// wrong ones, which must be 0.
static int storm_process(int id, long deadline)
{
	char own[8192], f1[8192], f2[8192], d1[8192], l1[8192], s1[8192];
	char deny1[8192], deny2[8192], deny3[8192], deny4[8192], deny5[8192];
	long decisions = 0, wrong = 0;

	snprintf(own, sizeof(own), "%s/storm/p%d", tree, id);
	if (mkdir(own, 0755) && errno != EEXIST)
		die("mkdir %s: %s", own, strerror(errno));
	snprintf(f1, sizeof(f1), "%s/f1", own);
	snprintf(f2, sizeof(f2), "%s/f2", own);
	snprintf(d1, sizeof(d1), "%s/d1", own);
	snprintf(l1, sizeof(l1), "%s/l1", own);
	snprintf(s1, sizeof(s1), "%s/s1", own);
	snprintf(deny1, sizeof(deny1), "%s/.git/hooks/storm%d", tree, id);
	snprintf(deny2, sizeof(deny2), "%s/.vscode/storm%d.json", tree, id);
	snprintf(deny3, sizeof(deny3), "%s/storm/p%d/.git", tree, id);
	snprintf(deny4, sizeof(deny4), "%s/.git/config", tree);
	snprintf(deny5, sizeof(deny5), "%s/.git/hooks/pre-commit", tree);
	while (ns_now() < deadline) {
		int fd;

		// Permitted, each must succeed.
		fd = open(f1, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		decisions++;
		if (fd < 0)
			wrong++;
		else
			close(fd);
		decisions++;
		if (rename(f1, f2))
			wrong++;
		decisions++;
		if (link(f2, l1))
			wrong++;
		decisions++;
		if (symlink("f2", s1))
			wrong++;
		decisions++;
		if (mkdir(d1, 0755))
			wrong++;
		decisions++;
		if (chmod(f2, 0600))
			wrong++;
		decisions++;
		if (unlink(l1) || unlink(s1) || unlink(f2) || rmdir(d1))
			wrong++;
		// Refused, each must answer EPERM.
		decisions++;
		if (open(deny1, O_CREAT | O_WRONLY, 0644) >= 0 || errno != EPERM)
			wrong++;
		decisions++;
		if (open(deny2, O_CREAT | O_WRONLY, 0644) >= 0 || errno != EPERM)
			wrong++;
		decisions++;
		if (open(deny3, O_CREAT | O_WRONLY, 0644) >= 0 || errno != EPERM)
			wrong++;
		decisions++;
		if (open(deny4, O_WRONLY) >= 0 || errno != EPERM)
			wrong++;
		decisions++;
		if (link(deny5, f1) == 0 || errno != EPERM)
			wrong++;
		decisions++;
		if (symlink("x", deny1) == 0 || errno != EPERM)
			wrong++;
		decisions++;
		if (rename(deny5, f1) == 0 || errno != EPERM)
			wrong++;
	}
	printf("storm process=%d decisions=%ld wrong=%ld\n", id, decisions, wrong);
	return wrong ? 1 : 0;
}

static int cmd_storm(int procs, int seconds)
{
	long deadline = ns_now() + seconds * 1000000000L;
	int failed = 0;

	for (int i = 0; i < procs; i++) {
		pid_t pid = fork();

		if (pid < 0)
			die("fork: %s", strerror(errno));
		if (pid == 0)
			_exit(storm_process(i, deadline));
	}
	for (int i = 0; i < procs; i++) {
		int status;

		if (wait(&status) < 0)
			die("wait: %s", strerror(errno));
		if (!WIFEXITED(status) || WEXITSTATUS(status))
			failed++;
	}
	printf("storm processes=%d failed=%d\n", procs, failed);
	return failed ? 1 : 0;
}

// ---------------------------------------------------------------------------------------------
// Sockets and descriptors
// ---------------------------------------------------------------------------------------------

static int cmd_bind(const char *path)
{
	int sock = bind_at(path);

	printf("bind path=%s result=%s\n", path, result(sock));
	if (sock >= 0)
		close(sock);
	return sock >= 0 ? 0 : 1;
}

static void on_alarm(int signal)
{
	(void)signal;
	fprintf(stderr, "exercise: timed out\n");
	_exit(3);
}

static int connect_at(const char *path)
{
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	char dir[8192], cwd[4096];
	const char *base;
	char *slash;
	int sock, rc, saved;

	snprintf(dir, sizeof(dir), "%s", path);
	slash = strrchr(dir, '/');
	if (!slash)
		die("connect: %s has no directory", path);
	*slash = 0;
	base = slash + 1;
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
	if (!getcwd(cwd, sizeof(cwd)) || chdir(dir)) {
		saved = errno;
		close(sock);
		errno = saved;
		return -1;
	}
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", base);
	rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	saved = errno;
	if (chdir(cwd))
		die("chdir: %s", strerror(errno));
	if (rc < 0)
		close(sock);
	errno = saved;
	return rc < 0 ? -1 : sock;
}

// One message holding `count` descriptors and one byte.
static int send_fds(int sock, const int *fds, int count)
{
	struct msghdr msg = {};
	char byte = 'x';
	struct iovec iov = {.iov_base = &byte, .iov_len = 1};
	union {
		struct cmsghdr header;
		unsigned char bytes[CMSG_SPACE(sizeof(int) * 16)];
	} control = {};
	struct cmsghdr *cmsg;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &control;
	msg.msg_controllen = CMSG_SPACE(sizeof(int) * count);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * count);
	memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * count);
	return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int cmd_serve(const char *sock_path, int argc, char **argv)
{
	int fds[16], count = 0, sock, peer, pair[2], pipe_fds[2], then_exit = 0;
	char byte;

	signal(SIGALRM, on_alarm);
	alarm(60);
	for (int i = 0; i < argc && count < 16; i++) {
		const char *spec = argv[i];
		int fd = -1;

		if (!strcmp(spec, "then-exit")) {
			then_exit = 1;
			continue;
		}
		if (!strncmp(spec, "ro:", 3))
			fd = open(spec + 3, O_RDONLY);
		else if (!strncmp(spec, "rw:", 3))
			fd = open(spec + 3, O_RDWR);
		else if (!strncmp(spec, "dir:", 4))
			fd = open(spec + 4, O_RDONLY | O_DIRECTORY);
		else if (!strcmp(spec, "pipe"))
			fd = pipe(pipe_fds) ? -1 : pipe_fds[1];
		else if (!strcmp(spec, "pair"))
			fd = socketpair(AF_UNIX, SOCK_STREAM, 0, pair) ? -1 : pair[0];
		else
			die("serve: unknown spec %s", spec);
		printf("serve spec=%s open=%s\n", spec, result(fd));
		if (fd < 0)
			return 1;
		fds[count++] = fd;
	}
	sock = bind_at(sock_path);
	if (sock < 0) {
		printf("serve bind=%s\n", result(-1));
		return 1;
	}
	if (listen(sock, 1))
		die("listen: %s", strerror(errno));
	printf("serve listening=%s\n", sock_path);
	fflush(stdout);
	peer = accept(sock, NULL, NULL);
	if (peer < 0)
		die("accept: %s", strerror(errno));
	printf("serve sent=%d result=%s\n", count, result(send_fds(peer, fds, count)));
	fflush(stdout);
	if (then_exit) {
		printf("serve exiting\n");
		return 0;
	}
	// Wait for the peer to finish with what it received, then leave.
	if (read(peer, &byte, 1) < 0)
		die("read: %s", strerror(errno));
	close(peer);
	close(sock);
	unlink(sock_path);
	return 0;
}

static int cmd_receive(const char *sock_path, int argc, char **argv)
{
	int sock, received[16], count = 0;
	struct msghdr msg = {};
	char byte;
	struct iovec iov = {.iov_base = &byte, .iov_len = 1};
	union {
		struct cmsghdr header;
		unsigned char bytes[CMSG_SPACE(sizeof(int) * 16)];
	} control = {};
	struct cmsghdr *cmsg;
	ssize_t got;

	signal(SIGALRM, on_alarm);
	signal(SIGPIPE, SIG_IGN);
	alarm(60);
	for (int attempt = 0; attempt < 100; attempt++) {
		sock = connect_at(sock_path);
		if (sock >= 0)
			break;
		if (errno != ENOENT && errno != ECONNREFUSED) {
			printf("receive connect=%s\n", result(-1));
			return 1;
		}
		usleep(100000);
	}
	if (sock < 0) {
		printf("receive connect=%s\n", result(-1));
		return 1;
	}
	if (argc > 0 && !strncmp(argv[0], "wait-for:", 9)) {
		const char *marker = argv[0] + 9;

		while (access(marker, F_OK))
			usleep(100000);
		printf("receive waited_for=%s\n", marker);
		argc--;
		argv++;
	}
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);
	got = recvmsg(sock, &msg, 0);
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			if (count > 16)
				count = 16;
			memcpy(received, CMSG_DATA(cmsg), sizeof(int) * count);
		}
	printf("receive recvmsg=%s received=%d ctrunc=%d\n", result(got < 0 ? -1 : 0), count,
	       (msg.msg_flags & MSG_CTRUNC) != 0);
	for (int i = 0; i < count; i++) {
		char proc[64], target[4096];
		ssize_t len;

		snprintf(proc, sizeof(proc), "/proc/self/fd/%d", received[i]);
		len = readlink(proc, target, sizeof(target) - 1);
		if (len < 0)
			len = 0;
		target[len] = 0;
		printf("receive fd=%d names=%s\n", i, target);
	}
	for (int i = 0; i < argc; i++) {
		char action[256], name[256];
		int index = -1, rc = -1, fd;

		snprintf(action, sizeof(action), "%s", argv[i]);
		name[0] = 0;
		if (sscanf(action, "write:%d", &index) == 1 && index < count) {
			rc = write(received[index], "x", 1);
		} else if (sscanf(action, "openat:%d:%255s", &index, name) == 2 && index < count) {
			fd = openat(received[index], name, O_CREAT | O_WRONLY, 0644);
			rc = fd;
			if (fd >= 0)
				close(fd);
		} else if (sscanf(action, "unlinkat:%d:%255s", &index, name) == 2 && index < count) {
			rc = unlinkat(received[index], name, 0);
		} else if (sscanf(action, "mkdirat:%d:%255s", &index, name) == 2 && index < count) {
			rc = mkdirat(received[index], name, 0755);
		} else if (sscanf(action, "reopen:%d", &index) == 1 && index < count) {
			char proc[64];

			snprintf(proc, sizeof(proc), "/proc/self/fd/%d", received[index]);
			fd = open(proc, O_WRONLY);
			rc = fd;
			if (fd >= 0)
				close(fd);
		} else {
			printf("receive action=%s result=not-received\n", action);
			continue;
		}
		printf("receive action=%s result=%s\n", action, result(rc));
	}
	fflush(stdout);
	// A sender that exited has no peer to tell; the write then fails and is not an error.
	if (write(sock, "d", 1) < 0 && errno != EPIPE && errno != ECONNRESET)
		die("write: %s", strerror(errno));
	close(sock);
	return 0;
}

// ---------------------------------------------------------------------------------------------
// The namespaces and mounts the seccomp profile must refuse ("Mounts")
// ---------------------------------------------------------------------------------------------

static int cmd_namespaces(void)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		int rc = unshare(CLONE_NEWUSER);

		printf("namespaces unshare_newuser=%s\n", result(rc));
		rc = unshare(CLONE_NEWNS);
		printf("namespaces unshare_newns=%s\n", result(rc));
		rc = mount("none", "/tmp", "tmpfs", 0, NULL);
		printf("namespaces mount=%s\n", result(rc));
		rc = syscall(__NR_fsopen, "tmpfs", 0);
		printf("namespaces fsopen=%s\n", result(rc));
		rc = syscall(__NR_open_tree, AT_FDCWD, "/tmp", 1);	// OPEN_TREE_CLONE
		printf("namespaces open_tree=%s\n", result(rc));
		rc = syscall(__NR_move_mount, AT_FDCWD, "/tmp", AT_FDCWD, "/tmp", 0);
		printf("namespaces move_mount=%s\n", result(rc));
		rc = syscall(__NR_fsmount, -1, 0, 0);
		printf("namespaces fsmount=%s\n", result(rc));
		rc = syscall(__NR_fspick, AT_FDCWD, "/tmp", 0);
		printf("namespaces fspick=%s\n", result(rc));
		rc = syscall(__NR_mount_setattr, AT_FDCWD, "/tmp", 0, NULL, 0);
		printf("namespaces mount_setattr=%s\n", result(rc));
		rc = umount2("/tmp", 0);
		printf("namespaces umount2=%s\n", result(rc));
		rc = syscall(SYS_pivot_root, "/tmp", "/tmp");
		printf("namespaces pivot_root=%s\n", result(rc));
		fflush(stdout);
		_exit(0);
	}
	waitpid(pid, &status, 0);
	return 0;
}

// ---------------------------------------------------------------------------------------------
// The descriptors a process holds
// ---------------------------------------------------------------------------------------------

// The descriptors of `pid` beyond 0, 1 and 2, each printed with what it names; `count` is their
// number. The runtime must leave none of its own in the container's first process.
static void list_fds(const char *pid, int *count)
{
	char dir[64];
	DIR *fds;
	struct dirent *entry;

	snprintf(dir, sizeof(dir), "/proc/%s/fd", pid);
	fds = opendir(dir);
	if (!fds) {
		printf("fds pid=%s error=%s\n", pid, result(-1));
		return;
	}
	while ((entry = readdir(fds))) {
		char link[4096], target[4096];
		ssize_t len;
		int fd = atoi(entry->d_name);

		if (entry->d_name[0] == '.' || fd <= 2 || fd == dirfd(fds))
			continue;
		snprintf(link, sizeof(link), "%s/%s", dir, entry->d_name);
		len = readlink(link, target, sizeof(target) - 1);
		target[len < 0 ? 0 : len] = 0;
		printf("fds pid=%s fd=%d names=%s\n", pid, fd, target);
		(*count)++;
	}
	closedir(fds);
}

static int cmd_fds(void)
{
	int count = 0;

	list_fds("self", &count);
	list_fds("1", &count);
	printf("fds beyond_standard=%d\n", count);
	return count ? 1 : 0;
}

// ---------------------------------------------------------------------------------------------
// The walk's cost
// ---------------------------------------------------------------------------------------------

static int cmd_walk_cost(const char *path, int count)
{
	long start, rdwr, rdonly, lstat_ns;
	struct stat st;
	int failed = 0;

	start = ns_now();
	for (int i = 0; i < count; i++) {
		int fd = open(path, O_RDWR);

		if (fd < 0)
			failed++;
		else
			close(fd);
	}
	rdwr = (ns_now() - start) / count;
	start = ns_now();
	for (int i = 0; i < count; i++) {
		int fd = open(path, O_RDONLY);

		if (fd < 0)
			failed++;
		else
			close(fd);
	}
	rdonly = (ns_now() - start) / count;
	start = ns_now();
	for (int i = 0; i < count; i++)
		if (lstat(path, &st))
			failed++;
	lstat_ns = (ns_now() - start) / count;
	printf("walk-cost path=%s n=%d open_rdwr_ns=%ld open_rdonly_ns=%ld lstat_ns=%ld failed=%d\n", path, count,
	       rdwr, rdonly, lstat_ns, failed);
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc < 2)
		die("usage: see the header of exercise.c");
	if (!strcmp(argv[1], "groups"))
		return cmd_groups();
	if (!strcmp(argv[1], "namespaces"))
		return cmd_namespaces();
	if (!strcmp(argv[1], "fds"))
		return cmd_fds();
	if (argc < 3)
		die("usage: see the header of exercise.c");
	tree = argv[2];
	if (!strcmp(argv[1], "make-tree") && argc == 3)
		return cmd_make_tree();
	if (!strcmp(argv[1], "corpus") && (argc == 3 || argc == 4))
		return cmd_corpus(argc == 4 ? argv[3] : NULL);
	if (!strcmp(argv[1], "check") && argc == 3)
		return cmd_check();
	if (!strcmp(argv[1], "race") && argc == 4)
		return cmd_race(atoi(argv[3]));
	if (!strcmp(argv[1], "storm") && argc == 5)
		return cmd_storm(atoi(argv[3]), atoi(argv[4]));
	if (!strcmp(argv[1], "bind") && argc == 3)
		return cmd_bind(argv[2]);
	if (!strcmp(argv[1], "serve") && argc >= 3)
		return cmd_serve(argv[2], argc - 3, argv + 3);
	if (!strcmp(argv[1], "receive") && argc >= 3)
		return cmd_receive(argv[2], argc - 3, argv + 3);
	if (!strcmp(argv[1], "walk-cost") && argc == 4)
		return cmd_walk_cost(argv[2], atoi(argv[3]));
	die("usage: see the header of exercise.c");
}
