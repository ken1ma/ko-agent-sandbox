//! The policy's static corpus, shared by the tests that run it through `policy.rs`
//! (`file_rules.rs`, `git_corpus.rs`) and through the BPF backend's classifier
//! (`bpf_equivalence.rs`): the file rules' conformance table (`data/file-rules.conformance`) and
//! what real git writes, recorded from `probe/observe-git.sh` (`doc/git-metadata.md`,
//! "Premises"); needs no git at test time.

#![allow(dead_code)] // each test binary uses a subset of the corpus

use ko_agent_fs::policy::{RuleLine, RuleWord, fold};

pub struct Case {
    pub name: String,
    pub lines: Vec<(String, String)>,
    pub rows: Vec<Row>,
}

pub struct Row {
    pub folded: bool,
    pub path: String,
    pub expected: String,
}

/// The conformance table's cases, a resolved line list and the rows with their answers.
pub fn conformance_cases() -> Vec<Case> {
    let text = include_str!("../data/file-rules.conformance");
    let mut cases: Vec<Case> = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            [""] => {}
            [comment, ..] if comment.starts_with('#') => {}
            ["case", name @ ..] => cases.push(Case {
                name: name.join(" "),
                lines: Vec::new(),
                rows: Vec::new(),
            }),
            ["line", word, name] => cases
                .last_mut()
                .expect("a line before its case")
                .lines
                .push((word.to_string(), name.to_string())),
            [kind @ ("path" | "folded"), path, expected] => cases
                .last_mut()
                .expect("a row before its case")
                .rows
                .push(Row {
                    folded: *kind == "folded",
                    path: path.to_string(),
                    expected: expected.to_string(),
                }),
            _ => panic!("not a conformance line: {line:?}"),
        }
    }
    assert!(cases.len() >= 10, "the table did not parse into its cases");
    cases
}

/// A resolved line as the launcher and the guard write it, `word` one of the table's four.
pub fn rule_line(word: &str, name: &str) -> RuleLine {
    let (word, anchored) = match word {
        "read-only" => (RuleWord::ReadOnly, false),
        "writable" => (RuleWord::Writable, false),
        "read-only-path" => (RuleWord::ReadOnly, true),
        "pinned-path" => (RuleWord::Pinned, true),
        other => panic!("not a resolved word: {other}"),
    };
    RuleLine {
        word,
        components: name
            .split('/')
            .map(|component| {
                if anchored {
                    fold(component.as_bytes())
                } else {
                    component.as_bytes().to_vec()
                }
            })
            .collect(),
        anchored,
    }
}

/// Where the git corpus's submodule gitdirs are (`policy::GitContext::ModuleNamespace`). Linked
/// worktrees need no entry — always one component (`doc/git-metadata.md`, P1).
pub const GITDIR_ROOTS: &[&[u8]] = &[b".git/modules/sub", b".git/modules/libs/foo"];

/// Operational state git writes during normal operations, which stays writable.
pub const OPERATIONAL: &[&str] = &[
    // Refs and their reflogs, the scratch messages, the ref-store files.
    ".git/HEAD",
    ".git/ORIG_HEAD",
    ".git/FETCH_HEAD",
    ".git/MERGE_HEAD",
    ".git/index",
    ".git/packed-refs",
    // A lock inherits its target's class; `policy::classify_within_gitdir` has why that is a
    // rule rather than an enumeration.
    ".git/index.lock",
    ".git/HEAD.lock",
    ".git/AUTO_MERGE.lock",
    ".git/REBASE_HEAD.lock",
    ".git/packed-refs.lock",
    ".git/AUTO_MERGE",
    ".git/REBASE_HEAD",
    ".git/COMMIT_EDITMSG",
    ".git/MERGE_MSG",
    ".git/refs/heads/main",
    ".git/refs/tags/v1",
    ".git/refs/remotes/donor/main",
    ".git/logs/HEAD",
    ".git/logs/refs/heads/main",
    ".git/objects/pack/pack-0123.pack",
    ".git/objects/ab/cdef0123456789",
    ".git/objects/info/packs", // git gc, through update-server-info
    ".git/objects/info/commit-graph",
    ".git/objects/info/commit-graphs/commit-graph-chain",
    ".git/info/exclude",
    // The bisect state, data to git 2.34 and later (`policy::classify_within_gitdir`).
    ".git/BISECT_START",
    ".git/BISECT_LOG",
    ".git/BISECT_NAMES",
    ".git/BISECT_TERMS",
    ".git/BISECT_EXPECTED_REV",
    ".git/BISECT_ANCESTORS_OK",
    ".git/BISECT_FIRST_PARENT",
    ".git/BISECT_RUN",
    // A submodule's own gitdir (.git/modules/<name>) re-roots, so its *operational* state is
    // writable — its own config, hooks and redirections are frozen, and are asserted so in
    // `PROTECTED`.
    ".git/modules/sub/HEAD",
    ".git/modules/sub/index",
    ".git/modules/sub/refs/heads/main",
    ".git/modules/sub/objects/ab/cd",
    ".git/modules/sub/logs/HEAD",
    // A submodule in a subdirectory — the common layout, and a two-component name.
    ".git/modules/libs/foo/HEAD",
    ".git/modules/libs/foo/index",
    ".git/modules/libs/foo/objects/ab/cd",
    ".git/modules/libs/foo/refs/heads/main",
    // A linked worktree's gitdir (.git/worktrees/<name>) re-roots; its per-worktree state too.
    ".git/worktrees/wt/HEAD",
    ".git/worktrees/wt/ORIG_HEAD",
    ".git/worktrees/wt/index",
    ".git/worktrees/wt/logs/HEAD",
];

/// What `probe/observe-git.sh` cannot see, because it is gone when the command ends or only a
/// command the script does not run writes it. Recorded with `strace -f` around one git 2.47.3
/// command each, except the lines that name git's source instead. Stays writable.
pub const OPERATIONAL_UNOBSERVED: &[&str] = &[
    ".git/index.stash.3943",               // git stash
    ".git/index.stash.3943.lock",          // git stash
    ".git/next-index-3999.lock",           // git commit <pathspec>
    ".git/packed-refs.new",                // git gc, pack-refs, branch -d or tag -d of a packed ref
    ".git/gc.pid.lock",                    // git gc
    ".git/objects/info/commit-graph.lock", // commit-graph.c, write_commit_graph_file
    ".git/objects/info/commit-graphs/commit-graph-chain.lock",
    ".git/objects/info/commit-graphs/tmp_graph_Ab12Cd",
    ".git/objects/info/packs_Ab12Cd", // server-info.c, update_info_file
    ".git/gc.pid",
    ".git/gc.log.lock",              // git gc --auto, detached
    ".git/MERGE_AUTOSTASH.lock",     // git merge --autostash
    ".git/NOTES_MERGE_PARTIAL.lock", // git notes merge
    ".git/NOTES_MERGE_REF.lock",
    ".git/NOTES_MERGE_WORKTREE/7875ff97b57f0181f7dbea31886e290d0462d976",
    ".git/NOTES_EDITMSG",    // git notes edit
    ".git/EDIT_DESCRIPTION", // git branch --edit-description
    ".git/ADD_EDIT.patch",   // git add -e
    ".git/REPLACE_EDITOBJ",  // git replace --edit
    ".git/sharedindex.c78dfdba23422a067a1b890713e7bc6535d24598", // git update-index --split-index
    ".git/sharedindex_AltQxj",
    ".git/shallow_Ab12Cd", // shallow.c, setup_temporary_shallow
    ".git/lost-found/commit/1aed62d97f0249bd46b04ed52216e59699ec7c21", // git fsck --lost-found
    ".git/reftable/tables.list.lock", // a reftable repository's refs
    ".git/reftable/0x000000000001-0x000000000002-f3ae823b.ref",
    ".git/worktrees/wt/index.stash.3943", // a linked worktree's stash
    // git filter-repo a40bce5, under strace on 2026-10-24: its metadata beside the gitdir's own
    // state, and `git update-server-info`'s temporary file.
    ".git/filter-repo/already_ran",
    ".git/filter-repo/commit-map",
    ".git/filter-repo/ref-map",
    ".git/filter-repo/analysis/README",
    ".git/info/refs_hH1f3M",
    // git-lfs's store (git-lfs 3.7.0, `fs/fs.go`): objects by hash, temporaries, the lock cache
    // and logs.
    ".git/lfs/objects/ab/cd/abcdef0123456789",
    ".git/lfs/tmp/abcdef0123456789",
    ".git/lfs/incomplete/abcdef0123456789",
    ".git/lfs/cache/locks/refs/heads/main/verifiable",
    ".git/lfs/logs/20261024T000000.log",
];

/// The entries that stay frozen.
pub const PROTECTED: &[&str] = &[
    // The command-defining config files and the hook tree: what the filter exists to freeze.
    ".git/config",
    ".git/config.worktree",
    ".git/hooks/pre-commit",
    ".git/hooks/post-checkout.sample",
    // A submodule gitdir's own config and hooks, reached through the re-root.
    ".git/modules/sub/config",
    ".git/modules/sub/hooks/pre-commit",
    ".git/modules/libs/foo/config",
    ".git/modules/libs/foo/hooks/pre-commit",
    // The namespace between `modules` and the gitdir (`GitContext::ModuleNamespace`).
    ".git/modules/libs",
    // A worktree's redirection markers — re-aiming these would relocate config/hooks resolution.
    ".git/worktrees/wt/gitdir",
    ".git/worktrees/wt/commondir",
    ".git/worktrees/wt/config.worktree",
    // A protected entry's lock is protected: the inheritance rule must not become a way in.
    ".git/config.lock",
    ".git/config.worktree.lock",
    // Frozen, each for a reason `policy::classify_within_gitdir` records.
    ".git/rr-cache/0123/preimage",
    ".git/MERGE_RR",
    ".git/objects/info/alternates",
    ".git/objects/info/alternates.lock",
    ".git/objects/info/http-alternates",
    ".git/modules/sub/objects/info/alternates",
    ".git/modules/libs/foo/objects/info/alternates",
    ".git/worktrees/wt/objects/info/alternates",
    // Only the exact shapes of git's scratch names.
    ".git/index.stash.",
    ".git/index.stash.12x",
    ".git/next-index-",
    ".git/sharedindex.xyz",
    ".git/shallow_12345",
    ".git/shallow_1234567",
];

/// Rebase and sequencer todo state, frozen like hooks despite git writing them constantly
/// (`doc/git-metadata.md`, group 1): security overrides compatibility here, so those commands do
/// not work in the workspace.
pub const PROTECTED_TODO_STATE: &[&str] = &[
    ".git/rebase-merge/git-rebase-todo",
    ".git/rebase-apply/0001",
    ".git/sequencer/todo",
];

/// The `.git` entry itself, frozen however it is named: a new `.git` (dir or pointer file) is
/// name-refused at create; an existing one is immutable.
pub const DOTGIT_ENTRIES: &[&str] = &[".git", "sub/.git", "deep/nested/.git"];
