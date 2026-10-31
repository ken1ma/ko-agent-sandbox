//! The BPF cgroup-LSM backend's classifier (`bpf/ko-agent-bpf/policy.bpf.c` at the repository
//! root), built for the host against the stand-in headers in `bpf/ko-agent-bpf/test/host/`, and the
//! policy's corpus (`corpus`) run through it and through `policy.rs`: the two classifiers give one
//! answer to every query (`doc/bpf-lsm-cgroup.md`, "What is gained and what is lost"). The
//! rules reach the program as the guard writes them, through `bpf_records::compile`, so the
//! compiler is under test too. What the host build cannot show is the glue around the
//! classifier: the CO-RE reads, the walk's bounds under the verifier and the hooks' arguments,
//! which the probe measures on the machines.
//!
//! Needs a C compiler, `$CC` or `cc`, and the sources beside the crate, unless
//! `KO_AGENT_FS_POLICY_HOST` names a classifier built already, as the self-test image's builder
//! does for the relocated suite (`container/ko-agent-self-test/Containerfile`).

mod corpus;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use ko_agent_fs::bpf_records::compile;
use ko_agent_fs::guard::{GuardedKind, GuardedPath};
use ko_agent_fs::policy::{
    Decision, FileRules, GitContext, Mutation, RuleContext, authorize, authorize_create,
    authorize_region_move, authorize_rule, authorize_rule_create, child_rule_context,
    context_of_relative_path, fold, is_dotgit_name, is_sandbox_config_name, rule_context_of_path,
};

const FS_TYPE: &str = "virtiofs";
/// Where a directory of the corpus is moved to, a name no line names.
const MOVED: &str = "moved";

fn host_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bpf/ko-agent-bpf/test/host")
}

/// This run's files, under the system's temporary directory: the packaged suite has no Cargo
/// target directory.
fn scratch_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "ko-agent-fs-bpf-equivalence-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    })
}

/// The classifier's host build: the one `KO_AGENT_FS_POLICY_HOST` names, else compiled once for
/// the test binary.
fn classifier() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| {
        if let Some(built) = std::env::var_os("KO_AGENT_FS_POLICY_HOST") {
            return PathBuf::from(built);
        }
        let out = scratch_dir().join("policy-host");
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let host = host_dir();
        let output = Command::new(&cc)
            .args(["-std=gnu17", "-O1", "-Wall", "-I"])
            .arg(&host)
            .arg("-I")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("include"))
            .arg("-o")
            .arg(&out)
            .arg(host.join("policy_host.c"))
            .arg(host.join("records_file.c"))
            .output()
            .unwrap_or_else(|err| {
                panic!("{cc}: {err}; the classifier's host build needs a C compiler, $CC or cc")
            });
        assert!(
            output.status.success(),
            "{cc} failed to build the classifier:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        out
    })
}

#[derive(Debug, Clone)]
enum Query {
    Write(String),
    Unlink(String),
    Create(String),
    /// A directory moved to [`MOVED`] at the root: the region rule beside the removal's.
    MoveDir(String),
}

impl Query {
    /// Every query the corpus asks of one path.
    fn all(path: &str) -> Vec<Query> {
        vec![
            Query::Write(path.to_string()),
            Query::Unlink(path.to_string()),
            Query::Create(path.to_string()),
            Query::MoveDir(path.to_string()),
        ]
    }

    fn line(&self) -> String {
        match self {
            Query::Write(path) => format!("write\t{path}"),
            Query::Unlink(path) => format!("unlink\t{path}"),
            Query::Create(path) => format!("create\t{path}"),
            Query::MoveDir(path) => format!("rename\tdir\t{path}\t{MOVED}"),
        }
    }
}

struct Case {
    name: String,
    rules: FileRules,
    gitdir_roots: Vec<&'static [u8]>,
    queries: Vec<Query>,
}

/// `policy.rs`'s answers, combined as the FUSE layer combines them (`fs.rs`, `allow_child`,
/// `allow_create` and `allow_region_move`), with the three rules the program adds for the
/// directories it cannot refuse (`doc/bpf-lsm-cgroup.md`, "Directories"): no new `HEAD` in a
/// `.git`, the rules applying in git state too, and a `.ko-agent-sandbox` protected in git state.
impl Case {
    fn contexts(&self, path: &str) -> (GitContext, RuleContext) {
        if path.is_empty() {
            return (GitContext::root(), RuleContext::root());
        }
        let mut git = context_of_relative_path(path.as_bytes(), &self.gitdir_roots);
        if let GitContext::InGit(rel) = &git
            && rel
                .iter()
                .any(|component| is_sandbox_config_name(component))
        {
            git = GitContext::SandboxConfig;
        }
        // The rules at every position; `rule_context_of_path` stops at git state, where the
        // filter's inode table gives an entry the root's context (`inode.rs`, `child_contexts`).
        let rule =
            path.split('/')
                .enumerate()
                .fold(RuleContext::root(), |parent, (depth, component)| {
                    child_rule_context(&self.rules, &parent, depth == 0, component.as_bytes())
                });
        (git, rule)
    }

    fn existing(&self, path: &str, op: Mutation) -> Decision {
        let (git, rule) = self.contexts(path);
        match authorize(&git, op) {
            Decision::Allow => authorize_rule(&self.rules, &rule, op),
            deny => deny,
        }
    }

    fn creation(&self, path: &str) -> Decision {
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let (parent_git, _) = self.contexts(parent);
        let decision = match authorize_create(&parent_git, name.as_bytes(), false) {
            Decision::Allow => authorize_rule_create(&self.rules, &self.contexts(path).1, false),
            deny => deny,
        };
        let parent_name = parent.rsplit('/').next().unwrap_or("");
        if decision == Decision::Allow
            && is_dotgit_name(parent_name.as_bytes())
            && fold(name.as_bytes()) == b"head"
        {
            return Decision::Deny("Directories: no new HEAD in a .git");
        }
        decision
    }

    fn decide(&self, query: &Query) -> Decision {
        match query {
            Query::Write(path) => self.existing(path, Mutation::Write),
            Query::Unlink(path) => self.existing(path, Mutation::Unlink),
            Query::Create(path) => self.creation(path),
            Query::MoveDir(path) => {
                for decision in [
                    self.existing(path, Mutation::RenameFrom),
                    self.creation(MOVED),
                ] {
                    if decision != Decision::Allow {
                        return decision;
                    }
                }
                let (from_git, from) = self.contexts(path);
                let (to_git, to) = self.contexts(MOVED);
                authorize_region_move(&self.rules, (&from_git, &from), (&to_git, &to))
            }
        }
    }

    /// The guarded objects the guard records for every workspace, and this case's gitdirs.
    fn guarded(&self) -> Vec<GuardedPath> {
        let mut guarded = vec![
            GuardedPath {
                kind: GuardedKind::Workspace,
                path: Vec::new(),
            },
            GuardedPath {
                kind: GuardedKind::GitEntry,
                path: b".git".to_vec(),
            },
            GuardedPath {
                kind: GuardedKind::SandboxEntry,
                path: b".ko-agent-sandbox".to_vec(),
            },
        ];
        for root in &self.gitdir_roots {
            guarded.push(GuardedPath {
                kind: GuardedKind::Gitdir,
                path: root.to_vec(),
            });
        }
        guarded
    }

    /// The program's answers, one `allow` or `deny` with its reason per query.
    fn run_program(&self, index: usize) -> Vec<(bool, String)> {
        let records = compile(&self.rules, &self.guarded())
            .unwrap_or_else(|err| panic!("{}: the records: {err}", self.name));
        let records_path = scratch_dir().join(format!("case-{index}.records"));
        std::fs::write(&records_path, records.to_bytes()).expect("the records file");
        let mut child = Command::new(classifier())
            .arg(&records_path)
            .arg(FS_TYPE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the classifier's host build runs");
        let mut input = String::new();
        for query in &self.queries {
            input.push_str(&query.line());
            input.push('\n');
        }
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("the queries");
        let output = child.wait_with_output().expect("the answers");
        assert!(
            output.status.success(),
            "{}: the program failed: {}",
            self.name,
            String::from_utf8_lossy(&output.stderr)
        );
        let answers: Vec<(bool, String)> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| {
                let (verdict, reason) = line.split_once(' ').expect("verdict and reason");
                (verdict == "allow", reason.to_string())
            })
            .collect();
        assert_eq!(
            answers.len(),
            self.queries.len(),
            "{}: one answer per query",
            self.name
        );
        answers
    }
}

fn file_rules(lines: &[(&str, &str)]) -> FileRules {
    FileRules::new(
        lines
            .iter()
            .map(|(word, name)| corpus::rule_line(word, name))
            .collect(),
    )
}

/// The conformance table: each case's lines, each row's path, the folded rows included.
fn conformance_cases() -> Vec<Case> {
    corpus::conformance_cases()
        .into_iter()
        .map(|case| {
            let lines: Vec<(&str, &str)> = case
                .lines
                .iter()
                .map(|(word, name)| (word.as_str(), name.as_str()))
                .collect();
            Case {
                name: format!("conformance: {}", case.name),
                rules: file_rules(&lines),
                gitdir_roots: Vec::new(),
                queries: case
                    .rows
                    .iter()
                    .flat_map(|row| Query::all(&row.path))
                    .collect(),
            }
        })
        .collect()
}

/// The git corpus, under no rules and under the lines of the conformance table's dependency
/// case: the lines name nothing in a gitdir, so both classifiers decide by git state alone.
fn git_cases() -> Vec<Case> {
    let paths = [
        corpus::OPERATIONAL,
        corpus::OPERATIONAL_UNOBSERVED,
        corpus::PROTECTED,
        corpus::PROTECTED_TODO_STATE,
        corpus::DOTGIT_ENTRIES,
    ];
    let queries: Vec<Query> = paths
        .iter()
        .flat_map(|list| list.iter())
        .flat_map(|path| Query::all(path))
        .collect();
    let rule_sets: [(&str, &[(&str, &str)]); 2] = [
        ("no rules", &[]),
        (
            "the dependency directory's rules",
            &[
                ("read-only", ".vscode"),
                ("read-only", ".claude/settings.json"),
                ("read-only", ".opencode"),
                ("writable", "node_modules"),
            ],
        ),
    ];
    rule_sets
        .iter()
        .map(|(name, lines)| Case {
            name: format!("git corpus under {name}"),
            rules: file_rules(lines),
            gitdir_roots: corpus::GITDIR_ROOTS.to_vec(),
            queries: queries.clone(),
        })
        .collect()
}

/// Two symlink ends the guard records as aliases, one below the other, so that an entry under
/// both stands under three names at once (`FileRules::push_alias`; the program's `ALIAS_SLOTS`).
fn alias_case() -> Case {
    let mut rules = file_rules(&[
        ("read-only", ".claude/settings.json"),
        ("writable", "node_modules"),
        ("read-only", "node_modules/foo/bar"),
        ("read-only", "*.code-workspace"),
    ]);
    let context_of = |rules: &FileRules, path: &str| {
        let components: Vec<&[u8]> = path.split('/').map(str::as_bytes).collect();
        rule_context_of_path(rules, &components).expect("an ordinary path")
    };
    let claude = context_of(&rules, ".claude");
    let node_modules = context_of(&rules, "node_modules");
    rules.push_alias("shared/claude", claude);
    rules.push_alias("shared/claude/pkgs", node_modules);
    let paths = [
        "shared",
        "shared/claude",
        "shared/claude/settings.json",
        "shared/claude/notes.md",
        "shared/claude/pkgs",
        "shared/claude/pkgs/foo",
        "shared/claude/pkgs/foo/bar",
        "shared/claude/pkgs/foo/other",
        "shared/claude/pkgs/x.code-workspace",
        "shared/claude/pkgs/settings.json",
        "x/shared/claude/settings.json",
        ".claude/settings.json",
        "node_modules/foo/bar",
        "node_modules/x.code-workspace",
    ];
    Case {
        name: "aliases".to_string(),
        rules,
        gitdir_roots: Vec::new(),
        queries: paths.iter().flat_map(|path| Query::all(path)).collect(),
    }
}

/// The three rules of "Directories", at the positions they decide.
fn directories_case() -> Case {
    let paths = [
        ".git/HEAD",
        ".git/head",
        ".git/HEAD.lock",
        "apps/.git/HEAD",
        "apps/.GIT/HEAD",
        "apps/.git/HEAD.lock",
        "apps/.git/refs/HEAD",
        "locked/.git/HEAD",
        "locked/.git/objects/payload",
        "locked/.git/hooks/pre-commit",
        "locked/.git/objects",
        "node_modules/pkg/.git/objects/x",
        "node_modules/pkg/.git",
        ".git/objects/x/.ko-agent-sandbox",
        ".git/objects/x/.ko-agent-sandbox/f",
        ".git/objects/x/.KO-AGENT-SANDBOX/f",
        ".git/modules/libs/.ko-agent-sandbox",
    ];
    Case {
        name: "the Directories rules".to_string(),
        rules: file_rules(&[("read-only", "locked"), ("writable", "node_modules")]),
        gitdir_roots: corpus::GITDIR_ROOTS.to_vec(),
        queries: paths.iter().flat_map(|path| Query::all(path)).collect(),
    }
}

/// `<name>.lock` of each class of one-component name: a lock inherits its target's class, the
/// operational trees' and files' included (`policy.rs`, `classify_within_gitdir`).
fn lock_case() -> Case {
    let paths = [
        ".git/lfs.lock",
        ".git/objects.lock",
        ".git/filter-repo.lock",
        ".git/HEAD.lock",
        ".git/BISECT_LOG.lock",
        ".git/index.stash.42.lock",
        ".git/sharedindex.xyz.lock",
        ".git/config.lock",
        ".git/hooks.lock",
        ".git/rr-cache.lock",
        ".git/modules/sub/lfs.lock",
        ".git/modules/sub/config.lock",
    ];
    Case {
        name: "locks".to_string(),
        rules: FileRules::default(),
        gitdir_roots: corpus::GITDIR_ROOTS.to_vec(),
        queries: paths.iter().flat_map(|path| Query::all(path)).collect(),
    }
}

#[test]
fn the_program_and_the_policy_decide_the_corpus_alike() {
    let mut cases = conformance_cases();
    cases.extend(git_cases());
    cases.push(alias_case());
    cases.push(directories_case());
    cases.push(lock_case());
    let mut mismatches = Vec::new();
    let (mut allowed, mut denied) = (0, 0);
    for (index, case) in cases.iter().enumerate() {
        let answers = case.run_program(index);
        for (query, (program_allows, reason)) in case.queries.iter().zip(answers) {
            let policy = case.decide(query);
            if program_allows {
                allowed += 1;
            } else {
                denied += 1;
            }
            if (policy == Decision::Allow) != program_allows {
                mismatches.push(format!(
                    "{}: {}: policy.rs {policy:?}, the program {} ({reason})",
                    case.name,
                    query.line().replace('\t', " "),
                    if program_allows { "allows" } else { "denies" },
                ));
            }
        }
    }
    let _ = std::fs::remove_dir_all(scratch_dir());
    assert!(
        mismatches.is_empty(),
        "{} of the decisions differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert!(
        allowed > 0 && denied > 0,
        "the corpus exercised both answers"
    );
}
