//! The policy core: position and raw bytes in, a decision out. No syscalls, no FUSE, no `String`
//! (Linux names are byte sequences). This is the whole security surface worth auditing closely;
//! `doc/git-metadata.md` is the reasoning it transcribes, save for the one rule that protects the
//! launcher's own `.ko-agent-sandbox` ([`is_sandbox_config_name`]).
//!
//! The plumbing (the FUSE layer) never re-derives protection from a path string. It caches one
//! [`GitContext`] per inode, computed once at lookup from the parent's context plus the child's
//! name ([`child_context`], O(1)), and asks this module to [`classify`] or [`authorize`] against
//! it. The overwhelming majority of files in a build are outside any gitdir, so their context is a
//! single `NotGit` tag and every operation on them is an immediate allow.

/// A filesystem-mutating operation the filter may authorize. Reads are never routed here.
///
/// Exactly the operations the FUSE layer passes, so that a test iterating this enum is iterating
/// the real deny surface rather than a wish list. Everything that *creates* a name — `create`,
/// `mkdir`, `mknod`, `symlink`, a rename's destination, a link's destination — goes through
/// [`authorize_create`] instead, because the `.git` name rule has to see the new name. A truncate
/// arrives as `open(O_TRUNC)` or a `setattr` carrying a size, so it is `Write` or `SetAttr` by the
/// time it reaches here. Xattr variants belong here the day `setxattr`/`removexattr` are
/// implemented at all (`doc/TODO.md`, "Non-TODOs") and not before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    Write,
    SetAttr,
    Unlink,
    Rmdir,
    RenameFrom,
    Link,
}

/// A decision, carrying a stable reason for the deny log (never file contents). A denial maps to
/// `EPERM` at the FUSE boundary — the immutable-inode / fanotify-deny convention for "this
/// operation is forbidden regardless of file mode", not `EACCES` ("you lack access").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitPathClass {
    /// Operational state git must write, or project data outside Git control state. Writable.
    Operational,
    /// Control state — config, hooks, redirections. Immutable to the sandbox.
    Control,
}

/// The cached position of an inode relative to the state this filter protects. Stored per inode by
/// the FUSE layer. Git metadata is the bulk of it and `doc/git-metadata.md` the reasoning; the
/// launcher's own configuration directory is protected here too, for the reason
/// [`is_sandbox_config_name`] gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitContext {
    /// Not inside any gitdir — ordinary writable project data.
    NotGit,
    /// Inside a gitdir; the path components relative to that gitdir's root. An empty vector is the
    /// gitdir entry itself — the `.git` directory root or a `.git` pointer file — which is control.
    InGit(Vec<Vec<u8>>),
    /// A directory under `<gitdir>/modules` that is not itself a gitdir root — the namespace a
    /// submodule whose name carries a `/` creates.
    ///
    /// It exists because a submodule's name defaults to its *path*, so `libs/foo` puts the real
    /// gitdir at `modules/libs/foo` and leaves `modules/libs` holding nothing but other gitdirs.
    /// Names alone cannot say which of the two a directory is — `modules/a/b` is `a/b`'s gitdir if
    /// the submodule is at `a/b`, and `a`'s own subdirectory if it is at `a` — so this is the one
    /// position the core cannot derive, and [`gitdir_root`] is what the plumbing swaps in once it
    /// has looked. Control until then, which is what stops a namespace being written into and so
    /// made to *look* like a gitdir.
    ModuleNamespace,
    /// The `.ko-agent-sandbox` entry itself or anything below it. No depth is tracked because
    /// nothing in there is writable: unlike a gitdir, it holds no operational state.
    SandboxConfig,
}

impl GitContext {
    pub fn root() -> GitContext {
        GitContext::NotGit
    }
}

/// UTF-8 encodings of the invisible code points a filesystem may ignore when comparing names. A
/// name that reads as `.git` once these are dropped is refused; none of them belongs in a filename.
const IGNORABLE: &[&[u8]] = &[
    b"\xc2\xad",     // U+00AD soft hyphen
    b"\xe2\x80\x8b", // U+200B zero width space
    b"\xe2\x80\x8c", // U+200C zero width non-joiner
    b"\xe2\x80\x8d", // U+200D zero width joiner
    b"\xe2\x81\xa0", // U+2060 word joiner
    b"\xef\xbb\xbf", // U+FEFF zero width no-break space
];

/// Whether `name` (a raw basename, no slashes) must be refused as a new `.git` entry.
///
/// The rule as executed: strip trailing `.` and space, drop [`IGNORABLE`], fold U+0130/U+0131 to
/// `i`, ASCII case-fold, compare to `.git`. Byte-safe: a non-UTF-8 `name` simply fails to match
/// and is allowed, never a panic. Why each step: `doc/git-metadata.md`, "The name rule".
pub fn is_dotgit_name(name: &[u8]) -> bool {
    folds_to(name, b".git")
}

/// Whether `name` must be refused as a new `.ko-agent-sandbox` entry — the launcher's own
/// boundary configuration, which a session must never write because the *next* launch reads it
/// (`SECURITY.md`, "A project loosening its own confinement"). The launcher mounts that directory
/// back over itself read-only, and this rule is what holds when that mount is not there: a mount
/// cannot follow its source, so a host that removes or replaces the directory takes the mount with
/// it and leaves the path writable inside an otherwise writable workspace.
///
/// At any depth, not only the workspace root, because a launch takes its policy from whatever
/// directory it starts in: a session at the repository root planting `apps/web/.ko-agent-sandbox`
/// would be writing boundary configuration for a later launch from `apps/web`. The host creates
/// these directories, as it creates repositories.
///
/// Folded exactly like `.git` and for the same reason: the launcher resolves the name on the host,
/// so a case-insensitive backing would find `.KO-AGENT-SANDBOX` under it.
pub fn is_sandbox_config_name(name: &[u8]) -> bool {
    folds_to(name, b".ko-agent-sandbox")
}

/// The single fold behind every reserved-name rule, so no two of them can disagree about what a
/// backing filesystem might treat as the same name. `target` is ASCII.
fn folds_to(name: &[u8], target: &[u8]) -> bool {
    // The i-family folds to ASCII 'i' (U+0130 is C4 B0, U+0131 is C4 B1) and ignorables are dropped.
    let mut folded: Vec<u8> = Vec::with_capacity(name.len());
    let mut i = 0;
    'outer: while i < name.len() {
        for ignorable in IGNORABLE {
            if name[i..].starts_with(ignorable) {
                i += ignorable.len();
                continue 'outer;
            }
        }
        if i + 1 < name.len() && name[i] == 0xC4 && (name[i + 1] == 0xB0 || name[i + 1] == 0xB1) {
            folded.push(b'i');
            i += 2;
        } else {
            folded.push(name[i]);
            i += 1;
        }
    }

    let mut end = folded.len();
    while end > 0 && (folded[end - 1] == b'.' || folded[end - 1] == b' ') {
        end -= 1;
    }

    folded[..end].eq_ignore_ascii_case(target)
}

/// The context of a directory the plumbing has identified as a gitdir root in its own right. The
/// one position this core cannot derive from names ([`GitContext::ModuleNamespace`] has why), and
/// so the one it is told.
pub fn gitdir_root() -> GitContext {
    GitContext::InGit(Vec::new())
}

/// Compute a child's context from its parent's context and the child's raw name. O(1), called once
/// per lookup and cached on the inode.
///
/// The subtle case is nested gitdirs: `<gitdir>/modules/<name>` and `<gitdir>/worktrees/<name>` are
/// themselves gitdirs, so classification must restart at `<name>` — otherwise a submodule's
/// writable `objects/` would be judged against the outer gitdir's layout and wrongly frozen.
///
/// The two differ in how far `<name>` reaches (`doc/git-metadata.md`, P1): a linked worktree's is
/// always one component and re-roots here; a submodule's is not knowable from the path, so those
/// children become [`GitContext::ModuleNamespace`] until the plumbing says otherwise. Both compose
/// recursively.
pub fn child_context(parent: &GitContext, child_name: &[u8]) -> GitContext {
    match parent {
        GitContext::NotGit => {
            if is_dotgit_name(child_name) {
                GitContext::InGit(Vec::new())
            } else if is_sandbox_config_name(child_name) {
                GitContext::SandboxConfig
            } else {
                GitContext::NotGit
            }
        }
        // Everything below it, at any depth: a `.git` inside would be the launcher's business, not
        // a repository, and there is nothing there git should discover either way.
        GitContext::SandboxConfig => GitContext::SandboxConfig,
        // A namespace holds only gitdirs, so its children are candidates for the same question.
        GitContext::ModuleNamespace => GitContext::ModuleNamespace,
        GitContext::InGit(rel) => {
            if rel.len() == 1 && rel[0] == b"worktrees" {
                gitdir_root()
            } else if rel.len() == 1 && rel[0] == b"modules" {
                GitContext::ModuleNamespace
            } else {
                let mut child = rel.clone();
                child.push(child_name.to_vec());
                GitContext::InGit(child)
            }
        }
    }
}

pub fn classify(context: &GitContext) -> GitPathClass {
    match context {
        GitContext::NotGit => GitPathClass::Operational,
        GitContext::SandboxConfig => GitPathClass::Control,
        GitContext::ModuleNamespace => GitPathClass::Control,
        GitContext::InGit(rel) => {
            let refs: Vec<&[u8]> = rel.iter().map(Vec::as_slice).collect();
            classify_within_gitdir(&refs)
        }
    }
}

/// Classify a whole workspace-relative path by walking [`child_context`] from the mount root. A
/// convenience for validation and tests — the FUSE layer never splits a path, it computes each
/// inode's context incrementally at lookup; this reproduces the same result so tests and the
/// real-git corpus exercise identical logic.
///
/// `gitdir_roots` supplies the workspace-relative paths of the submodule gitdirs
/// ([`GitContext::ModuleNamespace`]). A caller that names none is saying there are none, and every
/// directory under `modules/` then reads as a namespace — control, the stricter answer.
pub fn classify_relative_path(rel: &[u8], gitdir_roots: &[&[u8]]) -> GitPathClass {
    let mut context = GitContext::root();
    let mut walked: Vec<u8> = Vec::new();
    for component in rel.split(|&byte| byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if !walked.is_empty() {
            walked.push(b'/');
        }
        walked.extend_from_slice(component);
        context = child_context(&context, component);
        if context == GitContext::ModuleNamespace && gitdir_roots.contains(&walked.as_slice()) {
            context = gitdir_root();
        }
    }
    classify(&context)
}

/// Classify a path by its components *relative to the enclosing gitdir root*. Empty `components`
/// is the gitdir entry itself, which is control (it holds the config and hooks).
///
/// Allowlist / fail-closed: `Operational` only for the enumerated writable set; everything else is
/// `Control`. A git operational file we failed to enumerate breaks that git command loudly (the
/// integration suite catches it); a future git file that executes a command is denied by default.
///
/// This sees a path relative to one gitdir; [`child_context`] re-roots nested gitdirs before a path
/// can reach here, so no recursion is needed. The redirection files a worktree keeps at its own
/// root (`gitdir`, `commondir`, `config.worktree`) are covered below.
pub fn classify_within_gitdir(components: &[&[u8]]) -> GitPathClass {
    let first = match components.first() {
        None => return GitPathClass::Control,
        Some(component) => *component,
    };

    match first {
        b"config" | b"config.worktree" => return GitPathClass::Control,
        b"hooks" => return GitPathClass::Control,
        b"commondir" | b"gitdir" => return GitPathClass::Control,
        _ => {}
    }

    const OPERATIONAL_TREES: &[&[u8]] = &[
        b"objects", b"refs", b"logs",
        b"info", // exclude/sparse-checkout/attributes patterns — data, never executed
    ];
    if OPERATIONAL_TREES.contains(&first) {
        return GitPathClass::Operational;
    }

    // Deliberately NOT operational, though git writes them: `rebase-merge`, `rebase-apply`, and
    // `sequencer` hold the rebase/cherry-pick todo, whose `exec` lines a later host
    // `git rebase --continue` runs — a file whose content git executes, exactly like a hook. They
    // fall through to Control below, so a rebase/am/sequenced cherry-pick cannot be left in
    // /workspace for the host to resume. This note marks the spot where they must not be added.

    if components.len() == 1 {
        const OPERATIONAL_FILES: &[&[u8]] = &[
            b"HEAD",
            b"ORIG_HEAD",
            b"FETCH_HEAD",
            b"MERGE_HEAD",
            b"CHERRY_PICK_HEAD",
            b"REVERT_HEAD",
            b"REBASE_HEAD",
            b"AUTO_MERGE",
            b"BISECT_HEAD",
            b"index",
            b"packed-refs",
            b"COMMIT_EDITMSG",
            b"MERGE_MSG",
            b"MERGE_MODE",
            b"SQUASH_MSG",
            b"TAG_EDITMSG",
            b"shallow",
        ];
        if OPERATIONAL_FILES.contains(&first) {
            return GitPathClass::Operational;
        }
        // git writes `<name>.lock` beside anything it locks and renames it into place, so a lock
        // inherits its target's class: `HEAD.lock` and `AUTO_MERGE.lock` are operational, while
        // `config.lock` stays control. Enumerating lockable names by hand instead freezes whichever
        // one it forgot — `AUTO_MERGE.lock`, breaking `git merge` (`doc/git-metadata.md`, P2).
        if let Some(base) = first.strip_suffix(b".lock") {
            return classify_within_gitdir(&[base]);
        }
    }

    GitPathClass::Control
}

/// Both the `.git` name rule (a new gitdir the host would discover) and the destination
/// classification (creating inside a protected tree) apply.
pub fn authorize_create(parent_ctx: &GitContext, new_name: &[u8]) -> Decision {
    if is_dotgit_name(new_name) {
        return Decision::Deny("protected-git-entry: refusing to create a .git entry");
    }
    // Named separately from the control-state refusal below, which would also catch it: the deny
    // log's reason is what a user reads when a legitimate name is swallowed, and a "control state"
    // reason would send them looking in `.git` rather than at this rule.
    if is_sandbox_config_name(new_name) {
        return Decision::Deny(
            "protected-sandbox-config: refusing to create a .ko-agent-sandbox entry",
        );
    }
    if classify(&child_context(parent_ctx, new_name)) == GitPathClass::Control {
        return Decision::Deny(match parent_ctx {
            GitContext::SandboxConfig => {
                "protected-sandbox-config: refusing to create inside .ko-agent-sandbox"
            }
            _ => "protected-git-control: refusing to create control state",
        });
    }
    Decision::Allow
}

/// Creation — a rename's destination included — goes through [`authorize_create`] so the name rule
/// fires.
pub fn authorize(ctx: &GitContext, op: Mutation) -> Decision {
    if classify(ctx) != GitPathClass::Control {
        return Decision::Allow;
    }
    Decision::Deny(match (ctx, op) {
        (GitContext::SandboxConfig, Mutation::Unlink | Mutation::Rmdir) => {
            "protected-sandbox-config: refusing to remove the launcher's configuration"
        }
        (GitContext::SandboxConfig, Mutation::RenameFrom) => {
            "protected-sandbox-config: refusing to rename the launcher's configuration"
        }
        (GitContext::SandboxConfig, _) => {
            "protected-sandbox-config: refusing to mutate the launcher's configuration"
        }
        (_, Mutation::Unlink | Mutation::Rmdir) => {
            "protected-git-control: refusing to remove control state"
        }
        (_, Mutation::RenameFrom) => "protected-git-control: refusing to rename control state",
        (_, _) => "protected-git-control: refusing to mutate control state",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- The .git name rule -------------------------------------------------

    #[test]
    fn plain_dotgit_is_matched() {
        assert!(is_dotgit_name(b".git"));
    }

    #[test]
    fn case_variants_are_matched() {
        for name in [b".GIT".as_slice(), b".Git", b".gIt", b".giT"] {
            assert!(is_dotgit_name(name), "{name:?}");
        }
    }

    #[test]
    fn trailing_dots_and_spaces_are_matched() {
        for name in [
            b".git.".as_slice(),
            b".git ",
            b".git. ",
            b".GIT.",
            b".git   ",
        ] {
            assert!(is_dotgit_name(name), "{name:?}");
        }
    }

    #[test]
    fn i_family_is_folded_and_matched() {
        // ".gıt" (U+0131 dotless i) and ".gİt" (U+0130 dotted capital I).
        assert!(is_dotgit_name("\u{2e}g\u{131}t".as_bytes()));
        assert!(is_dotgit_name("\u{2e}g\u{130}t".as_bytes()));
    }

    #[test]
    fn invisible_codepoints_are_dropped_before_comparing() {
        // The HFS+ half of CVE-2014-9390: a filesystem ignoring these resolves the name to `.git`.
        assert!(is_dotgit_name("\u{2e}gi\u{200c}t".as_bytes())); // ZWNJ inside
        assert!(is_dotgit_name("\u{2e}g\u{200b}it".as_bytes())); // zero width space
        assert!(is_dotgit_name("\u{feff}\u{2e}git".as_bytes())); // leading BOM
        assert!(is_dotgit_name("\u{2e}git\u{00ad}".as_bytes())); // trailing soft hyphen
        assert!(is_dotgit_name("\u{2e}G\u{2060}IT".as_bytes())); // combined with case folding
    }

    #[test]
    fn normalization_needs_no_handling_because_dotgit_is_ascii() {
        // Accented forms never fold to ASCII g/i/t, so a normalization-insensitive backing (APFS)
        // introduces no collision — these stay ordinary, allowed names.
        assert!(!is_dotgit_name("\u{2e}gít".as_bytes())); // precomposed í (NFC)
        assert!(!is_dotgit_name("\u{2e}gi\u{0301}t".as_bytes())); // decomposed i + acute (NFD)
    }

    #[test]
    fn ordinary_names_are_not_matched() {
        for name in [
            b".gitignore".as_slice(),
            b".github",
            b".gitattributes",
            b".gitmodules",
            b"git",
            b"dotgit",
            b".g",
            b"..git",
            b".git\n", // an embedded newline is not trailing punctuation
        ] {
            assert!(!is_dotgit_name(name), "{name:?}");
        }
        // An ignorable inside an ordinary name is dropped but the result is still not `.git`.
        assert!(!is_dotgit_name("\u{2e}git\u{200c}ignore".as_bytes()));
        assert!(!is_dotgit_name("sub\u{200b}dir".as_bytes()));
    }

    #[test]
    fn non_utf8_never_panics_and_does_not_match() {
        assert!(!is_dotgit_name(&[0xff, 0xfe, 0x2e, b'g']));
        assert!(!is_dotgit_name(&[0xC4])); // lone lead byte of the i-family sequence
        assert!(!is_dotgit_name(&[0xC4, 0xB1])); // just "ı", not ".git"
    }

    #[test]
    fn empty_name_is_not_dotgit() {
        assert!(!is_dotgit_name(b""));
        assert!(!is_dotgit_name(b"."));
        assert!(!is_dotgit_name(b"   "));
    }

    // --- The .ko-agent-sandbox name rule ------------------------------------

    #[test]
    fn the_launcher_configuration_name_is_matched_through_the_same_fold() {
        assert!(is_sandbox_config_name(b".ko-agent-sandbox"));
        for name in [
            b".KO-AGENT-SANDBOX".as_slice(),
            b".Ko-Agent-Sandbox",
            b".ko-agent-sandbox.",
            b".ko-agent-sandbox ",
            b".ko-agent-sandbox. ",
        ] {
            assert!(is_sandbox_config_name(name), "{name:?}");
        }
        // An ignorable code point inside it collapses on a backing that ignores them, exactly as
        // for `.git`; the launcher then resolves the name and finds what the sandbox wrote.
        assert!(is_sandbox_config_name(
            "\u{200b}.ko-agent-sandbox".as_bytes()
        ));
        assert!(is_sandbox_config_name(".ko-agent\u{ad}-sandbox".as_bytes()));
    }

    #[test]
    fn names_merely_resembling_the_launcher_configuration_stay_allowed() {
        for name in [
            b".ko-agent-sandbox-notes".as_slice(),
            b"ko-agent-sandbox",
            b".ko-agent",
            b".ko_agent_sandbox",
            b".ko-agent-sandboxes",
        ] {
            assert!(!is_sandbox_config_name(name), "{name:?}");
            assert!(!is_dotgit_name(name), "{name:?}");
        }
        assert!(!is_sandbox_config_name(b""));
        assert!(!is_sandbox_config_name(&[0xff, 0xfe]));
    }

    #[test]
    fn the_launcher_configuration_is_control_at_every_depth() {
        // The second line behind the launcher's read-only mount (`is_sandbox_config_name`). Unlike
        // a gitdir it has no operational half, so depth changes nothing.
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox", &[]),
            GitPathClass::Control
        );
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox/egress", &[]),
            GitPathClass::Control
        );
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox/egress/allowed", &[]),
            GitPathClass::Control
        );
        assert_eq!(
            classify_relative_path(b"apps/web/.ko-agent-sandbox/egress/denied", &[]),
            GitPathClass::Control
        );
        // A repository below it is the launcher's own business, not something to re-root into a
        // gitdir with a writable objects/.
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox/.git/objects/ab/cdef", &[]),
            GitPathClass::Control
        );
        // The name remains writable project data everywhere it is not that name.
        assert_eq!(
            classify_relative_path(b"docs/ko-agent-sandbox/notes.md", &[]),
            GitPathClass::Operational
        );
    }

    #[test]
    fn creating_or_mutating_the_launcher_configuration_is_refused_by_its_own_reason() {
        let root = GitContext::root();
        assert_eq!(
            authorize_create(&root, b".ko-agent-sandbox"),
            Decision::Deny(
                "protected-sandbox-config: refusing to create a .ko-agent-sandbox entry"
            )
        );
        assert_eq!(
            authorize_create(&GitContext::SandboxConfig, b"egress"),
            Decision::Deny("protected-sandbox-config: refusing to create inside .ko-agent-sandbox")
        );
        assert_eq!(
            authorize(&GitContext::SandboxConfig, Mutation::Write),
            Decision::Deny(
                "protected-sandbox-config: refusing to mutate the launcher's configuration"
            )
        );
        assert_eq!(
            authorize(&GitContext::SandboxConfig, Mutation::Unlink),
            Decision::Deny(
                "protected-sandbox-config: refusing to remove the launcher's configuration"
            )
        );
        // Every mutation the enum carries, so the deny surface is the type rather than the cases
        // thought of here. A rename's destination is not among them: it creates a name, so it goes
        // through authorize_create above.
        for op in [
            Mutation::Write,
            Mutation::SetAttr,
            Mutation::Unlink,
            Mutation::Rmdir,
            Mutation::RenameFrom,
            Mutation::Link,
        ] {
            assert!(
                matches!(authorize(&GitContext::SandboxConfig, op), Decision::Deny(_)),
                "{op:?}"
            );
        }
    }

    // --- Context transitions (child_context) --------------------------------

    fn ingit(parts: &[&[u8]]) -> GitContext {
        GitContext::InGit(parts.iter().map(|p| p.to_vec()).collect())
    }

    #[test]
    fn a_dotgit_child_of_a_normal_dir_enters_a_gitdir() {
        assert_eq!(child_context(&GitContext::NotGit, b".git"), ingit(&[]));
        assert_eq!(child_context(&GitContext::NotGit, b".GIT"), ingit(&[]));
    }

    #[test]
    fn a_normal_child_of_a_normal_dir_stays_out() {
        assert_eq!(
            child_context(&GitContext::NotGit, b"src"),
            GitContext::NotGit
        );
    }

    #[test]
    fn descending_a_gitdir_extends_the_relative_path() {
        let hooks = child_context(&ingit(&[]), b"hooks");
        assert_eq!(hooks, ingit(&[b"hooks"]));
        assert_eq!(
            child_context(&hooks, b"pre-commit"),
            ingit(&[b"hooks", b"pre-commit"])
        );
    }

    #[test]
    fn a_directory_under_modules_is_a_namespace_until_the_plumbing_says_otherwise() {
        let modules = ingit(&[b"modules"]);
        assert_eq!(
            child_context(&modules, b"libs"),
            GitContext::ModuleNamespace
        );
        assert_eq!(
            child_context(&GitContext::ModuleNamespace, b"foo"),
            GitContext::ModuleNamespace
        );
        assert_eq!(
            classify(&GitContext::ModuleNamespace),
            GitPathClass::Control
        );
        assert!(matches!(
            authorize_create(&GitContext::ModuleNamespace, b"HEAD"),
            Decision::Deny(_)
        ));
        for op in [Mutation::Write, Mutation::Unlink, Mutation::RenameFrom] {
            assert!(
                matches!(
                    authorize(&GitContext::ModuleNamespace, op),
                    Decision::Deny(_)
                ),
                "{op:?}"
            );
        }
    }

    #[test]
    fn a_submodule_name_may_carry_a_slash_and_its_gitdir_still_re_roots() {
        // `libs/foo` is the ordinary name for a submodule at `libs/foo`, so the gitdir is two
        // components below `modules` — and once the plumbing has identified it, everything under it
        // classifies exactly as a top-level submodule's does.
        let namespace = child_context(&ingit(&[b"modules"]), b"libs");
        assert_eq!(namespace, GitContext::ModuleNamespace);
        let foo = gitdir_root(); // what the plumbing swaps in for `.git/modules/libs/foo`
        for (name, expected) in [
            (b"objects".as_slice(), GitPathClass::Operational),
            (b"refs", GitPathClass::Operational),
            (b"HEAD", GitPathClass::Operational),
            (b"index", GitPathClass::Operational),
            (b"config", GitPathClass::Control),
            (b"hooks", GitPathClass::Control),
        ] {
            assert_eq!(
                classify(&child_context(&foo, name)),
                expected,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn a_submodule_gitdir_re_roots_so_its_objects_stay_writable() {
        // .git/modules/foo is itself a gitdir; classification must restart there, which for a
        // one-component name is what the plumbing's answer amounts to.
        let modules = ingit(&[b"modules"]);
        assert_eq!(child_context(&modules, b"foo"), GitContext::ModuleNamespace);
        let foo = gitdir_root();
        assert_eq!(foo, ingit(&[]));
        let objects = child_context(&foo, b"objects");
        assert_eq!(
            classify(&child_context(&objects, b"ab")),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&child_context(&foo, b"config")),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&child_context(&foo, b"hooks")),
            GitPathClass::Control
        );
    }

    #[test]
    fn a_worktree_gitdir_re_roots_and_its_redirections_are_control() {
        let worktrees = ingit(&[b"worktrees"]);
        let wt = child_context(&worktrees, b"feature"); // .git/worktrees/feature
        assert_eq!(wt, ingit(&[]));
        assert_eq!(
            classify(&child_context(&wt, b"HEAD")),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&child_context(&wt, b"gitdir")),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&child_context(&wt, b"commondir")),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&child_context(&wt, b"config.worktree")),
            GitPathClass::Control
        );
    }

    // --- Classification -----------------------------------------------------

    #[test]
    fn outside_a_gitdir_everything_is_operational() {
        assert_eq!(classify(&GitContext::NotGit), GitPathClass::Operational);
    }

    #[test]
    fn the_gitdir_entry_and_control_files_are_control() {
        assert_eq!(classify(&ingit(&[])), GitPathClass::Control);
        assert_eq!(classify(&ingit(&[b"config"])), GitPathClass::Control);
        assert_eq!(
            classify(&ingit(&[b"config.worktree"])),
            GitPathClass::Control
        );
        assert_eq!(classify(&ingit(&[b"commondir"])), GitPathClass::Control);
    }

    #[test]
    fn hooks_are_control_at_every_depth() {
        assert_eq!(classify(&ingit(&[b"hooks"])), GitPathClass::Control);
        assert_eq!(
            classify(&ingit(&[b"hooks", b"pre-commit"])),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&ingit(&[b"hooks", b"nested", b"x"])),
            GitPathClass::Control
        );
    }

    #[test]
    fn a_lock_inherits_the_class_of_what_it_locks() {
        // Why inheritance rather than an enumeration: `classify_within_gitdir`, at the rule.
        assert_eq!(
            classify(&ingit(&[b"AUTO_MERGE.lock"])),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&ingit(&[b"REBASE_HEAD.lock"])),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&ingit(&[b"MERGE_HEAD.lock"])),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&ingit(&[b"packed-refs.lock"])),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&ingit(&[b"shallow.lock"])),
            GitPathClass::Operational
        );
        // A lock on control state is control, and a lock on an unknown name stays fail-closed.
        assert_eq!(classify(&ingit(&[b"config.lock"])), GitPathClass::Control);
        assert_eq!(
            classify(&ingit(&[b"config.worktree.lock"])),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&ingit(&[b"unknown-thing.lock"])),
            GitPathClass::Control
        );
    }

    #[test]
    fn operational_trees_and_files_are_writable() {
        assert_eq!(
            classify(&ingit(&[b"objects", b"ab", b"cd"])),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&ingit(&[b"refs", b"heads", b"main"])),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&ingit(&[b"logs", b"HEAD"])),
            GitPathClass::Operational
        );
        assert_eq!(classify(&ingit(&[b"HEAD"])), GitPathClass::Operational);
        assert_eq!(
            classify(&ingit(&[b"index.lock"])),
            GitPathClass::Operational
        );
        assert_eq!(classify(&ingit(&[b"HEAD.lock"])), GitPathClass::Operational);
    }

    #[test]
    fn unknown_gitdir_paths_are_control_fail_closed() {
        assert_eq!(classify(&ingit(&[b"description"])), GitPathClass::Control);
        assert_eq!(
            classify(&ingit(&[b"some-future-exec-file"])),
            GitPathClass::Control
        );
        assert_eq!(classify(&ingit(&[b"config.lock"])), GitPathClass::Control);
        assert_eq!(
            classify(&ingit(&[b"HEAD", b"child"])),
            GitPathClass::Control
        );
    }

    #[test]
    fn rebase_and_sequencer_state_is_control_because_its_todo_can_exec() {
        // Why they are not operational: the "Deliberately NOT operational" note in
        // `classify_within_gitdir`, at the rule this pins.
        assert_eq!(
            classify(&ingit(&[b"rebase-merge", b"git-rebase-todo"])),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&ingit(&[b"rebase-apply", b"0001"])),
            GitPathClass::Control
        );
        assert_eq!(
            classify(&ingit(&[b"sequencer", b"todo"])),
            GitPathClass::Control
        );
    }

    // --- Authorization ------------------------------------------------------

    #[test]
    fn creating_dotgit_is_denied_anywhere() {
        assert!(matches!(
            authorize_create(&GitContext::NotGit, b".git"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&GitContext::NotGit, b".GIT"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&ingit(&[b"refs"]), b".git"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn creating_ordinary_files_is_allowed() {
        assert_eq!(
            authorize_create(&GitContext::NotGit, b"main.rs"),
            Decision::Allow
        );
        assert_eq!(
            authorize_create(&GitContext::NotGit, b".gitignore"),
            Decision::Allow
        );
        assert_eq!(
            authorize_create(&ingit(&[b"refs", b"heads"]), b"feature"),
            Decision::Allow
        );
    }

    #[test]
    fn creating_control_state_inside_a_gitdir_is_denied() {
        assert!(matches!(
            authorize_create(&ingit(&[]), b"config"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&ingit(&[]), b"hooks"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&ingit(&[b"hooks"]), b"pre-commit"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn mutating_control_state_is_denied_for_every_op() {
        // Every variant of Mutation, which is every mutation the FUSE layer routes here — the enum
        // holds exactly that set, precisely so this list is exhaustive rather than aspirational.
        let hooks = ingit(&[b"hooks", b"pre-commit"]);
        for op in [
            Mutation::Write,
            Mutation::SetAttr,
            Mutation::Unlink,
            Mutation::Rmdir,
            Mutation::RenameFrom,
            Mutation::Link,
        ] {
            assert!(matches!(authorize(&hooks, op), Decision::Deny(_)), "{op:?}");
        }
    }

    #[test]
    fn mutating_the_gitdir_pointer_entry_is_denied() {
        assert!(matches!(
            authorize(&ingit(&[]), Mutation::Write),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize(&ingit(&[]), Mutation::RenameFrom),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn mutating_operational_or_ordinary_state_is_allowed() {
        assert_eq!(
            authorize(&ingit(&[b"index"]), Mutation::Write),
            Decision::Allow
        );
        assert_eq!(
            authorize(&ingit(&[b"objects", b"x"]), Mutation::Write),
            Decision::Allow
        );
        assert_eq!(
            authorize(&GitContext::NotGit, Mutation::Write),
            Decision::Allow
        );
        assert_eq!(
            authorize(&GitContext::NotGit, Mutation::Unlink),
            Decision::Allow
        );
    }
}
