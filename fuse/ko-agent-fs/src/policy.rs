//! The policy core: position and raw bytes in, a decision out. No syscalls, no FUSE, no `String`
//! (Linux names are byte sequences). Every per-operation FUSE authorization rule is here, the part worth
//! auditing closely; `doc/git-metadata.md` is the reasoning it transcribes, save for the one rule that protects the
//! launcher's own `.ko-agent-sandbox` ([`is_sandbox_config_name`]) and the file rules ([`FileRules`]), whose
//! reasoning is `../../doc/file-rules.md`, "Why these files", and `../../SECURITY.md`.
//!
//! The FUSE layer never re-derives protection from a path string. It caches one
//! [`GitContext`] per inode, computed once at lookup from the parent's context plus the child's
//! name ([`child_context`], O(1)), and asks this module to [`classify`] or [`authorize`] against
//! it. The overwhelming majority of files in a build are outside any gitdir, so their context is a
//! single `NotGit` tag and every operation on them is an immediate allow.

/// A filesystem-mutating operation the filter may authorize. Reads are never routed here.
///
/// Exactly the operations the FUSE layer passes to [`authorize`]. Everything that *creates* a
/// name — `create`, `mkdir`, `mknod`, `symlink`, a rename's destination, a link's destination — goes through
/// [`authorize_create`] instead, because the `.git` name rule has to see the new name. A truncate
/// arrives as `open(O_TRUNC)` or a `setattr` with a size, so it is `Write` or `SetAttr` by the
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

/// A decision, with a stable reason for the deny log (never file contents). A denial maps to
/// `EPERM` at the FUSE boundary — the immutable-inode / fanotify-deny convention for "this
/// operation is forbidden regardless of file mode", not `EACCES` ("you lack access").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitPathClass {
    /// Writable Git metadata and ordinary project data.
    Operational,
    /// Entries the sandbox cannot modify, including Git hooks and launcher configuration.
    Protected,
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
    /// gitdir entry itself — the `.git` directory root or a `.git` pointer file — which is
    /// protected.
    InGit(Vec<Vec<u8>>),
    /// A directory under `<gitdir>/modules` that is not itself a gitdir root — the namespace a
    /// submodule whose name contains a `/` creates.
    ///
    /// It exists because a submodule's name defaults to its *path*, so `libs/foo` puts the real
    /// gitdir at `modules/libs/foo` and leaves `modules/libs` holding nothing but other gitdirs.
    /// Names alone cannot say which of the two a directory is — `modules/a/b` is `a/b`'s gitdir if
    /// the submodule is at `a/b`, and `a`'s own subdirectory if it is at `a` — so this is the one
    /// position the core cannot derive, and [`gitdir_root`] is what the FUSE layer swaps in once it
    /// has looked. Protected until then, which is what stops a namespace being written into and so
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

/// UTF-8 encodings of the letters outside ASCII that a filesystem may compare equal to an ASCII
/// letter, with that letter. APFS resolves the last two to `k` and `s`, which `.ko-agent-sandbox`
/// has and `.git` has not (`doc/git-metadata.md`, "The name rule").
const FOLDS_TO_ASCII: &[(&[u8], u8)] = &[
    (b"\xc4\xb0", b'i'),     // U+0130 latin capital letter i with dot above
    (b"\xc4\xb1", b'i'),     // U+0131 latin small letter dotless i
    (b"\xe2\x84\xaa", b'k'), // U+212A kelvin sign
    (b"\xc5\xbf", b's'),     // U+017F latin small letter long s
];

/// Whether `name` (a raw basename, no slashes) must be refused as a new `.git` entry.
///
/// The rule as executed: strip trailing `.` and space, drop [`IGNORABLE`], fold
/// [`FOLDS_TO_ASCII`], ASCII case-fold, compare to `.git`. Byte-safe: a non-UTF-8 `name` fails to
/// match and is allowed, never a panic. Why each step: `doc/git-metadata.md`, "The name rule".
pub fn is_dotgit_name(name: &[u8]) -> bool {
    folds_to(name, GUARDED_NAMES[0])
}

/// Whether `name` must be refused as a new `.ko-agent-sandbox` entry — the launcher's own
/// boundary configuration, which a session must never write because the *next* launch reads it
/// (`SECURITY.md`, "A project loosening its own confinement"). This rule is the whole protection
/// in a writable session: the launcher mounts nothing over the directory.
///
/// At any depth, not only the workspace root, because a launch takes its policy from whatever
/// directory it starts in: a session at the repository root planting `apps/web/.ko-agent-sandbox`
/// would be writing boundary configuration for a later launch from `apps/web`. The host creates
/// these directories, as it creates repositories.
///
/// Folded exactly like `.git` and for the same reason: the launcher resolves the name on the host,
/// so a case-insensitive backing would find `.KO-AGENT-SANDBOX` under it.
pub fn is_sandbox_config_name(name: &[u8]) -> bool {
    folds_to(name, GUARDED_NAMES[1])
}

/// The names [`child_context`] gives a context of their own under an ordinary directory. The FUSE
/// layer stats these beside an ordinarily named entry, because a backing filesystem can give a
/// guarded entry a second name no fold predicts (`fs.rs`, `policy_name`).
pub const GUARDED_NAMES: [&[u8]; 2] = [b".git", b".ko-agent-sandbox"];

/// The single fold behind every reserved-name rule, so no two of them can disagree about what a
/// backing filesystem might treat as the same name. `target` is lowercase ASCII.
fn folds_to(name: &[u8], target: &[u8]) -> bool {
    fold(name) == target
}

/// `name` as a backing filesystem might compare it: `IGNORABLE` dropped, `FOLDS_TO_ASCII`
/// folded, trailing `.` and space stripped, ASCII lowercased. Byte-safe on non-UTF-8.
pub fn fold(name: &[u8]) -> Vec<u8> {
    let mut folded: Vec<u8> = Vec::with_capacity(name.len());
    let mut i = 0;
    'outer: while i < name.len() {
        for ignorable in IGNORABLE {
            if name[i..].starts_with(ignorable) {
                i += ignorable.len();
                continue 'outer;
            }
        }
        for (letter, ascii) in FOLDS_TO_ASCII {
            if name[i..].starts_with(letter) {
                folded.push(*ascii);
                i += letter.len();
                continue 'outer;
            }
        }
        folded.push(name[i]);
        i += 1;
    }

    let mut end = folded.len();
    while end > 0 && (folded[end - 1] == b'.' || folded[end - 1] == b' ') {
        end -= 1;
    }
    folded.truncate(end);
    folded.make_ascii_lowercase();
    folded
}

/// The context of a directory the FUSE layer has identified as a gitdir root in its own right. The
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
/// children become [`GitContext::ModuleNamespace`] until the FUSE layer says otherwise. Both compose
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
        GitContext::SandboxConfig => GitPathClass::Protected,
        GitContext::ModuleNamespace => GitPathClass::Protected,
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
/// directory under `modules/` then reads as a namespace — protected, the stricter answer.
pub fn classify_relative_path(rel: &[u8], gitdir_roots: &[&[u8]]) -> GitPathClass {
    classify(&context_of_relative_path(rel, gitdir_roots))
}

/// [`classify_relative_path`]'s walk, returning the context itself: the guard tells ordinary
/// project data ([`GitContext::NotGit`]) from a gitdir's writable state by it.
pub fn context_of_relative_path(rel: &[u8], gitdir_roots: &[&[u8]]) -> GitContext {
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
    context
}

/// Classify a path by its components *relative to the enclosing gitdir root*. Empty `components`
/// is the gitdir entry itself, which is protected (it holds the config and hooks).
///
/// Allowlist / fail-closed: `Operational` only for the enumerated writable set; everything else is
/// `Protected`. A git operational file we failed to enumerate breaks that git command loudly (the
/// integration suite catches it); a future git file that executes a command is denied by default.
///
/// This sees a path relative to one gitdir; [`child_context`] re-roots nested gitdirs before a path
/// can reach here, so no recursion is needed. The redirection files a worktree keeps at its own
/// root (`gitdir`, `commondir`, `config.worktree`) are covered below.
pub fn classify_within_gitdir(components: &[&[u8]]) -> GitPathClass {
    let first = match components.first() {
        None => return GitPathClass::Protected,
        Some(component) => *component,
    };

    match first {
        b"config" | b"config.worktree" => return GitPathClass::Protected,
        b"hooks" => return GitPathClass::Protected,
        b"commondir" | b"gitdir" => return GitPathClass::Protected,
        _ => {}
    }

    if first == b"objects" && components.len() > 2 && fold(components[1]) == b"info" {
        return classify_within_object_info(&components[2..]);
    }

    const OPERATIONAL_TREES: &[&[u8]] = &[
        b"objects", // except below `objects/info`: [`classify_within_object_info`]
        b"refs",
        b"logs",
        b"info",     // exclude/sparse-checkout/attributes patterns — data, never executed
        b"reftable", // the refs of a `--ref-format=reftable` repository
        b"NOTES_MERGE_WORKTREE",
        b"lost-found", // `git fsck --lost-found`
    ];
    if OPERATIONAL_TREES.contains(&first) {
        return GitPathClass::Operational;
    }

    // Deliberately NOT operational, though git writes them: `rebase-merge`, `rebase-apply`, and
    // `sequencer` hold the rebase/cherry-pick todo, whose `exec` lines a later host
    // `git rebase --continue` runs — a file whose content git executes, exactly like a hook. They
    // fall through to Protected below, so a rebase/am/sequenced cherry-pick cannot be left in
    // the workspace for the host to resume. This note marks the spot where they must not be added.
    //
    // Nor the bisect state (`BISECT_START`, `BISECT_LOG`, `BISECT_NAMES`, …): the host's git may be
    // older than the image's, and through git 2.33 `git bisect visualize` runs `eval` over
    // BISECT_NAMES (`git-bisect.sh`), so writing it plants shell code. `git bisect start` writes it
    // and BISECT_LOG every time, so bisecting does not work in the workspace.
    //
    // Nor `rr-cache` and `MERGE_RR`: with `rerere.enabled` unset, host git enables rerere when
    // `rr-cache` exists, so creating it switches on replaying recorded resolutions in host merges,
    // a switch that belongs to the protected config. Nor `lfs`: the image has no git-lfs, and its
    // downloads are refused.

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
            b"MERGE_AUTOSTASH",
            b"NOTES_MERGE_PARTIAL",
            b"NOTES_MERGE_REF",
            b"index",
            b"packed-refs",
            b"packed-refs.new", // renamed onto `packed-refs`, which every packed ref deletion rewrites
            b"COMMIT_EDITMSG",
            b"MERGE_MSG",
            b"MERGE_MODE",
            b"SQUASH_MSG",
            b"TAG_EDITMSG",
            b"NOTES_EDITMSG",
            b"EDIT_DESCRIPTION",
            b"ADD_EDIT.patch",
            b"REPLACE_EDITOBJ",
            b"shallow",
            b"BISECT_HEAD",
            b"gc.pid",
            // Host `git gc --auto` prints this through `warning()`, which replaces control
            // characters with `?` (git 2.20 and later).
            b"gc.log",
        ];
        if OPERATIONAL_FILES.contains(&first) || is_operational_scratch_name(first) {
            return GitPathClass::Operational;
        }
        // git writes `<name>.lock` beside anything it locks and renames it into place, so a lock
        // inherits its target's class: `HEAD.lock` and `AUTO_MERGE.lock` are operational, while
        // `config.lock` stays protected. Enumerating lockable names by hand instead freezes
        // whichever one it forgot — `AUTO_MERGE.lock`, breaking `git merge` (`doc/git-metadata.md`,
        // P2).
        if let Some(base) = first.strip_suffix(b".lock") {
            return classify_within_gitdir(&[base]);
        }
    }

    GitPathClass::Protected
}

/// Classify a path below a gitdir's `objects/info` by its components there: the allowlist of what
/// git writes in it for itself, the commit-graph and the dumb-HTTP pack list. What it leaves out is
/// protected, `alternates` and `http-alternates` among it:
///
/// - `alternates` names further object directories, and host git opens each one — a network path on
///   a host that reaches one by name, such as a Windows UNC path. Git writes it only when it
///   creates a repository (`git clone --shared` or `--reference`), which the session cannot do in
///   the project.
/// - `http-alternates` names object stores by URL for a client fetching this repository over dumb
///   HTTP; git never writes it.
///
/// [`is_pinned_within_gitdir`] keeps either from arriving inside a directory moved into place.
fn classify_within_object_info(components: &[&[u8]]) -> GitPathClass {
    let name = components[0];
    if name == b"commit-graphs" {
        return GitPathClass::Operational;
    }
    if components.len() == 1 {
        // `packs_XXXXXX` is `git update-server-info`'s temporary file, renamed onto `packs`.
        let packs_scratch = name.strip_prefix(b"packs_").is_some_and(|suffix| {
            suffix.len() == 6 && suffix.iter().all(u8::is_ascii_alphanumeric)
        });
        if name == b"commit-graph" || name == b"packs" || packs_scratch {
            return GitPathClass::Operational;
        }
        if let Some(base) = name.strip_suffix(b".lock") {
            return classify_within_object_info(&[base]);
        }
    }
    GitPathClass::Protected
}

/// A gitdir's `objects` and `objects/info` directories, which lead to `alternates`
/// ([`classify_within_object_info`]). Created only by `mkdir`, which starts them empty, and never
/// renamed or unlinked, so an `alternates` written in another directory cannot be moved into place.
/// `rmdir` stays allowed: it removes only an empty directory. Git never moves either directory.
fn is_pinned_within_gitdir(context: &GitContext) -> bool {
    let GitContext::InGit(rel) = context else {
        return false;
    };
    match rel.as_slice() {
        [objects] => objects == b"objects",
        [objects, info] => objects == b"objects" && fold(info) == b"info",
        _ => false,
    }
}

/// The temporary index and shallow files git names after its process or a random suffix beside
/// their permanent ones: `index.stash.<pid>` (`git stash`), `next-index-<pid>` (`git commit
/// <pathspec>`), `sharedindex.<hash>` and `sharedindex_XXXXXX` (a split index), `shallow_XXXXXX`
/// (a fetch into a shallow repository).
fn is_operational_scratch_name(name: &[u8]) -> bool {
    let all =
        |text: &[u8], accepted: fn(&u8) -> bool| !text.is_empty() && text.iter().all(accepted);
    if let Some(pid) = name
        .strip_prefix(b"index.stash.")
        .or_else(|| name.strip_prefix(b"next-index-"))
    {
        return all(pid, u8::is_ascii_digit);
    }
    if let Some(hash) = name.strip_prefix(b"sharedindex.") {
        return all(hash, u8::is_ascii_hexdigit);
    }
    name.strip_prefix(b"sharedindex_")
        .or_else(|| name.strip_prefix(b"shallow_"))
        .is_some_and(|suffix| suffix.len() == 6 && all(suffix, u8::is_ascii_alphanumeric))
}

/// Both the `.git` name rule (a new gitdir the host would discover) and the destination
/// classification (creating inside a protected tree) apply, and a pinned directory
/// ([`is_pinned_within_gitdir`]) is created only by `mkdir`.
pub fn authorize_create(parent_ctx: &GitContext, new_name: &[u8], is_mkdir: bool) -> Decision {
    if is_dotgit_name(new_name) {
        return Decision::Deny("protected-git-entry: refusing to create a .git entry");
    }
    // Name the launcher configuration in the refusal so the user checks it rather than Git
    // metadata.
    if is_sandbox_config_name(new_name) {
        return Decision::Deny(
            "protected-sandbox-config: refusing to create a .ko-agent-sandbox entry",
        );
    }
    if classify(&child_context(parent_ctx, new_name)) == GitPathClass::Protected {
        return Decision::Deny(match parent_ctx {
            GitContext::SandboxConfig => {
                "protected-sandbox-config: refusing to create inside .ko-agent-sandbox"
            }
            _ => "protected-git-control: refusing to create a protected Git entry",
        });
    }
    if !is_mkdir && is_pinned_within_gitdir(&child_context(parent_ctx, new_name)) {
        return Decision::Deny(
            "pinned-git-component: refusing to create a Git object directory except by mkdir",
        );
    }
    Decision::Allow
}

/// Creation — a rename's destination included — goes through [`authorize_create`] so the name rule
/// fires.
pub fn authorize(ctx: &GitContext, op: Mutation) -> Decision {
    if classify(ctx) != GitPathClass::Protected {
        if is_pinned_within_gitdir(ctx) && matches!(op, Mutation::Unlink | Mutation::RenameFrom) {
            return Decision::Deny(
                "pinned-git-component: refusing to rename or unlink a Git object directory",
            );
        }
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
            "protected-git-control: refusing to remove a protected Git entry"
        }
        (_, Mutation::RenameFrom) => {
            "protected-git-control: refusing to rename a protected Git entry"
        }
        (_, _) => "protected-git-control: refusing to modify a protected Git entry",
    })
}

// --- File rules ---------------------------------------------------------------
//
// The project files a host program executes on an event, not when the user builds or runs the project
// (`.ko-agent-sandbox/file/rule` over the launcher's defaults), decided for ordinary entries only:
// under a `.git` or `.ko-agent-sandbox` entry the rules above decide alone.

/// What a line does to the entry it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleWord {
    /// The entry and everything below it are read-only.
    ReadOnly,
    /// The entry and everything below it are writable: a writable region.
    Writable,
    /// The entry itself is pinned ([`RuleContext::pinned`]); the guard's traversed components.
    Pinned,
}

/// One resolved line. The launcher writes the rule lines, `readonly` and `writable`; the guard adds
/// the anchored ones, `readonly-path` and `pinned-path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLine {
    pub word: RuleWord,
    /// Folded components. In a floating line a `*` matches any run of bytes within one name; an
    /// anchored line's components are the names the guard found, matched exactly.
    pub components: Vec<Vec<u8>>,
    /// Matched from the workspace root only, where a floating line matches at any depth.
    pub anchored: bool,
}

/// The ordered lines, the defaults first, the project's next and the guard's last, so a line the
/// guard found decides over every rule line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileRules {
    lines: Vec<RuleLine>,
    /// `(line, context)`: an anchored `pinned-path` line naming the end of a symlink the guard
    /// followed, and the symlink's context, which that end and every entry below it get as well
    /// (`RuleContext::also`).
    aliases: Vec<(u32, RuleContext)>,
}

impl FileRules {
    pub fn new(lines: Vec<RuleLine>) -> FileRules {
        FileRules {
            lines,
            aliases: Vec::new(),
        }
    }

    /// Add an anchored `pinned-path` line for `path`, which, with every entry below it, also stands
    /// where `context` says: the directory `shared/claude` that `.claude -> shared/claude` makes
    /// `.claude`.
    pub fn push_alias(&mut self, path: &str, context: RuleContext) {
        self.aliases.push((self.lines.len() as u32, context));
        self.lines.push(RuleLine {
            word: RuleWord::Pinned,
            components: path
                .split('/')
                .map(|component| fold(component.as_bytes()))
                .collect(),
            anchored: true,
        });
    }

    pub fn lines(&self) -> &[RuleLine] {
        &self.lines
    }

    fn alias(&self, line: u32) -> Option<&RuleContext> {
        self.aliases
            .iter()
            .find(|(alias, _)| *alias == line)
            .map(|(_, context)| context)
    }

    fn word(&self, line: u32) -> RuleWord {
        self.lines[line as usize].word
    }
}

/// Where an ordinary entry stands under the file rules. Computed once per lookup from the
/// parent's and the folded name ([`child_rule_context`]) and cached on the inode, as
/// [`GitContext`] is; no inode stores a path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct RuleContext {
    /// `(line, matched)`: lines whose first `matched` components the entry and its nearest
    /// ancestors match, short of the whole line, and which could still decide or pin an entry
    /// below.
    partial: Vec<(u32, u32)>,
    /// The last line whose name matches the entry or one of its ancestors.
    deciding: Option<u32>,
    /// A `pinned-path` line names this entry.
    pinned_path: bool,
    /// The contexts of the other names a symlink gives the entry ([`FileRules::push_alias`]):
    /// `shared/claude/settings.json` is also `.claude/settings.json`. The entry is read-only or
    /// pinned when it is under any of its names.
    also: Vec<RuleContext>,
}

impl RuleContext {
    /// The workspace root's: no line names the root.
    pub fn root() -> RuleContext {
        RuleContext::default()
    }

    /// Whether the deciding line is `readonly` or a guard's `readonly-path`, under any of the
    /// entry's names (`also`).
    pub fn read_only(&self, rules: &FileRules) -> bool {
        self.deciding
            .is_some_and(|line| rules.word(line) == RuleWord::ReadOnly)
            || self.also.iter().any(|name| name.read_only(rules))
    }

    /// The `writable` line whose region the entry is in, if any.
    pub fn region(&self, rules: &FileRules) -> Option<u32> {
        self.deciding
            .filter(|&line| rules.word(line) == RuleWord::Writable)
    }

    /// Whether renaming, replacing or unlinking the entry could change what a line decides below
    /// it: the entry is an interior component of a line later than its own deciding line, a
    /// guard's traversed component, or either under another of its names (`also`). Renaming
    /// `.claude` to `saved`, writing `saved/settings.json` and renaming it back would otherwise
    /// defeat `readonly .claude/settings.json`.
    pub fn pinned(&self) -> bool {
        self.pinned_path || !self.partial.is_empty() || self.also.iter().any(RuleContext::pinned)
    }

    /// Whether the context can still make the entry or one below it read-only or pinned.
    fn decides_anything(&self, rules: &FileRules) -> bool {
        self.read_only(rules) || self.pinned()
    }

    /// The rests of the `readonly` lines the entry is an interior component of, under any of its
    /// names, as `/`-joined folded patterns: what a directory a symlink reaches under this name
    /// protects below it. A `writable` line lifting part of a rest is ignored, which is stricter.
    pub fn read_only_rests(&self, rules: &FileRules) -> Vec<String> {
        let mut rests: Vec<String> = self
            .partial
            .iter()
            .filter(|&&(line, _)| rules.word(line) == RuleWord::ReadOnly)
            .map(|&(line, matched)| {
                rules.lines[line as usize].components[matched as usize..]
                    .iter()
                    .map(|component| String::from_utf8_lossy(component).into_owned())
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .collect();
        for name in &self.also {
            rests.extend(name.read_only_rests(rules));
        }
        rests.sort();
        rests.dedup();
        rests
    }
}

/// Whether the folded `name` matches one folded pattern component, where `*` matches any run of
/// bytes. Iterative, with one backtrack point, so a pattern of many stars stays polynomial, never
/// exponential.
fn component_matches(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, n));
            p += 1;
        } else if p < pattern.len() && pattern[p] == name[n] {
            p += 1;
            n += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p + 1;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

/// A child's rule context from its parent's and its raw name. `parent_is_root` starts the
/// anchored lines, which match from the workspace root only. Called only for a child whose
/// [`child_context`] is [`GitContext::NotGit`].
pub fn child_rule_context(
    rules: &FileRules,
    parent: &RuleContext,
    parent_is_root: bool,
    name: &[u8],
) -> RuleContext {
    let mut child = RuleContext {
        partial: Vec::new(),
        deciding: parent.deciding,
        pinned_path: false,
        also: Vec::new(),
    };
    if rules.lines.is_empty() {
        return child;
    }
    for other in &parent.also {
        let below = child_rule_context(rules, other, false, name);
        if below.decides_anything(rules) && !child.also.contains(&below) {
            child.also.push(below);
        }
    }
    let folded = fold(name);
    let matches = |line: &RuleLine, component: usize| {
        let pattern = &line.components[component];
        if line.anchored {
            *pattern == folded
        } else {
            component_matches(pattern, &folded)
        }
    };
    let mut reached: Vec<(u32, u32)> = Vec::new();
    for &(line, matched) in &parent.partial {
        if matches(&rules.lines[line as usize], matched as usize) {
            reached.push((line, matched + 1));
        }
    }
    for (index, line) in rules.lines.iter().enumerate() {
        if (!line.anchored || parent_is_root) && matches(line, 0) {
            reached.push((index as u32, 1));
        }
    }
    for (line, matched) in reached {
        let rule = &rules.lines[line as usize];
        if matched as usize == rule.components.len() {
            match rule.word {
                RuleWord::Pinned => {
                    child.pinned_path = true;
                    if let Some(other) = rules.alias(line)
                        && !child.also.contains(other)
                    {
                        child.also.push(other.clone());
                    }
                }
                RuleWord::ReadOnly | RuleWord::Writable => {
                    child.deciding = child.deciding.max(Some(line));
                }
            }
        } else {
            child.partial.push((line, matched));
        }
    }
    // A line earlier than the deciding one decides nothing below it; a `pinned-path` line pins
    // regardless of what decides.
    let deciding = child.deciding;
    child.partial.retain(|&(line, _)| {
        rules.word(line) == RuleWord::Pinned || deciding.is_none_or(|decided| line > decided)
    });
    child.partial.sort_unstable();
    child.partial.dedup();
    child
}

/// The rule context of a workspace-relative path, walked from the root as lookups would, or
/// `None` where the path enters a `.git` or `.ko-agent-sandbox` entry, which the rules do not
/// decide. For a symlink's target ([`authorize_symlink_target`]) and for tests.
pub fn rule_context_of_path(rules: &FileRules, components: &[&[u8]]) -> Option<RuleContext> {
    let mut rule = RuleContext::root();
    for (depth, component) in components.iter().enumerate() {
        if child_context(&GitContext::NotGit, component) != GitContext::NotGit {
            return None;
        }
        rule = child_rule_context(rules, &rule, depth == 0, component);
    }
    Some(rule)
}

/// The rule decision for a mutation of an existing ordinary entry. Creation — a rename's
/// destination included — goes through [`authorize_rule_create`].
pub fn authorize_rule(rules: &FileRules, ctx: &RuleContext, op: Mutation) -> Decision {
    if ctx.read_only(rules) {
        return Decision::Deny(match op {
            Mutation::Unlink | Mutation::Rmdir => {
                "protected-file-rule: refusing to remove a file a host program executes"
            }
            Mutation::RenameFrom => {
                "protected-file-rule: refusing to rename a file a host program executes"
            }
            _ => "protected-file-rule: refusing to modify a file a host program executes",
        });
    }
    // `rmdir` stays allowed: it removes only an empty directory, and a later `mkdir` restores
    // the name with nothing below it.
    if ctx.pinned() && matches!(op, Mutation::Unlink | Mutation::RenameFrom) {
        return Decision::Deny(
            "pinned-file-rule-component: refusing to rename or unlink a component a file rule names",
        );
    }
    Decision::Allow
}

/// The rule decision for creating an ordinary entry whose context would be `child`. A read-only
/// name is refused whatever creates it, since a symlink or directory planted at the name would be
/// what the host program reads next; a pinned name only by `mkdir`, which starts it empty.
pub fn authorize_rule_create(rules: &FileRules, child: &RuleContext, is_mkdir: bool) -> Decision {
    if child.read_only(rules) {
        return Decision::Deny(
            "protected-file-rule: refusing to create a name a host program executes",
        );
    }
    if child.pinned() && !is_mkdir {
        return Decision::Deny(
            "pinned-file-rule-component: refusing to create a component a file rule names, \
             except by mkdir",
        );
    }
    Decision::Allow
}

/// A directory or symlink moving from `from` to `to`, by rename, exchange or a hard link of a
/// symlink. A writable region holds names the other lines protect, so what leaves it would carry
/// them to where those lines decide: moving `node_modules/x`, whose `.vscode/tasks.json` the
/// session wrote, to `apps/x`. A gitdir's operational state, where no line decides, holds such
/// names too: `.git/objects/x` moved to `apps/x` would carry the same file. Git itself never moves
/// an entry out of a gitdir into the worktree.
pub fn authorize_region_move(
    rules: &FileRules,
    (from_git, from): (&GitContext, &RuleContext),
    (to_git, to): (&GitContext, &RuleContext),
) -> Decision {
    if *to_git != GitContext::NotGit {
        return Decision::Allow;
    }
    if *from_git != GitContext::NotGit {
        return if rules.lines.is_empty() {
            Decision::Allow
        } else {
            Decision::Deny(
                "file-rule-region: refusing to move a directory or symlink out of a Git \
                 directory into the project",
            )
        };
    }
    match from.region(rules) {
        Some(line) if to.deciding != Some(line) => Decision::Deny(
            "file-rule-region: refusing to move a directory or symlink out of a writable region",
        ),
        _ => Decision::Allow,
    }
}

/// The workspace-relative paths a symlink `target` passes through, resolved lexically from the
/// link's directory `from`: one after each component that names an entry, the end included. The
/// host resolves a symlink met on the way, so a `..` after it leaves from wherever that symlink
/// leads: `../node_modules/s/../../x` ends lexically at `x`, while through `node_modules/s ->
/// pkg/sub` it reaches `node_modules/x`. Each of these paths is checked, not the end alone.
pub fn symlink_target_paths(from: &[Vec<u8>], target: &std::path::Path) -> Vec<Vec<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;
    let mut resolved = from.to_vec();
    let mut paths = Vec::new();
    for component in target.components() {
        match component {
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(part) => {
                resolved.push(part.as_bytes().to_vec());
                paths.push(resolved.clone());
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    paths
}

/// Whether a path a symlink target passes enters a gitdir: its first `.git` or `.ko-agent-sandbox`
/// component is a `.git` one. `apps/x -> ../.git/objects/x` would show what the session wrote
/// there, `.vscode/tasks.json` among it, under an ordinary name. A link to a protected gitdir entry
/// counts too: `apps/hooks -> ../.git/hooks` would let `apps/web -> hooks/../objects/x` reach
/// `.git/objects/x`.
pub fn enters_gitdir(components: &[&[u8]]) -> bool {
    components
        .iter()
        .find(|component| child_context(&GitContext::NotGit, component) != GitContext::NotGit)
        .is_some_and(|component| is_dotgit_name(component))
}

/// A symlink at `link` whose target, resolved lexically, has the context `target`. The same route
/// as [`authorize_region_move`] without a move: `apps/x -> ../node_modules/x` makes the region's
/// content readable as `apps/x`. A link inside the region to the region, npm's
/// `node_modules/.bin`, stays allowed.
pub fn authorize_symlink_target(
    rules: &FileRules,
    link: &RuleContext,
    target: &RuleContext,
) -> Decision {
    match target.region(rules) {
        Some(line) if link.deciding != Some(line) => Decision::Deny(
            "file-rule-region: refusing a symlink into a writable region from outside it",
        ),
        _ => Decision::Allow,
    }
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
    fn letters_apfs_resolves_to_k_and_s_are_the_launcher_configuration_name() {
        // Measured on APFS (`doc/verification-log.md`): each spelling resolves to an existing
        // `.ko-agent-sandbox`. Looked up as well as created: an access through the spelling
        // reaches a directory the host made, which only its classification protects.
        for name in [
            ".\u{212a}o-agent-sandbox",
            ".ko-agent-\u{17f}andbox",
            ".\u{212a}O-AGENT-\u{17f}ANDBOX",
        ] {
            assert!(is_sandbox_config_name(name.as_bytes()), "{name:?}");
            assert_eq!(
                classify_relative_path(format!("apps/{name}/egress/rule").as_bytes(), &[]),
                GitPathClass::Protected,
                "{name:?}"
            );
            assert!(matches!(
                authorize_create(&GitContext::NotGit, name.as_bytes(), false),
                Decision::Deny(_)
            ));
        }
        // A lone lead byte of either sequence is not the letter.
        assert!(!is_sandbox_config_name(b".\xe2\x84o-agent-sandbox"));
        assert!(!is_sandbox_config_name(b".ko-agent-\xc5andbox"));
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
    fn the_launcher_configuration_is_protected_at_every_depth() {
        // Unlike a gitdir it has no operational half, so depth changes nothing.
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox", &[]),
            GitPathClass::Protected
        );
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox/egress", &[]),
            GitPathClass::Protected
        );
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox/egress/rule", &[]),
            GitPathClass::Protected
        );
        assert_eq!(
            classify_relative_path(b"apps/web/.ko-agent-sandbox/egress/rule", &[]),
            GitPathClass::Protected
        );
        // A repository below it is the launcher's own business, not a candidate to re-root into a
        // gitdir with a writable objects/.
        assert_eq!(
            classify_relative_path(b".ko-agent-sandbox/.git/objects/ab/cdef", &[]),
            GitPathClass::Protected
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
            authorize_create(&root, b".ko-agent-sandbox", false),
            Decision::Deny(
                "protected-sandbox-config: refusing to create a .ko-agent-sandbox entry"
            )
        );
        assert_eq!(
            authorize_create(&GitContext::SandboxConfig, b"egress", false),
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
        // Every variant `Mutation` has, listed by hand: a new variant needs a row here. A
        // rename's destination is not among them: it creates a name, so it goes
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
    fn a_directory_under_modules_is_a_namespace_until_the_fuse_layer_says_otherwise() {
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
            GitPathClass::Protected
        );
        assert!(matches!(
            authorize_create(&GitContext::ModuleNamespace, b"HEAD", false),
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
        // components below `modules` — and once the FUSE layer has identified it, everything under it
        // classifies exactly as a top-level submodule's does.
        let namespace = child_context(&ingit(&[b"modules"]), b"libs");
        assert_eq!(namespace, GitContext::ModuleNamespace);
        let foo = gitdir_root(); // what the FUSE layer swaps in for `.git/modules/libs/foo`
        for (name, expected) in [
            (b"objects".as_slice(), GitPathClass::Operational),
            (b"refs", GitPathClass::Operational),
            (b"HEAD", GitPathClass::Operational),
            (b"index", GitPathClass::Operational),
            (b"config", GitPathClass::Protected),
            (b"hooks", GitPathClass::Protected),
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
        // one-component name is what the FUSE layer's answer amounts to.
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
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&child_context(&foo, b"hooks")),
            GitPathClass::Protected
        );
    }

    #[test]
    fn a_worktree_gitdir_re_roots_and_its_redirections_are_protected() {
        let worktrees = ingit(&[b"worktrees"]);
        let wt = child_context(&worktrees, b"feature"); // .git/worktrees/feature
        assert_eq!(wt, ingit(&[]));
        assert_eq!(
            classify(&child_context(&wt, b"HEAD")),
            GitPathClass::Operational
        );
        assert_eq!(
            classify(&child_context(&wt, b"gitdir")),
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&child_context(&wt, b"commondir")),
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&child_context(&wt, b"config.worktree")),
            GitPathClass::Protected
        );
    }

    // --- Classification -----------------------------------------------------

    #[test]
    fn outside_a_gitdir_everything_is_operational() {
        assert_eq!(classify(&GitContext::NotGit), GitPathClass::Operational);
    }

    #[test]
    fn the_gitdir_entry_and_protected_files_are_protected() {
        assert_eq!(classify(&ingit(&[])), GitPathClass::Protected);
        assert_eq!(classify(&ingit(&[b"config"])), GitPathClass::Protected);
        assert_eq!(
            classify(&ingit(&[b"config.worktree"])),
            GitPathClass::Protected
        );
        assert_eq!(classify(&ingit(&[b"commondir"])), GitPathClass::Protected);
    }

    #[test]
    fn hooks_are_protected_at_every_depth() {
        assert_eq!(classify(&ingit(&[b"hooks"])), GitPathClass::Protected);
        assert_eq!(
            classify(&ingit(&[b"hooks", b"pre-commit"])),
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&ingit(&[b"hooks", b"nested", b"x"])),
            GitPathClass::Protected
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
        // A protected entry's lock is protected, and a lock on an unknown name stays fail-closed.
        assert_eq!(classify(&ingit(&[b"config.lock"])), GitPathClass::Protected);
        assert_eq!(
            classify(&ingit(&[b"config.worktree.lock"])),
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&ingit(&[b"unknown-thing.lock"])),
            GitPathClass::Protected
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
    fn in_objects_info_only_what_git_writes_is_writable() {
        let info = |rest: &[&[u8]]| {
            let mut components: Vec<&[u8]> = vec![b"objects", b"info"];
            components.extend_from_slice(rest);
            classify(&ingit(&components))
        };
        assert_eq!(info(&[]), GitPathClass::Operational);
        for name in [
            b"commit-graph".as_slice(),
            b"commit-graph.lock",
            b"packs",
            b"packs_Ab12Cd",
        ] {
            assert_eq!(
                info(&[name]),
                GitPathClass::Operational,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        assert_eq!(
            info(&[b"commit-graphs", b"commit-graph-chain.lock"]),
            GitPathClass::Operational
        );
        for name in [
            b"alternates".as_slice(),
            b"alternates.lock",
            b"http-alternates",
            b"ALTERNATES",
            b"ALTERN~1",
            b"packs_12345",
            b"some-future-file",
        ] {
            assert_eq!(
                info(&[name]),
                GitPathClass::Protected,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        // A case-insensitive backing reaches `info` as `INFO` too.
        assert_eq!(
            classify(&ingit(&[b"objects", b"INFO", b"alternates"])),
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&ingit(&[b"objects", b"ab", b"alternates"])),
            GitPathClass::Operational
        );
    }

    #[test]
    fn unknown_gitdir_paths_are_protected_fail_closed() {
        assert_eq!(classify(&ingit(&[b"description"])), GitPathClass::Protected);
        assert_eq!(
            classify(&ingit(&[b"some-future-exec-file"])),
            GitPathClass::Protected
        );
        assert_eq!(classify(&ingit(&[b"config.lock"])), GitPathClass::Protected);
        assert_eq!(
            classify(&ingit(&[b"HEAD", b"child"])),
            GitPathClass::Protected
        );
    }

    #[test]
    fn rebase_and_sequencer_state_is_protected_because_its_todo_can_exec() {
        // Why they are not operational: the "Deliberately NOT operational" note in
        // `classify_within_gitdir`, at the rule this tests.
        assert_eq!(
            classify(&ingit(&[b"rebase-merge", b"git-rebase-todo"])),
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&ingit(&[b"rebase-apply", b"0001"])),
            GitPathClass::Protected
        );
        assert_eq!(
            classify(&ingit(&[b"sequencer", b"todo"])),
            GitPathClass::Protected
        );
    }

    // --- Authorization ------------------------------------------------------

    #[test]
    fn creating_dotgit_is_denied_anywhere() {
        assert!(matches!(
            authorize_create(&GitContext::NotGit, b".git", false),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&GitContext::NotGit, b".GIT", false),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&ingit(&[b"refs"]), b".git", false),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn creating_ordinary_files_is_allowed() {
        assert_eq!(
            authorize_create(&GitContext::NotGit, b"main.rs", false),
            Decision::Allow
        );
        assert_eq!(
            authorize_create(&GitContext::NotGit, b".gitignore", false),
            Decision::Allow
        );
        assert_eq!(
            authorize_create(&ingit(&[b"refs", b"heads"]), b"feature", false),
            Decision::Allow
        );
    }

    #[test]
    fn creating_protected_entries_inside_a_gitdir_is_denied() {
        assert!(matches!(
            authorize_create(&ingit(&[]), b"config", false),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&ingit(&[]), b"hooks", false),
            Decision::Deny(_)
        ));
        assert!(matches!(
            authorize_create(&ingit(&[b"hooks"]), b"pre-commit", false),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn the_directories_leading_to_alternates_are_created_only_by_mkdir_and_never_moved() {
        let objects = ingit(&[b"objects"]);
        for (parent, name) in [
            (ingit(&[]), b"objects".as_slice()),
            (objects.clone(), b"info"),
        ] {
            assert_eq!(authorize_create(&parent, name, true), Decision::Allow);
            assert!(matches!(
                authorize_create(&parent, name, false),
                Decision::Deny(_)
            ));
        }
        assert!(matches!(
            authorize_create(&objects, b"INFO", false),
            Decision::Deny(_)
        ));
        for pinned in [objects.clone(), ingit(&[b"objects", b"info"])] {
            for op in [Mutation::Unlink, Mutation::RenameFrom] {
                assert!(
                    matches!(authorize(&pinned, op), Decision::Deny(_)),
                    "{op:?}"
                );
            }
            for op in [Mutation::Rmdir, Mutation::SetAttr] {
                assert_eq!(authorize(&pinned, op), Decision::Allow, "{op:?}");
            }
        }
        // Below them, and beside them, entries move as other operational state does.
        assert_eq!(
            authorize(&ingit(&[b"objects", b"pack"]), Mutation::RenameFrom),
            Decision::Allow
        );
        assert_eq!(
            authorize_create(&ingit(&[b"objects", b"info"]), b"commit-graph", false),
            Decision::Allow
        );
    }

    #[test]
    fn mutating_protected_entries_is_denied_for_every_op() {
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

    // --- File rules ---------------------------------------------------------
    //
    // What each context means is the conformance table's (`tests/file_rules.rs`); these hold what
    // the FUSE layer asks of a context.

    fn floating(word: RuleWord, name: &str) -> RuleLine {
        RuleLine {
            word,
            components: name.split('/').map(|c| c.as_bytes().to_vec()).collect(),
            anchored: false,
        }
    }

    fn defaults_like() -> FileRules {
        FileRules::new(vec![
            floating(RuleWord::ReadOnly, ".vscode"),
            floating(RuleWord::ReadOnly, ".claude/settings.json"),
            floating(RuleWord::Writable, "node_modules"),
        ])
    }

    fn at(rules: &FileRules, path: &str) -> RuleContext {
        let components: Vec<&[u8]> = path.split('/').map(str::as_bytes).collect();
        rule_context_of_path(rules, &components).expect("an ordinary path")
    }

    #[test]
    fn a_star_matches_any_run_within_one_component_and_nothing_else_is_a_wildcard() {
        assert!(component_matches(b"*.code-workspace", b"a.code-workspace"));
        assert!(component_matches(b"*.code-workspace", b".code-workspace"));
        assert!(component_matches(b"mise.*.toml", b"mise.local.toml"));
        assert!(component_matches(b"mise.*.toml", b"mise.a.b.toml"));
        assert!(!component_matches(b"mise.*.toml", b"mise.toml"));
        assert!(component_matches(b"*", b""));
        assert!(component_matches(b"a**b", b"ab"));
        assert!(!component_matches(b"lefthook.*", b"lefthook"));
        assert!(!component_matches(b".vscode", b".vscodex"));
        assert!(!component_matches(b"a?c", b"abc"));
        assert!(!component_matches(b"[ab]", b"a"));
    }

    #[test]
    fn a_read_only_entry_refuses_every_mutation_and_its_creation_by_any_means() {
        let rules = defaults_like();
        let tasks = at(&rules, ".vscode/tasks.json");
        for op in [
            Mutation::Write,
            Mutation::SetAttr,
            Mutation::Unlink,
            Mutation::Rmdir,
            Mutation::RenameFrom,
            Mutation::Link,
        ] {
            assert!(
                matches!(authorize_rule(&rules, &tasks, op), Decision::Deny(_)),
                "{op:?}",
            );
        }
        let fresh = at(&rules, "apps/.vscode");
        assert!(matches!(
            authorize_rule_create(&rules, &fresh, true),
            Decision::Deny(_),
        ));
        assert!(matches!(
            authorize_rule_create(&rules, &fresh, false),
            Decision::Deny(_),
        ));
    }

    #[test]
    fn a_pinned_entry_is_created_only_by_mkdir_and_never_renamed_or_unlinked() {
        let rules = defaults_like();
        let claude = at(&rules, ".claude");
        assert!(claude.pinned() && !claude.read_only(&rules));
        assert_eq!(
            authorize_rule_create(&rules, &claude, true),
            Decision::Allow,
        );
        assert!(matches!(
            authorize_rule_create(&rules, &claude, false),
            Decision::Deny(_),
        ));
        for op in [Mutation::RenameFrom, Mutation::Unlink] {
            assert!(
                matches!(authorize_rule(&rules, &claude, op), Decision::Deny(_)),
                "{op:?}",
            );
        }
        // Emptied, it may go: `mkdir` brings the name back with nothing below it.
        for op in [Mutation::Rmdir, Mutation::Write, Mutation::SetAttr] {
            assert_eq!(
                authorize_rule(&rules, &claude, op),
                Decision::Allow,
                "{op:?}",
            );
        }
        // Its other children are ordinary.
        let notes = at(&rules, ".claude/notes.md");
        assert_eq!(
            authorize_rule(&rules, &notes, Mutation::Write),
            Decision::Allow,
        );
    }

    #[test]
    fn a_directory_a_symlink_reaches_under_a_line_s_name_stands_under_both_names() {
        // `.claude -> shared/claude` and `.vscode/claude` reached as `.claude` too.
        let mut rules = FileRules::new(vec![
            floating(RuleWord::ReadOnly, ".vscode"),
            floating(RuleWord::ReadOnly, ".claude/*.json"),
            floating(RuleWord::Writable, ".claude/x.json"),
        ]);
        let claude = at(&rules, ".claude");
        rules.push_alias("shared/claude", claude.clone());
        rules.push_alias(".vscode/claude", claude.clone());
        // What the session would create there is what the host reads as `.claude/y.json`.
        assert!(at(&rules, "shared/claude/y.json").read_only(&rules));
        assert!(at(&rules, "shared/claude").pinned());
        // The name's own later line lifts under that name, and nothing else is protected.
        assert!(!at(&rules, "shared/claude/x.json").read_only(&rules));
        assert!(!at(&rules, "shared/claude/notes.md").read_only(&rules));
        assert!(!at(&rules, "shared/other/y.json").read_only(&rules));
        // A lift under one name does not lift what the other name protects.
        assert!(at(&rules, ".vscode/claude/x.json").read_only(&rules));
        assert_eq!(claude.read_only_rests(&rules), vec!["*.json".to_string()]);
    }

    #[test]
    fn a_directory_or_symlink_does_not_leave_a_writable_region() {
        let rules = defaults_like();
        let ordinary = GitContext::NotGit;
        let inside = at(&rules, "node_modules/inflection");
        let also_inside = at(&rules, "node_modules/.inflection-retired");
        let outside = at(&rules, "apps/inflection");
        assert_eq!(inside.region(&rules), Some(2));
        assert!(matches!(
            authorize_region_move(&rules, (&ordinary, &inside), (&ordinary, &outside)),
            Decision::Deny(_),
        ));
        // npm's own renames stay inside the one region.
        assert_eq!(
            authorize_region_move(&rules, (&ordinary, &inside), (&ordinary, &also_inside)),
            Decision::Allow,
        );
        // Moving in carries nothing a line protects out of anywhere.
        assert_eq!(
            authorize_region_move(&rules, (&ordinary, &outside), (&ordinary, &inside)),
            Decision::Allow,
        );
        // The region's root itself: renamed, it would take the region's content with it.
        let root_entry = at(&rules, "node_modules");
        let renamed = at(&rules, "node_modules.bak");
        assert!(matches!(
            authorize_region_move(&rules, (&ordinary, &root_entry), (&ordinary, &renamed)),
            Decision::Deny(_),
        ));
    }

    #[test]
    fn a_symlink_target_path_entering_a_gitdir_is_told_from_one_that_does_not() {
        let path = |text: &'static str| -> Vec<&'static [u8]> {
            text.split('/').map(str::as_bytes).collect()
        };
        for entering in [
            ".git",
            ".GIT",
            ".git/config",
            ".git/objects/x",
            "sub/.git/hooks",
        ] {
            assert!(enters_gitdir(&path(entering)), "{entering}");
        }
        for other in [
            "apps/x",
            ".gitignore",
            ".ko-agent-sandbox",
            ".ko-agent-sandbox/file",
        ] {
            assert!(!enters_gitdir(&path(other)), "{other}");
        }
    }

    #[test]
    fn a_directory_or_symlink_does_not_leave_a_gitdir_for_the_project_under_file_rules() {
        let staged = GitContext::InGit(vec![b"objects".to_vec(), b"x".to_vec()]);
        let packed = GitContext::InGit(vec![b"objects".to_vec(), b"pack".to_vec()]);
        let ordinary = GitContext::NotGit;
        let root = RuleContext::root();
        let rules = defaults_like();
        let apps = at(&rules, "apps/x");
        assert!(matches!(
            authorize_region_move(&rules, (&staged, &root), (&ordinary, &apps)),
            Decision::Deny(_),
        ));
        // Git's own renames stay inside the gitdir; moving in carries nothing out.
        assert_eq!(
            authorize_region_move(&rules, (&staged, &root), (&packed, &root)),
            Decision::Allow,
        );
        assert_eq!(
            authorize_region_move(&rules, (&ordinary, &apps), (&staged, &root)),
            Decision::Allow,
        );
        // Without lines there is nothing to carry past.
        assert_eq!(
            authorize_region_move(&FileRules::default(), (&staged, &root), (&ordinary, &root)),
            Decision::Allow,
        );
    }

    #[test]
    fn a_symlink_into_a_writable_region_is_refused_from_outside_it_only() {
        let rules = defaults_like();
        let target = at(&rules, "node_modules/typescript/bin/tsc");
        let bin_link = at(&rules, "node_modules/.bin/tsc");
        let apps_link = at(&rules, "apps/x");
        assert_eq!(
            authorize_symlink_target(&rules, &bin_link, &target),
            Decision::Allow,
        );
        assert!(matches!(
            authorize_symlink_target(&rules, &apps_link, &target),
            Decision::Deny(_),
        ));
        let plain = at(&rules, "src/lib");
        assert_eq!(
            authorize_symlink_target(&rules, &apps_link, &plain),
            Decision::Allow,
        );
    }

    #[test]
    fn a_symlink_target_is_checked_at_every_path_it_passes_not_its_lexical_end_alone() {
        let from = vec![b"apps".to_vec()];
        let paths = symlink_target_paths(&from, std::path::Path::new("../node_modules/s/../../x"));
        let spelled: Vec<String> = paths
            .iter()
            .map(|path| String::from_utf8(path.join(&b'/')).unwrap())
            .collect();
        assert_eq!(spelled, ["node_modules", "node_modules/s", "x"]);
        // `node_modules/s` may be a symlink inside the region; the path through it is refused.
        let rules = defaults_like();
        let apps_link = at(&rules, "apps/x");
        assert!(matches!(
            authorize_symlink_target(&rules, &apps_link, &at(&rules, "node_modules/s")),
            Decision::Deny(_),
        ));
    }

    #[test]
    fn the_rules_do_not_reach_into_git_or_launcher_configuration() {
        let rules = FileRules::new(vec![floating(RuleWord::Writable, "*")]);
        assert_eq!(rule_context_of_path(&rules, &[b".git", b"config"]), None);
        assert_eq!(
            rule_context_of_path(&rules, &[b"apps", b".ko-agent-sandbox"]),
            None,
        );
    }

    #[test]
    fn without_rules_nothing_is_decided() {
        let rules = FileRules::default();
        let context = at(&rules, ".vscode/tasks.json");
        assert_eq!(context, RuleContext::root());
        assert_eq!(
            authorize_rule(&rules, &context, Mutation::Write),
            Decision::Allow,
        );
        assert_eq!(
            authorize_rule_create(&rules, &context, false),
            Decision::Allow,
        );
    }
}
