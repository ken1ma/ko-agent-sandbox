//! Startup guards: the conditions under which the filter refuses to mount at all, and what it
//! protects beyond names — the file rules' anchored paths.
//!
//! The binding rule and the snapshot argument are `doc/git-metadata.md`, "Relocated hook
//! directories"; the scope gap — root repository only, once, before the mount — is `SECURITY.md`.
//! What the walk below listed entries protects is `../../doc/file-rules.md`, "What is
//! read-only", and `SECURITY.md`, "A host program executing a project file on an event".

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::policy::{
    FileRules, GitContext, GitPathClass, RuleContext, RuleWord, child_context, child_rule_context,
    classify, context_of_relative_path,
};

/// Symlink hops before resolution refuses as a loop — the kernel's own SYMLOOP_MAX.
const MAX_SYMLINK_HOPS: usize = 40;

/// Why the filter refused to serve a backing tree. Rendered for the operator, who has to act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    pub remedy: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}\n{}", self.reason, self.remedy)
    }
}

/// What the guard adds to the file rules, as workspace-relative paths spelled as the host spells
/// them: the directories and files a chain from a hook setting ends at, read-only whole, the
/// components a chain traverses, pinned, and the end of a chain from a symlink the rules reach,
/// with that symlink's context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Additions {
    pub read_only: BTreeSet<String>,
    pub pinned: BTreeSet<String>,
    pub aliases: Vec<(String, RuleContext)>,
}

impl Additions {
    /// The anchored lines, read-only roots first, for [`crate::rulefile::RuleFile::with_additions`].
    pub fn lines(&self) -> Vec<(RuleWord, String)> {
        self.read_only
            .iter()
            .map(|path| (RuleWord::ReadOnly, path.clone()))
            .chain(
                self.pinned
                    .iter()
                    .map(|path| (RuleWord::Pinned, path.clone())),
            )
            .collect()
    }
}

/// Refuse the tree, or say what the mount protects beyond names: the relocated hook directories
/// and the ends of symlinks at or below the entries `rules` make read-only or pin. `host_view`
/// names the directories whose objects the daemon sees as the host does; a chain leaving them
/// refuses.
pub fn resolve(
    backing_root: &Path,
    rules: &FileRules,
    host_view: &[PathBuf],
) -> Result<Additions, Refusal> {
    let root = backing_root.canonicalize().map_err(|err| Refusal {
        reason: format!("cannot canonicalize the backing directory {backing_root:?}: {err}"),
        remedy: "The filter will not serve a tree it cannot resolve.".to_string(),
    })?;

    let mut workspace = Workspace::open(root, host_view.to_vec(), rules.clone())?;
    match workspace.locate_gitdir()? {
        Some(gitdir) => workspace.check_repository(&gitdir)?,
        None => workspace.check_bare_root()?,
    }
    workspace.walk_listed()?;
    Ok(workspace.additions)
}

/// Whether a workspace component a chain traverses refuses the tree or is recorded: a hook
/// directory is served read-only and a listed entry's target gets the entry's context; anything
/// else refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnOrdinary {
    Refuse,
    Record,
}

/// A resolved chain: where it ends, whether that exists, and the ordinary workspace components
/// it traversed, the end included when it is one.
struct Chain {
    end: PathBuf,
    exists: bool,
    traversed: Vec<PathBuf>,
}

struct Workspace {
    root: PathBuf,
    /// Submodule gitdir roots as workspace-relative byte paths — discovered by the `HEAD` each
    /// gitdir holds, the same question the FUSE layer asks of the tree (`fs.rs`, `is_gitdir_root`),
    /// so this guard's `Protected` means the runtime's `Protected`. Without them, everything under
    /// `modules/` would read as namespace — Protected, and so *exempt* here — while the runtime
    /// serves an identified gitdir's `objects/` writable: the fail-open direction, closed by asking
    /// the tree the same question at the same answer.
    gitdir_roots: Vec<Vec<u8>>,
    /// `resolve`'s `host_view`.
    host_view: Vec<PathBuf>,
    /// The rule lines, which decide what the walk descends into and what needs no addition.
    rules: FileRules,
    additions: Additions,
}

impl Workspace {
    fn open(
        root: PathBuf,
        host_view: Vec<PathBuf>,
        rules: FileRules,
    ) -> Result<Workspace, Refusal> {
        let mut workspace = Workspace {
            root,
            gitdir_roots: Vec::new(),
            host_view,
            rules,
            additions: Additions::default(),
        };
        let modules = workspace.root.join(".git/modules");
        workspace.collect_gitdir_roots(&modules, b".git/modules", 0)?;
        Ok(workspace)
    }

    /// Walk the submodule namespace exactly as the runtime classifies it: a directory under
    /// `modules/` is a namespace until it holds a regular `HEAD`, which makes it a gitdir root;
    /// a nested submodule's namespace re-enters only at that gitdir's own `modules/`. A blind
    /// find-every-HEAD would over-collect — `refs/remotes/origin/HEAD` is a regular file inside
    /// state the runtime never asks the root question about.
    fn collect_gitdir_roots(
        &mut self,
        dir: &Path,
        rel: &[u8],
        depth: usize,
    ) -> Result<(), Refusal> {
        if depth > 32 {
            return Err(Refusal {
                reason: format!("{dir:?} nests submodule namespaces deeper than 32 levels"),
                remedy: "The guard will not classify a tree it cannot finish mapping.".to_string(),
            });
        }
        let entries = match fs::read_dir(dir) {
            // NotADirectory is an absence too: a pointer-file `.git` has no modules tree of its
            // own — the real gitdir's modules tree is under the directory locate_gitdir accepted.
            Err(err)
                if err.kind() == ErrorKind::NotFound || err.kind() == ErrorKind::NotADirectory =>
            {
                return Ok(());
            }
            Err(err) => {
                return Err(Refusal {
                    reason: format!("cannot enumerate the submodule gitdirs under {dir:?}: {err}"),
                    remedy: "The guard classifies paths by these roots and will not guess at them."
                        .to_string(),
                });
            }
            Ok(entries) => entries,
        };
        for entry in entries {
            let entry = entry.map_err(|err| Refusal {
                reason: format!("cannot enumerate the submodule gitdirs under {dir:?}: {err}"),
                remedy: "The guard classifies paths by these roots and will not guess at them."
                    .to_string(),
            })?;
            let file_type = entry.file_type().map_err(|err| Refusal {
                reason: format!("cannot read {:?}: {err}", entry.path()),
                remedy: "The guard classifies paths by these roots and will not guess at them."
                    .to_string(),
            })?;
            if file_type.is_symlink() {
                return Err(Refusal {
                    reason: format!("{:?} is a symlink", entry.path()),
                    remedy: "The guard will not map submodule gitdirs through a symlink."
                        .to_string(),
                });
            }
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let child_rel = [rel, b"/", name.as_bytes()].concat();
            let head = entry.path().join("HEAD");
            let is_root = match fs::symlink_metadata(&head) {
                Ok(metadata) => metadata.is_file(),
                Err(err) if err.kind() == ErrorKind::NotFound => false,
                Err(err) => {
                    return Err(Refusal {
                        reason: format!("cannot read {head:?}: {err}"),
                        remedy: "The guard classifies paths by these roots and will not guess at \
                                 them."
                            .to_string(),
                    });
                }
            };
            if is_root {
                let nested_rel = [child_rel.as_slice(), b"/modules"].concat();
                let nested_dir = entry.path().join("modules");
                self.gitdir_roots.push(child_rel);
                self.collect_gitdir_roots(&nested_dir, &nested_rel, depth + 1)?;
            } else {
                self.collect_gitdir_roots(&entry.path(), &child_rel, depth + 1)?;
            }
        }
        Ok(())
    }

    /// The path's workspace-relative bytes when it lies strictly inside the root; `None` for the
    /// root itself and everything outside. The root as a traversed component needs no check: its
    /// own name is in its parent directory, which the mount never serves.
    fn relative_bytes(&self, path: &Path) -> Option<Vec<u8>> {
        let rel = path.strip_prefix(&self.root).ok()?;
        if rel.as_os_str().is_empty() {
            return None;
        }
        Some(rel.as_os_str().as_bytes().to_vec())
    }

    fn refuse_operational(&self, subject: &str, component: &Path) -> Refusal {
        Refusal {
            reason: format!(
                "{subject} resolves through {component:?}, inside the workspace and writable by \
                 the sandbox"
            ),
            remedy: "Hooks, configuration and object stores reachable through a writable \
                     workspace path would be writable by the sandbox and used by your git. Move \
                     them outside it; hooks and configuration can also go under the repository's \
                     protected .git state."
                .to_string(),
        }
    }

    fn refuse_unverifiable(&self, subject: &str, component: &Path) -> Refusal {
        Refusal {
            reason: format!(
                "{subject} resolves through {component:?}, outside the workspace and outside the \
                 directories the podman machine shares with the host",
            ),
            remedy: "The filter runs in the podman machine and cannot tell whether the host \
                     follows that path back into the workspace. Replace the link or setting with \
                     a real file or directory, inside the workspace or under a shared directory."
                .to_string(),
        }
    }

    /// Whether the daemon sees `path`, outside the workspace, as the host does: under a
    /// `host_view` directory, or an ancestor of one that the chain only passes through.
    fn verifiable(&self, path: &Path, passing_through: bool) -> bool {
        self.host_view
            .iter()
            .any(|view| path.starts_with(view) || (passing_through && view.starts_with(path)))
    }

    /// [`Self::resolve_chain`] for a path whose chain must stay among protected components: Git
    /// configuration and redirection files. `None` when it does not exist.
    fn resolve_checked(&self, path: &Path, subject: &str) -> Result<Option<PathBuf>, Refusal> {
        let chain = self.resolve_chain(path, subject, OnOrdinary::Refuse)?;
        Ok(chain.exists.then_some(chain.end))
    }

    /// Resolve an absolute `path` the way the host kernel will, proving the binding rule as it
    /// walks: each named component that lies inside the workspace must classify as `Protected`
    /// before it is even looked up — existence cannot weaken the answer, because a missing
    /// operational name is one the sandbox can create. Under [`OnOrdinary::Record`] an ordinary
    /// workspace component is recorded instead, for the caller to protect; a gitdir's writable
    /// state still refuses. A component outside the workspace must be one the daemon sees as the
    /// host does ([`Self::verifiable`]). `subject` names what is being resolved, for the refusal an
    /// operator reads.
    fn resolve_chain(
        &self,
        path: &Path,
        subject: &str,
        ordinary: OnOrdinary,
    ) -> Result<Chain, Refusal> {
        let roots: Vec<&[u8]> = self.gitdir_roots.iter().map(Vec::as_slice).collect();
        let mut pending: VecDeque<OsString> = components_of(path).into();
        let mut current = PathBuf::from("/");
        let mut traversed: Vec<PathBuf> = Vec::new();
        let mut hops = 0usize;
        let mut missing = false;
        while let Some(part) = pending.pop_front() {
            if part == "/" {
                current = PathBuf::from("/");
            } else if part == "." {
            } else if part == ".." {
                current.pop();
            } else {
                let next = current.join(&part);
                match self.relative_bytes(&next) {
                    Some(rel) => {
                        let context = context_of_relative_path(&rel, &roots);
                        if classify(&context) != GitPathClass::Protected {
                            if ordinary == OnOrdinary::Record && context == GitContext::NotGit {
                                traversed.push(next.clone());
                            } else {
                                return Err(self.refuse_operational(subject, &next));
                            }
                        }
                    }
                    None => {
                        if !next.starts_with(&self.root)
                            && !self.verifiable(&next, !pending.is_empty())
                        {
                            return Err(self.refuse_unverifiable(subject, &next));
                        }
                    }
                }
                if missing {
                    current = next;
                    continue;
                }
                match fs::symlink_metadata(&next) {
                    Err(err) if err.kind() == ErrorKind::NotFound => {
                        missing = true;
                        current = next;
                    }
                    Err(err) => {
                        return Err(Refusal {
                            reason: format!(
                                "cannot resolve {next:?} while locating {subject}: {err}"
                            ),
                            remedy: "Repair the reported Git path or symlink on the host, then relaunch."
                                .to_string(),
                        });
                    }
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(Refusal {
                                reason: format!(
                                    "{subject} takes more than {MAX_SYMLINK_HOPS} symlink hops to \
                                     resolve"
                                ),
                                remedy: "Repair the reported Git path or symlink on the host, then relaunch."
                                    .to_string(),
                            });
                        }
                        let target = fs::read_link(&next).map_err(|err| Refusal {
                            reason: format!("cannot read the symlink {next:?}: {err}"),
                            remedy: "Repair the reported Git path or symlink on the host, then relaunch."
                                .to_string(),
                        })?;
                        for component in components_of(&target).into_iter().rev() {
                            pending.push_front(component);
                        }
                    }
                    Ok(_) => current = next,
                }
            }
        }
        // The loop lets a chain pass through an ancestor of a shared directory; one ending there,
        // `/var/..` say, ends where the daemon's objects are not the host's.
        if !current.starts_with(&self.root) && !self.verifiable(&current, false) {
            return Err(self.refuse_unverifiable(subject, &current));
        }
        Ok(Chain {
            end: current,
            exists: !missing,
            traversed,
        })
    }

    /// Protect what a chain recorded: its end read-only when it is ordinary workspace data, every
    /// other ordinary component it traversed pinned. Refuses, naming `subject`, a chain ending at
    /// the workspace root itself, which no read-only root can express short of the whole tree.
    fn record(&mut self, chain: &Chain, subject: &str) -> Result<(), Refusal> {
        if chain.end == self.root {
            return Err(Refusal {
                reason: format!("{subject} resolves to the workspace root itself"),
                remedy: "Its files would be writable by the sandbox and executed on the host. \
                         Point it at a directory of its own."
                    .to_string(),
            });
        }
        for component in &chain.traversed {
            let spelled = self.spelled(component, subject)?;
            let end = *component == chain.end;
            if self.covered(&spelled) || (!end && self.pinned_by_rules(&spelled)) {
                continue;
            }
            if end {
                self.additions.read_only.insert(spelled);
            } else {
                self.additions.pinned.insert(spelled);
            }
        }
        Ok(())
    }

    /// Whether a rule line already pins `spelled`, so a pinned addition would repeat it.
    fn pinned_by_rules(&self, spelled: &str) -> bool {
        let components: Vec<&[u8]> = spelled.split('/').map(str::as_bytes).collect();
        crate::policy::rule_context_of_path(&self.rules, &components)
            .is_some_and(|context| context.pinned())
    }

    /// Whether a rule line or an earlier read-only root already makes `spelled` read-only, so an
    /// addition would repeat it.
    fn covered(&self, spelled: &str) -> bool {
        let components: Vec<&[u8]> = spelled.split('/').map(str::as_bytes).collect();
        crate::policy::rule_context_of_path(&self.rules, &components)
            .is_some_and(|context| context.read_only(&self.rules))
            || self.additions.read_only.iter().any(|root| {
                spelled == root
                    || spelled
                        .strip_prefix(root.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
    }

    /// A workspace path as the resolved rule lines carry it: relative, UTF-8, and without the
    /// whitespace that separates their words.
    fn spelled(&self, path: &Path, subject: &str) -> Result<String, Refusal> {
        let rel = path
            .strip_prefix(&self.root)
            .ok()
            .and_then(|rel| rel.to_str())
            .filter(|rel| !rel.is_empty() && !rel.chars().any(char::is_whitespace));
        rel.map(str::to_string).ok_or_else(|| Refusal {
            reason: format!(
                "{subject} resolves through {path:?}, whose name the filter cannot record as \
                 read-only",
            ),
            remedy: "Rename it on the host without whitespace or non-UTF-8 bytes, then relaunch."
                .to_string(),
        })
    }

    /// The gitdir of the workspace-root repository: `.git` itself when it is a directory, or the
    /// resolved path a `.git` pointer file names. `None` when there is no `.git` entry at all —
    /// the caller then asks whether the root is itself a bare layout.
    fn locate_gitdir(&self) -> Result<Option<PathBuf>, Refusal> {
        let dotgit = self.root.join(".git");
        let metadata = match fs::symlink_metadata(&dotgit) {
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(Refusal {
                    reason: format!("cannot read {dotgit:?}: {err}"),
                    remedy: "The filter will not serve a repository whose gitdir it cannot locate."
                        .to_string(),
                });
            }
            Ok(metadata) => metadata,
        };

        if metadata.is_dir() {
            return Ok(Some(dotgit));
        }

        if metadata.file_type().is_symlink() {
            // Refused outright, as the launcher refuses a symlinked `.ko-agent-sandbox`: a link
            // decides where Git metadata resides, and following it would make the guarded set
            // depend on where it points at this instant.
            return Err(Refusal {
                reason: format!("{dotgit:?} is a symlink"),
                remedy: "Replace it with a real directory, or a `gitdir:` pointer file."
                    .to_string(),
            });
        }

        // A pointer file: `gitdir: <path>`, absolute or relative to the worktree.
        let text = fs::read_to_string(&dotgit).map_err(|err| Refusal {
            reason: format!("cannot read the .git pointer file {dotgit:?}: {err}"),
            remedy: "The filter will not serve a repository whose gitdir it cannot locate."
                .to_string(),
        })?;
        let Some(target) = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("gitdir:"))
        else {
            return Err(Refusal {
                reason: format!("{dotgit:?} is a file but names no gitdir"),
                remedy: "Expected a `gitdir: <path>` pointer file.".to_string(),
            });
        };
        let named = resolve_against(&self.root, target.trim());
        let subject = format!("the gitdir {dotgit:?} names");
        match self.resolve_checked(&named, &subject)? {
            None => Err(Refusal {
                reason: format!("{dotgit:?} names a gitdir that does not exist: {named:?}"),
                remedy: "The filter will not serve a repository whose gitdir it cannot locate."
                    .to_string(),
            }),
            Some(gitdir) => match fs::symlink_metadata(&gitdir) {
                Ok(metadata) if metadata.is_dir() => Ok(Some(gitdir)),
                Ok(_) => Err(Refusal {
                    reason: format!("{dotgit:?} names {gitdir:?}, which is not a directory"),
                    remedy: "The filter will not serve a repository whose gitdir it cannot locate."
                        .to_string(),
                }),
                Err(err) => Err(Refusal {
                    reason: format!("cannot read {gitdir:?}: {err}"),
                    remedy: "The filter will not serve a repository whose gitdir it cannot locate."
                        .to_string(),
                }),
            },
        }
    }

    /// The common gitdir, which holds `config` and `hooks` for a linked worktree: the directory
    /// the gitdir's `commondir` file names, or the gitdir itself when there is none.
    fn common_of(&self, gitdir: &Path) -> Result<PathBuf, Refusal> {
        let commondir_path = gitdir.join("commondir");
        let subject = format!("the commondir file {commondir_path:?}");
        let Some(resolved) = self.resolve_checked(&commondir_path, &subject)? else {
            return Ok(gitdir.to_path_buf());
        };
        let text = match fs::read_to_string(&resolved) {
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(gitdir.to_path_buf()),
            Err(err) => {
                return Err(Refusal {
                    reason: format!("cannot read {commondir_path:?}: {err}"),
                    remedy: "The filter will not serve a repository whose common gitdir it \
                             cannot locate."
                        .to_string(),
                });
            }
            Ok(text) => text,
        };
        let named = resolve_against(gitdir, text.trim());
        let subject = format!("the common gitdir {commondir_path:?} names");
        match self.resolve_checked(&named, &subject)? {
            None => Err(Refusal {
                reason: format!(
                    "{commondir_path:?} names a directory that does not exist: {named:?}"
                ),
                remedy: "The filter will not serve a repository whose common gitdir it cannot \
                         locate."
                    .to_string(),
            }),
            Some(common) => match fs::symlink_metadata(&common) {
                Ok(metadata) if metadata.is_dir() => Ok(common),
                Ok(_) => Err(Refusal {
                    reason: format!(
                        "{commondir_path:?} names {common:?}, which is not a directory"
                    ),
                    remedy: "The filter will not serve a repository whose common gitdir it \
                             cannot locate."
                        .to_string(),
                }),
                Err(err) => Err(Refusal {
                    reason: format!("cannot read {common:?}: {err}"),
                    remedy: "The filter will not serve a repository whose common gitdir it \
                             cannot locate."
                        .to_string(),
                }),
            },
        }
    }

    fn check_repository(&mut self, gitdir: &Path) -> Result<(), Refusal> {
        let common = self.common_of(gitdir)?;

        // Every effective hooks directory, as named and as the refusal names it: where git looks
        // by default — the common gitdir's `hooks`, which is `.git/hooks` when `.git` is the
        // gitdir — plus every directory a decidable `hooksPath` names, collected below.
        let mut hooks_dirs: Vec<(PathBuf, String)> = Vec::new();
        for dir in [common.join("hooks"), gitdir.join("hooks")] {
            if !hooks_dirs.iter().any(|(named, _)| *named == dir) {
                let subject = format!("the hook directory {dir:?}");
                hooks_dirs.push((dir, subject));
            }
        }

        // The config files git reads for this repository: the shared config is in the common
        // gitdir — for a linked worktree that is NOT the located gitdir, which holds only
        // `config.worktree` — so scanning `gitdir/config` alone misses the file that names the
        // hooks git actually runs.
        for config_path in [common.join("config"), gitdir.join("config.worktree")] {
            let subject = format!("the config file {config_path:?}");
            let Some(resolved) = self.resolve_checked(&config_path, &subject)? else {
                continue;
            };
            let bytes = match fs::read(&resolved) {
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(Refusal {
                        reason: format!("cannot read {config_path:?}: {err}"),
                        remedy: "The filter cannot tell where hooks would run from, so it will \
                                 not serve this repository."
                            .to_string(),
                    });
                }
                Ok(bytes) => bytes,
            };
            // Only NotFound means absent; a config whose bytes cannot be decoded is a config
            // whose values cannot be compared with the path hooks run from, which is the same
            // doubt every Undecidable resolves to: refusal.
            let Ok(text) = String::from_utf8(bytes) else {
                return Err(Refusal {
                    reason: format!(
                        "{config_path:?} is not valid UTF-8, so its values cannot be read"
                    ),
                    remedy: "The filter cannot tell where hooks would run from, so it will not \
                             serve this repository. Re-encode the file, or remove the setting."
                        .to_string(),
                });
            };
            match scan_hooks_path(&text) {
                HooksPath::Absent => {}
                HooksPath::Undecidable(what) => {
                    return Err(Refusal {
                        reason: format!("{config_path:?} {what}"),
                        remedy: "The filter cannot tell where hooks would run from, so it will \
                                 not serve this repository. Set an explicit core.hooksPath \
                                 outside the workspace, or remove it."
                            .to_string(),
                    });
                }
                // Every value, not the last one: the scanner cannot see sections, so it cannot
                // know which of them git will read as `core.hooksPath` — and judging one of them
                // lets the others through (`scan_hooks_path`).
                HooksPath::Values(values) => {
                    // A relative value resolves against the directory git runs hooks from, and
                    // that is not one directory: most hooks run from the worktree root, but the
                    // receive-side hooks (pre-receive, update, post-receive) run from $GIT_DIR.
                    // Every base is judged — worktree, gitdir, common gitdir — and each one
                    // resolving to ordinary workspace paths is served read-only; protecting a
                    // spelling only one base makes a hook directory is the scanner's own price.
                    let mut bases: Vec<&Path> = vec![self.root.as_path()];
                    for base in [gitdir, common.as_path()] {
                        if !bases.contains(&base) {
                            bases.push(base);
                        }
                    }
                    for value in values {
                        for base in &bases {
                            let named = resolve_against(base, &value);
                            if !hooks_dirs.iter().any(|(dir, _)| *dir == named) {
                                let subject =
                                    format!("{config_path:?} sets a hooksPath to {value:?}, which");
                                hooks_dirs.push((named, subject));
                            }
                        }
                    }
                }
            }
        }

        for (dir, subject) in hooks_dirs {
            self.check_hook_entries(&dir, &subject)?;
        }
        self.check_object_store(&common)
    }

    /// The common gitdir's `objects`, `objects/info` and its two alternates files. The filter
    /// protects `alternates` by its name below `objects/info` and pins the two directories
    /// (`policy::classify_within_object_info`); through a symlink the host made, the sandbox would
    /// write the file under the name the link leads to.
    ///
    /// - In a gitdir outside the workspace the sandbox writes none of them, only an ordinary
    ///   workspace entry a link there leads back to, which is served read-only as a hook's is.
    /// - In the workspace, a link at one of them must lead outside it, with the entries below it:
    ///   `objects` and `objects/info` are operational, so a chain back through the workspace cannot
    ///   be proved. Objects kept on another disk stay served.
    fn check_object_store(&mut self, common: &Path) -> Result<(), Refusal> {
        const ENTRIES: [(&str, bool); 4] = [
            ("objects", true),
            ("objects/info", true),
            ("objects/info/alternates", false),
            ("objects/info/http-alternates", false),
        ];
        if self.relative_bytes(common).is_none() {
            for (name, _) in ENTRIES {
                let path = common.join(name);
                let subject = format!("the object store entry {path:?}");
                let chain = self.resolve_chain(&path, &subject, OnOrdinary::Record)?;
                self.record(&chain, &subject)?;
            }
            return Ok(());
        }
        for (name, is_directory) in ENTRIES {
            let path = common.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let target = fs::read_link(&path).map_err(|err| Refusal {
                        reason: format!("cannot read the symlink {path:?}: {err}"),
                        remedy:
                            "Repair the reported Git path or symlink on the host, then relaunch."
                                .to_string(),
                    })?;
                    let target = link_target(path.parent().unwrap_or(common), &target);
                    for (below, _) in ENTRIES {
                        let Some(suffix) = below
                            .strip_prefix(name)
                            .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
                        else {
                            continue;
                        };
                        let entry = target.join(suffix.trim_start_matches('/'));
                        let subject = format!("the object store entry {:?}", common.join(below));
                        let chain = self.resolve_chain(&entry, &subject, OnOrdinary::Refuse)?;
                        if chain.end.starts_with(&self.root) {
                            return Err(Refusal {
                                reason: format!(
                                    "{subject}, a symlink or below one, leads into the workspace, \
                                     to {:?}",
                                    chain.end
                                ),
                                remedy: "The filter protects objects/info/alternates, whose paths \
                                         your git opens, by its name, and a link into the \
                                         workspace would let the sandbox write it under another. \
                                         Point the link outside the workspace, or replace it with \
                                         the directory or file it names."
                                    .to_string(),
                            });
                        }
                    }
                    if is_directory {
                        return Ok(());
                    }
                }
                Ok(_) => {}
                // A missing directory has no link below it to find.
                Err(err) if err.kind() == ErrorKind::NotFound && is_directory => return Ok(()),
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(Refusal {
                        reason: format!("cannot read {path:?}: {err}"),
                        remedy: "The filter will not serve a repository whose object store it \
                                 cannot inspect."
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// An effective hooks directory and every entry in it, resolved under the binding rule, with
    /// what the chains reach in ordinary workspace data served read-only: the directory itself
    /// when the host keeps its hooks there — husky's `.husky/_`, a `githooks/` — and an
    /// individual hook that is a symlink back into the workspace, the same relocation one level
    /// down. Each chain's ordinary components are pinned, so the sandbox cannot re-aim it.
    fn check_hook_entries(&mut self, dir: &Path, subject: &str) -> Result<(), Refusal> {
        let chain = self.resolve_chain(dir, subject, OnOrdinary::Record)?;
        self.record(&chain, subject)?;
        if !chain.exists {
            return Ok(());
        }
        let resolved = chain.end;
        let entries = match fs::read_dir(&resolved) {
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            // A hooks *file* runs nothing — git opens the directory or finds none — so it is an
            // absence here, not a doubt.
            Err(err) if err.kind() == ErrorKind::NotADirectory => return Ok(()),
            Err(err) => {
                return Err(Refusal {
                    reason: format!("cannot list the hook directory {resolved:?}: {err}"),
                    remedy: "The filter will not serve hooks it cannot inspect.".to_string(),
                });
            }
            Ok(entries) => entries,
        };
        for entry in entries {
            let entry = entry.map_err(|err| Refusal {
                reason: format!("cannot list the hook directory {resolved:?}: {err}"),
                remedy: "The filter will not serve hooks it cannot inspect.".to_string(),
            })?;
            let hook = resolved.join(entry.file_name());
            let subject = format!("the hook {hook:?}");
            let chain = self.resolve_chain(&hook, &subject, OnOrdinary::Record)?;
            self.record(&chain, &subject)?;
        }
        Ok(())
    }

    /// The redirections at and below the entries the rules make read-only or pin, from the
    /// workspace root down: a symlink there is resolved, its chain pinned and its end in ordinary
    /// workspace data given the symlink's rule context ([`Self::follow`]), since the host program
    /// reads the target through the link while the sandbox would write it under its own name.
    /// Nested deeper than a listed entry at the root is the gap SECURITY.md records for nested
    /// repositories.
    fn walk_listed(&mut self) -> Result<(), Refusal> {
        if self.rules.lines().is_empty() {
            return Ok(());
        }
        let root = self.root.clone();
        let mut visited = HashSet::new();
        self.walk_rule_dir(&RuleContext::root(), true, &root, &mut visited)
    }

    /// One directory of [`Self::walk_listed`]: `physical` is where the entries are, `context` the
    /// rule context of the logical position. Below a read-only entry every entry is walked but one
    /// a later `writable` line lifts. `visited` holds each directory with the context it was walked
    /// under: a directory reached again under another name, `.kiro -> .claude`, is walked again for
    /// the lines that name reaches.
    fn walk_rule_dir(
        &mut self,
        context: &RuleContext,
        is_root: bool,
        physical: &Path,
        visited: &mut HashSet<(PathBuf, RuleContext)>,
    ) -> Result<(), Refusal> {
        if !visited.insert((physical.to_path_buf(), context.clone())) {
            return Ok(());
        }
        for (name, path) in self.list(physical)? {
            if child_context(&GitContext::NotGit, name.as_bytes()) != GitContext::NotGit {
                continue;
            }
            let child = child_rule_context(&self.rules, context, is_root, name.as_bytes());
            let read_only = child.read_only(&self.rules);
            if !read_only && !child.pinned() {
                continue;
            }
            let subject = format!("the listed entry {path:?}");
            let (end, is_dir) = self.follow(&path, &subject, &child)?;
            if let (Some(end), true) = (end, is_dir) {
                self.walk_rule_dir(&child, false, &end, visited)?;
            }
        }
        Ok(())
    }

    /// Where the walk continues from an entry, and whether that is a directory. A symlink's chain
    /// is resolved and recorded, and an end in ordinary workspace data gets the entry's context
    /// ([`Additions::aliases`]): what the session creates there later is what the host reads under
    /// the entry's name, and a later `writable` line lifts there as under the name. An end outside
    /// the workspace is walked too, since a symlink there can lead back in; an end holding the
    /// workspace refuses.
    fn follow(
        &mut self,
        path: &Path,
        subject: &str,
        context: &RuleContext,
    ) -> Result<(Option<PathBuf>, bool), Refusal> {
        let metadata = fs::symlink_metadata(path).map_err(|err| Refusal {
            reason: format!("cannot read {subject}: {err}"),
            remedy: "The filter will not serve an entry it protects without inspecting it."
                .to_string(),
        })?;
        if !metadata.file_type().is_symlink() {
            return Ok((Some(path.to_path_buf()), metadata.is_dir()));
        }
        let mut chain = self.resolve_chain(path, subject, OnOrdinary::Record)?;
        if chain.end != self.root && self.root.starts_with(&chain.end) {
            return Err(Refusal {
                reason: format!(
                    "{subject} resolves to {:?}, which holds the workspace",
                    chain.end,
                ),
                remedy: "The host would read project files under its name, which the filter \
                         cannot protect there. Point it at a directory of its own."
                    .to_string(),
            });
        }
        if chain.traversed.contains(&chain.end) {
            chain.traversed.retain(|component| component != &chain.end);
            let spelled = self.spelled(&chain.end, subject)?;
            if !context.read_only(&self.rules) {
                // An interior component: moving its end would move what the line names below it.
                self.additions.pinned.insert(spelled.clone());
            }
            let alias = (spelled, context.clone());
            if !self.additions.aliases.contains(&alias) {
                self.additions.aliases.push(alias);
            }
        }
        self.record(&chain, subject)?;
        let is_dir =
            chain.exists && fs::metadata(&chain.end).is_ok_and(|metadata| metadata.is_dir());
        Ok((chain.exists.then_some(chain.end), is_dir))
    }

    /// A directory's entries as (name, path), refused when it cannot be listed; an absent
    /// directory has none. The walks need no depth bound: the visited set ends a symlink cycle,
    /// and the path length limit bounds the depth of real directories.
    fn list(&self, dir: &Path) -> Result<Vec<(OsString, PathBuf)>, Refusal> {
        let entries = match fs::read_dir(dir) {
            Err(err)
                if err.kind() == ErrorKind::NotFound || err.kind() == ErrorKind::NotADirectory =>
            {
                return Ok(Vec::new());
            }
            Err(err) => {
                return Err(Refusal {
                    reason: format!("cannot list {dir:?}, below a listed entry: {err}"),
                    remedy: "The filter will not serve an entry it protects without inspecting it."
                        .to_string(),
                });
            }
            Ok(entries) => entries,
        };
        let mut listed = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|err| Refusal {
                reason: format!("cannot list {dir:?}, below a listed entry: {err}"),
                remedy: "The filter will not serve an entry it protects without inspecting it."
                    .to_string(),
            })?;
            listed.push((entry.file_name(), entry.path()));
        }
        listed.sort();
        Ok(listed)
    }

    /// Whether the workspace root is itself laid out as a gitdir — `git init --bare`,
    /// `git clone --bare|--mirror`, or hand-assembled. Host git's ascending discovery adopts such
    /// a directory, and its config and hooks have ordinary names the filter must keep writable,
    /// so it is refused. The recognition mirrors git's own `is_git_directory`: a valid `HEAD`
    /// (symref or detached hash), an `objects` directory, a `refs` directory — a triple reftable
    /// repositories also keep, precisely so old gits recognize them.
    fn check_bare_root(&self) -> Result<(), Refusal> {
        let head = self.root.join("HEAD");
        let text = match fs::read_to_string(&head) {
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) if err.kind() == ErrorKind::IsADirectory => return Ok(()),
            Err(err) => {
                return Err(Refusal {
                    reason: format!("cannot read {head:?}: {err}"),
                    remedy: "The filter will not serve a tree whose repository layout it cannot \
                             decide."
                        .to_string(),
                });
            }
            Ok(text) => text,
        };
        let first = text.lines().next().unwrap_or("").trim();
        // git's validate_headref: a symref must aim under refs/ — `ref: nonsense` is a file git
        // does not recognize, and refusing on it would call a non-repository project a repository.
        let head_valid = match first.strip_prefix("ref:") {
            Some(target) => target.trim_start().starts_with("refs/"),
            None => {
                (first.len() == 40 || first.len() == 64)
                    && first.chars().all(|ch| ch.is_ascii_hexdigit())
            }
        };
        if !head_valid {
            return Ok(());
        }
        for name in ["objects", "refs"] {
            match fs::metadata(self.root.join(name)) {
                Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    return Err(Refusal {
                        reason: format!("cannot read {:?}: {err}", self.root.join(name)),
                        remedy: "The filter will not serve a tree whose repository layout it \
                                 cannot decide."
                            .to_string(),
                    });
                }
                Ok(metadata) if !metadata.is_dir() => return Ok(()),
                Ok(_) => {}
            }
        }
        Err(Refusal {
            reason: format!(
                "{:?} is itself laid out as a git directory (a bare repository): it holds a \
                 valid HEAD, objects/ and refs/",
                self.root
            ),
            remedy: "Its config and hooks have workspace-root names the filter must keep \
                     writable, so it cannot be served. Launch from a worktree with a .git entry, \
                     or move the bare repository elsewhere."
                .to_string(),
        })
    }
}

fn components_of(path: &Path) -> Vec<OsString> {
    path.components()
        .map(|component| match component {
            Component::RootDir | Component::Prefix(_) => OsString::from("/"),
            Component::CurDir => OsString::from("."),
            Component::ParentDir => OsString::from(".."),
            Component::Normal(name) => name.to_os_string(),
        })
        .collect()
}

/// Where a symlink in `directory` leads, with the target's leading `..` taken lexically from
/// `directory`: the walk above found every component of it a real directory, and resolving the
/// joined path from the root would refuse at the first one that is a gitdir's writable state,
/// `.git/objects`, before reaching the `..` that leaves it. The rest of the target is left for
/// [`Workspace::resolve_chain`] to prove.
fn link_target(directory: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        return target.to_path_buf();
    }
    let mut base = directory.to_path_buf();
    let mut components = target.components();
    loop {
        let rest = components.as_path();
        match components.next() {
            Some(Component::ParentDir) => {
                base.pop();
            }
            Some(Component::CurDir) => {}
            _ => return base.join(rest),
        }
    }
}

fn resolve_against(base: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HooksPath {
    Absent,
    /// Every `hooksPath` the file states, in file order, in each reading [`value_readings`] gives
    /// it. Which one git reads is not this scanner's to say, so the caller judges them all.
    Values(Vec<String>),
    /// The file could hide a `hooksPath` somewhere this scanner cannot follow.
    Undecidable(&'static str),
}

/// A deliberately conservative scanner, not a git-config parser. It answers one question — could this file
/// put hooks inside the workspace — and every doubt resolves to [`HooksPath::Undecidable`], which
/// refuses the mount.
///
/// Conservative has to mean erring *toward refusing*, which is what to preserve when changing
/// this scanner. It skips section headers without reading their names, so it reports every
/// `hooksPath` in the file and lets the caller protect *every* one that resolves inside the
/// workspace — keeping only the last would be the fail-open reading — and each doubt refuses
/// because reading it any other way would compare a different string than the one hooks run from.
/// The worked example, the git syntax it reads and the per-doubt reasons are
/// `doc/git-metadata.md`, "Relocated hook directories".
fn scan_hooks_path(text: &str) -> HooksPath {
    let mut found: Vec<String> = Vec::new();
    for raw in text.strip_prefix('\u{feff}').unwrap_or(text).lines() {
        let Some(line) = strip_comment(raw) else {
            return HooksPath::Undecidable(
                "leaves a double quote open, so its values cannot be read",
            );
        };
        let Some(line) = after_section_headers(line) else {
            return HooksPath::Undecidable(
                "leaves a section header open, so its keys cannot be read",
            );
        };
        let lowercased = line.to_ascii_lowercase();

        if lowercased.starts_with("path") && lowercased.contains('=') {
            // Section names are not read here, so this cannot tell `include.path` from any other
            // bare `path` key; the message says what was seen rather than asserting the section.
            return HooksPath::Undecidable(
                "has a bare `path` key, which under `include` or `includeIf` would name a file \
                 this scanner does not follow",
            );
        }

        if !lowercased.starts_with("hookspath") {
            continue;
        }
        let Some((_, value)) = line.split_once('=') else {
            continue;
        };
        if value.contains('\\') {
            return HooksPath::Undecidable("sets a hooksPath containing a backslash escape");
        }
        for reading in value_readings(value) {
            if reading.starts_with('~') {
                return HooksPath::Undecidable("sets a hooksPath relative to a home directory");
            }
            if !reading.is_empty() && !found.contains(&reading) {
                found.push(reading);
            }
        }
    }
    if found.is_empty() {
        HooksPath::Absent
    } else {
        HooksPath::Values(found)
    }
}

/// The line with any comment removed, or `None` when it leaves a double quote open.
///
/// `#` and `;` begin a comment only *outside* quotes. Truncating at a quoted one would compare a
/// shorter path than the one hooks run from — `hooksPath = "#githooks"` would read as no value at
/// all, and `"./git#hooks"` as `./git` — so the quoted forms are carried through and judged whole.
/// A backslash escapes the character after it, so `\"` in a section header's subsection does not
/// close the quote.
fn strip_comment(line: &str) -> Option<&str> {
    let mut quoted = false;
    let mut characters = line.char_indices();
    while let Some((at, ch)) = characters.next() {
        match ch {
            '\\' => {
                characters.next();
            }
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => return Some(&line[..at]),
            _ => {}
        }
    }
    if quoted { None } else { Some(line) }
}

/// The line past every section header it begins with, as git reads `[a][core] hooksPath = x`, or
/// `None` when a header is left open. A `]` inside the quoted subsection does not end the header.
fn after_section_headers(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    while rest.starts_with('[') {
        let mut quoted = false;
        let mut header_end = None;
        let mut characters = rest.char_indices();
        while let Some((at, ch)) = characters.next() {
            match ch {
                '\\' => {
                    characters.next();
                }
                '"' => quoted = !quoted,
                ']' if !quoted => {
                    header_end = Some(at);
                    break;
                }
                _ => {}
            }
        }
        rest = rest[header_end? + 1..].trim_start();
    }
    Some(rest)
}

/// The whitespace git's config parser skips: `isspace` of git's own `ctype.c`, without the
/// newline that ends a line.
fn is_git_space(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r')
}

/// What git reads from the text after a key's `=`, which holds balanced quotes and no backslash:
/// the quote characters removed, whitespace outside quotes dropped before the value and after its
/// last other character, and everything inside quotes kept. A quote character counts as such a
/// character, so `./x<TAB>""` keeps its tab. Whitespace outside quotes that is kept has two
/// readings: git 2.39 replaces each such character with a space and git 2.47 keeps it
/// (`parse_value`, config.c). Both are returned when they differ.
fn value_readings(text: &str) -> Vec<String> {
    let mut verbatim = String::new();
    let mut spaced = String::new();
    let mut pending = String::new();
    let mut quoted = false;
    for ch in text.chars() {
        if is_git_space(ch) && !quoted {
            if !verbatim.is_empty() {
                pending.push(ch);
            }
            continue;
        }
        verbatim.push_str(&pending);
        spaced.extend(pending.drain(..).map(|_| ' '));
        if ch == '"' {
            quoted = !quoted;
        } else {
            verbatim.push(ch);
            spaced.push(ch);
        }
    }
    if verbatim == spaced {
        vec![verbatim]
    } else {
        vec![verbatim, spaced]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_without_hooks_path_is_absent() {
        assert_eq!(
            scan_hooks_path("[core]\n\tbare = false\n\trepositoryformatversion = 0\n"),
            HooksPath::Absent
        );
    }

    fn values(scanned: HooksPath) -> Vec<String> {
        match scanned {
            HooksPath::Values(values) => values,
            other => panic!("expected values, got {other:?}"),
        }
    }

    #[test]
    fn a_hooks_path_value_is_read_whatever_the_spacing_or_case() {
        assert_eq!(
            values(scan_hooks_path("[core]\n\thooksPath = ./githooks\n")),
            vec!["./githooks".to_string()]
        );
        assert_eq!(
            values(scan_hooks_path("[core]\nhookspath=/opt/hooks\n")),
            vec!["/opt/hooks".to_string()]
        );
        assert_eq!(
            values(scan_hooks_path(
                "[core]\n\tHooksPath = \"./quoted hooks\"\n"
            )),
            vec!["./quoted hooks".to_string()]
        );
    }

    #[test]
    fn every_hooks_path_is_reported_because_sections_are_invisible() {
        // The fail-open reading this scanner must not have. `tool.hooksPath` is a key git never reads
        // for hooks, so git runs `./githooks` from inside the worktree; a scanner keeping only the
        // last value would answer `/opt/hooks` and leave `./githooks` writable. Both are reported
        // instead, and the caller serves each one that resolves inside read-only.
        assert_eq!(
            values(scan_hooks_path(
                "[core]\n\thooksPath = ./githooks\n[tool]\n\thooksPath = /opt/hooks\n"
            )),
            vec!["./githooks".to_string(), "/opt/hooks".to_string()]
        );
    }

    #[test]
    fn a_quoted_comment_character_stays_in_the_value() {
        // Git reads `#` and `;` inside quotes literally (measured against git 2.47). Truncating
        // there would compare a shorter path than hooks run from — and `"#githooks"` would read as
        // no value at all, which is the fail-open direction.
        assert_eq!(
            values(scan_hooks_path("[core]\n\thooksPath = \"./git#hooks\"\n")),
            vec!["./git#hooks".to_string()]
        );
        assert_eq!(
            values(scan_hooks_path("[core]\n\thooksPath = \"#githooks\"\n")),
            vec!["#githooks".to_string()]
        );
        assert_eq!(
            values(scan_hooks_path("[core]\n\thooksPath = \"./a;b\"\n")),
            vec!["./a;b".to_string()]
        );
        assert_eq!(
            values(scan_hooks_path(
                "[core]\n\thooksPath = ./githooks # the shared ones\n"
            )),
            vec!["./githooks".to_string()]
        );
    }

    #[test]
    fn a_value_this_scanner_cannot_read_faithfully_is_undecidable() {
        // Each of these would otherwise compare a different string than the one git resolves.
        assert!(matches!(
            scan_hooks_path("[core]\n\thooksPath = \"./unterminated\n"),
            HooksPath::Undecidable(_)
        ));
        assert!(matches!(
            scan_hooks_path("[core]\n\thooksPath = ./git\\\\hooks\n"),
            HooksPath::Undecidable(_)
        ));
    }

    #[test]
    fn a_hooks_path_after_a_section_header_on_its_line_is_read() {
        // Each spelling measured against git 2.47, which reads `core.hookspath` from all of them.
        for (config, read) in [
            ("[core]hooksPath=./x\n", "./x"),
            ("[core] hooksPath = ./githooks\n", "./githooks"),
            ("[a][core] hooksPath = ./two\n", "./two"),
            ("[a \"]\"][core] hooksPath = ./bracket\n", "./bracket"),
            ("[a \"\\\"#\"][core] hooksPath = ./escaped\n", "./escaped"),
            ("\u{feff}[core]hooksPath=./bom\n", "./bom"),
        ] {
            assert_eq!(
                values(scan_hooks_path(config)),
                vec![read.to_string()],
                "{config:?}"
            );
        }
        assert!(matches!(
            scan_hooks_path("[core\nhooksPath = ./x\n"),
            HooksPath::Undecidable(_)
        ));
    }

    #[test]
    fn a_hooks_path_value_is_read_without_its_quotes_as_git_reads_it() {
        // Measured against git 2.47: quotes anywhere in the value are removed, and whitespace is
        // kept inside them, at the ends too.
        for (config, read) in [
            ("[core]\n\thooksPath = ./a\"b\"c\n", "./abc"),
            ("[core]\n\thooksPath = \" ./sp \"\n", " ./sp "),
            ("[core]\n\thooksPath = \"\"./x\"\"\n", "./x"),
            ("[core]\n\thooksPath = \"./x\" ; c\n", "./x"),
            ("[core]\n\thooksPath = ./x\u{a0}\n", "./x\u{a0}"),
        ] {
            assert_eq!(
                values(scan_hooks_path(config)),
                vec![read.to_string()],
                "{config:?}"
            );
        }
        // `~` is expanded in what git read, whether or not it was quoted.
        assert!(matches!(
            scan_hooks_path("[core]\n\thooksPath = \"~/hooks\"\n"),
            HooksPath::Undecidable(_)
        ));
    }

    #[test]
    fn whitespace_inside_an_unquoted_value_is_reported_in_both_of_gits_readings() {
        // git 2.47 keeps the tab (measured); `parse_value` of git 2.39 replaces it with a space.
        assert_eq!(
            values(scan_hooks_path("[core]\n\thooksPath = ./a\tb\n")),
            vec!["./a\tb".to_string(), "./a b".to_string()]
        );
        assert_eq!(
            values(scan_hooks_path("[core]\n\thooksPath = ./a  b\n")),
            vec!["./a  b".to_string()]
        );
        // A quote character ends the run of whitespace git would trim (measured against git
        // 2.47), so the tab before an empty pair of quotes is part of the directory's name.
        for (config, read) in [
            ("[core]\n\thooksPath = ./g\t\"\"\n", vec!["./g\t", "./g "]),
            (
                "[core]\n\thooksPath = ./g\t\"\" \t\n",
                vec!["./g\t", "./g "],
            ),
            (
                "[core]\n\thooksPath = ./g \t\"x\"\n",
                vec!["./g \tx", "./g  x"],
            ),
            ("[core]\n\thooksPath = ./g \"\" \n", vec!["./g "]),
            ("[core]\n\thooksPath = \"\" ./g\n", vec!["./g"]),
        ] {
            assert_eq!(values(scan_hooks_path(config)), read, "{config:?}");
        }
    }

    #[test]
    fn a_commented_hooks_path_is_not_a_value() {
        assert_eq!(
            scan_hooks_path("[core]\n\t# hooksPath = ./githooks\n"),
            HooksPath::Absent
        );
    }

    #[test]
    fn an_include_makes_the_answer_undecidable() {
        // The setting could be in the included file, which this scanner does not follow — so the
        // mount is refused rather than guessed at.
        assert!(matches!(
            scan_hooks_path("[include]\n\tpath = ../shared.config\n"),
            HooksPath::Undecidable(_)
        ));
        assert!(matches!(
            scan_hooks_path("[includeIf \"gitdir:~/work/\"]\n\tpath = work.config\n"),
            HooksPath::Undecidable(_)
        ));
        assert!(matches!(
            scan_hooks_path("[include] path = other\n"),
            HooksPath::Undecidable(_)
        ));
    }

    #[test]
    fn a_home_relative_hooks_path_is_undecidable() {
        assert!(matches!(
            scan_hooks_path("[core]\n\thooksPath = ~/dotfiles/hooks\n"),
            HooksPath::Undecidable(_)
        ));
    }

    // --- The end-to-end guard, over real directories -------------------------

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ko-agent-fs-guard-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .unwrap()
                .subsec_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// The guard with no file rules, in the host's own namespace: the repository checks alone.
    fn check_hook_location(root: &Path) -> Result<Additions, Refusal> {
        resolve(root, &FileRules::default(), &[PathBuf::from("/")])
    }

    #[track_caller]
    fn served_read_only(root: &Path) -> Additions {
        check_hook_location(root)
            .unwrap_or_else(|refusal| panic!("{root:?} was refused: {refusal}"))
    }

    #[track_caller]
    fn refused_with(root: &Path, token: &str) -> Refusal {
        let refusal = check_hook_location(root).expect_err(&format!(
            "{root:?} was served; expected a refusal naming {token:?}"
        ));
        assert!(
            refusal.reason.contains(token),
            "the refusal does not name {token:?}: {refusal}"
        );
        refusal
    }

    #[test]
    fn a_tree_without_a_repository_is_served() {
        let root = scratch("norepo");
        fs::write(root.join("file.txt"), b"x").unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_ordinary_repository_is_served() {
        let root = scratch("ordinary");
        fs::create_dir_all(root.join(".git/hooks")).unwrap();
        fs::write(root.join(".git/hooks/pre-commit"), b"#!/bin/sh\n").unwrap();
        fs::write(root.join(".git/config"), b"[core]\n\tbare = false\n").unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_symlink_inside_the_workspace_is_served_read_only() {
        let root = scratch("symlinked-in");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("shared-hooks")).unwrap();
        std::os::unix::fs::symlink("../shared-hooks", root.join(".git/hooks")).unwrap();
        let additions = served_read_only(&root);
        assert_eq!(
            additions.read_only,
            BTreeSet::from(["shared-hooks".to_string()]),
        );
        assert!(additions.pinned.is_empty(), "{additions:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_symlink_out_of_the_workspace_is_served() {
        // Unreachable through the mount, so the sandbox cannot write it: nothing to refuse.
        let root = scratch("symlinked-out");
        let outside = scratch("symlinked-out-target");
        fs::create_dir_all(root.join(".git")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".git/hooks")).unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_hooks_path_inside_the_workspace_is_served_read_only_with_its_ancestors_pinned() {
        // husky's `.husky/_` is this case: every husky repository sets it.
        let root = scratch("hookspath-in");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("tools/githooks")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = ./tools/githooks\n",
        )
        .unwrap();
        let additions = served_read_only(&root);
        assert_eq!(
            additions.read_only,
            BTreeSet::from(["tools/githooks".to_string()]),
        );
        assert_eq!(additions.pinned, BTreeSet::from(["tools".to_string()]));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_resolving_to_the_workspace_root_is_refused() {
        // No read-only root short of the whole tree could hold hooks kept at the top.
        let root = scratch("hookspath-root");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), b"[core]\n\thooksPath = .\n").unwrap();
        refused_with(&root, "workspace root");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_through_writable_git_state_is_still_refused() {
        // A gitdir's operational state is not ordinary data a read-only root can hold: git
        // rewrites it.
        let root = scratch("hookspath-objects");
        fs::create_dir_all(root.join(".git/objects/hooks")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = .git/objects/hooks\n",
        )
        .unwrap();
        refused_with(&root, "objects");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_masked_by_a_later_section_is_still_protected() {
        // End to end, the property `every_hooks_path_is_reported_because_sections_are_invisible`
        // checks at the scanner: the directory git would run `./githooks` from is read-only,
        // whatever follows it in the file.
        let root = scratch("hookspath-masked");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = ./githooks\n[tool]\n\thooksPath = /opt/hooks\n",
        )
        .unwrap();
        assert!(served_read_only(&root).read_only.contains("githooks"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_on_its_section_headers_line_is_protected() {
        let root = scratch("hookspath-header-line");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::write(root.join(".git/config"), b"[core] hooksPath = ./githooks\n").unwrap();
        assert!(served_read_only(&root).read_only.contains("githooks"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_ending_in_whitespace_before_empty_quotes_is_judged_with_the_whitespace() {
        // The directory git runs hooks from is `githooks<TAB>`, a name the file rules cannot
        // record, so the mount is refused; read without the tab, `githooks` would be protected
        // and the hook directory left writable.
        let root = scratch("hookspath-trailing-tab");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::create_dir_all(root.join("githooks\t")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = ./githooks\t\"\"\n",
        )
        .unwrap();
        refused_with(&root, "githooks\\t");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_outside_the_workspace_is_served() {
        let root = scratch("hookspath-out");
        let outside = scratch("hookspath-out-target");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(
            root.join(".git/config"),
            format!("[core]\n\thooksPath = {}\n", outside.display()).as_bytes(),
        )
        .unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_symlinked_dotgit_is_refused() {
        let root = scratch("symlinked-dotgit");
        let elsewhere = scratch("symlinked-dotgit-target");
        std::os::unix::fs::symlink(&elsewhere, root.join(".git")).unwrap();
        refused_with(&root, "symlink");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn a_pointer_file_gitdir_is_followed() {
        // A linked worktree's `.git` names its gitdir; the guard checks that gitdir's hooks.
        let root = scratch("pointer");
        let gitdir = scratch("pointer-gitdir");
        fs::create_dir_all(root.join("shared-hooks")).unwrap();
        fs::write(
            root.join(".git"),
            format!("gitdir: {}\n", gitdir.display()).as_bytes(),
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("shared-hooks"), gitdir.join("hooks")).unwrap();
        assert!(served_read_only(&root).read_only.contains("shared-hooks"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&gitdir);
    }

    #[test]
    fn a_pointer_file_naming_an_in_workspace_gitdir_is_refused() {
        // `git init --separate-git-dir admin .` run by the host: the gitdir's config and hooks
        // then have ordinary workspace names, and the host's next `git status` reads them.
        let root = scratch("separate-gitdir");
        fs::create_dir_all(root.join("admin/hooks")).unwrap();
        fs::write(root.join("admin/HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(root.join(".git"), b"gitdir: admin\n").unwrap();
        refused_with(&root, "admin");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_commondir_naming_an_in_workspace_directory_is_refused() {
        let root = scratch("commondir-in");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("common-git")).unwrap();
        fs::write(root.join(".git/commondir"), b"../common-git\n").unwrap();
        refused_with(&root, "common-git");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_common_config_reached_through_commondir_is_scanned() {
        // A linked worktree's shared config is in the common gitdir, not beside the worktree's
        // own `config.worktree`; a scan of the located gitdir alone misses the file that names
        // the hooks git actually runs.
        let root = scratch("worktree");
        let gitdir = scratch("worktree-gitdir");
        let main = scratch("worktree-common");
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::write(main.join("config"), b"[core]\n\thooksPath = ./githooks\n").unwrap();
        fs::write(
            gitdir.join("commondir"),
            format!("{}\n", main.display()).as_bytes(),
        )
        .unwrap();
        fs::write(
            root.join(".git"),
            format!("gitdir: {}\n", gitdir.display()).as_bytes(),
        )
        .unwrap();
        assert!(served_read_only(&root).read_only.contains("githooks"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&gitdir);
        let _ = fs::remove_dir_all(&main);
    }

    #[test]
    fn a_worktree_config_with_an_inside_hooks_path_is_served_read_only() {
        let root = scratch("config-worktree");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::write(
            root.join(".git/config.worktree"),
            b"[core]\n\thooksPath = ./githooks\n",
        )
        .unwrap();
        assert!(served_read_only(&root).read_only.contains("githooks"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_protected_file_aliased_through_a_reaimable_workspace_intermediate_is_refused() {
        // The two-hop chain a final-target check misses: at validation the chain ends outside the
        // workspace, but its intermediate is an ordinary workspace name the sandbox can re-aim.
        let outside = scratch("two-hop-target");
        fs::write(outside.join("real-config"), b"[core]\n").unwrap();

        let root = scratch("two-hop-config");
        fs::create_dir_all(root.join(".git")).unwrap();
        std::os::unix::fs::symlink("../cfglink", root.join(".git/config")).unwrap();
        std::os::unix::fs::symlink(outside.join("real-config"), root.join("cfglink")).unwrap();
        refused_with(&root, "cfglink");
        let _ = fs::remove_dir_all(&root);

        // For hooks the intermediate is pinned instead, so it cannot be re-aimed; the chain
        // ends outside, where the mount reaches nothing.
        let root = scratch("two-hop-hooks");
        fs::create_dir_all(root.join(".git")).unwrap();
        std::os::unix::fs::symlink("../hooklink", root.join(".git/hooks")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("hooklink")).unwrap();
        let additions = served_read_only(&root);
        assert_eq!(additions.pinned, BTreeSet::from(["hooklink".to_string()]));
        assert!(additions.read_only.is_empty(), "{additions:?}");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_config_aliased_into_operational_git_state_is_refused() {
        // "Under .git" is not an exemption: the operational subtrees are writable, so a config
        // whose bytes are in .git/objects is a config the sandbox chooses.
        let root = scratch("alias-operational");
        fs::create_dir_all(root.join(".git/objects")).unwrap();
        fs::write(root.join(".git/objects/aux"), b"[core]\n").unwrap();
        std::os::unix::fs::symlink("objects/aux", root.join(".git/config")).unwrap();
        refused_with(&root, "objects");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_object_store_link_into_the_workspace_is_refused_and_one_leading_out_is_served() {
        // Each link leads the filter's protected name to an ordinary one the sandbox writes.
        for (link, target) in [
            (".git/objects", "../objects"),
            (".git/objects/info", "../../info"),
            (".git/objects/info/alternates", "../../../alternates"),
            (".git/objects/info/http-alternates", "../../../alternates"),
            (".git/objects", ".."),
        ] {
            let root = scratch("alternates-link");
            let link_path = root.join(link);
            fs::create_dir_all(link_path.parent().unwrap()).unwrap();
            fs::create_dir_all(root.join("objects/info")).unwrap();
            fs::create_dir_all(root.join("info")).unwrap();
            std::os::unix::fs::symlink(target, &link_path).unwrap();
            let refusal =
                check_hook_location(&root).expect_err(&format!("{link} -> {target} was served"));
            assert!(refusal.reason.contains("workspace"), "{refusal}");
            let _ = fs::remove_dir_all(&root);
        }

        // Objects kept outside, and a link out that leads back in below it.
        let root = scratch("objects-outside");
        let store = scratch("objects-outside-store");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(store.join("info")).unwrap();
        std::os::unix::fs::symlink(&store, root.join(".git/objects")).unwrap();
        assert!(check_hook_location(&root).is_ok());
        std::os::unix::fs::symlink(root.join("payload"), store.join("info/alternates")).unwrap();
        let refusal = check_hook_location(&root).expect_err("a link back in was served");
        assert!(refusal.reason.contains("alternates"), "{refusal}");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&store);

        // A relative link leading out leaves `.git/objects` by `..`, and is served too. The scratch
        // directories are siblings, so `root/../<store>` is the store.
        for (link, up) in [
            (".git/objects", "../.."),
            (".git/objects/info", "../../.."),
            (".git/objects/info/alternates", "../../../.."),
            (".git/objects/info/http-alternates", "../../../.."),
        ] {
            let root = scratch("objects-relative");
            let store = scratch("objects-relative-store");
            let store_name = store.file_name().unwrap().to_str().unwrap();
            let link_path = root.join(link);
            fs::create_dir_all(link_path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(format!("{up}/{store_name}"), &link_path).unwrap();
            assert!(
                check_hook_location(&root).is_ok(),
                "{link} -> {up}/{store_name} was refused"
            );
            let _ = fs::remove_dir_all(&root);
            let _ = fs::remove_dir_all(&store);
        }

        let root = scratch("alternates-real");
        fs::create_dir_all(root.join(".git/objects/info")).unwrap();
        fs::write(root.join(".git/objects/info/alternates"), b"/elsewhere\n").unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_external_gitdir_whose_object_store_links_back_into_the_workspace_protects_the_target() {
        for (link, target) in [
            ("objects/info/alternates", "payload"),
            ("objects/info", "info"),
        ] {
            let root = scratch("external-objects");
            let gitdir = scratch("external-objects-gitdir");
            fs::write(
                root.join(".git"),
                format!("gitdir: {}\n", gitdir.display()).as_bytes(),
            )
            .unwrap();
            let link_path = gitdir.join(link);
            fs::create_dir_all(link_path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(root.join(target), &link_path).unwrap();
            assert_eq!(
                served_read_only(&root).read_only,
                BTreeSet::from([target.to_string()]),
                "{link}",
            );
            let _ = fs::remove_dir_all(&root);
            let _ = fs::remove_dir_all(&gitdir);
        }
    }

    #[test]
    fn module_gitdirs_are_classified_with_the_roots_the_runtime_would_discover() {
        // With the submodule's HEAD present, `modules/sub` is a gitdir root and its `objects` is
        // operational — writable at runtime, so a config aliased there is refused. Without the
        // HEAD nothing under `modules/` ever becomes writable, and the same link resolves through
        // protected paths alone to a file that does not exist: an absent config, served.
        let root = scratch("modules-roots");
        fs::create_dir_all(root.join(".git/modules/sub")).unwrap();
        fs::write(
            root.join(".git/modules/sub/HEAD"),
            b"ref: refs/heads/main\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("modules/sub/objects/pack", root.join(".git/config")).unwrap();
        refused_with(&root, "objects");
        let _ = fs::remove_dir_all(&root);

        let root = scratch("modules-no-roots");
        fs::create_dir_all(root.join(".git/modules/sub")).unwrap();
        std::os::unix::fs::symlink("modules/sub/objects/pack", root.join(".git/config")).unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_external_hooks_directory_with_a_link_back_into_the_workspace_protects_the_target() {
        // An out-of-workspace hooksPath is legitimate, but an individual hook symlinked back into
        // ordinary workspace data is the same relocation one level down.
        let root = scratch("external-hooks");
        let outside = scratch("external-hooks-dir");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(
            root.join(".git/config"),
            format!("[core]\n\thooksPath = {}\n", outside.display()).as_bytes(),
        )
        .unwrap();
        std::os::unix::fs::symlink(root.join("payload"), outside.join("pre-commit")).unwrap();
        assert_eq!(
            served_read_only(&root).read_only,
            BTreeSet::from(["payload".to_string()]),
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn unreadable_or_undecodable_protected_files_refuse_rather_than_read_as_absent() {
        // Only NotFound means absent. A config that cannot be decoded holds values that cannot be
        // compared with the path hooks run from, and a config that cannot be read at all is the
        // same doubt.
        let root = scratch("non-utf8-config");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), [0xff, 0xfe, b'[', b'c', b'\n']).unwrap();
        refused_with(&root, "UTF-8");
        let _ = fs::remove_dir_all(&root);

        let root = scratch("config-as-directory");
        fs::create_dir_all(root.join(".git/config")).unwrap();
        refused_with(&root, "cannot read");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_bare_layout_at_the_workspace_root_is_refused_and_near_misses_are_served() {
        let root = scratch("bare-root");
        fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::create_dir_all(root.join("refs")).unwrap();
        refused_with(&root, "bare");
        let _ = fs::remove_dir_all(&root);

        // The recognition is git's own triple, so a partial or invalid layout stays an ordinary
        // project: a HEAD without refs, and a HEAD git would not validate.
        let root = scratch("bare-near-miss");
        fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::create_dir_all(root.join("objects")).unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);

        let root = scratch("bare-invalid-head");
        fs::write(root.join("HEAD"), b"an ordinary file named HEAD\n").unwrap();
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::create_dir_all(root.join("refs")).unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);

        // A symref git's own validate_headref rejects — the target must be under refs/ — so
        // the guard must not call this a repository either.
        let root = scratch("bare-invalid-symref");
        fs::write(root.join("HEAD"), b"ref: nonsense\n").unwrap();
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::create_dir_all(root.join("refs")).unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_relative_hooks_path_is_judged_from_every_directory_git_runs_hooks_in() {
        // Most hooks run from the worktree root, but the receive-side hooks run from $GIT_DIR:
        // `../hooksx` read from the worktree leaves this workspace, while the same value read from
        // `.git` is `hooksx` at the root — the directory `pre-receive` executes from on a
        // host-side push into this checkout, and so read-only.
        let root = scratch("hookspath-gitdir-base");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("hooksx")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = ../hooksx\n",
        )
        .unwrap();
        assert!(served_read_only(&root).read_only.contains("hooksx"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlink_loop_on_a_protected_path_is_refused_rather_than_spun_on() {
        let root = scratch("symlink-loop");
        fs::create_dir_all(root.join(".git")).unwrap();
        std::os::unix::fs::symlink("config", root.join(".git/config")).unwrap();
        refused_with(&root, "symlink hops");
        let _ = fs::remove_dir_all(&root);
    }

    // --- The walk below listed entries, and the shares ----------------------

    fn listed(names: &[&str]) -> FileRules {
        FileRules::new(
            names
                .iter()
                .map(|name| crate::policy::RuleLine {
                    word: RuleWord::ReadOnly,
                    components: name.split('/').map(|c| c.as_bytes().to_vec()).collect(),
                    anchored: false,
                })
                .collect(),
        )
    }

    fn protected(root: &Path, rules: &FileRules) -> Additions {
        resolve(root, rules, &[PathBuf::from("/")])
            .unwrap_or_else(|refusal| panic!("{root:?} was refused: {refusal}"))
    }

    fn set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| path.to_string()).collect()
    }

    /// Every path the additions make read-only whole: the read-only roots and the ends of the
    /// read-only aliases.
    fn read_only_paths(additions: &Additions, rules: &FileRules) -> BTreeSet<String> {
        let aliased = additions
            .aliases
            .iter()
            .filter(|(_, context)| context.read_only(rules))
            .map(|(path, _)| path.clone());
        additions.read_only.iter().cloned().chain(aliased).collect()
    }

    #[test]
    fn a_symlink_below_a_listed_entry_makes_its_target_read_only() {
        let root = scratch("listed-link");
        fs::create_dir_all(root.join(".vscode/sub")).unwrap();
        fs::write(root.join("tasks-data.json"), b"{}").unwrap();
        fs::write(root.join("deeper.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("../tasks-data.json", root.join(".vscode/tasks.json")).unwrap();
        std::os::unix::fs::symlink("../../deeper.json", root.join(".vscode/sub/x.json")).unwrap();
        let rules = listed(&[".vscode"]);
        let additions = protected(&root, &rules);
        assert_eq!(
            read_only_paths(&additions, &rules),
            set(&["deeper.json", "tasks-data.json"]),
        );
        assert!(additions.pinned.is_empty(), "{additions:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlink_a_later_writable_line_lifts_below_a_listed_entry_is_left_alone() {
        let root = scratch("listed-lifted-link");
        fs::create_dir_all(root.join(".vscode")).unwrap();
        fs::write(root.join("settings.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("../settings.json", root.join(".vscode/settings.json")).unwrap();
        let mut lines = listed(&[".vscode"]).lines().to_vec();
        lines.push(crate::policy::RuleLine {
            word: RuleWord::Writable,
            components: vec![b".vscode".to_vec(), b"settings.json".to_vec()],
            anchored: false,
        });
        let additions = protected(&root, &FileRules::new(lines));
        assert_eq!(additions, Additions::default());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_chained_symlink_pins_every_component_it_traverses() {
        let root = scratch("listed-chain");
        fs::create_dir_all(root.join(".vscode")).unwrap();
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(root.join("data/tasks.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("data", root.join("alias")).unwrap();
        std::os::unix::fs::symlink("../alias/tasks.json", root.join(".vscode/tasks.json")).unwrap();
        let rules = listed(&[".vscode"]);
        let additions = protected(&root, &rules);
        assert_eq!(
            read_only_paths(&additions, &rules),
            set(&["data/tasks.json"]),
        );
        assert_eq!(additions.pinned, set(&["alias", "data"]));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_chain_leaving_and_re_entering_the_workspace_protects_what_it_re_enters() {
        let root = scratch("listed-reenter");
        let outside = scratch("listed-reenter-outside");
        fs::create_dir_all(root.join(".vscode")).unwrap();
        fs::write(root.join("payload.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(root.join("payload.json"), outside.join("back.json")).unwrap();
        std::os::unix::fs::symlink(outside.join("back.json"), root.join(".vscode/tasks.json"))
            .unwrap();
        let rules = listed(&[".vscode"]);
        let additions = protected(&root, &rules);
        assert_eq!(read_only_paths(&additions, &rules), set(&["payload.json"]));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_listed_directory_outside_the_workspace_is_walked_for_links_back_in() {
        let root = scratch("listed-outside-dir");
        let outside = scratch("listed-outside-dir-shared");
        fs::write(root.join("payload.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(root.join("payload.json"), outside.join("tasks.json")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".vscode")).unwrap();
        let rules = listed(&[".vscode"]);
        let additions = protected(&root, &rules);
        assert_eq!(read_only_paths(&additions, &rules), set(&["payload.json"]));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_listed_directory_outside_the_workspace_linking_out_of_the_shares_is_refused() {
        // Through a podman machine the host may follow that link back into the workspace unseen.
        let root = scratch("listed-outside-unshared");
        let outside = scratch("listed-outside-unshared-dir");
        std::os::unix::fs::symlink(
            "/nonexistent-elsewhere/tasks.json",
            outside.join("tasks.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".vscode")).unwrap();
        let shares = [outside.parent().unwrap().to_path_buf()];
        let refusal = resolve(&root, &listed(&[".vscode"]), &shares)
            .expect_err("a link out of the shares was served");
        assert!(
            refusal.reason.contains("outside the directories"),
            "{refusal}"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_dangling_symlink_makes_the_name_it_waits_for_read_only() {
        // The sandbox would otherwise create the target the host program then reads.
        let root = scratch("listed-dangling");
        fs::create_dir_all(root.join(".vscode")).unwrap();
        std::os::unix::fs::symlink("../later/tasks.json", root.join(".vscode/tasks.json")).unwrap();
        let rules = listed(&[".vscode"]);
        let additions = protected(&root, &rules);
        assert_eq!(
            read_only_paths(&additions, &rules),
            set(&["later/tasks.json"]),
        );
        assert_eq!(additions.pinned, set(&["later"]));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlinked_interior_component_is_followed_and_its_target_pinned() {
        let root = scratch("listed-interior");
        fs::create_dir_all(root.join("shared/claude")).unwrap();
        fs::write(root.join("shared/claude/settings.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("shared/claude", root.join(".claude")).unwrap();
        let rules = listed(&[".claude/settings.json"]);
        let additions = protected(&root, &rules);
        // `settings.json` there stands under the alias's context, not a path of its own.
        assert!(
            read_only_paths(&additions, &rules).is_empty(),
            "{additions:?}",
        );
        assert_eq!(additions.pinned, set(&["shared", "shared/claude"]));
        let components: [&[u8]; 1] = [b".claude"];
        let claude = crate::policy::rule_context_of_path(&rules, &components).unwrap();
        assert_eq!(
            additions.aliases,
            vec![("shared/claude".to_string(), claude)],
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlinked_interior_component_s_target_gets_its_context_before_it_exists() {
        // The session would otherwise make `shared/claude/settings.json` after the mount.
        let root = scratch("listed-interior-absent");
        std::os::unix::fs::symlink("shared/claude", root.join(".claude")).unwrap();
        let rules = listed(&[".claude/settings.json"]);
        let additions = protected(&root, &rules);
        assert_eq!(additions.pinned, set(&["shared", "shared/claude"]));
        assert_eq!(additions.aliases.len(), 1, "{additions:?}");
        assert_eq!(additions.aliases[0].0, "shared/claude");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_reached_under_two_names_is_walked_under_each() {
        // Two layouts, each linking one listed directory to the other: whichever name the walk
        // lists first, one of them reaches the directory first under the name that lists nothing
        // inside it, and the other name's symlink must still be found.
        for (real, alias, inside, target) in [
            (
                ".claude",
                ".kiro",
                "settings/mcp.json",
                "../../payload.json",
            ),
            (".kiro", ".claude", "settings.json", "../payload.json"),
        ] {
            let root = scratch("listed-two-names");
            let entry = root.join(real).join(inside);
            fs::create_dir_all(entry.parent().unwrap()).unwrap();
            fs::write(root.join("payload.json"), b"{}").unwrap();
            std::os::unix::fs::symlink(target, &entry).unwrap();
            std::os::unix::fs::symlink(real, root.join(alias)).unwrap();
            let rules = listed(&[".claude/settings.json", ".kiro/settings/mcp.json"]);
            let additions = protected(&root, &rules);
            assert!(
                read_only_paths(&additions, &rules).contains("payload.json"),
                "{real} as {alias}: {additions:?}",
            );
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn a_listed_symlink_to_a_directory_holding_the_workspace_is_refused() {
        let root = scratch("listed-ancestor");
        std::os::unix::fs::symlink("..", root.join(".vscode")).unwrap();
        let refusal = resolve(&root, &listed(&[".vscode"]), &[PathBuf::from("/")])
            .expect_err("a listed entry holding the workspace was served");
        assert!(refusal.reason.contains("holds the workspace"), "{refusal}");
        fs::remove_file(root.join(".vscode")).unwrap();
        std::os::unix::fs::symlink(".", root.join(".vscode")).unwrap();
        let refusal = resolve(&root, &listed(&[".vscode"]), &[PathBuf::from("/")])
            .expect_err("a listed entry leading to the workspace root was served");
        assert!(
            refusal.reason.contains("the workspace root itself"),
            "{refusal}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_later_writable_line_lifts_inside_a_symlinked_directory_as_under_its_name() {
        let root = scratch("listed-interior-lifted");
        fs::create_dir_all(root.join("shared/claude/skills/cache")).unwrap();
        std::os::unix::fs::symlink("shared/claude", root.join(".claude")).unwrap();
        let file =
            crate::rulefile::parse("readonly .claude/skills\nwritable .claude/skills/cache\n")
                .unwrap();
        let additions = protected(&root, &file.rules);
        let (rules, text) = file.with_additions(&additions.lines(), &additions.aliases);
        let at = |path: &str| {
            let components: Vec<&[u8]> = path.split('/').map(str::as_bytes).collect();
            crate::policy::rule_context_of_path(&rules, &components).unwrap()
        };
        assert!(at("shared/claude/skills/new.md").read_only(&rules));
        assert!(!at("shared/claude/skills/cache/entry").read_only(&rules));
        assert!(
            text.contains("readonly-under shared/claude skills\n"),
            "{text}",
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_outside_the_listed_entries_is_walked() {
        let root = scratch("listed-unlisted");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("x.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("../x.json", root.join("src/link.json")).unwrap();
        let additions = protected(&root, &listed(&[".vscode"]));
        assert_eq!(additions, Additions::default());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_chain_leaving_the_shares_refuses_and_one_staying_in_them_is_followed() {
        // Through a podman machine the daemon sees the host's objects only in the shared
        // directories; outside them the host may follow a path back into the workspace unseen.
        let root = scratch("shares");
        let outside = scratch("shares-outside");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(
            root.join(".git/config"),
            format!("[core]\n\thooksPath = {}\n", outside.display()).as_bytes(),
        )
        .unwrap();
        let elsewhere = [PathBuf::from("/nonexistent-share")];
        let refusal = resolve(&root, &FileRules::default(), &elsewhere)
            .expect_err("a hooksPath outside the shares was served");
        assert!(
            refusal.reason.contains("outside the directories"),
            "{refusal}",
        );
        let shared = [outside.parent().unwrap().to_path_buf()];
        assert!(resolve(&root, &FileRules::default(), &shared).is_ok());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }
}
