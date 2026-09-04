//! Startup guards: the conditions under which the filter refuses to mount at all.
//!
//! The binding rule and the snapshot argument are `doc/git-metadata.md`, "Relocated hook
//! directories"; the scope residue — root repository only, once, before the mount — is `SECURITY.md`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::policy::{GitPathClass, classify_relative_path};

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

pub fn check_hook_location(backing_root: &Path) -> Result<(), Refusal> {
    let root = backing_root.canonicalize().map_err(|err| Refusal {
        reason: format!("cannot canonicalize the backing directory {backing_root:?}: {err}"),
        remedy: "The filter will not serve a tree it cannot resolve.".to_string(),
    })?;

    let workspace = Workspace::open(root)?;
    match workspace.locate_gitdir()? {
        Some(gitdir) => workspace.check_repository(&gitdir),
        None => workspace.check_bare_root(),
    }
}

struct Workspace {
    root: PathBuf,
    /// Submodule gitdir roots as workspace-relative byte paths — discovered by the `HEAD` each
    /// gitdir holds, the same question the runtime plumbing asks of the tree (`fs.rs`,
    /// `is_gitdir_root`), so this guard's `Control` means the runtime's `Control`. Without them,
    /// everything under `modules/` would read as namespace — Control, and so *exempt* here —
    /// while the runtime serves an identified gitdir's `objects/` writable: the fail-open
    /// direction, closed by asking the tree the same question at the same answer.
    gitdir_roots: Vec<Vec<u8>>,
}

impl Workspace {
    fn open(root: PathBuf) -> Result<Workspace, Refusal> {
        let mut workspace = Workspace {
            root,
            gitdir_roots: Vec::new(),
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
            // own — the real gitdir's lives wherever locate_gitdir vetted.
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
    /// own name lives in its parent directory, which the mount never serves.
    fn relative_bytes(&self, path: &Path) -> Option<Vec<u8>> {
        let rel = path.strip_prefix(&self.root).ok()?;
        if rel.as_os_str().is_empty() {
            return None;
        }
        Some(rel.as_os_str().as_bytes().to_vec())
    }

    fn refuse_operational(&self, origin: &str, component: &Path) -> Refusal {
        Refusal {
            reason: format!(
                "{origin} resolves through {component:?}, inside the workspace and writable by \
                 the sandbox"
            ),
            remedy: "Hooks and configuration reachable through a writable workspace path would \
                     be writable by the sandbox and executed by your git. Move them outside it, \
                     or under the repository's protected .git state."
                .to_string(),
        }
    }

    /// Resolve an absolute `path` the way the host kernel will, proving the binding rule as it
    /// walks: each named component that lies inside the workspace must classify `Control` before
    /// it is even looked up — existence cannot weaken the answer, because a missing operational
    /// name is one the sandbox can create. Returns the resolved path, or `None` when it does not
    /// exist, which is reached only through components the rule admitted. `origin` names what is
    /// being resolved, for the refusal an operator reads.
    fn resolve_checked(&self, path: &Path, origin: &str) -> Result<Option<PathBuf>, Refusal> {
        let roots: Vec<&[u8]> = self.gitdir_roots.iter().map(Vec::as_slice).collect();
        let mut pending: VecDeque<OsString> = components_of(path).into();
        let mut current = PathBuf::from("/");
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
                if let Some(rel) = self.relative_bytes(&next)
                    && classify_relative_path(&rel, &roots) != GitPathClass::Control
                {
                    return Err(self.refuse_operational(origin, &next));
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
                                "cannot resolve {next:?} while locating {origin}: {err}"
                            ),
                            remedy: "The filter will not serve control state it cannot resolve."
                                .to_string(),
                        });
                    }
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(Refusal {
                                reason: format!(
                                    "{origin} takes more than {MAX_SYMLINK_HOPS} symlink hops to \
                                     resolve"
                                ),
                                remedy: "The filter will not serve control state it cannot \
                                         resolve."
                                    .to_string(),
                            });
                        }
                        let target = fs::read_link(&next).map_err(|err| Refusal {
                            reason: format!("cannot read the symlink {next:?}: {err}"),
                            remedy: "The filter will not serve control state it cannot resolve."
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
        if missing { Ok(None) } else { Ok(Some(current)) }
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
            // The launcher refuses a symlinked `.git` outright and so does this: a link decides
            // where the whole of the control state lives, and following it would make the guarded set
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
        let origin = format!("the gitdir {dotgit:?} names");
        match self.resolve_checked(&named, &origin)? {
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

    /// The common gitdir — where `config` and `hooks` live for a linked worktree: the directory
    /// the gitdir's `commondir` file names, or the gitdir itself when there is none.
    fn common_of(&self, gitdir: &Path) -> Result<PathBuf, Refusal> {
        let commondir_path = gitdir.join("commondir");
        let origin = format!("the commondir file {commondir_path:?}");
        let Some(resolved) = self.resolve_checked(&commondir_path, &origin)? else {
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
        let origin = format!("the common gitdir {commondir_path:?} names");
        match self.resolve_checked(&named, &origin)? {
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

    fn check_repository(&self, gitdir: &Path) -> Result<(), Refusal> {
        let common = self.common_of(gitdir)?;

        // Every effective hooks directory: where git looks by default — the common gitdir's
        // `hooks`, which is `.git/hooks` when `.git` is the gitdir — plus every directory a
        // decidable `hooksPath` names, collected below.
        let mut hooks_dirs: Vec<PathBuf> = vec![common.join("hooks")];
        if !hooks_dirs.contains(&gitdir.join("hooks")) {
            hooks_dirs.push(gitdir.join("hooks"));
        }

        // The config files git reads for this repository: the shared config lives in the common
        // gitdir — for a linked worktree that is NOT the located gitdir, which holds only
        // `config.worktree` — so scanning `gitdir/config` alone misses the file that names the
        // hooks git actually runs.
        for config_path in [common.join("config"), gitdir.join("config.worktree")] {
            let origin = format!("the config file {config_path:?}");
            let Some(resolved) = self.resolve_checked(&config_path, &origin)? else {
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
                    // Every base is judged — worktree, gitdir, common gitdir — and any one
                    // landing on writable workspace paths refuses; over-refusing a spelling only
                    // one base makes dangerous is the scanner's own price.
                    let mut bases: Vec<&Path> = vec![self.root.as_path()];
                    for base in [gitdir, common.as_path()] {
                        if !bases.contains(&base) {
                            bases.push(base);
                        }
                    }
                    for value in values {
                        for base in &bases {
                            let named = resolve_against(base, &value);
                            let origin =
                                format!("{config_path:?} sets a hooksPath to {value:?}, which");
                            if let Some(dir) = self.resolve_checked(&named, &origin)?
                                && !hooks_dirs.contains(&dir)
                            {
                                hooks_dirs.push(dir);
                            }
                        }
                    }
                }
            }
        }

        for dir in hooks_dirs {
            self.check_hook_entries(&dir)?;
        }
        Ok(())
    }

    /// Every entry of an effective hooks directory, resolved under the binding rule: the
    /// directory may legitimately live outside the workspace, but an individual hook that is a
    /// symlink back into ordinary workspace data is the same relocation one level down.
    fn check_hook_entries(&self, dir: &Path) -> Result<(), Refusal> {
        let origin = format!("the hook directory {dir:?}");
        let Some(resolved) = self.resolve_checked(dir, &origin)? else {
            return Ok(());
        };
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
            let origin = format!("the hook {hook:?}");
            self.resolve_checked(&hook, &origin)?;
        }
        Ok(())
    }

    /// Whether the workspace root is itself laid out as a gitdir — `git init --bare`,
    /// `git clone --bare|--mirror`, or hand-assembled. Host git's ascending discovery adopts such
    /// a directory, and its config and hooks sit at ordinary names the filter must keep writable,
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
            remedy: "Its config and hooks sit at workspace-root names the filter must keep \
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
    /// Every `hooksPath` the file states, in file order. Which one git reads is not this scanner's
    /// to say, so the caller judges them all.
    Values(Vec<String>),
    /// The file could hide a `hooksPath` somewhere this scanner cannot follow.
    Undecidable(&'static str),
}

/// A deliberately blunt scanner, not a git-config parser. It answers one question — could this file
/// put hooks inside the workspace — and every doubt resolves to [`HooksPath::Undecidable`], which
/// refuses the mount.
///
/// Blunt has to mean blunt *toward refusing*, which is the invariant to preserve when changing
/// this scanner. It reads no section headers, so it reports every `hooksPath` in
/// the file and lets the caller refuse if *any* lands inside the workspace — keeping only the last
/// would be the fail-open reading — and each doubt refuses because reading it any other way would
/// compare a different string than the one hooks run from. The worked example and the per-doubt
/// reasons are `doc/git-metadata.md`, "Relocated hook directories".
fn scan_hooks_path(text: &str) -> HooksPath {
    let mut found: Vec<String> = Vec::new();
    for raw in text.lines() {
        let Some(line) = strip_comment(raw) else {
            return HooksPath::Undecidable(
                "leaves a double quote open, so its values cannot be read",
            );
        };
        let line = line.trim();
        let lowercased = line.to_ascii_lowercase();

        if lowercased.starts_with("path") && lowercased.contains('=') {
            // Sections are invisible here, so this cannot tell `include.path` from any other bare
            // `path` key; the message says what was seen rather than asserting the section.
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
        let value = value.trim().trim_matches('"').trim();
        if value.starts_with('~') {
            return HooksPath::Undecidable("sets a hooksPath relative to a home directory");
        }
        if value.contains('\\') {
            return HooksPath::Undecidable("sets a hooksPath containing a backslash escape");
        }
        if !value.is_empty() {
            found.push(value.to_string());
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
fn strip_comment(line: &str) -> Option<&str> {
    let mut quoted = false;
    for (at, ch) in line.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => return Some(&line[..at]),
            _ => {}
        }
    }
    if quoted { None } else { Some(line) }
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
        // last value would answer `/opt/hooks` and serve the tree. Both are reported instead, and
        // the caller refuses on the first that lands inside.
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
    fn a_commented_hooks_path_is_not_a_value() {
        assert_eq!(
            scan_hooks_path("[core]\n\t# hooksPath = ./githooks\n"),
            HooksPath::Absent
        );
    }

    #[test]
    fn an_include_makes_the_answer_undecidable() {
        // The setting could live in the included file, which this scanner does not follow — so the
        // mount is refused rather than guessed at.
        assert!(matches!(
            scan_hooks_path("[include]\n\tpath = ../shared.config\n"),
            HooksPath::Undecidable(_)
        ));
        assert!(matches!(
            scan_hooks_path("[includeIf \"gitdir:~/work/\"]\n\tpath = work.config\n"),
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
    fn a_hooks_symlink_inside_the_workspace_is_refused() {
        let root = scratch("symlinked-in");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("shared-hooks")).unwrap();
        std::os::unix::fs::symlink("../shared-hooks", root.join(".git/hooks")).unwrap();
        let refusal = refused_with(&root, "shared-hooks");
        assert!(refusal.reason.contains("inside the workspace"), "{refusal}");
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
    fn a_hooks_path_inside_the_workspace_is_refused() {
        let root = scratch("hookspath-in");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = ./githooks\n",
        )
        .unwrap();
        // "a hooksPath", not "core.hooksPath": the scanner does not read sections, and a message
        // naming one it cannot see would send the operator to the wrong line.
        let refusal = refused_with(&root, "hooksPath");
        assert!(refusal.reason.contains("githooks"), "{refusal}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_masked_by_a_later_section_is_still_refused() {
        // End to end, the property `every_hooks_path_is_reported_because_sections_are_invisible`
        // pins at the scanner: the repository git would run `./githooks` from is refused, whatever
        // stands after it in the file.
        let root = scratch("hookspath-masked");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = ./githooks\n[tool]\n\thooksPath = /opt/hooks\n",
        )
        .unwrap();
        refused_with(&root, "githooks");
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
        let refusal = refused_with(&root, "shared-hooks");
        assert!(refusal.reason.contains("inside the workspace"), "{refusal}");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&gitdir);
    }

    #[test]
    fn a_pointer_file_naming_an_in_workspace_gitdir_is_refused() {
        // `git init --separate-git-dir admin .` run by the host: the gitdir's config and hooks
        // then sit at ordinary workspace names, and the host's next `git status` reads them.
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
        // A linked worktree's shared config lives in the common gitdir, not beside the worktree's
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
        refused_with(&root, "githooks");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&gitdir);
        let _ = fs::remove_dir_all(&main);
    }

    #[test]
    fn a_worktree_config_with_an_inside_hooks_path_is_refused() {
        let root = scratch("config-worktree");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("githooks")).unwrap();
        fs::write(
            root.join(".git/config.worktree"),
            b"[core]\n\thooksPath = ./githooks\n",
        )
        .unwrap();
        refused_with(&root, "githooks");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_control_file_aliased_through_a_reaimable_workspace_intermediate_is_refused() {
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

        let root = scratch("two-hop-hooks");
        fs::create_dir_all(root.join(".git")).unwrap();
        std::os::unix::fs::symlink("../hooklink", root.join(".git/hooks")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("hooklink")).unwrap();
        refused_with(&root, "hooklink");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_config_aliased_into_operational_git_state_is_refused() {
        // "Under .git" is not an exemption: the operational subtrees are writable, so a config
        // whose bytes live in .git/objects is a config the sandbox chooses.
        let root = scratch("alias-operational");
        fs::create_dir_all(root.join(".git/objects")).unwrap();
        fs::write(root.join(".git/objects/aux"), b"[core]\n").unwrap();
        std::os::unix::fs::symlink("objects/aux", root.join(".git/config")).unwrap();
        refused_with(&root, "objects");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn module_gitdirs_are_classified_with_the_roots_the_runtime_would_discover() {
        // With the submodule's HEAD present, `modules/sub` is a gitdir root and its `objects` is
        // operational — writable at runtime, so a config aliased there is refused. Without the
        // HEAD nothing under `modules/` ever becomes writable, and the same link resolves through
        // control state alone to a file that does not exist: an absent config, served.
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
    fn an_external_hooks_directory_with_a_link_back_into_the_workspace_is_refused() {
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
        refused_with(&root, "payload");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn unreadable_or_undecodable_control_files_refuse_rather_than_read_as_absent() {
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

        // A symref git's own validate_headref rejects — the target must live under refs/ — so
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
        // `.git` is the writable `hooksx` at the root — the directory `pre-receive` executes from
        // on a host-side push into this checkout.
        let root = scratch("hookspath-gitdir-base");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("hooksx")).unwrap();
        fs::write(
            root.join(".git/config"),
            b"[core]\n\thooksPath = ../hooksx\n",
        )
        .unwrap();
        refused_with(&root, "hooksx");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlink_loop_on_a_control_path_is_refused_rather_than_spun_on() {
        let root = scratch("symlink-loop");
        fs::create_dir_all(root.join(".git")).unwrap();
        std::os::unix::fs::symlink("config", root.join(".git/config")).unwrap();
        refused_with(&root, "symlink hops");
        let _ = fs::remove_dir_all(&root);
    }
}
