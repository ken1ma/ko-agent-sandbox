//! Startup guards: the conditions under which the filter refuses to mount at all.
//!
//! The policy protects hooks where git puts them, `$GIT_DIR/hooks`. A host can relocate its hook
//! directory *into the worktree* — by symlinking `.git/hooks` there, or by a `core.hooksPath` that
//! already names a worktree path — and then the files host `git` executes sit at an ordinary
//! worktree path that the filter classifies as writable project data. Protecting the symlink path
//! alone would be theatre, because the same bytes are reachable under the target's own name
//! (`docs/git-metadata.md`, "Relocated hook directories").
//!
//! So the filter refuses to serve such a repository, loudly, naming the path — the same answer the
//! launcher already gives a symlinked `.git/hooks`. The refusal is narrow on purpose: it fires only
//! when the hook directory resolves *inside* the workspace. Hooks kept outside it are unreachable
//! through the mount anyway, so there is nothing to refuse.
//!
//! Scope: the repository at the workspace root — the one host `git` discovers from the project
//! directory. A repository deeper in the tree is not scanned, matching the launcher's own root-only
//! pin (`SECURITY.md`, "The host's git executing what the sandbox wrote"); the sandbox cannot create
//! one, so this is residue from a host that nested one itself.
//!
//! Scope in time, too: this runs once, before the mount, and is never repeated. A host that
//! relocates its hooks mid-session is not caught — deliberately, since polling would be only as
//! fresh as its last poll and the sandbox cannot cause the relocation anyway
//! (`docs/git-metadata.md`, "Relocated hook directories", has the trade).

use std::fs;
use std::path::{Path, PathBuf};

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

/// Check the workspace-root repository's hook location. `Ok(())` means the filter may serve this
/// tree; `Err` means it must not.
pub fn check_hook_location(backing_root: &Path) -> Result<(), Refusal> {
    let root = backing_root.canonicalize().map_err(|err| Refusal {
        reason: format!("cannot canonicalize the backing directory {backing_root:?}: {err}"),
        remedy: "The filter will not serve a tree it cannot resolve.".to_string(),
    })?;

    let Some(gitdir) = locate_gitdir(&root)? else {
        return Ok(()); // no repository at the workspace root; nothing to check
    };

    check_hooks_symlink(&root, &gitdir)?;
    check_hooks_path_config(&root, &gitdir)
}

/// The gitdir of the workspace-root repository: `.git` itself when it is a directory, or the path a
/// `.git` pointer file names. `None` when there is no repository.
fn locate_gitdir(root: &Path) -> Result<Option<PathBuf>, Refusal> {
    let dotgit = root.join(".git");
    let Ok(metadata) = fs::symlink_metadata(&dotgit) else {
        return Ok(None);
    };

    if metadata.is_dir() {
        return Ok(Some(dotgit));
    }

    if metadata.is_symlink() {
        // The launcher refuses a symlinked `.git` outright and so does this: a link decides where
        // the whole control surface lives, and following it would make the guarded set depend on
        // where it points at this instant.
        return Err(Refusal {
            reason: format!("{dotgit:?} is a symlink"),
            remedy: "Replace it with a real directory, or a `gitdir:` pointer file.".to_string(),
        });
    }

    // A pointer file: `gitdir: <path>`, absolute or relative to the worktree.
    let text = fs::read_to_string(&dotgit).map_err(|err| Refusal {
        reason: format!("cannot read the .git pointer file {dotgit:?}: {err}"),
        remedy: "The filter will not serve a repository whose gitdir it cannot locate.".to_string(),
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
    Ok(Some(resolve_against(root, target.trim())))
}

/// A relative path in git's metadata is relative to the worktree; an absolute one stands alone.
fn resolve_against(root: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// Whether `path` lands inside the workspace — i.e. somewhere the sandbox can write. Unresolvable
/// paths count as inside, so an unknown is refused rather than waved through.
fn resolves_inside(root: &Path, path: &Path) -> bool {
    match path.canonicalize() {
        Ok(resolved) => resolved.starts_with(root),
        // A path that does not exist yet cannot be canonicalized; judge its lexical parent instead,
        // since git would create the hooks directory there.
        Err(_) => match path.parent().map(Path::canonicalize) {
            Some(Ok(parent)) => parent.starts_with(root),
            _ => true,
        },
    }
}

fn check_hooks_symlink(root: &Path, gitdir: &Path) -> Result<(), Refusal> {
    let hooks = gitdir.join("hooks");
    let Ok(metadata) = fs::symlink_metadata(&hooks) else {
        return Ok(());
    };
    if !metadata.is_symlink() {
        return Ok(());
    }
    if resolves_inside(root, &hooks) {
        return Err(Refusal {
            reason: format!("{hooks:?} is a symlink into the workspace"),
            remedy: "Hooks inside the workspace would be writable by the sandbox and executed by \
                     your git. Move them outside it, or replace the symlink with a real directory."
                .to_string(),
        });
    }
    Ok(())
}

fn check_hooks_path_config(root: &Path, gitdir: &Path) -> Result<(), Refusal> {
    for name in ["config", "config.worktree"] {
        let path = gitdir.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        match scan_hooks_path(&text) {
            HooksPath::Absent => {}
            HooksPath::Undecidable(what) => {
                return Err(Refusal {
                    reason: format!("{path:?} {what}"),
                    remedy: "The filter cannot tell where hooks would run from, so it will not \
                             serve this repository. Set an explicit core.hooksPath outside the \
                             workspace, or remove it."
                        .to_string(),
                })
            }
            HooksPath::Value(value) => {
                let resolved = resolve_against(root, &value);
                if resolves_inside(root, &resolved) {
                    return Err(Refusal {
                        reason: format!(
                            "{path:?} sets core.hooksPath to {value:?}, inside the \
                                         workspace"
                        ),
                        remedy: "Hooks inside the workspace would be writable by the sandbox and \
                                 executed by your git. Point core.hooksPath outside it, or remove \
                                 the setting."
                            .to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// What a config file says about `core.hooksPath`.
#[derive(Debug, PartialEq, Eq)]
enum HooksPath {
    Absent,
    Value(String),
    /// The file could hide a `hooksPath` somewhere this scanner cannot follow.
    Undecidable(&'static str),
}

/// A deliberately blunt scanner, not a git-config parser. It answers one question — could this file
/// put hooks inside the workspace — and any doubt resolves to [`HooksPath::Undecidable`], which
/// refuses the mount. A `~` value or an `include` directive are the two doubts: expanding `~` would
/// need the host's home, which this process does not have, and an include can carry the setting in a
/// file the scanner never sees.
fn scan_hooks_path(text: &str) -> HooksPath {
    let mut found: Option<String> = None;
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        let lowercased = line.to_ascii_lowercase();

        if lowercased.starts_with("path") && lowercased.contains('=') {
            // An `include.path` / `includeIf.*.path` entry: the setting could live in that file.
            return HooksPath::Undecidable("uses an include, which may set core.hooksPath");
        }

        if !lowercased.starts_with("hookspath") {
            continue;
        }
        let Some((_, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim();
        if value.starts_with('~') {
            return HooksPath::Undecidable("sets core.hooksPath relative to a home directory");
        }
        if !value.is_empty() {
            found = Some(value.to_string());
        }
    }
    match found {
        Some(value) => HooksPath::Value(value),
        None => HooksPath::Absent,
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

    #[test]
    fn a_hooks_path_value_is_read_whatever_the_spacing_or_case() {
        assert_eq!(
            scan_hooks_path("[core]\n\thooksPath = ./githooks\n"),
            HooksPath::Value("./githooks".to_string())
        );
        assert_eq!(
            scan_hooks_path("[core]\nhookspath=/opt/hooks\n"),
            HooksPath::Value("/opt/hooks".to_string())
        );
        assert_eq!(
            scan_hooks_path("[core]\n\tHooksPath = \"./quoted hooks\"\n"),
            HooksPath::Value("./quoted hooks".to_string())
        );
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
        fs::write(root.join(".git/config"), b"[core]\n\tbare = false\n").unwrap();
        assert!(check_hook_location(&root).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_symlink_into_the_workspace_is_refused() {
        let root = scratch("symlinked-in");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("shared-hooks")).unwrap();
        std::os::unix::fs::symlink("../shared-hooks", root.join(".git/hooks")).unwrap();
        let refusal = check_hook_location(&root).unwrap_err();
        assert!(
            refusal.reason.contains("symlink into the workspace"),
            "{refusal}"
        );
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
        let refusal = check_hook_location(&root).unwrap_err();
        assert!(refusal.reason.contains("core.hooksPath"), "{refusal}");
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
        let refusal = check_hook_location(&root).unwrap_err();
        assert!(refusal.reason.contains("symlink"), "{refusal}");
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
        let refusal = check_hook_location(&root).unwrap_err();
        assert!(
            refusal.reason.contains("symlink into the workspace"),
            "{refusal}"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&gitdir);
    }
}
