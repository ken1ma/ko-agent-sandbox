//! Startup guards: the conditions under which the filter refuses to mount at all.
//!
//! The policy protects hooks where git puts them, `$GIT_DIR/hooks`. A host can relocate its hook
//! directory *into the worktree* — by symlinking `.git/hooks` there, or by a `core.hooksPath` that
//! already names a worktree path — and then the files host `git` executes sit at an ordinary
//! worktree path that the filter classifies as writable project data. Protecting the symlink path
//! alone would be theatre, because the same bytes are reachable under the target's own name
//! (`doc/git-metadata.md`, "Relocated hook directories").
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
//! (`doc/git-metadata.md`, "Relocated hook directories", has the trade).

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
                });
            }
            // Every value, not the last one: the scanner cannot see sections, so it cannot know
            // which of them git will read as `core.hooksPath` — and judging one of them lets the
            // others through (`scan_hooks_path`).
            HooksPath::Values(values) => {
                for value in values {
                    let resolved = resolve_against(root, &value);
                    if resolves_inside(root, &resolved) {
                        return Err(Refusal {
                            reason: format!(
                                "{path:?} sets a hooksPath to {value:?}, inside the workspace"
                            ),
                            remedy: "Hooks inside the workspace would be writable by the sandbox \
                                     and executed by your git. Point core.hooksPath outside it, or \
                                     remove the setting."
                                .to_string(),
                        });
                    }
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
/// Blunt has to mean blunt *toward refusing*, which is the whole discipline here and the one thing
/// to preserve when touching this. It does not read section headers, so it cannot tell
/// `core.hooksPath` from a `hooksPath` under some other section — a key git never reads for hooks.
/// It therefore reports every one of them and lets the caller refuse if *any* lands inside the
/// workspace. Keeping only the last would be the fail-open shape: a stray
/// `[tool] hooksPath = /opt/hooks` after a real `[core] hooksPath = ./githooks` would answer for
/// both, and the worktree hooks git actually runs would be served as ordinary writable data. The
/// price is over-refusing a config whose only `hooksPath` inside the workspace is one git ignores,
/// which costs a mount, never a guarantee.
///
/// Soundness rests on the value being the value git reads: whatever git resolves `core.hooksPath`
/// to appears on some line here, so seeing every line suffices — provided each is read faithfully.
/// Hence the doubts, each of which would otherwise make this scanner compare a different string
/// than the one hooks run from: a `~` (expanding it needs the host's home, which this process does
/// not have), a backslash (git decodes escapes this does not), an unterminated quote, and a bare
/// `path` key, which under `include` or `includeIf` names a file the scanner never opens.
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
            return HooksPath::Undecidable("sets a hooksPath carrying a backslash escape");
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
        // The fail-open shape this scanner must not have. `tool.hooksPath` is a key git never reads
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
        // Outside quotes they still start a comment.
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
        // "a hooksPath", not "core.hooksPath": the scanner does not read sections, and a message
        // naming one it cannot see would send the operator to the wrong line.
        assert!(refusal.reason.contains("hooksPath"), "{refusal}");
        assert!(refusal.reason.contains("githooks"), "{refusal}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hooks_path_masked_by_a_later_section_is_still_refused() {
        // End to end, the shape `every_hooks_path_is_reported_because_sections_are_invisible`
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
        let refusal = check_hook_location(&root).unwrap_err();
        assert!(refusal.reason.contains("githooks"), "{refusal}");
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
