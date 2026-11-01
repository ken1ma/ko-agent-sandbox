//! The file rules as they pass between the launcher and the workspace policy: the lines the
//! launcher resolved from its defaults and the workspace's `.ko-agent-sandbox/file/rule`, and the
//! lines the guard adds. The launcher owns the grammar and has already refused every ambiguity.
//! This reads the resolved form and refuses anything else, so a launcher and a workspace policy of
//! different versions fail instead of disagreeing.
//!
//! One line per rule, words separated by single spaces. What the launcher writes:
//!
//! ```text
//! host-view /Users /private /var/folders   directories whose objects the daemon sees as the host does
//! read-only .vscode                         a rule line: a name at any depth, `*` within a component
//! writable node_modules
//! ```
//!
//! What the FUSE backend's daemon writes back when mounting, and what `--resolve` prints: the rule
//! lines, then the guard's, each naming a workspace-relative path from the root:
//!
//! ```text
//! read-only .vscode
//! writable node_modules
//! read-only-path .husky/_
//! pinned-path tools
//! read-only-under shared/claude settings.json
//! ```
//!
//! `read-only-under <dir> <rest>` makes `<rest>` below `<dir>` read-only. It is written where a
//! symlink makes `<dir>` an interior component of a line: `.claude -> shared/claude` under
//! `read-only .claude/settings.json`.

use std::path::{Path, PathBuf};

use crate::guard::{self, GuardedPath};
use crate::policy::{FileRules, RuleContext, RuleLine, RuleWord, fold};

/// A parsed file: the rules, and where the guard may follow a chain out of the workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFile {
    pub rules: FileRules,
    /// Absolute directories whose objects the daemon sees as the host does. A chain leaving
    /// them is one the guard cannot verify (`guard.rs`, `resolve`).
    pub host_view: Vec<PathBuf>,
    /// The rule lines as written, for the resolved output.
    rule_text: Vec<String>,
}

impl RuleFile {
    /// No rules, and the daemon's own namespace as the host's: a FUSE backend daemon started
    /// without `--file-rules`, as the self-test and the mounted suites start it.
    pub fn none() -> RuleFile {
        RuleFile {
            rules: FileRules::default(),
            host_view: vec![PathBuf::from("/")],
            rule_text: Vec::new(),
        }
    }

    /// The rule lines, then the guard's `additions` and `aliases`; and their text.
    /// - The additions come last, so they decide over every rule line.
    /// - A mount with `--file-rules` writes the text beside its input, and `--resolve` prints it.
    /// - The text is stricter than the returned rules where a `writable` line lifts under an
    ///   alias's name, because the Seatbelt profile built from it has no contexts. A read-only
    ///   alias prints as `read-only-path`; any other alias prints as one `read-only-under` per
    ///   `read-only` rest ([`RuleContext::read_only_rests`]).
    pub fn with_additions(
        &self,
        additions: &[(RuleWord, String)],
        aliases: &[(String, RuleContext)],
    ) -> (FileRules, String) {
        let mut lines = self.rules.lines().to_vec();
        let (mut read_only, mut pinned, mut under) = (Vec::new(), Vec::new(), Vec::new());
        for (word, path) in additions {
            lines.push(anchored_line(*word, path));
            match word {
                RuleWord::Pinned => pinned.push(format!("pinned-path {path}")),
                RuleWord::ReadOnly => read_only.push(format!("read-only-path {path}")),
                RuleWord::Writable => unreachable!("the guard adds no writable path"),
            }
        }
        let mut rules = FileRules::new(lines);
        for (path, context) in aliases {
            if context.read_only(&self.rules) {
                read_only.push(format!("read-only-path {path}"));
            } else {
                for rest in context.read_only_rests(&self.rules) {
                    under.push(format!("read-only-under {path} {rest}"));
                }
            }
            rules.push_alias(path, context.clone());
        }
        read_only.sort();
        read_only.dedup();
        let text: Vec<String> = [self.rule_text.clone(), read_only, pinned, under].concat();
        let mut rendered = text.join("\n");
        if !rendered.is_empty() {
            rendered.push('\n');
        }
        (rules, rendered)
    }
}

fn anchored_line(word: RuleWord, path: &str) -> RuleLine {
    RuleLine {
        word,
        components: path
            .split('/')
            .map(|component| fold(component.as_bytes()))
            .collect(),
        anchored: true,
    }
}

/// Parse the launcher's file. Every line is a rule, the `host-view` line or blank.
pub fn parse(text: &str) -> Result<RuleFile, String> {
    let mut lines = Vec::new();
    let mut rule_text = Vec::new();
    let mut host_view: Option<Vec<PathBuf>> = None;
    for (number, line) in text.lines().enumerate() {
        let words: Vec<&str> = line.split(' ').collect();
        let at = || format!("file rules line {}: {line:?}", number + 1);
        match words.as_slice() {
            [""] => {}
            ["host-view", roots @ ..] if !roots.is_empty() => {
                if host_view.is_some() {
                    return Err(format!("{}: a second host-view line", at()));
                }
                if roots.iter().any(|root| !root.starts_with('/')) {
                    return Err(format!("{}: a host-view directory is not absolute", at()));
                }
                host_view = Some(roots.iter().map(PathBuf::from).collect());
            }
            [word @ ("read-only" | "writable"), name] => {
                if !valid_name(name) {
                    return Err(format!("{}: not a resolved rule name", at()));
                }
                lines.push(RuleLine {
                    word: if *word == "read-only" {
                        RuleWord::ReadOnly
                    } else {
                        RuleWord::Writable
                    },
                    components: name.split('/').map(|c| c.as_bytes().to_vec()).collect(),
                    anchored: false,
                });
                rule_text.push(line.to_string());
            }
            _ => return Err(format!("{}: not a resolved file rule", at())),
        }
    }
    Ok(RuleFile {
        rules: FileRules::new(lines),
        host_view: host_view.unwrap_or_else(|| vec![PathBuf::from("/")]),
        rule_text,
    })
}

/// The rules the FUSE backend serves over `source`, or `--resolve` prints: the launcher's file at
/// `file_rules`, if any, with the guard's additions; their text; and the guarded objects. An error
/// names what failed, without the program's name.
pub fn resolve(
    source: &Path,
    file_rules: Option<&Path>,
) -> Result<(FileRules, String, Vec<GuardedPath>), String> {
    let rule_file = match file_rules {
        None => RuleFile::none(),
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|err| format!("cannot read the file rules {path:?}: {err}"))?;
            parse(&text)?
        }
    };
    let additions = guard::resolve(source, &rule_file.rules, &rule_file.host_view)
        .map_err(|refusal| format!("refusing to serve {source:?}\n{refusal}"))?;
    let (rules, text) = rule_file.with_additions(&additions.lines(), &additions.aliases);
    Ok((rules, text, additions.guarded))
}

/// A rule name as the launcher resolves it: `/`-separated components of `a`–`z`, `0`–`9`, `.`,
/// `_`, `-` and `*`; no empty, `.` or `..` component.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-' | b'*')
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resolved_form_parses_and_echoes_with_the_guard_additions_last() {
        let file = parse(
            "host-view /Users /private /var/folders\nread-only .vscode\nwritable node_modules\n\
             read-only *.code-workspace\n",
        )
        .unwrap();
        assert_eq!(
            file.host_view,
            vec![
                PathBuf::from("/Users"),
                PathBuf::from("/private"),
                PathBuf::from("/var/folders"),
            ],
        );
        let (rules, text) = file.with_additions(
            &[
                (RuleWord::ReadOnly, ".husky/_".to_string()),
                (RuleWord::Pinned, "Tools".to_string()),
            ],
            &[],
        );
        assert_eq!(
            text,
            "read-only .vscode\nwritable node_modules\nread-only *.code-workspace\n\
             read-only-path .husky/_\npinned-path Tools\n",
        );
        let last = &rules.lines()[4];
        assert!(last.anchored);
        assert_eq!(last.word, RuleWord::Pinned);
        // Matched folded, echoed as spelled: the profile names the path the host has.
        assert_eq!(last.components, vec![b"tools".to_vec()]);
    }

    #[test]
    fn an_alias_prints_the_read_only_rests_it_carries_and_decides_below_its_path() {
        let file = parse("read-only .claude/settings.json\nread-only .claude/skills\n").unwrap();
        let components: [&[u8]; 1] = [b".claude"];
        let claude = crate::policy::rule_context_of_path(&file.rules, &components).unwrap();
        let (rules, text) = file.with_additions(
            &[(RuleWord::Pinned, "Shared/claude".to_string())],
            &[("Shared/claude".to_string(), claude)],
        );
        assert_eq!(
            text,
            "read-only .claude/settings.json\nread-only .claude/skills\npinned-path Shared/claude\n\
             read-only-under Shared/claude settings.json\nread-only-under Shared/claude skills\n",
        );
        let components: [&[u8]; 4] = [b"shared", b"claude", b"skills", b"new.md"];
        let below = crate::policy::rule_context_of_path(&rules, &components).unwrap();
        assert!(below.read_only(&rules));
    }

    #[test]
    fn anything_but_the_resolved_form_is_refused() {
        for text in [
            "read-only\n",
            "read-only .vscode extra\n",
            "read-only  .vscode\n",
            "read-only .VSCODE\n",
            "read-only /.vscode\n",
            "read-only .vscode/\n",
            "read-only a//b\n",
            "read-only ../x\n",
            "read-only-path .husky/_\n",
            "allow .vscode\n",
            "host-view relative\n",
            "host-view /\nhost-view /\n",
            "read-only .vs code\n",
        ] {
            assert!(parse(text).is_err(), "{text:?} was accepted");
        }
    }

    #[test]
    fn without_a_host_view_line_the_daemon_sees_the_host_namespace() {
        assert_eq!(
            parse("read-only .idea\n").unwrap().host_view,
            vec![PathBuf::from("/")],
        );
    }
}
