//! The file rules as they cross between the launcher and the filter: the lines the launcher
//! resolved from its defaults and the project's `.ko-agent-sandbox/file/rule`, and the lines the
//! guard adds. The launcher owns the grammar and has already refused every ambiguity; this reads
//! the resolved form and refuses anything else, so a launcher and a filter of different versions
//! fail rather than disagree.
//!
//! One line per rule, words separated by single spaces. What the launcher writes:
//!
//! ```text
//! host-view /Users /private /var/folders   directories whose objects the daemon sees as the host does
//! readonly .vscode                          a rule line: a name at any depth, `*` within a component
//! writable node_modules
//! ```
//!
//! What the filter writes back when mounting and `--resolve` prints: the rule lines, then the
//! guard's, each naming a workspace-relative path from the root:
//!
//! ```text
//! readonly .vscode
//! writable node_modules
//! readonly-path .husky/_
//! pinned-path tools
//! readonly-under shared/claude settings.json
//! ```
//!
//! `readonly-under <dir> <rest>` makes `<rest>` below `<dir>` read-only, where a symlink makes
//! `<dir>` an interior component of a line: `.claude -> shared/claude` under
//! `readonly .claude/settings.json`.

use std::path::PathBuf;

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
    /// No rules, and the daemon's own namespace as the host's: a filter started without
    /// `--file-rules`, as the self-test and the mounted suites start it.
    pub fn none() -> RuleFile {
        RuleFile {
            rules: FileRules::default(),
            host_view: vec![PathBuf::from("/")],
            rule_text: Vec::new(),
        }
    }

    /// The rule lines followed by the guard's `additions`, which come last so they decide over
    /// every rule line, and the guard's `aliases`; and their text, which a mount with
    /// `--file-rules` writes beside its input and `--resolve` prints. The text is stricter than
    /// the returned rules where a `writable` line lifts under an alias's name, since the Seatbelt
    /// profile built from it has no contexts: a read-only alias prints as `readonly-path`, another
    /// as one `readonly-under` per `readonly` rest ([`RuleContext::read_only_rests`]).
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
                RuleWord::ReadOnly => read_only.push(format!("readonly-path {path}")),
                RuleWord::Writable => unreachable!("the guard adds no writable path"),
            }
        }
        let mut rules = FileRules::new(lines);
        for (path, context) in aliases {
            if context.read_only(&self.rules) {
                read_only.push(format!("readonly-path {path}"));
            } else {
                for rest in context.read_only_rests(&self.rules) {
                    under.push(format!("readonly-under {path} {rest}"));
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
            [word @ ("readonly" | "writable"), name] => {
                if !valid_name(name) {
                    return Err(format!("{}: not a resolved rule name", at()));
                }
                lines.push(RuleLine {
                    word: if *word == "readonly" {
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
            "host-view /Users /private /var/folders\nreadonly .vscode\nwritable node_modules\n\
             readonly *.code-workspace\n",
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
            "readonly .vscode\nwritable node_modules\nreadonly *.code-workspace\n\
             readonly-path .husky/_\npinned-path Tools\n",
        );
        let last = &rules.lines()[4];
        assert!(last.anchored);
        assert_eq!(last.word, RuleWord::Pinned);
        // Matched folded, echoed as spelled: the profile names the path the host has.
        assert_eq!(last.components, vec![b"tools".to_vec()]);
    }

    #[test]
    fn an_alias_prints_the_read_only_rests_it_carries_and_decides_below_its_path() {
        let file = parse("readonly .claude/settings.json\nreadonly .claude/skills\n").unwrap();
        let components: [&[u8]; 1] = [b".claude"];
        let claude = crate::policy::rule_context_of_path(&file.rules, &components).unwrap();
        let (rules, text) = file.with_additions(
            &[(RuleWord::Pinned, "Shared/claude".to_string())],
            &[("Shared/claude".to_string(), claude)],
        );
        assert_eq!(
            text,
            "readonly .claude/settings.json\nreadonly .claude/skills\npinned-path Shared/claude\n\
             readonly-under Shared/claude settings.json\nreadonly-under Shared/claude skills\n",
        );
        let components: [&[u8]; 4] = [b"shared", b"claude", b"skills", b"new.md"];
        let below = crate::policy::rule_context_of_path(&rules, &components).unwrap();
        assert!(below.read_only(&rules));
    }

    #[test]
    fn anything_but_the_resolved_form_is_refused() {
        for text in [
            "readonly\n",
            "readonly .vscode extra\n",
            "readonly  .vscode\n",
            "readonly .VSCODE\n",
            "readonly /.vscode\n",
            "readonly .vscode/\n",
            "readonly a//b\n",
            "readonly ../x\n",
            "readonly-path .husky/_\n",
            "allow .vscode\n",
            "host-view relative\n",
            "host-view /\nhost-view /\n",
            "readonly .vs code\n",
        ] {
            assert!(parse(text).is_err(), "{text:?} was accepted");
        }
    }

    #[test]
    fn without_a_host_view_line_the_daemon_sees_the_host_namespace() {
        assert_eq!(
            parse("readonly .idea\n").unwrap().host_view,
            vec![PathBuf::from("/")],
        );
    }
}
