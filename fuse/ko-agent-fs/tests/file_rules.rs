//! The file rules' conformance table (`tests/data/file-rules.conformance`), checked against the
//! policy the FUSE layer enforces. The launcher's `SeatbeltProfileTest` checks the same table
//! against the Seatbelt profile, so the two enforcement points hold one contract. No mount: the
//! decision is the policy's, and `rule_context_of_path` walks it as lookups would.

use ko_agent_fs::policy::{FileRules, RuleLine, RuleWord, fold, rule_context_of_path};

struct Case {
    name: String,
    lines: Vec<(String, String)>,
    rows: Vec<Row>,
}

struct Row {
    folded: bool,
    path: String,
    expected: String,
}

fn cases() -> Vec<Case> {
    let text = include_str!("data/file-rules.conformance");
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
    cases
}

fn rule_line(word: &str, name: &str) -> RuleLine {
    let (word, anchored) = match word {
        "readonly" => (RuleWord::ReadOnly, false),
        "writable" => (RuleWord::Writable, false),
        "readonly-path" => (RuleWord::ReadOnly, true),
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

fn answer(lines: &[(String, String)], path: &str) -> String {
    let rules = FileRules::new(
        lines
            .iter()
            .map(|(word, name)| rule_line(word, name))
            .collect(),
    );
    let components: Vec<&[u8]> = path.split('/').map(str::as_bytes).collect();
    let context = rule_context_of_path(&rules, &components).expect("an ordinary path");
    if context.read_only(&rules) {
        "readonly"
    } else if context.pinned() {
        "pinned"
    } else {
        "free"
    }
    .to_string()
}

#[test]
fn the_policy_answers_the_conformance_table() {
    let cases = cases();
    assert!(cases.len() >= 10, "the table did not parse into its cases");
    let mut failures = Vec::new();
    for case in &cases {
        for row in &case.rows {
            let got = answer(&case.lines, &row.path);
            if got != row.expected {
                failures.push(format!(
                    "{}: {} {:?}: expected {}, got {got}",
                    case.name,
                    if row.folded { "folded" } else { "path" },
                    row.path,
                    row.expected,
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
