//! The file rules' conformance table (`tests/data/file-rules.conformance`), checked against the
//! policy the FUSE layer enforces. The launcher's `SeatbeltProfileTest` checks the same table
//! against the Seatbelt profile, so the two enforcement points hold one contract. No mount: the
//! decision is the policy's, and `rule_context_of_path` walks it as lookups would.

mod corpus;

use ko_agent_fs::policy::{FileRules, rule_context_of_path};

fn answer(lines: &[(String, String)], path: &str) -> String {
    let rules = FileRules::new(
        lines
            .iter()
            .map(|(word, name)| corpus::rule_line(word, name))
            .collect(),
    );
    let components: Vec<&[u8]> = path.split('/').map(str::as_bytes).collect();
    let context = rule_context_of_path(&rules, &components).expect("an ordinary path");
    if context.read_only(&rules) {
        "read-only"
    } else if context.pinned() {
        "pinned"
    } else {
        "free"
    }
    .to_string()
}

#[test]
fn the_policy_answers_the_conformance_table() {
    let mut failures = Vec::new();
    for case in &corpus::conformance_cases() {
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
