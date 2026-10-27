//! The policy's map records for the BPF cgroup-LSM backend (`doc/plan-bpf-lsm-cgroup.md` at the
//! repository root, "The policy"): the resolved file rules, the alias contexts and the guarded
//! objects, compiled into fixed-size records the privileged controller loads into the programs'
//! maps without parsing text. `include/records.h` is the C rendering of the same layout, which the
//! programs and the controller include; [`c_header`] generates it, `--bpf-records-header` prints
//! it and a test compares the committed file with it.
//!
//! One file, in native byte order since the guard and the controller run on one machine:
//!
//! ```text
//! records_header               "KOFSBPF1", the layout stamp and the three counts
//! rule_line[rule_count]        the resolved lines in order, each naming the alias context it activates
//! alias_context[alias_count]   the context of the symlink whose end an anchored pinned-path line names
//! guarded_path[root_count]     the guarded objects by workspace-relative path, which the controller
//!                              turns into identities with its own statx
//! ```
//!
//! The layout stamp hashes the sizes, offsets and codes, so a controller built from another header
//! refuses the file before it reads a record.

use crate::guard::{GuardedKind, GuardedPath};
use crate::policy::{FileRules, RuleContext, RuleWord};

/// Rule lines the policy holds; the rules map's size.
pub const RULE_LINES: usize = 128;
/// Components of one line; bit `k` of a partial byte says the line's first `k` matched.
pub const RULE_COMPS: usize = 7;
/// Bytes of one component with its terminating zero.
pub const COMP_BYTES: usize = 64;
/// Alias contexts the policy holds; the aliases map's size.
pub const ALIASES: usize = 16;
/// Roots the policy holds; the roots map's size.
pub const ROOTS: usize = 64;
/// Guarded paths the guard writes: two of the root entries stay for the controller's own roots,
/// the proof fixture's and the persistent volume's.
pub const GUARDED_PATHS: usize = ROOTS - 2;
/// Bytes of a guarded path with its terminating zero.
pub const PATH_BYTES: usize = 4096;

pub const HEADER_BYTES: usize = 8 + 4 * 4;
pub const RULE_LINE_BYTES: usize = 4 + RULE_COMPS * COMP_BYTES;
pub const ALIAS_CONTEXT_BYTES: usize = RULE_LINES + 4 + 4;
pub const GUARDED_PATH_BYTES: usize = 4 + 4 + PATH_BYTES;

const MAGIC: &[u8; 8] = b"KOFSBPF1";

pub const WORD_READ_ONLY: u8 = 1;
pub const WORD_WRITABLE: u8 = 2;
pub const WORD_PINNED: u8 = 3;

pub const ROOT_WORKSPACE: u32 = 1;
pub const ROOT_GITDIR: u32 = 2;
/// Written by the controller alone: the persistent volume's root.
pub const ROOT_VOLUME: u32 = 3;
pub const ROOT_GUARDED_GIT: u32 = 4;
pub const ROOT_GUARDED_SANDBOX: u32 = 5;

/// What a rule line's record holds; the components as [`FileRules`] holds them, folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLineRecord {
    pub word: u8,
    pub anchored: bool,
    /// The alias context this line's end activates, 1-based; 0 for none.
    pub alias: u8,
    pub components: Vec<Vec<u8>>,
}

/// A [`RuleContext`] as the program keeps one: `partial[line]` bit `k` set where the line's first
/// `k` components matched, `deciding` the line or `-1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasContextRecord {
    pub partial: [u8; RULE_LINES],
    pub deciding: i32,
    pub pinned_path: bool,
}

/// A guarded object by its root kind code and workspace-relative path, empty for the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedPathRecord {
    pub kind: u32,
    pub path: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    pub rules: Vec<RuleLineRecord>,
    pub aliases: Vec<AliasContextRecord>,
    pub guarded: Vec<GuardedPathRecord>,
}

/// The stamp a file and a header carry: FNV-1a over the layout's description.
pub fn layout() -> u32 {
    let description = format!(
        "header {HEADER_BYTES} magic@0:8 layout@8 rule_count@12 alias_count@16 root_count@20; \
         rule_line {RULE_LINE_BYTES} word@0 anchored@1 ncomp@2 alias@3 comp@4:{RULE_COMPS}x{COMP_BYTES}; \
         alias_context {ALIAS_CONTEXT_BYTES} partial@0:{RULE_LINES} deciding@{RULE_LINES} \
         pinned_path@{}; guarded_path {GUARDED_PATH_BYTES} kind@0 len@4 path@8:{PATH_BYTES}; \
         bounds {RULE_LINES} {ALIASES} {ROOTS} {GUARDED_PATHS}; \
         words {WORD_READ_ONLY} {WORD_WRITABLE} {WORD_PINNED}; \
         kinds {ROOT_WORKSPACE} {ROOT_GITDIR} {ROOT_VOLUME} {ROOT_GUARDED_GIT} {ROOT_GUARDED_SANDBOX}",
        RULE_LINES + 4,
    );
    let mut hash: u32 = 0x811c_9dc5;
    for byte in description.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// The records of the resolved `rules`, aliases included, and of the guard's `guarded` objects, or
/// why they exceed a bound the policy holds.
pub fn compile(rules: &FileRules, guarded: &[GuardedPath]) -> Result<Records, String> {
    let lines = rules.lines();
    if lines.len() > RULE_LINES {
        return Err(format!(
            "the resolved file rules hold {} lines and the BPF policy holds at most {RULE_LINES}. \
             Remove lines from .ko-agent-sandbox/file/rule, or hook directories and symlinks the \
             filter records as paths.",
            lines.len(),
        ));
    }
    let mut alias_of_line = vec![0u8; lines.len()];
    let mut aliases = Vec::new();
    for (line, context) in rules.aliases() {
        if aliases.len() >= ALIASES {
            return Err(format!(
                "the file rules reach more than {ALIASES} symlinks whose ends the filter records \
                 as aliases, and the BPF policy holds at most {ALIASES}. Replace some of the \
                 symlinks the rule lines name with directories.",
            ));
        }
        aliases.push(alias_record(context, lines.len())?);
        alias_of_line[*line as usize] = aliases.len() as u8;
    }
    let mut records = Vec::with_capacity(lines.len());
    for (index, line) in lines.iter().enumerate() {
        let spelled = || {
            line.components
                .iter()
                .map(|component| String::from_utf8_lossy(component).into_owned())
                .collect::<Vec<_>>()
                .join("/")
        };
        if line.components.is_empty() || line.components.len() > RULE_COMPS {
            return Err(format!(
                "the file rule line {:?} has {} components and the BPF policy holds at most \
                 {RULE_COMPS}. Name a shorter path.",
                spelled(),
                line.components.len(),
            ));
        }
        for component in &line.components {
            if component.is_empty() || component.len() >= COMP_BYTES || component.contains(&0) {
                return Err(format!(
                    "the file rule line {:?} has a component of {} bytes and the BPF policy holds \
                     at most {}. Rename it on the host, then relaunch.",
                    spelled(),
                    component.len(),
                    COMP_BYTES - 1,
                ));
            }
        }
        records.push(RuleLineRecord {
            word: match line.word {
                RuleWord::ReadOnly => WORD_READ_ONLY,
                RuleWord::Writable => WORD_WRITABLE,
                RuleWord::Pinned => WORD_PINNED,
            },
            anchored: line.anchored,
            alias: alias_of_line[index],
            components: line.components.clone(),
        });
    }
    if guarded.len() > GUARDED_PATHS {
        return Err(format!(
            "the workspace holds {} guarded objects, gitdirs under .git/modules among them, and \
             the BPF policy records at most {GUARDED_PATHS}. Deinitialize submodules you do not \
             work on.",
            guarded.len(),
        ));
    }
    let guarded = guarded
        .iter()
        .map(|object| {
            if object.path.len() >= PATH_BYTES || object.path.contains(&0) {
                return Err(format!(
                    "the guarded object {:?} has a path of {} bytes and the BPF policy records at \
                     most {}. Move it nearer the workspace root.",
                    String::from_utf8_lossy(&object.path),
                    object.path.len(),
                    PATH_BYTES - 1,
                ));
            }
            Ok(GuardedPathRecord {
                kind: match object.kind {
                    GuardedKind::Workspace => ROOT_WORKSPACE,
                    GuardedKind::Gitdir => ROOT_GITDIR,
                    GuardedKind::GitEntry => ROOT_GUARDED_GIT,
                    GuardedKind::SandboxEntry => ROOT_GUARDED_SANDBOX,
                },
                path: object.path.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Records {
        rules: records,
        aliases,
        guarded,
    })
}

fn alias_record(context: &RuleContext, line_count: usize) -> Result<AliasContextRecord, String> {
    // The guard computes a symlink's context over the launcher's lines, before any alias exists,
    // so one standing under another alias is not produced; the program nests alias contexts at
    // the mutation instead, two at one position.
    if !context.also().is_empty() {
        return Err(
            "an alias context standing under another alias has no record in the BPF policy; \
             this is a defect in the filter's guard, report it."
                .to_string(),
        );
    }
    let mut partial = [0u8; RULE_LINES];
    for &(line, matched) in context.partial() {
        if line as usize >= line_count || matched == 0 || matched as usize >= RULE_COMPS {
            return Err(format!(
                "an alias context names line {line} at {matched} components, outside the \
                 resolved rules; this is a defect in the filter's guard, report it.",
            ));
        }
        partial[line as usize] |= 1 << matched;
    }
    Ok(AliasContextRecord {
        partial,
        deciding: context.deciding().map_or(-1, |line| line as i32),
        pinned_path: context.pinned_path(),
    })
}

impl Records {
    /// The file's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_BYTES
                + self.rules.len() * RULE_LINE_BYTES
                + self.aliases.len() * ALIAS_CONTEXT_BYTES
                + self.guarded.len() * GUARDED_PATH_BYTES,
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&layout().to_ne_bytes());
        for count in [self.rules.len(), self.aliases.len(), self.guarded.len()] {
            out.extend_from_slice(&(count as u32).to_ne_bytes());
        }
        for rule in &self.rules {
            out.extend_from_slice(&[
                rule.word,
                u8::from(rule.anchored),
                rule.components.len() as u8,
                rule.alias,
            ]);
            for k in 0..RULE_COMPS {
                let component = rule.components.get(k).map_or(&[][..], Vec::as_slice);
                out.extend_from_slice(component);
                out.resize(out.len() + COMP_BYTES - component.len(), 0);
            }
        }
        for alias in &self.aliases {
            out.extend_from_slice(&alias.partial);
            out.extend_from_slice(&alias.deciding.to_ne_bytes());
            out.extend_from_slice(&u32::from(alias.pinned_path).to_ne_bytes());
        }
        for object in &self.guarded {
            out.extend_from_slice(&object.kind.to_ne_bytes());
            out.extend_from_slice(&(object.path.len() as u32).to_ne_bytes());
            out.extend_from_slice(&object.path);
            out.resize(out.len() + PATH_BYTES - object.path.len(), 0);
        }
        out
    }

    /// The records of a file's bytes, or why the file is not one of this layout.
    pub fn parse(bytes: &[u8]) -> Result<Records, String> {
        let mut cursor = Cursor { bytes, at: 0 };
        if cursor.take(8)? != MAGIC {
            return Err("not a records file: the magic differs".to_string());
        }
        let stamp = cursor.u32()?;
        if stamp != layout() {
            return Err(format!(
                "a records file of layout {stamp:#010x}, where this build reads {:#010x}",
                layout(),
            ));
        }
        let (rule_count, alias_count, root_count) = (cursor.u32()?, cursor.u32()?, cursor.u32()?);
        if rule_count as usize > RULE_LINES
            || alias_count as usize > ALIASES
            || root_count as usize > GUARDED_PATHS
        {
            return Err(format!(
                "a records file of {rule_count} rules, {alias_count} aliases and {root_count} \
                 guarded paths, over the bounds {RULE_LINES}, {ALIASES} and {GUARDED_PATHS}",
            ));
        }
        let mut records = Records::default();
        for _ in 0..rule_count {
            let fixed = cursor.take(4)?;
            let (word, anchored, ncomp, alias) = (fixed[0], fixed[1], fixed[2], fixed[3]);
            let mut components = Vec::new();
            for k in 0..RULE_COMPS {
                let component = cursor.take(COMP_BYTES)?;
                if k < ncomp as usize {
                    components.push(zero_terminated(component)?);
                }
            }
            if ncomp as usize > RULE_COMPS || !(1..=3).contains(&word) || anchored > 1 {
                return Err("a rule line record outside the layout's codes".to_string());
            }
            records.rules.push(RuleLineRecord {
                word,
                anchored: anchored == 1,
                alias,
                components,
            });
        }
        for _ in 0..alias_count {
            let mut partial = [0u8; RULE_LINES];
            partial.copy_from_slice(cursor.take(RULE_LINES)?);
            let deciding = cursor.u32()? as i32;
            let pinned_path = cursor.u32()?;
            records.aliases.push(AliasContextRecord {
                partial,
                deciding,
                pinned_path: pinned_path != 0,
            });
        }
        for _ in 0..root_count {
            let kind = cursor.u32()?;
            let len = cursor.u32()? as usize;
            let path = cursor.take(PATH_BYTES)?;
            if len >= PATH_BYTES || path[len..].iter().any(|&byte| byte != 0) {
                return Err("a guarded path record whose length and bytes disagree".to_string());
            }
            records.guarded.push(GuardedPathRecord {
                kind,
                path: path[..len].to_vec(),
            });
        }
        if cursor.at != bytes.len() {
            return Err(format!(
                "a records file of {} bytes where its counts take {}",
                bytes.len(),
                cursor.at,
            ));
        }
        Ok(records)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], String> {
        let end = self.at + count;
        if end > self.bytes.len() {
            return Err(format!(
                "a records file of {} bytes, cut short at {end}",
                self.bytes.len(),
            ));
        }
        let taken = &self.bytes[self.at..end];
        self.at = end;
        Ok(taken)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

fn zero_terminated(field: &[u8]) -> Result<Vec<u8>, String> {
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| "a component record without its terminating zero".to_string())?;
    if field[end..].iter().any(|&byte| byte != 0) {
        return Err("a component record with bytes after its terminating zero".to_string());
    }
    Ok(field[..end].to_vec())
}

/// The C header of this layout, `include/records.h`.
pub fn c_header() -> String {
    let stamp = layout();
    format!(
        "/* Generated by `ko-agent-fs --bpf-records-header` from src/bpf_records.rs, which has the file\n\
         \x20* format; a test compares this file with the generator. The map records of the BPF cgroup-LSM\n\
         \x20* backend, as the guard writes them and the controller loads them (doc/plan-bpf-lsm-cgroup.md,\n\
         \x20* \"The policy\"), in native byte order. The types are the kernel's: include this after vmlinux.h\n\
         \x20* in a program, after <linux/types.h> in user space. */\n\
         #ifndef KO_AGENT_FS_RECORDS_H\n\
         #define KO_AGENT_FS_RECORDS_H\n\
         \n\
         #define RECORDS_MAGIC \"KOFSBPF1\"\n\
         #define RECORDS_LAYOUT {stamp:#010x}u\n\
         \n\
         #define RULE_LINES {RULE_LINES}\n\
         #define RULE_COMPS {RULE_COMPS}      /* bit k of a partial byte: the line's first k components matched */\n\
         #define COMP_BYTES {COMP_BYTES}\n\
         #define ALIASES {ALIASES}\n\
         #define ROOTS {ROOTS}\n\
         #define GUARDED_PATHS {GUARDED_PATHS}   /* the rest of ROOTS is the controller's: fixture and volume */\n\
         #define PATH_BYTES {PATH_BYTES}\n\
         \n\
         enum rule_word {{\n\
         \tWORD_READ_ONLY = {WORD_READ_ONLY},\n\
         \tWORD_WRITABLE = {WORD_WRITABLE},\n\
         \tWORD_PINNED = {WORD_PINNED},\n\
         }};\n\
         \n\
         enum root_kind {{\n\
         \t/* a workspace root, or the proof fixture's: the walk's position is NotGit */\n\
         \tROOT_WORKSPACE = {ROOT_WORKSPACE},\n\
         \t/* a gitdir the guard found under .git/modules: the position is InGit([]) */\n\
         \tROOT_GITDIR = {ROOT_GITDIR},\n\
         \t/* the persistent volume's root, the controller's own: the socket rule alone */\n\
         \tROOT_VOLUME = {ROOT_VOLUME},\n\
         \t/* a .git object, the root's or a submodule worktree's pointer file: any name is the gitdir entry */\n\
         \tROOT_GUARDED_GIT = {ROOT_GUARDED_GIT},\n\
         \t/* the root's .ko-agent-sandbox object: any name is the launcher's directory */\n\
         \tROOT_GUARDED_SANDBOX = {ROOT_GUARDED_SANDBOX},\n\
         }};\n\
         \n\
         struct records_header {{\n\
         \tchar magic[8];\n\
         \t__u32 layout;\n\
         \t__u32 rule_count;\n\
         \t__u32 alias_count;\n\
         \t__u32 root_count;\n\
         }};\n\
         \n\
         /* One resolved rule line, folded by the guard. `alias` names the alias context (1-based) the line's\n\
         \x20* end activates, for an anchored pinned-path line at the end of a symlink the guard followed; 0 is\n\
         \x20* none. */\n\
         struct rule_line {{\n\
         \t__u8 word;\n\
         \t__u8 anchored;\n\
         \t__u8 ncomp;\n\
         \t__u8 alias;\n\
         \tchar comp[RULE_COMPS][COMP_BYTES];\n\
         }};\n\
         \n\
         /* The rule context of the symlink whose end a pinned-path line names: what every entry below that\n\
         \x20* end also stands as (policy.rs, FileRules::push_alias). `deciding` is -1 for none. */\n\
         struct alias_context {{\n\
         \t__u8 partial[RULE_LINES];\n\
         \t__s32 deciding;\n\
         \t__u32 pinned_path;\n\
         }};\n\
         \n\
         /* A guarded object by workspace-relative path, empty for the root itself; the controller records\n\
         \x20* its identity with statx. */\n\
         struct guarded_path {{\n\
         \t__u32 kind;\n\
         \t__u32 len;\n\
         \tchar path[PATH_BYTES];\n\
         }};\n\
         \n\
         _Static_assert(sizeof(struct records_header) == {HEADER_BYTES}, \"records_header\");\n\
         _Static_assert(sizeof(struct rule_line) == {RULE_LINE_BYTES}, \"rule_line\");\n\
         _Static_assert(sizeof(struct alias_context) == {ALIAS_CONTEXT_BYTES}, \"alias_context\");\n\
         _Static_assert(sizeof(struct guarded_path) == {GUARDED_PATH_BYTES}, \"guarded_path\");\n\
         \n\
         #endif\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{RuleLine, rule_context_of_path};
    use crate::rulefile;

    fn floating(word: RuleWord, name: &str) -> RuleLine {
        RuleLine {
            word,
            components: name.split('/').map(|c| c.as_bytes().to_vec()).collect(),
            anchored: false,
        }
    }

    fn anchored(word: RuleWord, name: &str) -> RuleLine {
        RuleLine {
            anchored: true,
            ..floating(word, name)
        }
    }

    /// The rules of the Phase 3 probe (`bpf/probe/phase3/Phase3.scala`): an anchored line first, the
    /// launcher's lines, the `.claude` lines among them at indices 1 to 5, and the guard's lines
    /// last, the end of `.claude -> shared/claude` with `.claude`'s context as its alias.
    fn probe_rules() -> FileRules {
        let launcher = rulefile::parse(
            "read-only .claude/settings.json\nread-only .claude/settings.local.json\n\
             read-only .claude/skills\nread-only .claude/agents\nread-only .claude/commands\n\
             read-only .mcp.json\nread-only .vscode\nwritable node_modules\n\
             writable .vscode/settings.json\n",
        )
        .unwrap();
        let mut lines = vec![anchored(RuleWord::ReadOnly, "githooks")];
        lines.extend(launcher.rules.lines().iter().cloned());
        lines.push(anchored(RuleWord::Pinned, "shared"));
        let mut rules = FileRules::new(lines);
        // The context over the map's lines by their indices, as the controller computed it.
        let claude = rule_context_of_path(&rules, &[b".claude"]).unwrap();
        rules.push_alias("shared/claude", claude);
        rules
    }

    #[test]
    fn the_probe_rules_compile_as_the_phase3_controller_read_them() {
        // The controller's line on 2026-10-23 (out-macos/transcript.log):
        // `alias index=0 path=.claude deciding=-1 pinned_path=0 partial_lines=1:2,2:2,3:2,4:2,5:2,`
        let records = compile(&probe_rules(), &[]).unwrap();
        assert_eq!(records.rules.len(), 12);
        assert_eq!(records.aliases.len(), 1);
        let alias = &records.aliases[0];
        let mut expected = [0u8; RULE_LINES];
        expected[1..=5].fill(0x2);
        assert_eq!(alias.partial, expected);
        assert_eq!((alias.deciding, alias.pinned_path), (-1, false));
        let end = &records.rules[11];
        assert_eq!(
            end,
            &RuleLineRecord {
                word: WORD_PINNED,
                anchored: true,
                alias: 1,
                components: vec![b"shared".to_vec(), b"claude".to_vec()],
            },
        );
        assert!(records.rules[..11].iter().all(|rule| rule.alias == 0));
        assert_eq!(records.rules[0].word, WORD_READ_ONLY);
        assert!(records.rules[0].anchored);
        assert_eq!(records.rules[8].word, WORD_WRITABLE);
    }

    #[test]
    fn the_bytes_round_trip_and_hold_the_layout() {
        let guarded = vec![
            GuardedPath {
                kind: GuardedKind::Workspace,
                path: Vec::new(),
            },
            GuardedPath {
                kind: GuardedKind::GitEntry,
                path: b"sub/.git".to_vec(),
            },
        ];
        let records = compile(&probe_rules(), &guarded).unwrap();
        let bytes = records.to_bytes();
        assert_eq!(
            bytes.len(),
            HEADER_BYTES + 12 * RULE_LINE_BYTES + ALIAS_CONTEXT_BYTES + 2 * GUARDED_PATH_BYTES,
        );
        assert_eq!(&bytes[..8], b"KOFSBPF1");
        assert_eq!(Records::parse(&bytes).unwrap(), records);
        assert_eq!(records.guarded[1].kind, ROOT_GUARDED_GIT);
        // The first rule line's record: word, anchored, ncomp, alias, then the component.
        let first = &bytes[HEADER_BYTES..HEADER_BYTES + 4 + 9];
        assert_eq!(first, b"\x01\x01\x01\x00githooks\x00");

        let mut other_layout = bytes.clone();
        other_layout[8] ^= 1;
        assert!(
            Records::parse(&other_layout)
                .unwrap_err()
                .contains("layout")
        );
        assert!(
            Records::parse(&bytes[..bytes.len() - 1])
                .unwrap_err()
                .contains("cut short")
        );
    }

    #[test]
    fn the_committed_header_is_the_generated_one() {
        assert_eq!(
            include_str!("../include/records.h"),
            c_header(),
            "regenerate include/records.h with `ko-agent-fs --bpf-records-header`",
        );
    }

    #[test]
    fn each_bound_refuses_with_what_to_do() {
        let lines: Vec<RuleLine> = (0..=RULE_LINES)
            .map(|i| floating(RuleWord::ReadOnly, &format!("f{i}")))
            .collect();
        let err = compile(&FileRules::new(lines), &[]).unwrap_err();
        assert!(
            err.contains("129 lines") && err.contains("Remove lines"),
            "{err}"
        );

        let rules = FileRules::new(vec![floating(RuleWord::ReadOnly, "a/b/c/d/e/f/g/h")]);
        let err = compile(&rules, &[]).unwrap_err();
        assert!(err.contains("8 components"), "{err}");

        let rules = FileRules::new(vec![floating(RuleWord::ReadOnly, &"x".repeat(COMP_BYTES))]);
        let err = compile(&rules, &[]).unwrap_err();
        assert!(err.contains("64 bytes"), "{err}");

        let mut rules = FileRules::new(vec![floating(RuleWord::ReadOnly, ".claude/settings.json")]);
        let claude = rule_context_of_path(&rules, &[b".claude"]).unwrap();
        for i in 0..=ALIASES {
            rules.push_alias(&format!("end{i}"), claude.clone());
        }
        let err = compile(&rules, &[]).unwrap_err();
        assert!(err.contains("more than 16 symlinks"), "{err}");

        let guarded: Vec<GuardedPath> = (0..=GUARDED_PATHS)
            .map(|i| GuardedPath {
                kind: GuardedKind::Gitdir,
                path: format!(".git/modules/m{i}").into_bytes(),
            })
            .collect();
        let err = compile(&FileRules::default(), &guarded).unwrap_err();
        assert!(err.contains("63 guarded objects"), "{err}");

        let long = vec![GuardedPath {
            kind: GuardedKind::GitEntry,
            path: vec![b'd'; PATH_BYTES],
        }];
        let err = compile(&FileRules::default(), &long).unwrap_err();
        assert!(err.contains("4096 bytes"), "{err}");
    }

    #[test]
    fn an_alias_context_under_another_alias_is_refused_as_a_defect() {
        let mut rules = FileRules::new(vec![floating(RuleWord::ReadOnly, "a/b/c")]);
        let a = rule_context_of_path(&rules, &[b"a"]).unwrap();
        rules.push_alias("p", a);
        let under = rule_context_of_path(&rules, &[b"p", b"b"]).unwrap();
        assert!(!under.also().is_empty());
        rules.push_alias("q", under);
        let err = compile(&rules, &[]).unwrap_err();
        assert!(err.contains("under another alias"), "{err}");
    }
}
