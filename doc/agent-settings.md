# Agent settings

## Adding project instructions

Put a project's working conventions in `AGENTS.md` at the project root: `codex`, `agy`,
`kiro-cli`, `copilot` and `opencode` read it.

For `claude`, add a `.claude/CLAUDE.md` whose content is `@../AGENTS.md`, as this repository's
[.claude/CLAUDE.md](../.claude/CLAUDE.md) is. The import loads that one file: `claude` skips a
subdirectory's `AGENTS.md` unless that subdirectory has its own `.claude/CLAUDE.md` importing it.

Claude Code 2.1.277 and later read `AGENTS.md` themselves, subdirectories included, but not under
the image's `allowManagedHooksOnly`:
https://code.claude.com/docs/en/memory#when-agents-md-support-is-unavailable

The sandbox's own instructions describe the container and the session's permissions, not how to
work ([design.md](design.md#the-image-carries-no-working-conventions)).

## Restoring permission prompts

1. `claude`: edit the managed settings in the Containerfile and rebuild the image. They take
   precedence over user settings.
1. `codex`: set `approval_policy = "on-request"` in `~/.codex/config.toml`. Your configuration
   overrides the image's defaults.
1. `agy`: set `"toolPermission": "request-review"` in `~/.gemini/antigravity-cli/settings.json`
   (or via `/config`).
1. `kiro-cli`: remove entries from `allowedTools` in the supplied agent configuration,
   `~/.kiro/agents/ko-agent-sandbox.json`.
1. `copilot`: set `COPILOT_ALLOW_ALL=false`.
1. `opencode`: pass `OPENCODE_PERMISSION` with the value `{"*":"ask"}` through `--env` to
   override the image's permission setting for one launch.

## Claude Code status line

Show the model and effort level, like Codex, by adding this to `.claude/settings.json`
in the project:

```json
{
  "env": {
    "KO_CLAUDE_STATUSLINE_FORMAT": "${model.display_name} ${effort.level}"
  }
}
```

Use `${jsonField}` to insert a value from
[Available data](https://code.claude.com/docs/en/statusline#available-data),
using syntax like Scala’s:

| String | Shows | Example output |
| --- | --- | --- |
| `${model.display_name}` | Current model | `Fable 5.1` |
| `context=${context_window.used_percentage}%` | Context usage | `context=42%` |
| `cost=$$${cost.total_cost_usd}` | Estimated session cost | `cost=$1.25` |

1. Missing or null fields appear as empty text unless a fallback is supplied.
2. Set `KO_CLAUDE_STATUSLINE_FORMAT` to `""` to hide the status line.

Use `${context_window.used_percentage.getOrElse(0)}%` to show `0%` before usage is available.
`.getOrElse(literal)` supplies a fallback for missing or null fields. The literal can be a number,
boolean or double-quoted string, using JSON syntax. Existing `0`, `false` and empty strings
stay as-is.

### Format limits

1. Placeholders insert text, numbers or booleans. Objects and arrays produce empty text.
2. Only field paths and `.getOrElse(literal)` are supported; expressions, array indexing and
   environment lookups are unsupported.
3. Invalid placeholders stay literal, and inserted values are never evaluated.
4. Templates and output are limited to 4096 characters.
5. Output strips non-printable characters and outer whitespace,
   so it cannot contain terminal control sequences (including OSC 8 hyperlinks) or multiple lines.

### Mechanism

1. The image registers `/etc/claude-code/command/statusLine.py` through
   `/etc/claude-code/managed-settings.d/statusLine.json`.
2. An organization's remote policy can supersede
   these settings; `/status` identifies the active source.
3. Claude Code runs the command with `/usr/local/bin/python3 -I` on status refreshes,
   even when the format is empty or displayed values have not changed.
4. The command accepts at most 2 MiB of status JSON, runs no external tools or network requests,
   and writes no files.

## Holding agents to a line width

Without a program that measures, an agent checking a width limit spends tokens three ways:

1. It counts a line it has written and can still misjudge its width. Claude Fable 5.1 miscounted.
2. The commands it improvises disagree wherever a line is not ASCII, so one check leads to
   another. On this repository's Markdown files at a limit of 100, `awk 'length($0) > 100'`
   reports 130 lines, because the image's `awk` counts bytes; Python's `len()` reports 24, because
   it counts code points; 71 lines are wider than 100 columns.
3. It rewraps lines a wrong count reported, and counts again.

The image has `ko-sandbox-text-width`, which the sandbox's own instructions tell every agent to
use in place of counting:

```sh
ko-sandbox-text-width --over 100 FILE...  # path:line:width for every line wider than 100 columns
ko-sandbox-text-width FILE...             # per file, its widest line: the first of that width
```

Add `--show-text` to include the original line after each result, so the agent can inspect it for
project-permitted exceptions, such as a URL, without opening the file.

1. The program has no limit of its own. State yours in the project's `AGENTS.md`, with the files
   it applies to and the lines that may exceed it, as this repository's
   [AGENTS.md](../AGENTS.md#coding-style) does.
2. A file containing a tab is an error unless `--tab-width COLUMNS` is given. If your files have
   tabs, state the tab width beside the limit.
3. East Asian Wide and Fullwidth characters and emoji sequences count as 2 columns, and a line
   counts the same in NFC and NFD.
4. East Asian Ambiguous characters (`—`, `“`, `…`, `→`, `α`, `§`, `é`) also count as 2,
   matching Japanese, Korean or Chinese display settings configured to draw them wide.
   An editor drawing them in 1 column shows such a line shorter than the reported width.

## Finding the links a rename broke

Renaming a heading or moving a file breaks links in files the change did not touch, and nothing
shows it. An agent looking for them greps for the old name, which misses a link spelled another
way, and opens each target to compare headings.

The image has `ko-sandbox-markdown-link-check`, which the sandbox's own instructions tell every
agent to run after such a change:

```sh
ko-sandbox-markdown-link-check          # every *.md file of the repository that git does not ignore
ko-sandbox-markdown-link-check FILE...  # these files
```

```text
doc/setup.md:18: missing-file: scripts/install.sh
doc/setup.md:42: missing-anchor: README.md#install
doc/setup.md:57: unchecked-fragment: src/Main.scala#L10
summary: files 8; local references 40: valid 37, broken 2, unchecked 1; external excluded 12
```

1. [lychee](https://lychee.cli.rs) finds and checks the links; the program chooses its options
   and shortens its report. A project's own `lychee.toml` and `.lycheeignore` are not read: either
   can exclude a broken link, and the summary would count it as external.
2. Anchors follow lychee's rules; the program's `--help` says how far they are GitHub's. Another
   renderer can build anchors differently.
3. The working tree is checked, not the commit: a link to an untracked or ignored file is valid.
4. lychee looks for a fragment only in Markdown and HTML files. A fragment on any other file,
   such as `#L10` on a source file, is reported as `unchecked-fragment` and does not fail the run.
5. Links to `https:` and other schemes are counted and never fetched.
6. A link that resolves can still point at the wrong section. The program says that references
   resolve, not that they are right.
