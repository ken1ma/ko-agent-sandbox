# Agent settings

## Overriding the agent instructions

To replace the working conventions for a project, put yours in
`.ko-agent-sandbox/agent/AGENTS-CUSTOM.md` on the host; the next launch reads it. Start from the
image’s [AGENTS-CUSTOM.md](../container/ko-agent-sandbox/AGENTS-CUSTOM.md). Leave the file empty
to remove the image’s conventions; delete it to restore them. Sandbox facts and session
permissions remain in force.
[design.md](design.md#the-agent-instruction-override-replaces-only-the-conventions) explains the
scope of the override.

To add instructions, use the agent’s project-level file, such as `CLAUDE.md`, `AGENTS.md`, or
`GEMINI.md`.

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
