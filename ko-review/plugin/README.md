# The ko-review plugin's files

This directory holds the plugin's sources. Claude Code and Codex install the assembled plugin,
which `sbt pluginAssembly` (thin, for the runtime image) or `sbt dist` (with the dependencies' jars)
builds under `../target/`. `../doc/design.md` describes the plugin.

- `claude-plugin/plugin.json`: the manifest. The assembly copies it to `.claude-plugin/`, which
  Claude Code requires, and adds the version from `../build.sbt`.
- `skills/ko-review/SKILL.md`: the skill that the coordinator follows.
- `prompts/`: the reviewer's prompts, for the first turn and for the turns after it.
- `schemas/review-result.schema.json`: the reviewer's result.
- `bin/ko-review`: runs the helper from the assembly's `lib/`, which holds the helper's jar and
  `dependencies.txt`, and after `sbt dist` the dependencies' jars.

## Installing the assembled plugin

- Claude Code: `claude --plugin-dir <assembly>`, or a directory that `CLAUDE_CODE_PLUGIN_DIRS`
  names, as the runtime image does with `/etc/claude-code/plugins`.
- Codex: copy `skills/ko-review/` to `~/.agents/skills/ko-review/`, or `/etc/codex/skills/` as the
  image does, and put `bin/ko-review` on the PATH. Codex reads a copy, not a link
  (`container/ko-agent-sandbox/Containerfile` gives the reason).
- Both need Java 23 or later on the PATH, which `bin/ko-review`'s options require.
- The runtime image fetches the jars that `lib/dependencies.txt` lists with `cs fetch`
  (`container/ko-agent-sandbox/Containerfile`).
