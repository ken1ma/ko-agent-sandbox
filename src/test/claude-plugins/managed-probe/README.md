# managed-probe

A mod with one hook, which draws the band `managed-probe draws this band: its hooks run` above
Claude Code's prompt. Under the sandbox image's `allowManagedHooksOnly` the hook runs only when
the plugin is managed, so a launch with `--claude-plugin-dir` draws the band or nothing.

The launcher refuses a plugin directory inside the project, so copy this directory outside the
project before naming it:

```sh
mkdir -p /tmp/ko-agent-sandbox && cp -r src/test/claude-plugins/managed-probe /tmp/ko-agent-sandbox/
java -jar ko-agent-sandbox.jar --claude-plugin-dir=/tmp/ko-agent-sandbox/managed-probe \
    claude --debug
```

What to expect, and the mechanism, are in
[doc/agent-settings.md](../../../../doc/agent-settings.md#claude-code-plugins-and-mods).
`claude plugin test` on `tests/` runs on the host only: inside the sandbox the same key turns the
test kit off.
