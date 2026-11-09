# managed-probe

managed-probe is a mod with one hook. The hook draws the band
`managed-probe draws this band: its hooks run` above Claude Code's prompt.

- Under the sandbox image's `allowManagedHooksOnly`, the hook runs only when the plugin is managed.
- So a launch with `--claude-plugin-dir` draws the band or nothing.

The launcher refuses a plugin directory inside the workspace, so copy this directory outside the
workspace before naming it:

```sh
mkdir -p /tmp/ko-agent-sandbox && cp -r src/test/claude-plugins/managed-probe /tmp/ko-agent-sandbox/
java -jar ko-agent-sandbox.jar --claude-plugin-dir=/tmp/ko-agent-sandbox/managed-probe \
    claude --debug
```

[doc/agent-settings.md](../../../../doc/agent-settings.md#claude-code-plugins-and-mods) says what
to expect, and explains the mechanism.

`claude plugin test` on `tests/` runs on the host only. Inside the sandbox,
`allowManagedHooksOnly` turns the test kit off.

- On the host, `claude plugin test src/test/claude-plugins/managed-probe` passes its one test
  (Claude Code 2.1.321, logged in, 2026-11-10).
- A logged-out Claude Code 2.1.296 refused the run with `hooks modules are turned off in this
  process`. Update and log in to `claude`, then run the tests again.
