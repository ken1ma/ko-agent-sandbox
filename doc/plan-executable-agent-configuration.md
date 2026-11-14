# Plan: executable agent configuration in the persistent volume

A prompt-injected session can write a program into the persistent volume, and a later session
starts that program without a tool call. Such a program is an MCP server, a hook, a notification
command or a plugin. SECURITY.md records the exposure and names `--reset` as the remedy ("What the
persistent volume holds"), but nothing tells the user when to reset. This plan closes the route in
two phases:

1. At every launch, reconcile the keys that name such programs to a reviewed set.
2. Make the directories that agents load code from unwritable.

## What is measured

Measured on 2026-09-22 with the installed agents.

- `claude mcp add` writes each scope to a different place:
  - user scope: the top-level `mcpServers` of `~/.claude/.claude.json`;
  - local scope: `projects.<path>.mcpServers` in the same file;
  - project scope: the project's `.mcp.json`. The project file's servers wait for an approval dialog
    until `enableAllProjectMcpServers` is set in the volume's `settings.json`, and a session can
    write that file.
- A read-only mount cannot protect `.claude.json` or Codex's `config.toml`, so the plan sets keys
  instead of locking files:
  - the 70 other top-level keys of `.claude.json` and the 24 keys of a project entry are state the
    agent rewrites (`lastCost`, `numStartups`, feature caches);
  - `ko-sandbox-entrypoint` writes the trust entry into `.claude.json` at every launch;
  - Codex's `config.toml` holds the trust table and the model beside its `mcp_servers` tables.
- `CLAUDE_CODE_MANAGED_SETTINGS_PATH` is inert in Claude Code 2.1.278: a denied server stays
  listed. So the managed files have no scratch measurement.
  - Each managed file needs a variant image, because `/etc` is read-only in a session. The
    measurement of `allowManagedHooksOnly` used one (`container/ko-agent-sandbox/Containerfile`).
- Codex 0.155.1 ignores a `requirements.toml` in `CODEX_HOME`: a user-layer server stays enabled in
  `codex mcp list`.
- `codex mcp list --json` names the servers without starting them.
- `claude mcp list` health-checks every server it finds, and so executes each one. That command
  cannot serve as a check.
- Antigravity's `config/mcp_config.json` names no server.
- Kiro's `data/` holds its own `bun` and `tui.js`, which Kiro writes itself.
- Copilot's `config.json` names no server.
- OpenCode loads code and configuration from the volume:
  - OpenCode imports a JavaScript file under `~/.config/opencode/plugins/`, in the volume. The
    commands that load the configuration call the file's plugin functions (`opencode debug config`,
    `agent list`, `mcp list`).
  - OpenCode merges `opencode.json` and `opencode.jsonc` from the same directory. The `mcp` entries
    of both files load, and the later file's `plugin` array replaces the earlier file's.
  - At every start, OpenCode installs `config/node_modules` (26 packages) from
    `config/package.json`, for local plugins.

## Phase 1: reconciliation

`ko-sandbox-entrypoint` does the following under the volume lock, beside the trust entries it
writes, before the agent starts:

- The entrypoint sets each agent's executable keys to the reviewed set.
  - The reviewed set is one file per agent under `.ko-agent-sandbox/`, read-only in a session as
    the egress rule is.
  - An absent file means no definitions.
- The entrypoint prints every replaced definition with its command line before the entrypoint's
  pause. The user can then stop and run `--reset`, or run `podman volume rm` on a volume named
  through `--persistent-volume`, which `--reset` preserves.
- The entrypoint refuses the launch when a reviewed file does not parse.

A reviewed definition names a program in the image, or a program that `npx` fetches at start. A
definition that names a path under the volume belongs to phase 2.

The keys per agent:

- Claude: `mcpServers` at the top level and in each project entry of `.claude.json`, written
  through jq as the trust entry is, and `enableAllProjectMcpServers` in `settings.json`. Hooks and
  the status line are pinned (`allowManagedHooksOnly`).
- Codex: through its CLI, since `codex mcp list --json` names the servers and `codex mcp remove`
  drops one. `notify` and `hooks` in `config.toml` need the same treatment; `notify` is a
  user-layer command that Codex runs for notifications
  (https://learn.chatgpt.com/docs/config-file/config-reference).
- OpenCode: the `plugin` and `mcp` keys of both `opencode.json` and `opencode.jsonc`
  (https://opencode.ai/docs/config/, "Locations").
- The other agents: read the documentation for the keys, then the files in the volume.

Limits:

- Phase 1 covers the volume, not the workspace's `.mcp.json` or `.opencode/plugins/`.
- A server that an in-session `claude mcp add` adds works until the next launch.
- A concurrent session of the same workspace can add a server again. The next launch replaces the
  server and reports it again.
- Claude's file layout is measured, not documented, and has no safe self-check.

## Phase 1 confirmation: the agents' managed files

The agents' managed files are documented, and they also apply to the workspace's files. The managed
files refuse an in-session add with a clear message. Reconciliation stays as the check behind the
managed files. A workspace that needs a server names it in the reviewed file above, and the
launcher also mounts that file as the managed file.

- Claude: `managed-mcp.json` in `/etc/claude-code/` loads only the servers it names, and an empty
  map loads none. The file excludes plugin-provided servers and `--mcp-config`
  (https://code.claude.com/docs/en/managed-mcp, "Exclusive control with managed-mcp.json").
  - `strictPluginOnlyCustomization` is no substitute: it keeps plugin servers, and
    `~/.claude/plugins/` is in the volume.
- Codex: `/etc/codex/requirements.toml` is the admin-enforced layer. In precedence the layer ranks
  below the cloud bundle and the legacy `managed_config.toml`
  (https://learn.chatgpt.com/docs/enterprise/managed-configuration, "Locations and precedence").
  - An `mcp_servers` table that is present but empty disables every MCP server, plugin-bundled ones
    included.
  - An entry allows a server only when the server's name and identity match: the command or URL,
    and optionally each argument.
  - `features.plugins = false` disables plugins.
  - `allow_managed_hooks_only = true` skips user, project, session and plugin hooks.
  - No requirement pins `notify`, so `notify` stays with reconciliation.

## Phase 2: unwritable code directories

Phase 2 makes these directories unwritable:

- `~/.claude/plugins/`;
- Codex's `plugins/`;
- Kiro's `data/`;
- OpenCode's `plugins/` and `node_modules` (https://opencode.ai/docs/plugins/, "How plugins are
  installed").

The form is decided after each agent is measured on a refused write, because Kiro writes
`data/bun` itself and OpenCode runs `bun install` into `config/node_modules`. The candidates:

- a read-only mount, if the installed podman mounts a volume subpath;
- otherwise, separate volumes for the writable paths;
- or no persistence for those directories at all.

Whichever form is chosen:

- The form's first launch fills each directory from reviewed sources instead of keeping what the
  volume holds, because an earlier session may have planted a file there and phase 1 resets only
  keys. The launch moves the existing directory aside and lists its entries.
- The entrypoint's trust writes then move to a helper container that runs before the read-only
  start.
- A mount cannot split a directory that holds code beside state, as `~/.claude/plugins/` holds
  marketplace state.

## Deliberate exclusions

- Memory, skills and instructions in the volume. A later session reads them as text and acts on
  them through the model's own tool calls. SECURITY.md's `--reset` covers them.
