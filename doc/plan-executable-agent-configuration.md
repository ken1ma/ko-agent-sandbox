# Plan: executable agent configuration in the persistent volume

A prompt-injected session can write into the persistent volume a program a later session starts
without a tool call: an MCP server, a hook, a notification command, a plugin. SECURITY.md, "What
the persistent volume holds", records the exposure with `--reset` as the remedy, and nothing
signals when to use it. This plan closes the route in two phases: first reconcile the keys that
name such programs to a reviewed set at every launch, then make the directories agents load code
from unwritable.

## What is measured

Measured on 2026-09-22 with the installed agents.

- `claude mcp add` writes user scope to the top-level `mcpServers` of `~/.claude/.claude.json`,
  local scope to `projects.<path>.mcpServers` in the same file, and project scope to the
  project's `.mcp.json`, whose servers wait for an approval dialog until
  `enableAllProjectMcpServers` is set in the volume's `settings.json`, which a session can write.
- The file's 70 other top-level keys and the 24 keys of a project entry are state the agent
  rewrites (`lastCost`, `numStartups`, feature caches), and `ko-sandbox-entrypoint` writes the
  trust entry there at every launch. A read-only mount is therefore out for that file, and for
  Codex's `config.toml`, which holds the trust table and the model beside its `mcp_servers`
  tables: the keys are set, not the files locked.
- `CLAUDE_CODE_MANAGED_SETTINGS_PATH` is inert in Claude Code 2.1.278 (a denied server stays
  listed), so managed files have no scratch measurement; each needs a variant image, as
  `allowManagedHooksOnly` was measured (`container/ko-agent-sandbox/Containerfile`), since
  `/etc` is read-only in a session.
- A `requirements.toml` in `CODEX_HOME` is ignored by Codex 0.155.1: a user-layer server stays
  enabled in `codex mcp list`. `codex mcp list --json` names the servers without starting them.
- `claude mcp list` health-checks and so executes every server it finds; it cannot serve as a
  check.
- OpenCode imports a JavaScript file under `~/.config/opencode/plugins/`, in the volume, and
  calls its plugin functions from the commands that load the configuration (`opencode debug
  config`, `agent list`, `mcp list`). It merges `opencode.json` and `opencode.jsonc` under the
  same directory: `mcp` entries of both files load, and the later file's `plugin` array
  replaces the earlier one's. `config/node_modules` (26 packages) is installed at every start
  from `config/package.json` for local plugins.
- Antigravity's `config/mcp_config.json` and Copilot's `config.json` name no server. Kiro's
  `data/` holds its own `bun` and `tui.js`, which Kiro writes itself.

## Phase 1: reconciliation

In `ko-sandbox-entrypoint`, beside the trust entries it writes under the volume lock and before
the agent starts:

- Set each agent's executable keys to the reviewed set: one file per agent under
  `.ko-agent-sandbox/`, read-only in a session as the egress rule is, an absent file meaning
  none.
- Print every replaced definition with its command line before the entrypoint's pause, so the
  user can stop and reach for `--reset`, or for `podman volume rm` on a volume named through
  `KO_AGENT_SANDBOX_PERSISTENT_VOLUME`, which `--reset` preserves.
- Refuse the launch on a file that does not parse.
- A reviewed definition names a program in the image or one `npx` fetches at start; a path
  under the volume it names is phase 2's.

The keys per agent:

- Claude: `mcpServers` at the top level and in each project entry of `.claude.json`, through jq
  as the trust entry is, and `enableAllProjectMcpServers` in `settings.json`. Hooks and the
  status line are pinned (`allowManagedHooksOnly`).
- Codex: through its CLI, since `codex mcp list --json` names the servers and `codex mcp remove`
  drops one. `notify`, a user-layer command run for notifications, and `hooks` in `config.toml`
  need the same treatment (https://learn.chatgpt.com/docs/config-file/config-reference).
- OpenCode: the `plugin` and `mcp` keys of both `opencode.json` and `opencode.jsonc`
  (https://opencode.ai/docs/config/, "Locations").
- The other agents: read the documentation for the keys, then the files in the volume.

Limits:

- It covers the volume, not the project's `.mcp.json` or `.opencode/plugins/`.
- An in-session `claude mcp add` works until the next launch.
- A concurrent session of the same project can re-add, which the next launch replaces and reports
  again.
- Claude's file layout is measured, not documented, and has no safe self-check.

## Phase 1 confirmation: the agents' managed files

The managed files are documented, reach the project's files too, and refuse an in-session add
with a clear message; reconciliation stays as the check behind them. A project that needs a
server names it in the reviewed file above, which the launcher also mounts as the managed file.

- Claude: `managed-mcp.json` in `/etc/claude-code/` loads only the servers it names, an empty map
  none, and excludes plugin-provided servers and `--mcp-config`
  (https://code.claude.com/docs/en/managed-mcp, "Exclusive control with managed-mcp.json").
  `strictPluginOnlyCustomization` is no substitute: it keeps plugin servers, and
  `~/.claude/plugins/` is in the volume.
- Codex: `/etc/codex/requirements.toml` is the admin-enforced layer, below the cloud bundle and
  the legacy `managed_config.toml` in precedence
  (https://learn.chatgpt.com/docs/enterprise/managed-configuration, "Locations and precedence").
  An `mcp_servers` table that is present but empty disables every MCP server, plugin-bundled ones
  included; an entry allows a server only when its name and identity (command or URL, optionally
  each argument) match. `features.plugins = false` disables plugins, and
  `allow_managed_hooks_only = true` skips user, project, session and plugin hooks. No requirement
  pins `notify`, which stays with reconciliation.

## Phase 2: unwritable code directories

The directories: `~/.claude/plugins/`; OpenCode's `plugins/` and `node_modules`
(https://opencode.ai/docs/plugins/, "How plugins are installed"); Codex's `plugins/`; Kiro's
`data/`.

The form is decided after measuring each agent on a refused write, since OpenCode runs
`bun install` into `config/node_modules` and Kiro writes `data/bun` itself: a read-only mount, if
the installed podman mounts a volume subpath; else separate volumes for the writable paths; or
those directories not persisted at all.

Whichever form, its first launch establishes each directory's content from reviewed sources
instead of keeping what the volume holds, since an earlier session may have planted a file there
and phase 1 resets keys only: the existing directory is moved aside and its entries listed. The
entrypoint's trust writes then move to a helper container before the read-only start. A
directory that holds code beside state, as `~/.claude/plugins/` holds marketplace state, cannot
be split by a mount.

## Deliberate exclusions

Memory, skills and instructions in the volume, which a later session reads as text and acts on
through the model's own tool calls: SECURITY.md's `--reset` covers them.
