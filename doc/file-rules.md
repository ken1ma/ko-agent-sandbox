# Project files a host program executes

Some project files name a command a program on your host runs without you running the project: an
agent's hooks when you start it, a hook manager's configuration when you commit, an editor's tasks
when you open the folder, mise's hooks when you enter the directory, a Dev Container's
`initializeCommand` when you reopen it. One names a server instead: `.lfsconfig`, which git-lfs
on your host downloads from when you check out and uploads to when you push.

- In a writable session the workspace filter keeps these files read-only, and under
  `--run-on-host` so does the host command's profile.
- Build files, scripts and `package.json` stay writable: you run those yourself, and review their
  diff as any other (SECURITY.md, "The project directory").

## What is read-only

- The names the launcher's defaults list, at any depth:
  `src/main/resources/agentsandbox/file-rule-defaults` has them with their programs. They cover
  Claude Code, Codex, Gemini CLI, Copilot CLI, Antigravity, Kiro and OpenCode; husky, pre-commit
  and lefthook; VS Code, Visual Studio, IntelliJ IDEA, Cursor, Windsurf and Zed; Dev Containers;
  mise; and git-lfs.
- Inside `node_modules`, nothing: npm installs packages that carry these names.
- A Git hook directory the repository keeps in the worktree — husky's `.husky/_`, a
  `core.hooksPath` of `githooks` — found when the filter mounts.
- The target of a symlink inside a listed entry at the project root: with
  `.vscode/tasks.json -> ../tasks-data.json`, `tasks-data.json` is read-only too, also when
  `.vscode` itself links to a directory outside the project.
- The directory a symlink at the project root leads to, when it makes that directory part of a
  listed name: with `.claude -> shared/claude`, the session cannot create
  `shared/claude/settings.json`.
- A directory a listed name passes through, `.claude` for `.claude/settings.json`, can be created
  by `mkdir`, written in, and removed once empty, but not renamed or replaced.

The launch prints what the filter's guard adds when it mounts.

The session's own writes fail with `Operation not permitted`. Its agent sees the lines in
`$KO_AGENT_SANDBOX_FILE_RULES`.

## Changing a listed file

- Run the command meant to change it on the host, as you run `--update` for the agents:
  `pre-commit autoupdate`, `lefthook add`, `mise use`, `claude mcp add --scope project`,
  `gemini mcp add`, `/hooks` and `/permissions` in Claude Code.
- A git command in the session that must change a listed file — `switch`, `checkout`, `pull`,
  `reset`, `stash pop` — prints `unable to unlink old`, finishes, and leaves the old content
  showing as a local modification. Run it on the host, or leave that file out of the session's
  commits.
- An installer writing a listed name outside `node_modules`, a scaffolder's `.vscode/` among them,
  is refused that entry.
- A sandboxed agent's own write to a listed file fails: Claude Code's "Yes, and don't ask again",
  OpenCode's install into an existing `.opencode/`. A project whose agent or editor maintains a
  listed file in the sandbox makes it writable in its rule file, below.

## The rule file

`.ko-agent-sandbox/file/rule` in the project directory, read at every launch after the defaults.
One line per rule; `#` starts a comment at the start of a line or after whitespace, and blank
lines are ignored, as in `egress/rule`.

```text
readonly NAME      the entry and everything below it are read-only
writable NAME      the entry and everything below it are writable
```

- `NAME` is a basename, or `/`-separated components for a file a program reads under a fixed
  directory (`.claude/settings.json`). It matches at any depth.
- `*` matches any run of characters within one component; nothing else is a wildcard. In a
  directory component it pins every entry it matches: `*/hooks.json` leaves no file in the
  project creatable, renamable or removable.
- The characters are `a`–`z`, `0`–`9`, `.`, `_`, `-` and `*`. The filter folds case as the host's
  filesystem may, so `readonly .vscode` covers `.VSCode`.
- The last line naming the entry or one of its ancestors decides:

```text
readonly .vscode
writable .vscode/settings.json      settings.json writable, the rest of .vscode read-only
```

  In the reverse order `.vscode` decides, and `settings.json` stays read-only.

Below a directory a `writable` line names, a session can write names the other lines protect, so
the filter refuses:

- moving a directory or symlink out of it, renaming the directory itself included: `mv
  node_modules nm.bak` fails with `Operation not permitted`, while npm's renames inside it work;
- a hard link of a symlink out of it, and a symlink into it from outside.

A Git directory's operational state, `.git/objects` among it, is where no line applies, so the
filter refuses:

- moving a directory or symlink out of it into the project, and a hard link of a symlink out of
  it;
- a symlink in the project whose target names any `.git` entry, `.git/config` included, since
  another link's `..` after it reaches that state;
- a symlink whose target spells an NTFS 8.3 short name such as `GIT~1`, whatever that name holds
  when the link is made: a Windows host resolves the name when it reads the link, and the
  session can change what it holds meanwhile. Spell the long name instead.

Every ambiguity refuses the launch: an unknown word; a line that is not one word and one name; a
leading or trailing `/`, an empty, `.` or `..` component; a character outside the set above,
uppercase included; a `#` inside a token; a file with no lines; a `.git` or `.ko-agent-sandbox`
component, which the filter's own rules protect.

The launch prints the file's lines, and every `writable` line again as a widening.

`doc/file-rule-example/*/rule` holds complete files for common needs, to copy and trim:

- `direnv/rule`, for a project whose users approve a changed `.envrc` by reflex, lists `.envrc`;
  the defaults leave it writable because direnv asks again when it changes.

## Under `--run-on-host`

The host command's profile denies writing the same names, in the same order, with one limit and
two stricter spots:

- A host command can move a directory out of `node_modules` over a directory of the project, with
  a listed file the session or the command wrote in it: `node_modules/x`, holding
  `.vscode/tasks.json`, over `apps/web`.
- So under `--run-on-host` a listed name still cannot be written at the project root or inside a
  directory a line names, such as `.vscode/`. A listed file moved in the other way takes effect
  when a host program starts in its new directory: an editor opening `apps/web`, a Dev Container,
  mise, an agent.
- A session without `--run-on-host` has no such limit: the filter refuses the move.
- A project that wants a listed name read-only inside `node_modules` too repeats its line in its
  rule file, whose lines follow the defaults' `writable node_modules`. npm then installs a package
  without that entry, prints `npm warn tar TAR_ENTRY_ERROR` for it, and exits 0.
- The profile is stricter than the filter in two respects (`run-on-host.md`, "The host command's
  filesystem rules"):
  - a host command cannot `mkdir` a directory a line passes through, such as `.claude`, or
    `rmdir` it once empty;
  - below the target of a symlink the rules reach, `shared/claude` for `.claude -> shared/claude`,
    a `writable` line lifts nothing.

### Why a limit

- Seatbelt cannot refuse the move without breaking npm or every build: it checks a rename's source
  as a removal, as `rmdir` and `rm` are checked, and its destination as a creation, as `mkdir` is,
  and SBPL has no operation for a rename itself (`src/probe/seatbelt-semantics.sh`, E13-E16).
- Keeping every listed name read-only inside `node_modules` under `--run-on-host` alone would close
  it, at the costs `design.md`, "A `--run-on-host` limit, not a stricter form", weighs.

## One mount per project

Concurrent sessions of a project share one filter mount, which serves the rules its first session
resolved.

- A launch after an edit of the rule file, while other sessions of the project run, joins their
  mount under their rules. It prints a warning naming them, and its start prompt is the consent;
  the edit takes effect at a launch after they end.
- Without the start prompt, `KO_AGENT_SANDBOX_SESSION_START=immediate` or no terminal, that launch
  is refused, since the running rules may be weaker than the edit.

## Why these files

The list protects which command a host program runs on an event other than you running the
project, where a file you do not run selects that command; SECURITY.md, "A host program executing
a project file on an event", states the boundary and what stays open.

- It keeps a session from adding a command to an event or changing one a non-project file names:
  no `runOn: folderOpen` task added to `.vscode/tasks.json`, no `repo: local` entry of
  `.pre-commit-config.yaml` pointed at a script of its own.
- A project whose event configuration already runs project code gains nothing for that event:
  when a folder-open task runs `npm run build`, the session edits the `build` script in
  `package.json`, and the task runs the edit on the next open.
- The host's Claude Code asks before starting a project MCP server, once per project, so the
  `.mcp.json` line defends a changed server after that answer.
- The `.lfsconfig` line keeps a session from choosing the server a host checkout contacts, a
  connection the egress proxy never sees; SECURITY.md, "The project directory", has what it leaves
  open.

Which files a default line names:

- A file is listed unless a command you run for another purpose rewrites it, the way
  `npm install` rewrites `package-lock.json`.
- A file whose program approves each change of its content stays writable: direnv blocks a
  changed `.envrc`, and Codex a changed hook, until approved again. mise does so only in its
  paranoid mode, and VS Code's Allow and Claude Code's MCP approval are once per workspace, so
  their files are listed.
- A dependency directory is writable, since `npm install` places listed names in it
  ("Measurements", below).

Not listed:

- Build files, scripts, `package.json`, `Makefile`, `.cargo/config.toml`, `mise.lock`: you run
  them, or install from them.
- CI definitions (`.github/workflows`): the forge executes them, not the host.
- The commands `devcontainer.json` runs inside the container, `onCreateCommand` through
  `postAttachCommand`: what they reach is the dev container's, which you build from the project's
  own configuration, as the sandbox's container is. `.devcontainer` is listed for
  `initializeCommand` alone, and whole because one file holds both.
- Editor extensions that evaluate project files on open or save: no list of names closes them.
- Instruction files a model reads (`CLAUDE.md`, `.cursor/rules`, `.windsurf/rules`,
  `.devin/rules`, `.kiro/steering`, `.agents/skills`): no host program runs them.
- `.codex/hooks.json` and `.gemini/commands`: their programs approve a changed hook, or each run.
- Path patterns beyond `*` and a second precedence: `design.md`, "No richer rule format".

### What each program reads

Read on 2026-09-25 and 2026-09-26, from each program's documentation and source.

Agents:

- Claude Code (https://code.claude.com/docs/en/settings, https://code.claude.com/docs/en/hooks,
  https://code.claude.com/docs/en/skills, https://code.claude.com/docs/en/mcp):
  - `.claude/settings.json` and `.claude/settings.local.json` hold `hooks`, `statusLine`,
    `fileSuggestion`, `apiKeyHelper` and the other credential helpers; the workspace trust dialog
    gates them once per folder.
  - A skill's `SKILL.md` declares frontmatter `hooks` and runs its `` !`command` `` lines before the
    model sees the skill; a subagent under `.claude/agents` declares `hooks`.
  - `.mcp.json` servers wait for an approval, once per project, until `enableAllProjectMcpServers`.
  - "Yes, and don't ask again" writes `.claude/settings.local.json`; `/hooks` and `/permissions`
    write the settings files; `claude mcp add --scope project` writes `.mcp.json`.
  - In a session its project hooks are inert under the image's `allowManagedHooksOnly`
    (SECURITY.md, "Claude Code running commands from user or project hooks").
- Codex (https://github.com/openai/codex, `codex-rs/config/src/loader/mod.rs`,
  `codex-rs/tui/src/onboarding/trust_directory.rs`):
  - `.codex/config.toml` loads, from the repository root down to the working directory, for a
    project trusted once; its `[mcp_servers]` start with the session.
  - Hooks, in `.codex/hooks.json` or inline, run only after an approval of their content hash.
- Gemini CLI (https://github.com/google-gemini/gemini-cli,
  `packages/cli/src/config/trustedFolders.ts`, `packages/core/src/hooks/hookRegistry.ts`,
  `packages/cli/src/commands/mcp/add.ts`):
  - `.gemini/settings.json` names `mcpServers`, `hooks`, `tools.discoveryCommand` and
    `tools.callCommand`, loaded for a folder trusted once; changed hooks only warn.
  - `gemini mcp add` writes the project file by default.
  - A `.gemini/commands` `!{...}` command asks before it runs unless a policy allows it.
- GitHub Copilot CLI (https://docs.github.com/en/copilot/reference/hooks-configuration,
  https://docs.github.com/en/copilot/how-tos/copilot-cli):
  - After folder trust, once: hooks in `.github/hooks/*.json`, `.github/copilot/settings.json`,
    `.github/copilot/settings.local.json` and `.claude/settings.json`; MCP servers in `.mcp.json`
    and `.github/mcp.json`; LSP servers in `.github/lsp.json`.
  - `.github/extensions/<name>/extension.*` runs as a Node process under `--experimental`; an agent
    under `.github/agents` or `.claude/agents` starts its `mcp-servers` when used.
- Antigravity (https://antigravity.google/docs/hooks, https://antigravity.google/docs/mcp):
  `.agents/hooks.json`, `.agents/mcp_config.json` and plugins under `.agents/plugins`; whether
  folder trust gates them is not documented.
- Kiro (https://kiro.dev/docs/hooks/, https://kiro.dev/docs/custom-agents/,
  https://kiro.dev/docs/custom-agents/configuration-reference/,
  https://kiro.dev/docs/mcp/configuration/):
  - Hooks are JSON files in `.kiro/hooks/` and run shell commands when their event fires, unless
    the hook sets `confirm`.
  - Workspace agents under `.kiro/agents/` load only if the workspace is trusted; an agent file's
    `hooks` and `mcpServers` each name a `command`.
  - `.kiro/settings/mcp.json` is the workspace MCP file; agent and MCP configurations hot-reload.
- OpenCode (https://github.com/anomalyco/opencode, `packages/opencode/src/config/config.ts`,
  `packages/opencode/src/config/plugin.ts`, `packages/opencode/src/tool/registry.ts`,
  `packages/opencode/src/session/prompt.ts`):
  - It reads `opencode.json` and `opencode.jsonc` in every directory from the working directory up
    to the worktree root, and the same names in each `.opencode/`. No trust prompt exists.
  - In a `.opencode/`, `{plugin,plugins}/*.{ts,js}` load at startup and `{tool,tools}/*.{js,ts}`
    are imported when the tool registry starts; a `{command,commands}/**/*.md` body's `` !`cmd` ``
    runs on invocation without a permission check.
  - The config's `mcp`, `formatter`, `lsp` and `shell` keys name commands.
  - It installs `@opencode-ai/plugin` into each `.opencode/`, scripts ignored.

Git hook managers:

- husky (https://github.com/typicode/husky, `index.js`, `bin.js`):
  - `husky` runs `git config core.hooksPath .husky/_`, then writes the dispatcher `h` and one
    stub per hook there; the stub runs `.husky/<hook>`.
  - With `.git/config` unwritable, npm 11.19.0's `npm install` runs `prepare: husky`, which prints
    git's `could not lock config file` and exits 0; npm exits 0 and `.husky/` stays absent.
- pre-commit (https://github.com/pre-commit/pre-commit, `pre_commit/constants.py`,
  `pre_commit/commands/install_uninstall.py`): `.pre-commit-config.yaml` is its only name; the
  installed hook reads it at each run. `pre-commit autoupdate` rewrites its `rev` values.
- lefthook (https://github.com/evilmartians/lefthook, `internal/config/loader.go`,
  `internal/templates/hook.tmpl`):
  - `lefthook`, `.lefthook` and `.config/lefthook`, each with a `-local` variant, with `.yml`,
    `.yaml`, `.json`, `.jsonc` or `.toml`; the installed stub reads them at each commit.
  - The stub runs lefthook from the project, `node_modules/lefthook/bin/index.js` among others.

Editors:

- VS Code (https://github.com/microsoft/vscode-docs, `docs/editing/workspaces/workspace-trust.md`,
  `docs/debugtest/tasks.md`): Restricted Mode disables tasks, debugging, workspace settings, the
  terminal, AI agents and extensions until the folder is trusted; a `runOn: folderOpen` task runs
  after a one-time Allow.
- Visual Studio
  (https://learn.microsoft.com/en-us/visualstudio/ide/customize-build-and-debug-tasks-in-visual-studio):
  `tasks.vs.json` and `launch.vs.json`, in `.vs`, at the root, and `tasks.vs.json` in subfolders.
- Zed (https://github.com/zed-industries/zed, `crates/paths/src/paths.rs`, `docs/src/tasks.md`,
  `docs/src/worktree-trust.md`):
  - `.zed/settings.json`, `.zed/tasks.json` and `.zed/debug.json`, plus `.vscode/tasks.json` and
    `.vscode/launch.json`; settings start language servers, MCP servers and formatters.
  - A task with `hooks: ["create_worktree"]` runs when Zed creates a linked worktree.
- IntelliJ IDEA (https://www.jetbrains.com/help/idea/, `settings-tools-startup-tasks.html`,
  `using-file-watchers.html`, `run-debug-configuration.html`, `project-security.html`): startup
  tasks and shared run configurations under `.idea`, and File Watchers, run once the project is
  trusted.
- Cursor (https://cursor.com/docs/agent/hooks, https://cursor.com/docs/context/mcp):
  `.cursor/hooks.json` hooks run "in any trusted workspace"; `.cursor/mcp.json` names servers.
- Windsurf, documented as Devin Desktop (https://docs.devin.ai/desktop/cascade/hooks,
  https://docs.devin.ai/desktop/cascade/mcp): `.devin/hooks.json`, with `.windsurf/hooks.json`
  read only when it is absent.

Others:

- Dev Containers (https://github.com/devcontainers/spec, `docs/specs/devcontainer-reference.md`):
  `initializeCommand` runs on the host; the file is `.devcontainer/devcontainer.json`,
  `.devcontainer.json` or `.devcontainer/<folder>/devcontainer.json`.
- git-lfs (https://github.com/git-lfs/git-lfs, `git/config.go`, `config/git_fetcher.go`), read
  on 2026-09-28:
  - It reads `.lfsconfig` at the worktree root, or, when that is absent, `:.lfsconfig` from the
    index, then `HEAD:.lfsconfig`, through `git config --includes`; a key your Git configuration
    sets overrides the file's.
  - From that file it takes `lfs.url`, `lfs.pushurl`, `remote.<name>.lfsurl` and
    `lfs.<url>.access`, among others; it ignores the keys that name a command.
- direnv (https://github.com/direnv/direnv, `internal/cmd/rc.go`, `man/direnv-stdlib.1.md`):
  - An `.envrc`, or an `.env` under `load_dotenv`, loads only once allowed; the allow is a hash
    of the file's path and content.
  - A file `source_env` loads "is not checked by the security framework".
- mise (https://github.com/jdx/mise, `docs/configuration.md`, `docs/hooks.md`, `docs/paranoid.md`,
  `src/config/mod.rs`, `src/config/config_file/mod.rs`, `src/config/miserc.rs`):
  - A trusted file stays trusted by path: only `paranoid` compares content. It trusts every file in
    CI, under a trusted monorepo root or `trusted_config_paths`, and what `mise run`,
    `mise install` and `mise exec` load.
  - The config files: `mise.toml`, `.mise.toml`, `config.toml` under `mise/`, `.mise/` and
    `.config/mise/`, `.config/mise.toml`, their `.local` and `MISE_ENV` variants, `conf.d/` under
    the three directories, and `.tool-versions`, whose Tera templates can `exec`.
  - `.miserc.toml`, `.miserc.local.toml` and `.config/miserc.toml` set which config files load.
  - `[hooks] enter` runs on entering the project.

### Measurements

In the image on 2026-09-26:

- `npm install` of 45 popular packages (991 installed) placed three listed names:
  `pino-abstract-transport/.husky/pre-commit` and `thread-stream/.claude/settings.local.json`,
  both from `fastify`'s `pino`, and `inflection/.vscode/settings.json` from `sequelize`.
- `git switch` to a branch that changes a file the process cannot unlink printed
  `error: unable to unlink old '.vscode/settings.json'`, switched, exited 0, and left the old
  content as a local modification.
- Through the filter with those names read-only inside `node_modules`, npm 11 installing `fastify`
  and `sequelize` printed `npm warn tar TAR_ENTRY_ERROR` for each refused entry, exited 0, and left
  `pino-abstract-transport` without `.husky/pre-commit`, `inflection` without
  `.vscode/settings.json`, and `thread-stream/.claude` empty.
- In a `--write=live` session through the filter, writing a listed file, creating a listed name
  and renaming a directory a listed name passes through failed with `Operation not permitted`.
