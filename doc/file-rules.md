# Workspace files a host program executes

Some workspace files name a command that a program on your host runs without you running the
workspace's code:

- an agent's hooks, when you start the agent;
- a hook manager's configuration, when you commit;
- an editor's tasks, when you open the folder;
- mise's hooks, when you enter the directory;
- a Dev Container's `initializeCommand`, when you reopen the folder in the Dev Container.

One file names a server instead: git-lfs on your host downloads from the server that `.lfsconfig`
names when you check out, and uploads to that server when you push.

- In a writable session, the workspace filter keeps these files read-only. Under
  `--workspace=live,bpf`, the BPF policy keeps them read-only instead (`bpf-lsm-cgroup.md`).
- Under `--run-on-host`, the host command's profile also keeps these files read-only.
- Build files, scripts and `package.json` stay writable: you run those yourself, and you review
  their diff as you review any other diff (`../SECURITY.md`, "The workspace").

## What is read-only

- The names that the launcher's defaults list, at any depth.
  `src/main/resources/agentsandbox/file-rule-defaults` lists them with their programs. The defaults
  cover Claude Code, Codex, Gemini CLI, Copilot CLI, Antigravity, Kiro and OpenCode; husky,
  pre-commit and lefthook; VS Code, Visual Studio, IntelliJ IDEA, Cursor, Windsurf and Zed; Dev
  Containers; mise; and git-lfs.
- Inside `node_modules`, nothing: npm installs packages that carry these names.
- A Git hook directory that the repository keeps in the worktree, such as husky's `.husky/_` or a
  `core.hooksPath` of `githooks`. The filter finds such a directory when the filter mounts.
- The target of a symlink inside a listed entry at the workspace root. With
  `.vscode/tasks.json -> ../tasks-data.json`, `tasks-data.json` is read-only too, even when
  `.vscode` itself links to a directory outside the workspace.
- The directory that a symlink at the workspace root leads to, when the symlink makes that
  directory part of a listed name. With `.claude -> shared/claude`, the session cannot create
  `shared/claude/settings.json`.
- A directory that a listed name passes through, such as `.claude` for `.claude/settings.json`,
  cannot be renamed or replaced. The session can still create such a directory with `mkdir`, write
  in it, and remove it once it is empty.

When the filter mounts, the launch prints the paths that the filter's guard makes read-only.

The session's own writes to these paths fail with `Operation not permitted`. The session's agent
sees the rule lines in `$KO_AGENT_SANDBOX_FILE_RULES`.

## Changing a listed file

- Run the command meant to change a listed file on the host, as you run `--update` for the
  agents. Such commands include `pre-commit autoupdate`, `lefthook add`, `mise use`,
  `claude mcp add --scope project`, `gemini mcp add`, and `/hooks` and `/permissions` in Claude
  Code.
- A git command in the session that must change a listed file, such as `switch`, `checkout`,
  `pull`, `reset` or `stash pop`, prints `unable to unlink old` and finishes. The old content then
  shows as a local modification. Run such a command on the host, or leave that file out of the
  session's commits.
- An installer that writes a listed name outside `node_modules`, such as a scaffolder that writes
  `.vscode/`, has that entry refused.
- A sandboxed agent's own write to a listed file fails, for example Claude Code's "Yes, and don't
  ask again" or OpenCode's install into an existing `.opencode/`. A workspace whose agent or editor
  maintains a listed file in the sandbox makes that file writable in its rule file (below).

## The rule file

The launcher reads `.ko-agent-sandbox/file/rule` in the workspace root at every launch, after the
defaults. The file holds one rule per line. As in `egress/rule`, `#` starts a comment at the start
of a line or after whitespace, and blank lines are ignored.

```text
read-only NAME     the entry and everything below it are read-only
writable NAME      the entry and everything below it are writable
```

- `NAME` is a basename, or `/`-separated components for a file a program reads under a fixed
  directory (`.claude/settings.json`). It matches at any depth.
- `*` matches any run of characters within one component; nothing else is a wildcard. In a
  directory component, `*` pins every entry it matches: `*/hooks.json` leaves no file in the
  workspace creatable, renamable or removable.
- The characters are `a`–`z`, `0`–`9`, `.`, `_`, `-` and `*`. The filter folds case as the host's
  filesystem may, so `read-only .vscode` covers `.VSCode`.
- The last line naming the entry or one of its ancestors decides:

```text
read-only .vscode
writable .vscode/settings.json      settings.json writable, the rest of .vscode read-only
```

  In the reverse order `.vscode` decides, and `settings.json` stays read-only.

Below a directory that a `writable` line names, a session can write names that the other lines
protect. So the filter refuses:

- moving a directory or symlink out of that directory, including renaming the directory itself.
  `mv node_modules nm.bak` fails with `Operation not permitted`, while npm's renames inside
  `node_modules` work;
- a hard link of a symlink out of that directory, and a symlink into it from outside.

No line applies in a Git directory's operational state, such as `.git/objects`. So the filter,
and the BPF policy under `--workspace=live,bpf`, refuse:

- moving a directory or symlink out of that state into the workspace, and a hard link of a symlink
  out of that state;
- a symlink in the workspace whose target names any `.git` entry, `.git/config` included, since
  another link's `..` after that symlink reaches the state;
- a symlink whose target spells an NTFS 8.3 short name such as `GIT~1`, whatever that name holds
  when the link is made. A Windows host resolves the name when it reads the link, and the session
  can change what the name holds meanwhile. Spell the long name instead.

The launch refuses every ambiguity:

- an unknown word;
- a line that is not one word and one name;
- a leading or trailing `/`, or an empty, `.` or `..` component;
- a character outside the set above, uppercase included;
- a `#` inside a token;
- a `.git` or `.ko-agent-sandbox` component, which the filter's own rules protect.

The launcher reads a file that holds only comments and blank lines as no file.

The launch prints each line of the file once: first the `writable` lines, as a widening, with two
or more joined into `writable: <name>, <name>`; then the other lines.

`doc/file-rule-example/*/rule` holds complete files for common needs, to copy and trim:

- `direnv/rule` lists `.envrc`, for a workspace whose users approve a changed `.envrc` by reflex.
  The defaults leave `.envrc` writable because direnv asks again when the file changes.

## Under `--run-on-host`

The host command's profile denies writes to the same names, in the same order. The profile has
one limit, and the profile is stricter than the filter in two respects:

- A host command can move a directory out of `node_modules` over a directory of the workspace,
  together with a listed file that the session or the command wrote in the moved directory. For
  example, the command moves `node_modules/x`, holding `.vscode/tasks.json`, over `apps/web`.
- So under `--run-on-host`, a listed name still cannot be written at the workspace root or inside
  a directory that a line names, such as `.vscode/`. A listed file that arrives by such a move
  takes effect when a host program starts in its new directory: an editor opening `apps/web`, a
  Dev Container, mise, or an agent.
- A session without `--run-on-host` has no such limit: the filter refuses the move.
- A workspace that wants a listed name read-only inside `node_modules` too repeats the name's line
  in its rule file. The rule file's lines follow the defaults' `writable node_modules`. npm then
  installs a package without that entry, prints `npm warn tar TAR_ENTRY_ERROR` for the entry, and
  exits 0.
- The profile is stricter than the filter in two respects (`run-on-host.md`, "The host command's
  filesystem rules"):
  - a host command cannot `mkdir` a directory that a line passes through, such as `.claude`, or
    `rmdir` that directory once it is empty;
  - a `writable` line lifts nothing below the target of a symlink that the rules reach, such as
    `shared/claude` for `.claude -> shared/claude`.

### Why a limit

- Seatbelt cannot refuse the move without breaking npm or every build
  (`src/probe/seatbelt-semantics.sh`, E13-E16):
  - Seatbelt checks a rename's source as a removal, as it checks `rmdir` and `rm`;
  - Seatbelt checks a rename's destination as a creation, as it checks `mkdir`;
  - SBPL has no operation for a rename itself.
- Keeping every listed name read-only inside `node_modules`, under `--run-on-host` alone, would
  close the limit. `design.md` weighs the costs of that option in "A `--run-on-host` limit, not a
  stricter form".

## One mount per workspace

Concurrent sessions of a workspace share one filter mount. The mount serves the rules that its
first session resolved.

Under `--workspace=live,bpf` there is no mount:

- Each session's policy holds the rules that the session's own launch resolved.
- The launcher refuses a launch under the other backend while a live session of the workspace runs
  (`../ko-agent-fs/bpf/doc/architecture.md`, "The hooks", `file_receive`).

What happens after an edit of the rule file:

- A launch after the edit, while other sessions of the workspace run, joins their mount under
  their rules. The launch prints a warning that names those sessions, and the launch's start prompt
  is the consent. The edit takes effect at a launch after those sessions end.
- Without the start prompt, under `--session-start=immediate` or with no terminal, the launcher
  refuses that launch, since the running rules may be weaker than the edit.

## Why these files

The list protects which command a host program runs on an event other than you running the
workspace's code, when a file you do not run selects that command. SECURITY.md states the boundary
and what stays open (`../SECURITY.md`, "A host program executing a workspace file on an event").

- The list keeps a session from adding a command to an event, and from changing a command that a
  file you do not run names. For example, the session cannot add a `runOn: folderOpen` task to
  `.vscode/tasks.json`, or point a `repo: local` entry of `.pre-commit-config.yaml` at a script of
  its own.
- A workspace whose event configuration already runs one of its scripts gains nothing for that
  event: when a folder-open task runs `npm run build`, the session edits the `build` script in
  `package.json`, and the task runs the edit on the next open.
- The host's Claude Code asks before starting a project MCP server, once per project, so the
  `.mcp.json` line defends a changed server after that answer.
- The `.lfsconfig` line keeps a session from choosing the server that a host checkout contacts.
  The egress proxy never sees that connection. SECURITY.md says what the line leaves open
  (`../SECURITY.md`, "The workspace").

Which files a default line names:

- A file is listed unless a command you run for another purpose rewrites it, the way
  `npm install` rewrites `package-lock.json`.
- A file whose program approves each change of its content stays writable. direnv blocks a
  changed `.envrc`, and Codex blocks a changed hook, until the user approves the change again.
  - mise approves each change only in its paranoid mode, so mise's files are listed.
  - VS Code's Allow and Claude Code's MCP approval are once per workspace, so their files are
    listed.
- A dependency directory is writable, since `npm install` places listed names in it
  ("Measurements", below).

Not listed:

- Build files, scripts, `package.json`, `Makefile`, `.cargo/config.toml`, `mise.lock`: you run
  them, or install from them.
- CI definitions (`.github/workflows`): the forge executes them, not the host.
- The commands that `devcontainer.json` runs inside the container, `onCreateCommand` through
  `postAttachCommand`. What these commands reach belongs to the dev container. You build the dev
  container from the workspace's own configuration, as the sandbox's container is.
  - `.devcontainer` is listed for `initializeCommand` alone. The whole directory is listed because
    one file holds both kinds of command.
- Editor extensions that evaluate workspace files on open or save: no list of names closes them.
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
  - In a session, Claude Code's project hooks are inert under the image's `allowManagedHooksOnly`
    (`../SECURITY.md`, "Claude Code running commands from user or project hooks").
- Codex (https://github.com/openai/codex, `codex-rs/config/src/loader/mod.rs`,
  `codex-rs/tui/src/onboarding/trust_directory.rs`):
  - `.codex/config.toml` loads, from the repository root down to the working directory, for a
    project trusted once; its `[mcp_servers]` start with the session.
  - Hooks, in `.codex/hooks.json` or inline, run only after an approval of their content hash.
- Gemini CLI (https://github.com/google-gemini/gemini-cli,
  `packages/cli/src/config/trustedFolders.ts`, `packages/core/src/hooks/hookRegistry.ts`,
  `packages/cli/src/commands/mcp/add.ts`):
  - `.gemini/settings.json` names `mcpServers`, `hooks`, `tools.discoveryCommand` and
    `tools.callCommand`. Gemini CLI loads the file for a folder trusted once, and only warns about
    changed hooks.
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
  - OpenCode reads `opencode.json` and `opencode.jsonc` in every directory from the working
    directory up to the worktree root, and the same names in each `.opencode/`. No trust prompt
    exists.
  - In a `.opencode/`, `{plugin,plugins}/*.{ts,js}` load at startup and `{tool,tools}/*.{js,ts}`
    are imported when the tool registry starts; a `{command,commands}/**/*.md` body's `` !`cmd` ``
    runs on invocation without a permission check.
  - The config's `mcp`, `formatter`, `lsp` and `shell` keys name commands.
  - OpenCode installs `@opencode-ai/plugin` into each `.opencode/`, with the package's scripts
    ignored.

Git hook managers:

- husky (https://github.com/typicode/husky, `index.js`, `bin.js`):
  - `husky` runs `git config core.hooksPath .husky/_`, then writes the dispatcher `h` and one
    stub per hook there; the stub runs `.husky/<hook>`.
  - With `.git/config` unwritable, npm 11.19.0's `npm install` runs `prepare: husky`. husky prints
    git's `could not lock config file` and exits 0, npm exits 0, and `.husky/` stays absent.
- pre-commit (https://github.com/pre-commit/pre-commit, `pre_commit/constants.py`,
  `pre_commit/commands/install_uninstall.py`): `.pre-commit-config.yaml` is its only name; the
  installed hook reads it at each run. `pre-commit autoupdate` rewrites its `rev` values.
- lefthook (https://github.com/evilmartians/lefthook, `internal/config/loader.go`,
  `internal/templates/hook.tmpl`):
  - `lefthook`, `.lefthook` and `.config/lefthook`, each with a `-local` variant, with `.yml`,
    `.yaml`, `.json`, `.jsonc` or `.toml`; the installed stub reads them at each commit.
  - The stub runs lefthook from the workspace, `node_modules/lefthook/bin/index.js` among others.

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
  - git-lfs reads `.lfsconfig` through `git config --includes`: the file at the worktree root, or,
    when that file is absent, `:.lfsconfig` from the index, then `HEAD:.lfsconfig`.
  - A key that your Git configuration sets overrides the file's key.
  - From that file, git-lfs takes `lfs.url`, `lfs.pushurl`, `remote.<name>.lfsurl` and
    `lfs.<url>.access`, among others; it ignores the keys that name a command.
- direnv (https://github.com/direnv/direnv, `internal/cmd/rc.go`, `man/direnv-stdlib.1.md`):
  - An `.envrc`, or an `.env` under `load_dotenv`, loads only once allowed; the allow is a hash
    of the file's path and content.
  - A file `source_env` loads "is not checked by the security framework".
- mise (https://github.com/jdx/mise, `docs/configuration.md`, `docs/hooks.md`, `docs/paranoid.md`,
  `src/config/mod.rs`, `src/config/config_file/mod.rs`, `src/config/miserc.rs`):
  - A trusted file stays trusted by path: only `paranoid` compares content. mise trusts every file
    in CI, under a trusted monorepo root or `trusted_config_paths`, and what `mise run`,
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
- In a `--workspace=live` session through the filter, writing a listed file, creating a listed name
  and renaming a directory a listed name passes through failed with `Operation not permitted`.
