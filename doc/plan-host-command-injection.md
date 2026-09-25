# Plan: project files a host program executes on an event

A writable session may edit any project file except the Git entries host git executes and the
launcher's own configuration (SECURITY.md, "The host's git executing what the sandbox wrote").
Other host programs execute project files on an event the user does not read as running the
project:

- an agent starting in the project, on the host;
- an editor opening the folder;
- a shell entering the directory;
- a `git commit` dispatching through a hook manager;
- an editor reopening the project in a Dev Container, whose `initializeCommand` runs on the
  host.

This plan extends the filter's protection to the files those programs read, through a rule file
beside `egress/rule`.

The requirement: a session cannot change which command a host program runs on an event other
than the user running the project's own code, where a file the user does not run selects that
command.

- What the selected command then runs stays writable: a project script that a task or hook
  runs, a `package.json` script, a file that an `.envrc` sources. Editing build files and
  scripts is the job, and the user runs them deliberately (SECURITY.md, "The project directory").
- The list protects the selection, not the code selected.

## What is read and measured

Read on 2026-09-25.

The filter (`../fuse/ko-agent-fs/`):

- It classifies an inode from its parent's context and its own name, in O(1), on bytes, and
  caches the result per inode (`src/policy.rs`, `child_context`).
- It guards two names, `.git` and `.ko-agent-sandbox`, at any depth, through one fold
  (`folds_to`): drop ignorable code points, fold the letters a filesystem may compare equal,
  strip trailing dots and spaces, ignore ASCII case.
- The `.ko-agent-sandbox` context has no operational half: everything below it is protected.
- Beside an ordinarily named entry it stats both guarded names and compares object identity, so
  an NTFS 8.3 short name or a host hard link of a guarded entry is the guarded entry
  (`src/fs.rs`, `policy_name`).
- Its `rename` checks the source entry and the destination name, not the entries below a
  renamed directory (`src/fs.rs`, `rename`); a directory's children keep the contexts computed
  at their lookup until they are looked up again.
- The mount-time guard scans the root repository's `config` and `config.worktree` for every
  `hooksPath`, resolves each against the worktree, the gitdir and the common gitdir, and refuses
  the mount when a hook directory or a `.git/hooks` symlink resolves to writable workspace data
  (`src/guard.rs`, `check_repository`; `doc/git-metadata.md`, "Relocated hook directories").
- One filter mount serves a project; concurrent sessions share it (SECURITY.md, "The project
  directory").
- On macOS and Windows the daemon runs in the podman machine, whose view of the host is the
  directories the machine shares, `/Users`, `/private` and `/var/folders` on macOS (SECURITY.md,
  "Container, runtime and kernel escape"); the launcher does not read the machine's share list.
  On native Linux the daemon runs in the host's own namespace.
- `resolve_checked` returns `Ok(None)` for a chain with a component it cannot find
  (`src/guard.rs`).

The launcher:

- It never runs `git`.
- Under `--run-on-host`, the Seatbelt profile denies `file-write*`, `file-read*` and `file-link`
  on the two guarded names at any depth under the project (`SeatbeltProfile.GuardedNames`).
- SBPL is last-match-wins and matches a rule as written against the canonical accessed path, so
  the guard's denies are emitted after every allow and a rule must name a resolved path
  (`SeatbeltProfile.scala`, the header comment).
- `.ko-agent-sandbox/` holds only `egress/` and `run-on-host/`: any other entry refuses the
  launch, except a dot-prefixed one such as `.DS_Store`, which is editor or OS metadata and is
  ignored (`SandboxProject.boundaryDirRefusal`).
- The egress grammar is parsed in the proxy with a whitespace tokenizer where `#` opens a
  comment at a line's start or after whitespace; the project's lines fold over the defaults in
  order, the last applicable line deciding (`RulesetHelper.resolveRuleset`).

The agents:

- In a session, project hooks of Claude Code are inert under the image's
  `allowManagedHooksOnly` (SECURITY.md, "Claude Code running commands from user or project
  hooks").
- `claude mcp add` at project scope writes `.mcp.json`, and the host's Claude Code holds those
  servers behind an approval dialog until `enableAllProjectMcpServers` is set
  (`plan-executable-agent-configuration.md`, "What is measured").
- `/fewer-permission-prompts` writes the project's `.claude/settings.json`.
- A skill's or a subagent's frontmatter declares `hooks` with a `command`, in the settings
  files' format; Claude Code registers a skill's when the user or Claude invokes the skill and
  keeps them for the session, and a project skill's follow the workspace trust rule
  (https://code.claude.com/docs/en/hooks, "Hooks in skills and agents").

Tools, from their documentation, in the defaults' order:

- Agents:
  - Kiro (https://kiro.dev/docs/hooks/, https://kiro.dev/docs/custom-agents/):
    - Hooks are JSON files in `.kiro/hooks/` at the project root, for the IDE and the CLI alike,
      and run shell commands automatically when their event fires, unless the hook sets
      `confirm`.
    - They are created through the IDE, through chat with the agent, or by hand.
    - Workspace agents under `.kiro/agents/` load only if the workspace is trusted; an agent
      file's `hooks` (`agentSpawn`, `userPromptSubmit`, `preToolUse`, `postToolUse`) and
      `mcpServers` each name a `command` (`/docs/custom-agents/configuration-reference/`).
    - `.kiro/settings/mcp.json` is the workspace MCP file, each local server with a `command`;
      agent and MCP configurations hot-reload when saved (`/docs/mcp/configuration/`).
    - kiro-cli 2.23.1's `hook` subcommand is shell integration (`pre-exec`, `prompt`, `ssh`), not
      these hooks.
  - OpenCode (https://opencode.ai/docs/plugins/, https://opencode.ai/docs/config/,
    https://opencode.ai/docs/mcp-servers/):
    - Files in `.opencode/plugins/` load automatically at startup; the loader scans
      `{plugin,plugins}/*.{ts,js}`, so the singular directory too
      (https://github.com/anomalyco/opencode, `packages/opencode/src/config/plugin.ts`).
    - npm plugins named in the `plugin` key install into `~/.cache/opencode/node_modules/`, not
      the project.
    - `opencode.json` at the project root holds `plugin` and `mcp`; a local server with
      `enabled: true` starts at startup. No trust prompt is documented.
- Git hook managers:
  - husky (https://github.com/typicode/husky, `index.js`, `husky`):
    - `husky` sets `core.hooksPath` to `.husky/_` and writes there a dispatcher `h` and one stub
      per hook.
    - The stub sources `h`, which runs the script of the hook's name one directory up,
      `.husky/pre-commit`.
    - When `git config` fails, `husky` returns git's error.
  - pre-commit (https://github.com/pre-commit/pre-commit.com, `sections/usage.md`,
    `sections/advanced.md`, `sections/cli.md`):
    - `pre-commit install` writes the hook script into `.git/hooks`; the hook runs the checks
      `.pre-commit-config.yaml` configures at each commit.
    - A `repo: local` hook runs the command its `entry` names, for scripts distributed with the
      repository.
    - `pre-commit autoupdate` rewrites the config's `rev` values.
  - lefthook (https://github.com/evilmartians/lefthook, `docs/configuration.md`): `lefthook`,
    `.lefthook`, `lefthook-local` and `.lefthook-local` with `.yml`, `.yaml`, `.toml`, `.json` or
    `.jsonc`, at the root or under `.config/`.
- Editors:
  - VS Code (https://github.com/microsoft/vscode-docs,
    `docs/editing/workspaces/workspace-trust.md`, `docs/debugtest/tasks.md`):
    - Restricted Mode disables tasks, debugging, workspace settings, the terminal, AI agents and
      extensions until the folder is trusted.
    - A `runOn: folderOpen` task runs after a one-time Allow per workspace, never in an untrusted
      one.
  - Visual Studio
    (https://learn.microsoft.com/en-us/visualstudio/ide/customize-build-and-debug-tasks-in-visual-studio):
    - `tasks.vs.json` defines build commands and arbitrary tasks, run from Solution Explorer's
      context menu; `launch.vs.json` names the program the debugger starts on F5.
    - Both live in the hidden `.vs` folder, and are also read from the project root, where
      `.vs\launch.vs.json` takes precedence; `tasks.vs.json` is read from subfolders too.
  - Zed (https://github.com/zed-industries/zed, `docs/src/tasks.md`,
    `docs/src/configuring-zed.md`, `docs/src/configuring-languages.md`):
    - `.zed/tasks.json` tasks run a `command` in the terminal when spawned by hand, by keybinding
      or from a runnable; a task with `hooks: ["create_worktree"]` runs when Zed creates a linked
      worktree.
    - `.zed/settings.json` may set the language tooling options, among them a `formatter` with an
      `external` `command` and `format_on_save`, which runs on every save.
  - IntelliJ IDEA (https://www.jetbrains.com/help/idea/, `settings-tools-startup-tasks.html`,
    `using-file-watchers.html`, `run-debug-configuration.html`, `project-security.html`):
    - Startup tasks are run/debug configurations "launched automatically on the project start";
      a shared configuration is an XML file under `.idea/runConfigurations`, an unshared one
      lives in `.idea/workspace.xml`.
    - A File Watcher runs a command-line tool "as soon as a file of the selected type and in the
      selected scope is changed or saved".
    - An untrusted project opens in Safe Mode, which restricts executing code, builds and
      scripts; "Trust Project" enables every feature, startup tasks included. Whether trust
      survives a later change to the project's files is not stated.
  - Cursor (https://cursor.com/docs/agent/hooks, https://cursor.com/docs/context/mcp,
    https://cursor.com/docs/context/rules):
    - `.cursor/hooks.json` defines hooks, "spawned processes that communicate over stdio", on
      agent events such as `beforeShellExecution`, `afterFileEdit` and `stop`; project hooks
      "run in any trusted workspace".
    - `.cursor/mcp.json` names the command that starts a project MCP server; Cursor asks before
      a tool is used, and whether it asks before the server starts is not stated.
    - `.cursor/rules` holds `.mdc` files included in the model context, which the agent creates
      on request: instructions, not commands.
  - Windsurf, documented as Devin Desktop (https://docs.devin.ai/desktop/cascade/hooks,
    https://docs.devin.ai/desktop/cascade/mcp, https://docs.devin.ai/desktop/cascade/memories):
    - Hooks "are shell commands that run automatically when specific Cascade actions occur",
      before and after Cascade reads or writes a file, runs a terminal command or processes a
      prompt; the workspace file is `.devin/hooks.json`, with `.windsurf/hooks.json` read only
      when it is absent.
    - "Hooks do not load or run while a workspace is open in Restricted Mode."
    - MCP servers are configured in a user-level `mcp_config.json`; no workspace file exists.
    - Workspace rules under `.devin/rules` or `.windsurf/rules` tell Cascade how to behave:
      instructions, not commands.
- Dev Containers (https://github.com/devcontainers/spec, `docs/specs/devcontainer-reference.md`):
  - `initializeCommand` runs on the host; `onCreateCommand`, `updateContentCommand`,
    `postCreateCommand`, `postStartCommand` and `postAttachCommand` run inside the container.
  - The file is `.devcontainer/devcontainer.json`, `.devcontainer.json` or
    `.devcontainer/<folder>/devcontainer.json`.
- Environment managers:
  - direnv (https://github.com/direnv/direnv, `internal/cmd/rc.go`, `man/direnv-stdlib.1.md`):
    - An `.envrc` is loaded only when allowed; the allow record is named by a hash of the file's
      path and content, so a changed file is blocked until `direnv allow` again.
    - A file `source_env` loads "is not checked by the security framework".
  - mise (https://github.com/jdx/mise, `docs/configuration.md`, `docs/paranoid.md`,
    `src/config/config_file/mod.rs`):
    - A trusted file stays trusted by path: `is_trusted` checks the content hash only when
      `settings.paranoid` is set, and `mise run`, `mise install` and `mise exec` trust their
      configuration automatically.
    - The project config files (`src/config/mod.rs`, `LOCAL_CONFIG_FILENAMES`): `mise.toml`
      and `.mise.toml`, `config.toml` under `mise/`, `.mise/` and `.config/mise/`,
      `.config/mise.toml`, each with a `.local` variant and a `.<env>` variant for `MISE_ENV`,
      `conf.d/*.toml` and `conf.d/*/mise.toml` under those three directories, and
      `.tool-versions`.
    - `[hooks] enter` runs on entering the directory.

## Decision

Protect the class through a rule file with built-in defaults, enforced at both existing
enforcement points, in the smallest grammar that names the files.

Which files a default line names:

- A default line is read-only unless a command the user runs for another purpose rewrites the
  file, the way `npm install` rewrites `package-lock.json`.
- A deliberate command that rewrites it runs on the host, as `--update` does for the agents:
  `pre-commit autoupdate`, `lefthook add`, `mise use`, `claude mcp add --scope project`,
  `/fewer-permission-prompts`, a Kiro hook made through the IDE or in chat, an OpenCode plugin
  or server entry, a Claude skill, agent or command file.
- A file whose tool approves each change of its content stays writable by default: direnv
  blocks a changed `.envrc` until `direnv allow`, so the tool itself closes the route. mise does
  so only in its paranoid mode, and VS Code's Allow and Claude Code's MCP dialog are per
  workspace, once, so their files are listed. `doc/file-rule-example/direnv/rule` lists
  `.envrc` for a user who approves by reflex.
- Editors are assumed to run on the host; a project running one in the sandbox adds a
  `writable` line.

What the list does not close, stated in SECURITY.md beside the protection:

- a file a protected configuration names, which stays writable:
  - a project script that a VS Code task, a git hook or `initializeCommand` runs, such as
    `scripts/build.sh`;
  - a `package.json` script that a task runs through `npm run`;
  - a second `.envrc` that a read-only `.envrc` loads through `source_env`, which direnv does
    not check;
- an editor extension or import that evaluates a project file on open or save: a Gradle or sbt
  import, rust-analyzer's `build.rs`, an ESLint configuration;
- every build file or script the user runs.

Those stay "review the diff first" (SECURITY.md, "The project directory"):

- The list keeps a session from adding a command to an event or changing one a non-project
  file names: it cannot add a `runOn: folderOpen` task to `.vscode/tasks.json`, or point a
  `repo: local` entry of `.pre-commit-config.yaml` at a script of its own.
- A project whose event configuration already runs project code gains nothing for that event:
  when a folder-open task runs `npm run build`, the session edits the `build` script in
  `package.json`, and the task runs the edit on the next open as it did before.
- The host's Claude Code asks before starting a project MCP server, once per project, so the
  `.mcp.json` line defends a changed server after that answer. A user who answers direnv's
  "`.envrc` is blocked. Run `direnv allow` to approve its content" without reading the diff is
  who the example's line protects.

### The rule file

`.ko-agent-sandbox/file/rule`, one line per rule, comments and blank lines as in `egress/rule`:

    readonly NAME
    writable NAME

The name:

- `NAME` is a basename, or `/`-separated components for a file a tool reads under a fixed
  directory (`mise/config.toml`, `.config/mise/config.toml`).
- `*` matches any run of characters within one component; nothing else is a wildcard.
- Lowercase ASCII only; the filter folds the entry's name as it folds `.git`, so `.VSCODE` and
  `.vscode.` are `.vscode`.
- A name matches at any depth, as `.git` does: direnv and mise read the directory entered, an
  editor the folder opened, and a launch from a subdirectory takes that subdirectory's files.

The decision for an entry:

- The defaults apply first, then the file's lines in order.
- The deciding line is the last line whose name matches the entry or one of its ancestors, and
  its word decides:
  - `readonly .vscode` then `writable .vscode/settings.json` leaves that one file writable;
  - the reverse order makes it read-only;
  - `readonly *.code-workspace` then `writable demo.code-workspace` frees that file.
- The model is `egress/rule`'s: ordered lines over defaults, the last applicable one deciding.
  It differs in carrying one bit instead of grant words, and in letting `readonly` name a path,
  since the filter, not an origin, is the authority on how a name reads (SECURITY.md, "Adding
  hosts, not patterns").
- Both enforcement points implement this one contract, and one table of rule file, path and
  expected answer is checked against both.
- `writable` exists so a project whose agent maintains a listed file, or that runs an editor in
  the sandbox, can say so in a reviewed, committed line. The launch prints every default the
  file makes writable, as it prints an egress widening.

Every ambiguity refuses the launch:

- an unknown word;
- a leading or trailing `/`, an empty component, `.`, `..`;
- an uppercase or non-ASCII character;
- a `#` inside a token;
- a file with no lines;
- a `writable` naming `.git` or `.ko-agent-sandbox`.

The launcher parses and resolves; the filter and the profile receive the resolved list and no
grammar.

The defaults:

    # Files through which a session could inject a command that a program on your host runs when
    # you start an agent in the project, commit, open it in an editor, cd into it, or reopen it
    # in a Dev Container, whose initializeCommand runs on the host. A session cannot change these
    # files. Build files, scripts and package.json stay writable, because you run those yourself.
    #
    # A file is listed only if no command you run for another purpose rewrites it, the way
    # `npm install` rewrites package-lock.json, and only if its program does not ask you again
    # when the file changes, as direnv does (doc/file-rule-example/direnv/rule has its line).
    # When a command exists to change a listed file, such as `pre-commit autoupdate` or
    # `mise use`, run it on the host, as you run `--update` for the agents. Editors are assumed
    # to run on the host. If one runs in the sandbox, add `writable` lines for its files to
    # .ko-agent-sandbox/file/rule.

    # Agents on the host: hooks, plugins and servers their project files name. In a session
    # Claude Code's project hooks are inert (allowManagedHooksOnly). `claude mcp add --scope
    # project`, /fewer-permission-prompts, a Claude skill, agent or command file, a Kiro hook or
    # agent made through the IDE or in chat, and an OpenCode plugin or server entry are added on
    # the host; the host's Claude Code asks before starting a project MCP server. A project whose
    # sandboxed agent maintains its skills adds `writable .claude/skills`.
    readonly .claude/settings.json
    readonly .claude/settings.local.json
    readonly .claude/skills               # Claude Code: frontmatter hooks, registered on invocation
    readonly .claude/agents               # Claude Code: the same, while the subagent runs
    readonly .claude/commands             # Claude Code: the same
    readonly .mcp.json
    readonly .kiro/hooks                  # Kiro: run on file and session events
    readonly .kiro/agents                 # Kiro: hooks and MCP commands, hot-reloaded on save
    readonly .kiro/settings/mcp.json      # Kiro: workspace MCP servers, hot-reloaded on save
    readonly .opencode/plugins            # OpenCode: loaded at startup
    readonly .opencode/plugin             # OpenCode: the same, singular
    readonly opencode.json                # OpenCode: plugin and mcp keys
    readonly opencode.jsonc

    # Git hook managers: the installed hook dispatches through worktree configuration.
    # `pre-commit autoupdate`, `lefthook add` and `husky init` run on the host.
    readonly .husky                   # husky's dispatcher runs .husky/<hook>
    readonly .pre-commit-config.yaml
    readonly lefthook.*
    readonly .lefthook.*
    readonly lefthook-local.*
    readonly .lefthook-local.*

    # Editors: opened-folder configuration a trusted workspace executes
    readonly .vscode              # VS Code: tasks, launch, settings naming executables
    readonly *.code-workspace     # VS Code: the same, in a workspace file
    readonly .vs                  # Visual Studio: tasks.vs.json, launch.vs.json, uncommitted
    readonly tasks.vs.json        # Visual Studio: kept outside .vs, at the root or in a subfolder
    readonly launch.vs.json       # Visual Studio: kept outside .vs, at the root
    readonly .idea                # IntelliJ IDEA: run configurations, startup tasks, watchers
    readonly .cursor/hooks.json   # Cursor: agent-event hooks; .cursor/rules stays writable
    readonly .cursor/mcp.json     # Cursor: project MCP servers
    readonly .windsurf/hooks.json # Windsurf: agent-event hooks; .windsurf/rules stays writable
    readonly .devin/hooks.json    # Windsurf as Devin Desktop: the same, preferred location
    readonly .zed                 # Zed: tasks.json hooks, settings.json formatter on save

    # Dev Containers: initializeCommand runs on the host
    readonly .devcontainer
    readonly .devcontainer.json

    # mise: [hooks] enter runs on entering the directory, and a trusted file stays trusted by
    # path unless mise runs in paranoid mode. `mise use` and `mise set` run on the host. The
    # three directories are listed whole for their conf.d fragments; .tool-versions names
    # versions only and stays writable.
    readonly mise.toml
    readonly .mise.toml
    readonly mise.*.toml
    readonly .mise.*.toml
    readonly mise
    readonly .mise
    readonly .config/mise
    readonly .config/mise.toml
    readonly .config/mise.*.toml

- `.config/lefthook.*` is covered by `lefthook.*` at any depth.
- `CLAUDE.md`, `.cursor/rules` and the other instruction files stay writable: a model reads
  them, no host program runs them. A Claude skill, agent or command file can declare hooks, so
  those three directories are listed.

`doc/file-rule-example/*/rule` holds complete files for common needs, one per need, as
`doc/egress-rule-example/` does. The first, `direnv/rule`:

    # direnv loads the shell environment a project's .envrc defines whenever you enter the
    # directory, once you have allowed that file.
    #
    # - direnv blocks a changed .envrc until `direnv allow`, so the defaults leave it writable.
    # - This .ko-agent-sandbox/file/rule is for a project whose users approve a changed .envrc by
    #   reflex: the line makes the sandbox unable to change it at all.
    readonly .envrc

### Enforcement

The filter:

- The mount script writes the parsed rule lines to `readonly-set` in the project's mount
  directory, beside `source-id`, and names it with `--readonly-set` when it starts
  `ko-agent-fs`; the daemon adds what its guard finds, writes the full set back to that file,
  and compiles it into a trie over components.
- An ordinary directory's context carries the set of trie nodes its ancestry matched and the
  index of its deciding line.
- A child's context is those nodes advanced by its folded name plus the root; its deciding line
  is the highest index among the inherited one and the lines ending at this child.
- So a name matches at any depth, a later line overrides an earlier one below a read-only
  entry, and no inode stores a path.
- Creating a read-only name is refused as creating `.git` is, since a symlink or directory
  planted at the name would be what the host program reads next.

Pinned ancestors:

- `readonly .claude/settings.json` protects `settings.json` only while its parent directory is
  named `.claude`, since the filter classifies an entry from its parent's name at lookup. Without
  the pinning below, two attacks would defeat it: rename `.claude` to `saved`, write
  `saved/settings.json`, rename it back; or fill `staged/` and rename it to `.claude`.
- Every interior component of a resolved name, and of a relocated hook directory's path, is
  therefore pinned:
  - the name can be created only by `mkdir`, never as a rename or exchange destination, a
    symlink, a link or a `mknod`;
  - an entry bearing it cannot be renamed, exchanged, unlinked or replaced, and `rmdir` removes
    it only empty;
  - its other children stay writable.
- The rename and exchange cases are test rows for both enforcement points.

Relocated hooks:

- The mount-time guard, which refuses a `hooksPath` or a `.git/hooks` symlink resolving to
  writable worktree data, instead reports each such directory as a read-only root of the same
  set, and the launch prints it.
- An undecidable config still refuses: a `~`, an `include`, a backslash, an unterminated quote,
  non-UTF-8.
- `git-metadata.md`, "Relocated hook directories", changes from refusing to serving read-only,
  and "Why refusing rather than resolving" records that the second protected root is paid for
  by the rule file. The snapshot window and the nested-repository gap stay as written.
- Husky's dispatcher in `.husky/_` runs `.husky/<hook>`, which the read-only hook directory does
  not cover; the default `readonly .husky` does, and the measurement under "Work" says what
  `npm install` then does.

Redirections below a listed directory:

- Without the walk below, a host-created symlink `.vscode/tasks.json -> ../tasks-data.json`
  would leave `tasks-data.json`, the file VS Code reads through the link, writable under its
  own name at the project root; Seatbelt too matches the resolved path, so a deny on the
  `.vscode` spelling would not reach it.
- The guard walks each listed entry at the workspace root recursively, with the depth bound its
  walk under `.git/modules` has (`guard.rs`, `collect_gitdir_roots`), and resolves every symlink
  one component at a time with the hop bound `resolve_checked` has.
- The file the chain ends at, `tasks-data.json` here, becomes read-only as if a line named it.
- Every in-workspace component the chain traverses is pinned as an ancestor is: a directory,
  or a symlink node such as `alias` in `.vscode/tasks.json -> ../alias/tasks.json`,
  `alias -> data`. A symlink is replaced only by unlinking and recreating it, and both are
  refused. Resolving to the final file alone would lose the chain (`git-metadata.md`, "The
  binding rule").
- Resolution follows a chain out of the workspace as `resolve_checked` does, and a link
  pointing back in re-enters the rule: `.vscode/tasks.json -> /outside/back.json ->
  <project>/payload.json` makes `payload.json` read-only and pins the components re-entered,
  since the session writes the payload under its own name without touching the external link.
- Through a podman machine the daemon cannot verify a component outside the workspace: the
  path can be absent in the machine, or present as a different object, while the host follows
  it back into the workspace.
  - On macOS and Windows a chain that leaves the workspace therefore refuses the launch, naming
    the link and asking for a real file or directory in its place: for listed entries and for
    the hook walk alike, a `core.hooksPath` outside the workspace included.
  - On native Linux the daemon shares the host's namespace and follows such a chain as the host
    does; a chain that ends outside adds nothing.
  - The launcher tells the daemon which case holds, beside the rule lines in `readonly-set`.
- The chained case, the re-entering case and a chain leaving the workspace, refused under the
  machine setting and followed under the shared one, are test rows for both enforcement points,
  beside the guard's existing row for an external hooks directory that links back into the
  workspace (`guard.rs`).
- Below the root it is the gap SECURITY.md records for nested repositories.

Second names:

- `policy_name` stats the two fixed names beside every ordinary entry, unchanged.
- The list's names are stat'ed only when the looked-up name contains `~`, which every NTFS 8.3
  short name does.
- A host-created hard link to a listed file under another name is host setup, the residual
  `git-metadata.md` records for hooks.

One resolver:

- The resolved set is the rule lines, the relocated hook directories, the files symlink chains
  end at, and every pinned component. The filter binary's guard computes it, in the daemon at
  mount or standalone as `ko-agent-fs --resolve`, which prints it as one list.
- Under `--write=live` the daemon's own computation at mount is the run: the launcher reads
  the full set from the mount script's output, which it already waits for, so the common path
  starts no extra process.
- Under `--write=reject` with `--run-on-host`, where no daemon exists while host commands still
  write the project, the launch runs `--resolve` through the channel `--version` uses, started
  beside the proxy's ruleset dry run and read when the profile is built, so its round trip
  through the podman machine is hidden inside that longer step. This holds for the jar and the
  native image alike.
- Under `--write=reject` without `--run-on-host` the tree is read-only and nothing runs.

One mount per project, shared by its concurrent sessions:

- `readonly-set` has the mount's lifetime, as `source-id` has: a fresh mount overwrites it
  before the daemon starts, the last session's reap leaves it stale with the rest of the mount
  directory, and `--reset` removes the directory. Nothing reads it except the mount script.
- The mount script's reuse branch, which compares `source-id` before reusing a live mount,
  compares the rule lines too: the same, the launch joins the mount; different, the launch is
  refused, naming the running session, and runs again after that session ends.
- Every session on the mount runs under the set the first mount resolved. What the guard added
  is that mount's snapshot, the window SECURITY.md records for relocated hooks.

`--run-on-host`:

- The profile takes the resolved set after its allows and before its last two rules, the denies
  of `.git` and `.ko-agent-sandbox` at any depth, so that under last-match-wins a `writable`
  line can override a `readonly` line and never those two:
  - the lines in their order, each `readonly` a deny of writes and links and each `writable`
    the matching allow, every name anchored at any depth;
  - the hook directories and the files symlink chains end at, as denies by resolved path;
  - the pinned components as denies of rename, link and unlink.
- Reads stay allowed.
- Under SBPL's last-match-wins this is the same contract the filter implements.
- The profile's own denies name `.git` alone, which under `--write=reject` leaves a host
  command free to write a relocated hook directory the filter's guard would refuse to serve;
  the resolved set closes that in both modes.

### Documentation

- SECURITY.md:
  - a Defended bullet, "A host program executing a project file on an event that is not a run
    of the project", listing the defaults' tools and both enforcement points;
  - "The project directory" keeps build files, scripts and editor extensions under "review the
    diff";
  - "A project loosening its own confinement" names `file/rule` beside `egress/rule`.
- `design.md`: a standing decision, "No path patterns in the file rules", with the fold, the
  O(1) classification and "No richer rule format" as the reasons.
- README reference, `egress-proxy.md`'s boundary-directory list and its pointer to the
  examples, which gains `doc/file-rule-example/`, `run-on-host.md`'s profile rules,
  `git-metadata.md`'s immutable set and its binding rule, where "hooks kept outside it are
  unreachable through the mount" and "only NotFound means absent" hold on native Linux alone,
  a chain leaving the workspace being refused through a podman machine.
- AGENTS-SANDBOX.md's refused operations, which point agents at the appended section listing the
  resolved read-only names and saying that a command rewriting one runs on the host.

## Work

One change, in this order:

1. The launcher:
   - the grammar and resolver, with the refusals tested as `EgressRulesTest` tests the egress
     file;
   - the defaults file, and `doc/file-rule-example/direnv/rule`;
   - the launch print;
   - `file` in `BoundaryDirEntries`;
   - the conformance table of rule file, path and expected answer, which items 2 and 3 both
     check.
2. The filter:
   - the guard's walks, in the daemon and as `--resolve`;
   - the trie, the deciding-line contexts and the pinned components;
   - the `~` alias check;
   - the relocated hook directories and the symlink chains below listed root entries, with the
     refusal of a chain leaving the workspace through a podman machine, for hooks too;
   - the different-rule-lines refusal between launches;
   - unit rows in `policy.rs` and `guard.rs`;
   - mounted rows beside the `.ko-agent-sandbox` rows in `tests/mounted_mutate.rs`: the rename
     and exchange of a pinned ancestor, a staged directory renamed onto a pinned name, a chained
     symlink's intermediate link replaced, a chain re-entering the workspace from outside, a
     chain leaving the workspace under each namespace setting, a `writable` line below a
     read-only entry;
   - the relocated-hooks row turned from a mount refusal into a write refusal at the hook path;
   - the Windows self-test row for a listed name's 8.3 spelling, recorded in
     `verification-log.md`.
3. The Seatbelt lines and their acceptance rows, the conformance table and the chained symlink
   among them, under `--write=live` and under `--write=reject` with `--run-on-host`.
4. The husky measurement: `npm install` in a session on a husky project, with `.husky` read-only
   and `.husky/_` a read-only hook directory.
   - `husky` returns git's error when its `git config core.hooksPath` is refused, which the
     protected `.git/config` refuses, so the record says what npm does with that and whether
     the read-only set changes it.
   - A failing `npm install` is stated beside the default line as its cost.
5. The documentation above.

## Deliberate exclusions

- Build files, scripts, `package.json`, `Makefile`, `.cargo/config.toml`: the user runs them.
- CI definitions (`.github/workflows`): executed by the forge, not the host.
- The commands `devcontainer.json` runs inside the container, `onCreateCommand` through
  `postAttachCommand`: what they can reach is the dev container's, which the user builds from
  the project's own configuration, as the sandbox's container is. `.devcontainer` is listed for
  `initializeCommand` alone, and stays listed whole because one file holds both.
- Editor extensions that evaluate project files on open or save: no list of names closes them.
- Instruction files a model reads (`CLAUDE.md`, `.cursor/rules`, `.windsurf/rules`,
  `.devin/rules`, `.kiro/steering`): no host program runs them.
- gitignore syntax, negation and anchoring: `design.md`, "No richer rule format". A name
  matches at any depth, so anchoring has nothing to express.

## Sources

- https://github.com/microsoft/vscode-docs (`docs/editing/workspaces/workspace-trust.md`,
  `docs/debugtest/tasks.md`)
- https://github.com/direnv/direnv (`internal/cmd/rc.go`, `man/direnv-stdlib.1.md`)
- https://github.com/jdx/mise (`docs/configuration.md`, `docs/paranoid.md`,
  `src/config/config_file/mod.rs`, `src/config/mod.rs`)
- https://github.com/evilmartians/lefthook (`docs/configuration.md`)
- https://github.com/devcontainers/spec (`docs/specs/devcontainer-reference.md`)
- https://github.com/typicode/husky (`index.js`, `husky`)
- https://github.com/pre-commit/pre-commit.com (`sections/usage.md`, `sections/advanced.md`,
  `sections/cli.md`)
- https://learn.microsoft.com/en-us/visualstudio/ide/customize-build-and-debug-tasks-in-visual-studio
- https://github.com/zed-industries/zed (`docs/src/tasks.md`, `docs/src/configuring-zed.md`,
  `docs/src/configuring-languages.md`)
- https://www.jetbrains.com/help/idea/ (`settings-tools-startup-tasks.html`,
  `using-file-watchers.html`, `run-debug-configuration.html`, `project-security.html`)
- https://cursor.com/docs/agent/hooks, https://cursor.com/docs/context/mcp,
  https://cursor.com/docs/context/rules
- https://docs.devin.ai/desktop/cascade/hooks, https://docs.devin.ai/desktop/cascade/mcp,
  https://docs.devin.ai/desktop/cascade/memories
- https://kiro.dev/docs/hooks/, https://kiro.dev/docs/custom-agents/,
  https://kiro.dev/docs/custom-agents/configuration-reference/, https://kiro.dev/docs/mcp/configuration/
- https://opencode.ai/docs/plugins/, https://opencode.ai/docs/config/,
  https://opencode.ai/docs/mcp-servers/; https://github.com/anomalyco/opencode
  (`packages/opencode/src/config/plugin.ts`)
- https://code.claude.com/docs/en/hooks ("Hooks in skills and agents")
