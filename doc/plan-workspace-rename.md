# Plan: call the mounted directory the workspace, and select its mode with `--workspace`

The directory tree the launcher exposes to the sandbox is the **workspace**. The launch option that
selects how the sandbox's writes reach it is

```text
--workspace=read-only|live|staged
```

`read-only` replaces `--write=reject`; `live` stays the default; `staged` arrives with
`plan-staged.md`. `--write` and the value `reject` disappear: the launcher is unreleased, so no
alias and no deprecation text.

## Why these words

- **Workspace** is what the tools around the launcher call the directory a tool opens and acts in.
  Measured from the installed agents' `--help`: Codex names `--sandbox read-only|workspace-write`
  and "the primary workspace"; Antigravity's `--add-dir` adds "a directory to the workspace", while
  its `--project` is a cloud project ID. VS Code's documentation calls the folder a workspace and
  the feature Workspace Trust.
- **`--workspace=<mode>`**, like `--egress=` and `--clipboard=`, names the thing and takes its mode.
  The later option that adds directories to the workspace is `--add-dir` (doc/TODO.md), the
  spelling Claude Code, Codex, Antigravity and Copilot use in their help text, so `--workspace`
  keeps one meaning and never takes a path: the workspace root is the current directory.
- `--write=read-only` contradicts itself, and `--project=` collides with Antigravity's option.
- The value series names where writes land, or that they land nowhere: `read-only`, `live`,
  `staged`. `reject` names a verdict instead.

## Vocabulary after the rename

- **workspace**: the host directory tree the launcher exposes. Today one directory; later that
  directory plus the added ones.
- **workspace root**: the directory the launcher starts in. It is mounted at its own path, holds
  `.ko-agent-sandbox`, and its path identifies the workspace: id, hash, state directory, trust
  entries.
- **workspace mode**: how the sandbox's writes reach the workspace. Today "write mode" in most
  places; README's launch-output paragraph and the "workspace filter" sentences already say
  workspace.
- **project**: another system's concept: sbt's `project/`, a Gradle multi-project build, a
  JetBrains project, the agents' `projects` keys.

Rule for the word "project": replace it where it denotes the directory the launcher selects; keep it
where it names another system's concept. The agents' own names stay: Claude's `.projects` key and
`~/.claude/projects`, Codex's `[projects."…"]` table, and the `trustedWorkspaces` and
`trustedFolders` lists in `ko-sandbox-entrypoint`. Git's superproject, repository and working tree
stay git's: a workspace may hold one or more projects or repositories, or none, and the launcher
selects its boundary rather than inferring it from a build or a repository.

Where a sentence describes a workspace that is a build, as in "the workspace's `./mill`", use
workspace: the build tool's project is the thing inside it.

## Steps, one commit each

The working tree holds an uncommitted README edit (the run-on-host sub-item removed, the help text's
pointer to "Program prerequisites"). Commit or set it aside first so each step below is one diff.

1. **Documents.** Apply the rule across `README.md`, `SECURITY.md`, `doc/`, `fuse/ko-agent-fs/doc/`
   and `container/ko-agent-sandbox/AGENTS-SANDBOX.md`. The single directory is "the workspace
   root" where its path matters and "the workspace" otherwise. Renamed headings and the places
   that cite them by title:
   - SECURITY.md "Why the rules are per project, in the project, and read-only"
   - doc/file-rules.md "Project files a host program executes", which `SeatbeltProfile.scala` also
     writes as a comment into the profile, and "One mount per project", cited from
     `src/main/scala/KoAgentFs.scala`
   - doc/TODO.md "A FIFO in the project hangs the podman machine", "The project mounted at its own
     path"
   - fuse/ko-agent-fs/doc/git-metadata.md "Consequences: git operations blocked inside the project"
   - fuse/ko-agent-fs/doc/troubleshooting.md "The project mount is empty inside the container"

   Run `ko-sandbox-markdown-link-check`, and `rg` for each old title in quotes across `src`,
   `fuse` and `container`. `fuse/ko-agent-fs/src/fs.rs` cites SECURITY.md "The project
   directory", a heading SECURITY.md does not have; its symlink-target sentences sit under "Not
   defended", so point the comment there.
2. **Code identifiers and user-facing strings.** `SandboxProject` becomes `SandboxWorkspace`, with
   its file and test file; `projectDir` becomes `workspaceRoot`; `projectId`, `projectIdOf`,
   `projectHash`, `isForbiddenProjectDir`, `cacheRootOutsideProject`, `LaunchProject`,
   `ProjectUsage` and the rest of the family follow. Strings: the `--stats` "project" column and
   count, "refused as a project", "the working directory … is not inside the project", the
   launcher's header diagram, and the `project` shell variable in `ko-sandbox-entrypoint`, whose
   jq and TOML keys stay the agents' own. Rust: comments only, plus the test names
   `ordinary_project_work_is_unaffected` and `…_for_the_project_under_file_rules`. The run-on-host
   code keeps `project` where it means sbt's `project/target/active.json`.
3. **Persisted names stay.** `<state root>/projects/` and the run-on-host records file `project`
   keep their on-disk names: state written under them must stay visible to `--stats` and
   `--reset`, and a rename would need a migration. `LauncherState.projectsStateRoot` becomes
   `workspacesStateRoot` and still resolves `"projects"`, with that reason as its comment;
   `RunOnHostSession.ProjectFile` becomes `WorkspaceFile = "project"` and refers to it.
4. **The option.** In `CommandLine.scala`, `WriteModes` becomes `WorkspaceModes =
   Vector("read-only", "live")`, parsed from `--workspace=`. `ParsedCommandLine` keeps its two
   members apart: `write: Option[String]`, the option as given, becomes `workspace`, and the
   resolved `writeMode` becomes `workspaceMode`, with `DefaultWriteMode` becoming
   `DefaultWorkspaceMode`; the launcher's `"--write" -> parsed.write.isDefined` row, which refuses
   session options on management actions, follows. Then every text that spells `--write=`:
   - the usage text and its test ("--help covers … write modes"), and the SELinux refusal
     "`--write=reject` cannot mount …" in `AgentSandboxLauncher.scala`. The usage text says
     `read-only` is read-only to the sandbox's processes; the run-on-host entry keeps its sentence
     that host commands write the workspace even then
   - `LaunchMessages.scala`: the appended section's "gives its write mode", the read-only wording,
     and the run-on-host lines that say a host command writes under the read-only mode, with their
     test in `AgentSandboxLauncherTest`; `AGENTS-SANDBOX.md` line "names the project directory
     and gives its write mode"
   - tests: `AgentSandboxLauncherTest` (run-on-host lines, `renderArgument`, usage, appended
     section, `agentDocumentStamp`, `parseCommandLine`), `MountPathTest`, `SessionBoundaryTest`
   - documents: `README.md`, `SECURITY.md`, `doc/design.md`, `doc/egress-proxy.md`,
     `doc/file-rules.md`, `doc/run-on-host.md`, `doc/TODO.md`, the `doc/plan-*.md` files,
     `fuse/ko-agent-fs/doc/architecture.md` and `fuse/ko-agent-fs/doc/TODO.md`,
     `fuse/ko-agent-fs/probe/apfs-name-rule-probe.py`
   - `doc/plan-staged.md` in particular: `--write=staged` and `--write=reject` become
     `--workspace=staged` and `--workspace=read-only`, and its default-flip sentence names
     `read-only`. The default stays `live` until that plan's milestone
   - the phrase "write mode" everywhere becomes "workspace mode"; prose that already says
     "read-only" stays.

## Verification

- `rg -w -i project` over the repository, minus `.git`, leaves only lines the rule keeps. Read each
  remaining line rather than trusting the match.
- `rg -- '--write|writeMode|WriteModes|write mode'` finds nothing.
- `ko-sandbox-text-width --over 100` on the documents and `--over 120` on code and configuration.
- `ko-sandbox-markdown-link-check`.
- `ko-sandbox-run-on-host sbt test` on macOS; the Rust change is comments and test names, so
  `cargo test` in `fuse/ko-agent-fs` only if a test name changed.
- One launch each of `--workspace=read-only` and `--workspace=live`, reading the appended section
  and the start prompt for the new words, and `--stats` against state written before the rename.

## Deliberate exclusions

- No `--write` alias: unreleased.
- `.ko-agent-sandbox` keeps its name: it names the sandbox, not the directory it configures.
- Agents' trust keys and Claude's `~/.claude/projects` keep their names: they are the agents'.
- On-disk state names stay (step 3).
- Staged mode's own wording, among it that a stage is not Git's index, and what identifies a stage
  when one repository is launched from two roots, belong to `plan-staged.md`.
- Jujutsu's `.jj` metadata is separate work; this rename adds no name or assumption that equates
  the workspace root with a repository root.

## Decisions left open

- `SandboxWorkspace` versus `Workspace` for the class. Default: `SandboxWorkspace`, keeping the
  pairing with `SandboxStats` and `SandboxEntrypointTest`.
