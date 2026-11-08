# Plan: pi in the sandbox

pi (https://pi.dev, Earendil Works) is a Node.js agent harness with no fixed model provider. This
plan adds pi as the seventh preinstalled agent, launched as
`java -jar ko-agent-sandbox.jar --model-provider=<names> pi`.

The requirement: pi runs under the boundary the other agents have.

- pi's state lives in the persistent volume.
- The workspace is trusted without a prompt.
- No tool-approval prompt appears.
- pi's network reaches the selected providers, the proxy's host catalog, and nothing else.

The facts below were read on 2026-10-18 from three sources: the pi.dev documentation
(`/docs/latest`), the npm registry entry of `@earendil-works/pi-coding-agent` 1.3.0, and the
source on the `main` branch of https://github.com/earendil-works/pi. The install measurements are
under "Decisions". Nothing else is measured yet, and "Tests" lists each check.

## What is read

### Program

- The npm package `@earendil-works/pi-coding-agent` installs the `pi` command
  (`dist/bundle/cli.js`). The package requires Node.js 22.19.0 or newer, and the image has Node 26.
- pi's own container example installs pi with `npm install -g --ignore-scripts`.
  - The 1.3.0 tarball on the registry carries no `npm-shrinkwrap.json` (the tarball's file list,
    and the registry's `_hasShrinkwrap` flag). So that install resolves every dependency range from
    the registry.
- pi's installer API at `https://pi.dev/api/installer/releases` serves two kinds of answer:
  - `latest`: a metadata object naming the version, its packages, their tarballs and their sha512
    integrity;
  - per version: a `package.json` that depends on that one version, and a `package-lock.json` of
    the version's whole tree, 120 packages for 1.3.0.
- The managed install of `install.sh` downloads those two files and runs
  `npm ci --ignore-scripts --min-release-age=0 --omit=dev --include=optional` in a staging
  directory. The script's comment on the option: "Pi publishes npm-shrinkwrap.json, so the
  explicit installer/reinstaller can bypass npm's release-age gate without reopening transitive
  dependency ranges".
- `install.sh` installs Node.js through a package manager and pi into `~/.pi/agent/install`, then
  edits the shell profile. The script is not for the image.
- pi has no system-wide configuration layer. Settings come from the agent directory and the
  workspace's `.pi/`, and switches come from environment variables.

### State

- The agent directory, `~/.pi/agent` (`PI_CODING_AGENT_DIR`), holds everything that must persist:
  `auth.json` (API keys and OAuth tokens), `settings.json`, `models.json`, `mcp.json`,
  `trust.json`, `sessions/` grouped by working directory, and the user's extensions, skills,
  prompts, themes and packages.
- `pi --continue` opens the most recent session of the working directory, and `--resume` opens the
  picker.
- Shell commands that pi runs receive `PI_PROVIDER`, `PI_MODEL` and `PI_SESSION_FILE`. The process
  markers `AI_AGENT=pi` and `PI_CODING_AGENT=true` reach every child.

### Workspace files and trust

pi calls the workspace "the project". This document uses the sandbox's word.

- `.pi/` in the workspace holds `settings.json`, `mcp.json`, `SYSTEM.md`, `APPEND_SYSTEM.md`,
  `extensions/`, `skills/`, `prompts/` and `themes/`.
  - Extensions are TypeScript modules that run inside pi's process.
  - `settings.json` names packages that pi installs from npm or git.
  - pi also reads `.agents/skills` in the workspace or an ancestor.
- Any of those files triggers a trust decision. pi takes the first answer that this list gives:
  - `--approve` or `--no-approve` on the command line;
  - an extension;
  - `<agent-dir>/trust.json`, a JSON object from canonical directory path to `true`, `false` or
    `null` (`core/trust-manager.ts`);
  - the `defaultProjectTrust` setting, `"ask"` by default.

  Print and RPC modes cannot ask, so they skip the resources.
- A skill is a `SKILL.md` with supporting files, which "can instruct the model to run scripts"
  (`/docs/latest/skills`). Prompt templates are Markdown "without adding executable behavior"
  (`/docs/latest/prompt-templates`). Neither runs a command on its own.
- `AGENTS.md`, `AGENTS.override.md` and `CLAUDE.md` load from the agent directory, the working
  directory and its parents, whether the workspace is trusted or not.
- pi asks for no approval before tool calls: "it does not ask for approval before every tool call"
  (`/docs/latest/security`). So there is no prompt to turn off and none to restore. The
  repository's `examples/extensions/permission-gate.ts` adds such a prompt.

### Network

Besides model traffic, pi contacts these hosts. Each item names what stops the contact.

- The latest-version check at start, a GET of `pi.dev/api/latest-version`.
  `PI_SKIP_VERSION_CHECK` stops it (`utils/version-check.ts`).
- The model catalog refresh, at an interval: GETs of `pi.dev`. `PI_OFFLINE` stops both the refresh
  and the version check (`core/remote-catalog-provider.ts`, `main.ts`).
- An `HTTP-Referer: https://pi.dev` header on provider requests, and install and update telemetry,
  whose host is not read yet. `PI_TELEMETRY=0` or `enableInstallTelemetry: false` stops both
  (`core/provider-attribution.ts`, `core/telemetry.ts`).
- `/share`: a POST of a gist to `api.github.com`, or to `radius.pi.dev` when the user is signed in
  to Radius. No switch stops it.
  - The host catalog grants `read` of `api.github.com` and nothing of `radius.pi.dev`, so the proxy
    refuses both.
- `/bug`: a POST to `radius.pi.dev`, which the proxy refuses the same way.
- `pi install npm:…` and `git:…`: `registry.npmjs.org` and `github.com`, which the host catalog
  allows. The image's `min-release-age=7` applies to the npm source.

pi honors `HTTPS_PROXY` (`/docs/latest/environment-variables`; `utils/node-http-proxy.ts`). Node
trusts the proxy CA through the `NODE_EXTRA_CA_CERTS` that the launcher sets
(`AgentSandboxLauncher.scala`, the CA variables). So the inspected `pi.dev` reads work.

### Providers against the proxy's rules

Each item gives a pi provider id and its hosts, from `packages/ai/src/providers/*.ts` and
`packages/ai/src/auth/oauth/*.ts`. Each item then says whether the proxy's
`defaults/model-provider/` file of the same selection allows those hosts.

- `anthropic`: `api.anthropic.com`, with OAuth at `claude.ai/oauth/authorize` and
  `platform.claude.com/v1/oauth/token`. The `anthropic` selection allows all three.
- `openai`: `api.openai.com` with an API key. `openai-codex`: `chatgpt.com/backend-api`, with
  OAuth at `auth.openai.com`. The `openai` selection allows all three.
- `google`: `generativelanguage.googleapis.com` with an API key, and pi has no Google OAuth. The
  `google` selection allows it.
- `google-vertex`: `aiplatform.googleapis.com`, and `oauth2.googleapis.com` for the credential
  refresh. The `google` selection allows the global host, not a regional one.
- `github-copilot`: `api.individual.githubcopilot.com`, with the device flow at
  `github.com/login/device/code`, `github.com/login/oauth/access_token` and
  `api.github.com/copilot_internal/v2/token`. The `github` selection allows all four. An
  enterprise's `copilot-api.<domain>` is not in it.
- `amazon-bedrock`: `bedrock-runtime.<region>.amazonaws.com` through
  `@aws-sdk/client-bedrock-runtime`. The region comes from the model's ARN, from the AWS variables,
  or else is `us-east-1` (`api/bedrock-converse-stream.ts`). The `aws` selection holds Kiro's hosts
  and allows none of these.
- pi's other providers, OpenRouter, Groq, Mistral and the rest: no selection names their hosts.

pi's OAuth flows start a localhost callback server, and also accept the redirect URL or the code
pasted back (`/docs/latest/providers`, `auth/oauth/callback-server.ts`). xAI and Copilot use
device codes. README's "Sign-in" section describes the paste-back path.

## Steps

### 1. Image

- Install pi under `/opt/pi` as root at build time, the way pi's managed installer does, for the
  newest release at least seven days old:
  1. read the package's `time` field from the registry, and pick that version;
  2. download the version's `package.json` and `package-lock.json` from the installer API into
     `/opt/pi`;
  3. run `npm ci --ignore-scripts --omit=dev --include=optional` there;
  4. put `/opt/pi/node_modules/.bin` on `PATH`, as `/opt/codex/bin` is.

  `--ignore-scripts` is pi's own instruction. The lock's integrity hashes check every tarball. So
  TLS to `pi.dev` for the lock, and the hashes for the tarballs, are the integrity boundary, as TLS
  to github.com is for Codex.
- The Containerfile comment carries the reasoning, decided in "Decisions":
  - The seven days are the window SECURITY.md keeps for a compromised release to be noticed. The
    image applies the window to pi's own version, because pi is the one program that the image
    resolves through npm.
  - The lock gives the dependency set that pi tested for that version. `npm install -g` under the
    gate would instead resolve a week-old pi against today's dependencies.
  - The builtin `min-release-age=7` stays, and it costs a locked install nothing, since `npm ci`
    installs the lock's versions without resolving (SECURITY.md, "The supply chain").
  - The route is pi's own, the managed install of https://pi.dev/install.sh, less its bypass of
    the gate. The lock makes that bypass unnecessary.
- Smoke-test `HOME=/tmp/pi-smoke pi --version`, with a throwaway HOME as for the other agents, on
  both architectures the image builds for.
  - The 1.3.0 lock names no platform-specific package. The 1.1.0 lock carries esbuild's platform
    binaries as optional packages, `linux-x64` and `linux-arm64` among them, and `npm ci` picks
    one by platform.
  - `--ignore-scripts` skips the install scripts of `@google/genai`, `protobufjs` and, in 1.1.0,
    `esbuild`. The smoke test shows that pi starts without those scripts.
- `ENV PI_SKIP_VERSION_CHECK=1`: the program is the image's, and it updates by rebuild.
  - The check would read `pi.dev` at every start, and would announce an update that `pi update`
    cannot install into the read-only `/opt`.
- `ENV PI_TELEMETRY=0`: the variable stops the attribution header and the install telemetry.
- The model catalog refresh stays on. The refresh is a `read` of `pi.dev`, which the host catalog
  allows.
- Seed `$KO_SANDBOX_VOLUME_SEED/pi/agent`, and link `~/.pi` to `persistent-volume/pi`. The agent
  directory is then `~/.pi/agent`, inside the volume. Add the link to the `chown -h` list.
- Link `$KO_SANDBOX_VOLUME_SEED/pi/agent/AGENTS.md` to `/etc/ko-agent-sandbox/AGENTS.md`, in the
  Containerfile's block of instruction-file links. pi reads the agent directory's `AGENTS.md` as
  user instructions in every working directory, as Codex reads `~/.codex/AGENTS.md`.

### 2. Entrypoint

- Record the workspace's trust with `merge_json` on `$volume/pi/agent/trust.json`, with the filter
  `. + {($workspace): true}`.
  - The key is the canonical path. The workspace is mounted at its host path, so `$workspace` is
    the canonical path.
  - Without the entry, a `.pi/` in the workspace makes pi ask.
- The entry is deliberate, as it is for the four agents whose trust the entrypoint records today:
  - the sandbox is the boundary;
  - the agents run without prompts (README, the preinstalled list);
  - the read-only default for `.pi/extensions`, `.pi/settings.json` and `.pi/mcp.json` keeps a
    session from writing what the trust would load into the next session.
- `SandboxEntrypointTest`: `pi` joins the seeded set and the trust files.

### 3. Launcher and proxy

- `EgressRules.ProviderlessAgents` gains `"pi"`. A launch that names no provider, on the command
  line or in the options file, is then refused, as an opencode launch is. `EgressRulesTest` covers
  the refusal and the warning line.
- The usage text and the first-line comment of `AgentSandboxLauncher.scala` name pi. The two
  comments that list the volume's directories gain `~/.pi`.
- The proxy's host catalog holds `allow https://pi.dev/ read # pi`. The host serves the docs, the
  version check, the model catalog and the installer API.
- Bedrock gets a selection of its own, `aws-bedrock`:
  - The name joins `RulesetHelper.ModelProviders`.
  - The file `defaults/model-provider/aws-bedrock` holds
    `allow https://bedrock-runtime.us-east-1.amazonaws.com/ tunnel`. The file's comment gives the
    reason for the one region: pi defaults to `us-east-1`.
  - Another region is a workspace's own rule line, as the `aws` file says of an Identity Center
    elsewhere. The proxy's refusal names the host.
  - `aws` stays Kiro's.
  - The credentials come from the host through `--env-aws-cred` or
    `--env=AWS_BEARER_TOKEN_BEDROCK` (`doc/cloud-credentials.md`). pi reads the same variables as
    the AWS SDK.
  - The name joins the README's lists, the usage text and `doc/egress-proxy.md`.
  - The "No default names a Bedrock host" paragraph of `doc/cloud-credentials.md` names the
    selection, and keeps the other regions as rule lines.

### 4. File rules

- `file-rule-defaults` gains `read-only .pi/extensions`, `read-only .pi/settings.json` and
  `read-only .pi/mcp.json`. `doc/file-rules.md`, "Why these files", gains pi's paragraph:
  - extensions run in the process;
  - `settings.json` names extension paths and installs packages;
  - `mcp.json` names commands;
  - a trust prompt exists, and the entrypoint answers it.
- `.pi/skills`, `.pi/prompts`, `.pi/SYSTEM.md`, `.pi/APPEND_SYSTEM.md`, `.pi/themes` and
  `.agents/skills` stay writable, as `AGENTS.md` is. These directories hold text the model reads,
  and no program runs a command from them ("Decisions" has the condition and its check).

### 5. Documentation

- README:
  - the preinstalled list (`[pi](https://pi.dev) (multiple providers)`);
  - the `--model-provider` paragraph ("`opencode` and `pi` have no fixed provider");
  - the resume arguments (`pi --continue`);
  - the usage text;
  - a `#### pi` section: launch with the option; `/login` for an OAuth or API-key provider; paste
    the redirect URL back; Bedrock through `--model-provider=aws-bedrock` with forwarded
    credentials; `/share` and `/bug` are refused.
- `doc/egress-proxy.md`: the providerless sentence.
- `AGENTS-SANDBOX.md`: the list of paths into the volume.
- `doc/agent-settings.md`: pi reads `AGENTS.md`. "Restoring permission prompts" says pi has none to
  restore, and names the example extension.
- `doc/TODO.md`: the agents measured under the seccomp profile.
- Check every other mention of `opencode` in the documents for whether pi joins it.
- SECURITY.md names no agent in "What the persistent volume holds" or in the provider text. So
  pi's `auth.json` and selection need no sentence there.

## Tests

- The image builds, and `pi --version` runs in the smoke test.
- Under `--model-provider=anthropic`:
  - `pi` starts;
  - the model catalog refresh succeeds through the proxy, with no TLS error in the log;
  - `/login anthropic` with a pasted code reaches `claude.ai` and `platform.claude.com`;
  - a prompt reaches `api.anthropic.com`;
  - `/share` is refused;
  - a second launch with `pi --continue` finds the session.
- With a `.pi/settings.json` in the workspace, no trust prompt appears, and the setting applies.
- `pi -p "..."` runs under `--model-provider=openai`, with `OPENAI_API_KEY` passed through
  `--env`.
- `pi` without the option is refused, with the message naming `--model-provider`.
- The two new grants, each checked through `ko-sandbox-egress-check` and the proxy's log:
  - a GET of `pi.dev` succeeds, and a POST to `pi.dev` is refused;
  - under `--model-provider=aws-bedrock`, `bedrock-runtime.us-east-1.amazonaws.com` tunnels, and
    `bedrock-runtime.ap-northeast-1.amazonaws.com` is refused;
  - under `aws` alone, both are refused.

  `AgentEgressProxyTest` already checks that the provider names and the files under
  `defaults/model-provider/` match.
- `pi` starts under the seccomp profile (`doc/TODO.md`'s list).
- In fullscreen mode, in the terminals that `doc/plan-clipboard.md` lists: whether the conversation
  stays out of the terminal's scrollback after exit, and whether a mouse selection is copied
  through OSC 52.
- `EgressSessionTest` gains one case for the refusal, and one that launches `pi --version` with the
  option. So the suite that runs the image checks the image's install.

## Decisions

- Bedrock's selection is `aws-bedrock`, the user's proposal, answered "Yes for now" on 2026-10-18.
  - Kiro CLI's own traffic does not reach Bedrock, by the firewall list that the `aws` file cites.
    So putting the host under `aws` would widen every `kiro-cli` launch by a host that only AWS
    credentials in the session can use.
  - A workspace rule line would cost every pi workspace a line.
  - The name is the first of the form vendor-service, beside five vendor names.
  - The region is `us-east-1` alone, because pi defaults to it, and the rule's comment gives that
    reason. The user on 2026-10-18: "Follow it. Make sure to comment the reasoning: pi defaults".
- `.agents/skills` stays writable. The user on 2026-10-18: "I agree that it is not read-only as
  long as it cannot contain arbitrary command to be executed." The check of that condition, for
  each reader of the directory:
  - pi: a skill's frontmatter holds the Agent Skills specification's fields (`name`,
    `description`, `license`, `compatibility`, `metadata`, `allowed-tools`,
    `disable-model-invocation`), and none of them names a command. Bundled scripts run only when
    the model runs them (`/docs/latest/skills`).
    - `.claude/skills` is listed because Claude Code's skills carry hooks and `` !`command` ``
      lines, which pi's skills do not.
  - Codex reads `.agents/skills` from the working directory up to the repository root
    (https://developers.openai.com/codex/skills).
    - Codex's optional `agents/openai.yaml` declares `dependencies.tools`. The documented example
      is an MCP server over `streamable_http` with a URL.
    - Two points are not read: whether a command transport can be declared there, and whether
      Codex starts a declared dependency on its own. The condition holds for what the page
      documents.
  - Antigravity's CLI documentation names no skills directory.

  The same criterion keeps `.pi/skills`, `.pi/prompts`, the two system-prompt files and
  `.pi/themes` writable, and lists `.pi/extensions`, `.pi/settings.json` and `.pi/mcp.json` as
  read-only.
- The version check is off (step 1). Leaving it on costs one `pi.dev` read per start, and an update
  banner that no session can act on.
  - `PI_OFFLINE` is not set, because it would also stop the model catalog refresh, which is a `read`
    of an allowed host and keeps a week-old pi's model list current.
- The terminal mode is open.
  - pi's `tuiMode` defaults to `fullscreen`. `--tui-mode regular` and the setting are the
    alternatives.
  - The image keeps Claude Code's classic renderer for two reasons: the fullscreen renderer keeps
    the conversation out of the terminal's scrollback, and it copies a mouse selection through OSC
    52 (the Containerfile's `tui.json` note; `doc/plan-clipboard.md` reconsiders it).
  - "Tests" measures whether pi's fullscreen mode has the same costs.
  - pi has no managed layer. So a `regular` default would be a seeded `settings.json`, which is
    user state that the seed never touches again.
- A lock checked into this repository: not taken.
  - The image's agents update by rebuilding (`--update`), and a checked-in lock would need a commit
    per pi release.
  - The installer API's lock for the chosen version is the same file, fetched at build.
- `read-only .pi` whole, and leaving pi's trust prompt on: not taken.
  - The first exceeds the criterion that the defaults state (above).
  - The second breaks with the four agents whose trust the entrypoint records (step 2).
- How the image installs pi, measured in a session on 2026-10-18 with the image's npm, three days
  after 1.3.0's release:
  - `npm install -g @earendil-works/pi-coding-agent` under the gate installs 1.1.0 (released
    2026-10-07) and 121 packages. With `--min-release-age=0` it installs 1.3.0 and 118 packages.
    Other versions of a dozen `@aws-sdk/*` packages are among the differences.
    - The registry tarball has no shrinkwrap. So the gate here does what SECURITY.md says it is
      for, on pi's own version and on every transitive range.
    - pi's installer comment does not apply to this install.
  - `npm ci` from the installer API's `package-lock.json` installs 1.3.0 and 119 packages, the same
    with and without `--min-release-age=0`. The lock resolves, and the gate never does. That install
    is the route that pi's comment describes, and it needs no bypass.

  Settled on 2026-10-18, the user: "I would take the second. Agreed. Make sure to comment our
  reasoning."
  - The second is the locked `npm ci` for the newest release at least seven days old, chosen from
    the registry's `time` field for the package.
  - The installer API serves every version's lock: 1.0.0, 1.1.0 and 1.2.0 answered on 2026-10-18.
    So the gate applies to pi's own version, and the install is still the set that pi tested for
    that version.
  - The cost is the version arithmetic in the Containerfile.
  - The options not taken:
    - the locked `npm ci` of `latest`, which skips the window on pi's version;
    - `npm install -g` under the gate, which gives a week-old pi against today's dependencies;
    - the same with `--min-release-age=0`, which drops the gate on a hundred unpinned ranges;
    - `min-release-age-exclude=@earendil-works/*`, which takes the newest pi and gates its
      dependencies, and errors when pi requires a dependency version younger than a week.
  - No other program in the image is installed with npm at build time. The builtin npmrc stays,
    so sessions keep the gate.

## Excluded

- `install.sh` and the managed install under `~/.pi/agent/install`: the image installs pi, and the
  volume holds state only.
- Radius (`radius.pi.dev`), `/share` and `/bug`: they send data to an outside recipient. A
  workspace that wants them adds rule lines.
- pi's own isolation extensions (Gondolin, OpenShell, Docker Sandboxes): the sandbox is the
  boundary.
- ko-review: the reviewers stay `codex` and `claude`.

## Sources

- https://pi.dev/docs/latest, the pages `cli`, `configuration`, `environment-variables`,
  `providers`, `sessions`, `security`, `containerization`, `settings`
- https://github.com/earendil-works/pi, `packages/coding-agent/src/core/trust-manager.ts`,
  `remote-catalog-provider.ts`, `provider-attribution.ts`, `telemetry.ts`,
  `utils/version-check.ts`, `packages/ai/src/providers/`, `packages/ai/src/auth/oauth/`,
  `packages/ai/src/api/bedrock-converse-stream.ts`
- https://pi.dev/docs/latest/skills and https://developers.openai.com/codex/skills, for the
  `.agents/skills` check
- https://registry.npmjs.org/@earendil-works/pi-coding-agent/latest, version 1.3.0
- https://pi.dev/install.sh
