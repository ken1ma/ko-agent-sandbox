# Plan: pi in the sandbox

pi (https://pi.dev, Earendil Works) is a Node.js agent harness with no fixed model provider. This
plan adds it as the seventh preinstalled agent, launched as
`java -jar ko-agent-sandbox.jar --model-provider=<names> pi`.

The requirement: pi runs under the boundary the other agents have. Its state lives in the
persistent volume, the workspace is trusted without a prompt, no tool-approval prompt appears, and
its network reaches the selected providers, the proxy's host catalog and nothing else.

The facts below are read on 2026-10-18 from the pi.dev documentation (`/docs/latest`), the npm
registry entry of `@earendil-works/pi-coding-agent` 1.3.0 and the source on the `main` branch of
https://github.com/earendil-works/pi. The install measurements are under "Decisions"; nothing else
is measured yet, and "Tests" lists each check.

## What is read

### Program

- The npm package `@earendil-works/pi-coding-agent` installs the `pi` command
  (`dist/bundle/cli.js`) and requires Node.js 22.19.0 or newer; the image has Node 24. pi's own
  container example installs it with `npm install -g --ignore-scripts`. The 1.3.0 tarball on the
  registry carries no `npm-shrinkwrap.json` (its file list, and the registry's `_hasShrinkwrap`
  flag), so that install resolves every dependency range from the registry.
- pi's installer API at `https://pi.dev/api/installer/releases` serves `latest` (a metadata
  object naming the version, its packages, their tarballs and sha512 integrity) and, per version,
  a `package.json` depending on that one version and a `package-lock.json` of its whole tree, 120
  packages for 1.3.0. `install.sh`'s managed install downloads those two files and runs
  `npm ci --ignore-scripts --min-release-age=0 --omit=dev --include=optional` in a staging
  directory; its comment on the option: "Pi publishes npm-shrinkwrap.json, so the explicit
  installer/reinstaller can bypass npm's release-age gate without reopening transitive dependency
  ranges".
- `install.sh` installs Node.js through a package manager and pi into `~/.pi/agent/install`,
  then edits the shell profile. Not for the image.
- pi has no system-wide configuration layer: settings come from the agent directory and the
  workspace's `.pi/`, switches from environment variables.

### State

- The agent directory, `~/.pi/agent` (`PI_CODING_AGENT_DIR`), holds everything that must
  persist: `auth.json` (API keys and OAuth tokens), `settings.json`, `models.json`, `mcp.json`,
  `trust.json`, `sessions/` grouped by working directory, and the user's extensions, skills,
  prompts, themes and packages.
- `pi --continue` opens the most recent session of the working directory; `--resume` opens the
  picker.
- Shell commands pi runs receive `PI_PROVIDER`, `PI_MODEL` and `PI_SESSION_FILE`; the process
  markers `AI_AGENT=pi` and `PI_CODING_AGENT=true` reach every child.

### Workspace files and trust

pi calls the workspace the project; the sandbox's word is used below.

- `.pi/` in the workspace holds `settings.json`, `mcp.json`, `SYSTEM.md`, `APPEND_SYSTEM.md`,
  `extensions/`, `skills/`, `prompts/` and `themes/`. Extensions are TypeScript modules run inside
  pi's process; `settings.json` names packages pi installs from npm or git. `.agents/skills` in
  the workspace or an ancestor is read too.
- Any of those files triggers a trust decision: `--approve` or `--no-approve` on the command
  line, else an extension, else `<agent-dir>/trust.json`, a JSON object from canonical directory
  path to `true`, `false` or `null` (`core/trust-manager.ts`), else the `defaultProjectTrust`
  setting, `"ask"` by default. Print and RPC modes cannot ask and skip the resources.
- Skills are a `SKILL.md` with supporting files, which "can instruct the model to run scripts"
  (`/docs/latest/skills`); prompt templates are Markdown "without adding executable behavior"
  (`/docs/latest/prompt-templates`). Neither runs a command on its own.
- `AGENTS.md`, `AGENTS.override.md` and `CLAUDE.md` load from the agent directory, the working
  directory and its parents, trust or not.
- pi asks no approval before tool calls: "it does not ask for approval before every tool call"
  (`/docs/latest/security`). There is no prompt to turn off and none to restore; the repository's
  `examples/extensions/permission-gate.ts` adds one.

### Network

Model traffic aside, pi contacts these hosts. Each is listed with what stops it.

- The latest-version check at start: a GET of `pi.dev/api/latest-version`. `PI_SKIP_VERSION_CHECK`
  stops it (`utils/version-check.ts`).
- The model catalog refresh, at an interval: GETs of `pi.dev`. `PI_OFFLINE` stops it and the
  version check (`core/remote-catalog-provider.ts`, `main.ts`).
- An `HTTP-Referer: https://pi.dev` header on provider requests, and install and update
  telemetry, whose host is not read yet. `PI_TELEMETRY=0` or `enableInstallTelemetry: false`
  stops both (`core/provider-attribution.ts`, `core/telemetry.ts`).
- `/share`: a POST of a gist to `api.github.com`, or to `radius.pi.dev` when signed in to Radius.
  No switch; the host catalog grants `read` of `api.github.com` and nothing of `radius.pi.dev`,
  so the proxy refuses both.
- `/bug`: a POST to `radius.pi.dev`, refused the same way.
- `pi install npm:…` and `git:…`: `registry.npmjs.org` and `github.com`, which the host catalog
  allows; the image's `min-release-age=7` applies to the npm source.

pi honors `HTTPS_PROXY` (`/docs/latest/environment-variables`; `utils/node-http-proxy.ts`) and
Node trusts the proxy CA through the `NODE_EXTRA_CA_CERTS` the launcher sets
(`AgentSandboxLauncher.scala`, the CA variables), so the inspected `pi.dev` reads work.

### Providers against the proxy's rules

pi's provider ids, the hosts in `packages/ai/src/providers/*.ts` and
`packages/ai/src/auth/oauth/*.ts`, and whether the proxy's `defaults/model-provider/` file of the
same selection allows them:

- `anthropic`: `api.anthropic.com`; OAuth at `claude.ai/oauth/authorize` and
  `platform.claude.com/v1/oauth/token`. `anthropic` allows all three.
- `openai`: `api.openai.com` with an API key. `openai-codex`: `chatgpt.com/backend-api`, OAuth
  at `auth.openai.com`. `openai` allows all three.
- `google`: `generativelanguage.googleapis.com` with an API key; pi has no Google OAuth. `google`
  allows it. `google-vertex`: `aiplatform.googleapis.com` and `oauth2.googleapis.com` for the
  credential refresh; `google` allows the global host, not a regional one.
- `github-copilot`: `api.individual.githubcopilot.com`; the device flow at
  `github.com/login/device/code`, `github.com/login/oauth/access_token` and
  `api.github.com/copilot_internal/v2/token`. `github` allows all four; an enterprise's
  `copilot-api.<domain>` is not in it.
- `amazon-bedrock`: `bedrock-runtime.<region>.amazonaws.com` through
  `@aws-sdk/client-bedrock-runtime`, the region from the model's ARN, the AWS variables, or
  `us-east-1` (`api/bedrock-converse-stream.ts`). `aws` holds Kiro's hosts and allows none of
  them.
- pi's other providers, OpenRouter, Groq, Mistral and the rest: no selection names their hosts.

pi's OAuth flows start a localhost callback server and accept the redirect URL or code pasted
back (`/docs/latest/providers`, `auth/oauth/callback-server.ts`); xAI and Copilot use device
codes. README's "Sign-in" section describes this path.

## Steps

### 1. Image

- Install under `/opt/pi` as root at build time, the way pi's managed installer does, for the
  newest release at least seven days old: read the package's `time` field from the registry,
  pick that version, download its `package.json` and `package-lock.json` from the installer API
  into `/opt/pi`, run `npm ci --ignore-scripts --omit=dev --include=optional` there, and put
  `/opt/pi/node_modules/.bin` on `PATH` as `/opt/codex/bin` is. `--ignore-scripts` is pi's own
  instruction. The lock's integrity hashes check every tarball, so TLS to `pi.dev` for the lock
  and the hashes for the tarballs are the integrity boundary, as TLS to github.com is for Codex.
- The Containerfile comment carries the reasoning, decided in "Decisions": the seven days are
  the window SECURITY.md keeps for a compromised release to be noticed, applied here to pi's own
  version because pi is the one program the image resolves through npm; the lock gives the
  dependency set pi tested for that version, where `npm install -g` under the gate would resolve
  a week-old pi against today's dependencies; the builtin `min-release-age=7` stays and costs a
  locked install nothing, since `npm ci` installs the lock's versions without resolving
  (SECURITY.md, "The supply chain"); and the route is pi's own, https://pi.dev/install.sh's
  managed install, less its bypass of the gate, which that lock makes unnecessary.
- Smoke test `HOME=/tmp/pi-smoke pi --version`, with a throwaway HOME as for the others, on both
  architectures the image builds for. The 1.3.0 lock names no platform-specific package; the
  1.1.0 lock carries esbuild's platform binaries as optional packages, `linux-x64` and
  `linux-arm64` among them, which `npm ci` picks by platform. `--ignore-scripts` skips the
  install scripts of `@google/genai`, `protobufjs` and, in 1.1.0, `esbuild`; the smoke test is
  what shows pi starts without them.
- `ENV PI_SKIP_VERSION_CHECK=1`: the program is the image's and updates by rebuild; the check
  would read `pi.dev` at every start and announce an update that `pi update` cannot install into
  the read-only `/opt`. `ENV PI_TELEMETRY=0`: the attribution header and install telemetry. The
  model catalog refresh stays on; it is a `read` of `pi.dev`, which the host catalog allows.
- Seed `$KO_SANDBOX_VOLUME_SEED/pi/agent` and link `~/.pi` to `persistent-volume/pi`; the agent
  directory is `~/.pi/agent` inside it. Add the link to the `chown -h` list.
- Link `$KO_SANDBOX_VOLUME_SEED/pi/agent/AGENTS.md` to `/etc/ko-agent-sandbox/AGENTS.md`, in the
  Containerfile's block of instruction-file links: pi reads the agent directory's `AGENTS.md` as
  user instructions in every working directory, as Codex reads `~/.codex/AGENTS.md`.

### 2. Entrypoint

- Record the workspace's trust with `merge_json` on `$volume/pi/agent/trust.json`, the filter
  `. + {($workspace): true}`. The key is the canonical path; the workspace is mounted at its
  host path, so `$workspace` is it. Without the entry a `.pi/` in the workspace makes pi ask.
- The entry is deliberate, as for the four agents the entrypoint records today: the sandbox is
  the boundary, the agents run without prompts (README, the preinstalled list), and the read-only
  default for `.pi/extensions`, `.pi/settings.json` and `.pi/mcp.json` keeps a session from
  writing what the trust would load into the next.
- `SandboxEntrypointTest`: `pi` joins the seeded set and the trust files.

### 3. Launcher and proxy

- `EgressRules.ProviderlessAgents` gains `"pi"`: a launch naming no provider, on the command
  line or in the options file, is refused as opencode's is. `EgressRulesTest` covers the refusal
  and the warning line.
- The usage text and the first-line comment of `AgentSandboxLauncher.scala` name pi; the two
  comments listing the volume's directories gain `~/.pi`.
- The proxy's host catalog: `allow https://pi.dev/ read # pi`, which the working tree holds. The
  host serves the docs, the version check, the model catalog and the installer API.
- A selection of its own for Bedrock, `aws-bedrock`: the name joins `RulesetHelper.ModelProviders`
  and the file `defaults/model-provider/aws-bedrock` holds
  `allow https://bedrock-runtime.us-east-1.amazonaws.com/ tunnel`, its comment giving the reason
  for the one region: pi defaults to `us-east-1`. Another region is a workspace's own rule line, as
  the `aws` file says of an Identity Center elsewhere; the proxy's refusal names the host. `aws`
  stays Kiro's. The credentials come from the host through `--env-aws-cred` or
  `--env=AWS_BEARER_TOKEN_BEDROCK` (`doc/cloud-credentials.md`); pi reads the same variables as
  the AWS SDK. The name joins the README's lists, the usage text and `doc/egress-proxy.md`, and
  `doc/cloud-credentials.md`'s "No default names a Bedrock host" paragraph names the selection,
  keeping the other regions as rule lines.

### 4. File rules

- `file-rule-defaults` gains `read-only .pi/extensions`, `read-only .pi/settings.json` and
  `read-only .pi/mcp.json`, and `doc/file-rules.md`, "Why these files", gains pi's
  paragraph: extensions run in the process, `settings.json` names extension paths and installs
  packages, `mcp.json` names commands; a trust prompt exists, and the entrypoint answers it.
- `.pi/skills`, `.pi/prompts`, `.pi/SYSTEM.md`, `.pi/APPEND_SYSTEM.md`, `.pi/themes` and
  `.agents/skills` stay writable, as `AGENTS.md` is: text the model reads, which no program runs
  a command from ("Decisions" has the condition and its check).

### 5. Documentation

- README: the preinstalled list (`[pi](https://pi.dev) (multiple providers)`), the
  `--model-provider` paragraph ("`opencode` and `pi` have no fixed provider"), the resume
  arguments (`pi --continue`), the usage text, and a `#### pi` section: launch with the option,
  `/login` for an OAuth or API-key provider, paste the redirect URL back, Bedrock through
  `--model-provider=aws-bedrock` with forwarded credentials, `/share` and `/bug` are refused.
- `doc/egress-proxy.md`, the providerless sentence; `AGENTS-SANDBOX.md`, the list of paths into
  the volume; `doc/agent-settings.md`: pi reads `AGENTS.md`, and "Restoring permission prompts"
  says pi has none to restore and names the example extension; `doc/TODO.md`, the agents
  measured under the seccomp profile.
- Every other mention of `opencode` in the documents is checked for whether pi joins it.
  SECURITY.md names no agent in "What the persistent volume holds" or in the provider text, so
  pi's `auth.json` and selection need no sentence there.

## Tests

- The image builds and `pi --version` runs in the smoke test.
- Under `--model-provider=anthropic`: `pi` starts, the model catalog refresh succeeds through
  the proxy (no TLS error in the log), `/login anthropic` with a pasted code reaches `claude.ai`
  and `platform.claude.com`, a prompt reaches `api.anthropic.com`, `/share` is refused, and a
  second launch with `pi --continue` finds the session.
- With a `.pi/settings.json` in the workspace: no trust prompt, and the setting is applied.
- `pi -p "..."` under `--model-provider=openai` with `OPENAI_API_KEY` passed through `--env`.
- `pi` without the option is refused with the message naming `--model-provider`.
- The two new grants, each through `ko-sandbox-egress-check` and the proxy's log: a GET of
  `pi.dev` succeeds and a POST to it is refused; under `--model-provider=aws-bedrock`,
  `bedrock-runtime.us-east-1.amazonaws.com` tunnels and
  `bedrock-runtime.ap-northeast-1.amazonaws.com` is refused; under `aws` alone, both are refused.
  `AgentEgressProxyTest` already checks that the provider names and the files under
  `defaults/model-provider/` match.
- `pi` starts under the seccomp profile (`doc/TODO.md`'s list).
- In fullscreen mode: whether the conversation stays out of the terminal's scrollback after exit,
  and whether a mouse selection is copied through OSC 52, in the terminals `doc/plan-clipboard.md`
  lists.
- `EgressSessionTest` gains one case for the refusal and one launching `pi --version` with the
  option, so the image's install is checked by the suite that runs the image.

## Decisions

- Bedrock's selection: `aws-bedrock`, the user's proposal, "Yes for now" on 2026-10-18. Kiro
  CLI's own traffic does not reach Bedrock, by the firewall list the `aws` file cites, so putting
  the host under `aws` would widen every `kiro-cli` launch by a host only AWS credentials in the
  session can use, and a workspace rule line would cost every pi workspace a line. The name is the
  first of the form vendor-service beside five vendor names. The region: `us-east-1` alone,
  because pi defaults to it, with the rule's comment giving that reason; the user on 2026-10-18:
  "Follow it. Make sure to comment the reasoning: pi defaults".
- `.agents/skills` stays writable. The user on 2026-10-18: "I agree that it is not read-only as
  long as it cannot contain arbitrary command to be executed." The check of that condition, by
  reader of the directory:
  - pi: a skill's frontmatter is the Agent Skills specification's fields (`name`, `description`,
    `license`, `compatibility`, `metadata`, `allowed-tools`, `disable-model-invocation`), none
    of which names a command; bundled scripts run only when the model runs them
    (`/docs/latest/skills`). `.claude/skills` is listed because Claude Code's skills carry hooks
    and `` !`command` `` lines, which pi's do not.
  - Codex reads `.agents/skills` from the working directory up to the repository root
    (https://developers.openai.com/codex/skills). Its optional `agents/openai.yaml` declares
    `dependencies.tools`; the documented example is an MCP server over `streamable_http` with a
    URL. Whether a command transport can be declared there, and whether Codex starts a declared
    dependency on its own, is not read; the condition holds for what the page documents.
  - Antigravity's CLI documentation names no skills directory.
  The same criterion keeps `.pi/skills`, `.pi/prompts`, the two system-prompt files and
  `.pi/themes` writable, and lists `.pi/extensions`, `.pi/settings.json` and `.pi/mcp.json`.
- The version check: off, above. Leaving it on costs one `pi.dev` read per start and an update
  banner no session can act on. `PI_OFFLINE` is not set: it would also stop the model catalog
  refresh, a `read` of an allowed host that keeps a week-old pi's model list current.
- The terminal mode, open: pi's `tuiMode` defaults to `fullscreen`, with `--tui-mode regular` and
  the setting as the alternatives. The image keeps Claude Code's classic renderer because the
  fullscreen one keeps the conversation out of the terminal's scrollback and copies a mouse
  selection through OSC 52 (the Containerfile's `tui.json` note; `doc/plan-clipboard.md`
  reconsiders it). Whether pi's fullscreen mode has the same costs is measured in "Tests"; pi has
  no managed layer, so a `regular` default would be a seeded `settings.json`, user state the
  seed never touches again.
- A lock checked into this repository, not taken: the image's agents update by rebuilding
  (`--update`), and a checked-in lock would need a commit per pi release; the installer API's
  lock for the chosen version is the same file, fetched at build.
- `read-only .pi` whole, and leaving pi's trust prompt on, not taken: the first exceeds the
  criterion the defaults state (above), the second breaks with the four agents whose trust the
  entrypoint records (step 2).
- How the image installs pi, measured in a session on 2026-10-18 with the image's npm, three
  days after 1.3.0's release:
  - `npm install -g @earendil-works/pi-coding-agent` under the gate installs 1.1.0 (released
    2026-10-07) and 121 packages; with `--min-release-age=0`, 1.3.0 and 118 packages, with other
    versions of a dozen `@aws-sdk/*` packages among the differences. The registry tarball has no
    shrinkwrap, so the gate here does what SECURITY.md says it is for, on pi's own version and
    on every transitive range. pi's installer comment does not apply to this install.
  - `npm ci` from the installer API's `package-lock.json` installs 1.3.0 and 119 packages, the
    same with and without `--min-release-age=0`: the lock resolves, the gate never does. This is
    the route pi's comment describes, and it needs no bypass.
  Settled on 2026-10-18, the user: "I would take the second. Agreed. Make sure to comment our
  reasoning." The second is the locked `npm ci` for the newest release at least seven days old,
  chosen from the registry's `time` field for the package; the installer API serves every
  version's lock (1.0.0, 1.1.0 and 1.2.0 answered on 2026-10-18), so the gate applies to pi's
  own version and the install is still the set pi tested for it, at the cost of the version
  arithmetic in the Containerfile. The options not taken: the locked `npm ci` of `latest`, which
  skips the window on pi's version; `npm install -g` under the gate, a week-old pi against
  today's dependencies; the same with `--min-release-age=0`, which drops the gate on a hundred
  unpinned ranges; `min-release-age-exclude=@earendil-works/*`, pi newest and its dependencies
  gated, which errors when pi requires a dependency version younger than a week. No other
  program in the image is installed with npm at build time, and the builtin npmrc stays, so
  sessions keep the gate.

## Excluded

- `install.sh` and the managed install under `~/.pi/agent/install`: the image installs, and the
  volume holds state only.
- Radius (`radius.pi.dev`), `/share` and `/bug`: write recipients; a workspace that wants them adds
  rule lines.
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
