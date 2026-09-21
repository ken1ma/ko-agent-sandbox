# Plan: IDE integration through VS Code's Agent Host Protocol

VS Code's Agents window drives an agent whose runtime, tools and credentials stay in the sandbox.
VS Code reaches the agent through the Agent Host Protocol (AHP): a host process that owns the
sessions, and clients on a WebSocket to it. This plan investigates that integration in three
steps and implements it when they pass. The Agent Client Protocol (ACP), one client and one agent
over the agent's stdio, is deferred; "Deferred: ACP" keeps its design for when it is reopened.

The requirement every step serves: a compromised process inside the sandbox cannot make VS Code
exercise host authority the user did not grant. Every process in the sandbox is untrusted, so the
enforcement lives in VS Code or in a launcher-owned filter on the host, never in a setting the
sandbox side honors: a host that ignores its configuration still sends protocol messages.

## What is read and measured

Read and measured on 2026-09-22 and 2026-09-23. The VS Code documents carry an approval date of
2026-09-16; the VS Code source is release 1.138.0.

VS Code and AHP:

- The spec release is 0.9.0 of 2026-08-28, and breaking changes may land in minor versions until
  1.0.0.
- The user guide describes VS Code reaching a remote Agent Host through SSH, where VS Code
  installs its own CLI on the remote machine, through a dev tunnel, or inside the project's Dev
  Container. The source has more: the Agents window's command "Add Remote Agent Host..." takes a
  host, `host:port` or a WebSocket URL such as `ws://127.0.0.1:8080?tkn=abc-123`, stores it under
  the `chat.remoteAgentHosts` setting with an optional `connectionToken`, and connects to it. The
  command exists while `chat.remoteAgentHostsEnabled` is on, which it is by default; the settings
  are tagged experimental (`remoteAgentHostActions.ts`, `remoteAgentHost.contribution.ts`,
  `remoteAgentHostService.ts`).
- `code agent host` binds `localhost` on an ephemeral port by default, takes
  `--connection-token` or `--connection-token-file`, `--server-data-dir` and `--foreground`, and
  downloads the VS Code server release when its data directory lacks it (`cli/src/commands/`).
  `code agent relay <instance-id>` copies stdin and stdout to a running host's endpoint verbatim,
  interpreting nothing, for use as an SSH `ProxyCommand`.
- The Dev Container path runs VS Code's bundled devcontainers CLI on the host: `devcontainer up`,
  the VS Code remote CLI installed inside the container, and the host's WebSocket relayed over
  `devcontainer exec` stdio (`REMOTE_AGENT_HOST_SESSIONS_PROVIDER.md`).
- What the host can ask of VS Code, the client surface found so far:
  - tools a connected client contributes, VS Code's own and its extensions', which the host
    routes back to that client;
  - the read-only `vscode-agent-client://` file system, whose `browseDirectory` and
    `fetchContent` the connection proxies back to the client
    (`agentHostClientFileSystemProvider.ts`);
  - the MCP servers configured in the editor, which VS Code forwards to the host;
  - bearer tokens: on every connection change, and when the default account changes, VS Code
    resolves its existing sign-in sessions for each protected resource the host's agents
    advertise and pushes the tokens with `authenticate` (`agentHostAuth.ts`,
    `remoteAgentHost.contribution.ts`). The host has three further ways to ask: an
    `AuthRequired` error, code `-32007`, which any command may return with the resources in its
    data; the `auth/required` notification, for an expired token or a new requirement, which VS
    Code answers by recovering a session for the named resource; and the `authRequired` state of
    an MCP server or a tool call. The specification's example is a GitHub token for the Copilot
    agent. With the smoke-test driver enabled and `chat.agentHost.unsafeTestToken` set, VS Code
    pushes that string instead of a real session on two paths, the discovery pass over the agent
    list and interactive resolution; the `auth/required` handler recovers a real session
    regardless. The connection token is separate from all of these.
- The host runs terminals as its own pseudo-terminals, so a host inside the sandbox would run them
  inside it.
- The Copilot harness uses VS Code's GitHub session. The Claude harness alternatively reads
  `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`. Codex on the Agent Host is experimental.
- The image installs the `code` CLI at `/usr/local/bin/code` (Containerfile, "VS Code CLI").

ACP, for the deferred track:

- The stable protocol version is 1. The changelog's release 1.9.1 of 2026-09-18 carries
  `unstable-v2` entries, so v2 is a draft.
- Over the stdio transport the agent reads JSON-RPC from stdin and writes it to stdout, writes
  logs to stderr, and must write nothing else to stdout.
- What the agent may ask of the client, the v1 client surface: `session/request_permission`
  always; `fs/read_text_file` and `fs/write_text_file` on the client's file system, including
  unsaved editor buffers; `terminal/create`, `output`, `wait_for_exit`, `kill` and `release`,
  which run a command in the client's environment; `elicitation/create` in form mode, a schema
  the user fills in, or URL mode, where the client shows the full URL, obtains consent and opens
  a browser on it. The client advertises each in `initialize`, with `auth.terminal` beside them.
  The agent's notifications to the client are `session/update` and `elicitation/complete`.
- Extensions go both ways: `_meta` on most request, response, notification and nested types, and
  methods named with a leading underscore. An unknown request is answered "method not found"; an
  unknown notification is ignored.
- `session/new`, `session/load` and `session/resume` carry an absolute `cwd`, an `mcpServers`
  list, and, when the agent advertises `sessionCapabilities.additionalDirectories`,
  `additionalDirectories`, which widen the session's root set. A stdio MCP entry names an absolute
  command path, arguments and environment for the agent to spawn; an `http` or `sse` entry names a
  URL and headers.
- A `terminal` authentication method makes the client launch the configured agent command again in
  an interactive terminal, with the method's `args` appended and its `env` applied.
- In the image, `opencode acp` (OpenCode 1.18.32) and `copilot --acp` (Copilot CLI 1.0.87) answer
  an `initialize` on stdout with nothing on stderr. Both advertise `loadSession` and `http` and
  `sse` MCP transports. Copilot's authentication method carries a `_meta.terminal-auth` entry
  naming `/usr/local/bin/copilot login`. `codex` 0.155.1 and `claude` 2.1.278 have no ACP mode of
  their own.
- Zed runs a custom agent from `agent_servers.<name>` in its settings: `type: custom`, `command`,
  `args`, `env`. Its documentation says Zed-configured MCP servers may be forwarded to the agent
  over ACP, and that its `dev::OpenAcpLogs` action shows the messages exchanged.
- JetBrains' ACP documentation is unread; nothing here about it is verified.

The launcher:

- It creates the container with `-it`, then on POSIX execs `podman start --attach --interactive`;
  on Windows, and wherever exec is unavailable, it stays resident and waits for podman
  (`SandboxLifecycle.handOver`).
- Every launch line is written to stderr, as are the entrypoint's warnings; the entrypoint's start
  pause needs a terminal on stdin.
- The model provider a launch admits under egress is selected by the command's first word
  (`EgressRules`); `opencode` and `copilot` are recognized.
- No host process accepts a connection from the sandbox: the brokers read FIFOs through `podman
  exec` (SECURITY.md, "Clipboard" and "Run on host"). The listeners SECURITY.md documents, the
  per-program egress proxy and the mill and Gradle daemons' ports, serve host processes.
- The project is mounted at its real path on macOS and Linux, and on Windows at
  `/mnt/<drive>/...`, the spelling `SandboxProject.mountPathOf` derives from `C:\...`. An IDE that
  opened the project through a symbolic link sees a different spelling from the sandbox's;
  design.md, "Prior-art references worth retaining", records that open item.

## Decision: AHP is the active investigation; ACP is deferred

The native VS Code panel is the integration wanted, and its attachment by address exists in
released source, so the investigation that decides whether that outcome is practical comes first.
This is sequencing, not a finding that ACP is the harder track: ACP's work is identified, the
stdio lifecycle, the relay's policy, authentication handling and paths, while AHP's harder
questions, stopping client operations and credential pushes from a host treated as hostile, are
open until step 2. Implementing ACP before that would spend the work before it is known whether
its editors are wanted.

ACP is the fallback, its design kept under "Deferred: ACP". It is reopened, and its identified
work compared against AHP's measured cost, when step 2 shows AHP needing a filtering relay beyond
refusing the named operations, or step 3 shows no harness authenticating from the volume; and on
its own when Zed or JetBrains support is wanted.

## Step 1: attachment

What to run and record, on VS Code 1.138.0 or the release current at the time:

- `code agent host --foreground --connection-token-file ...` inside the image: the server download
  it needs, so the image change and the destination to admit; writable paths; and every other
  destination it opens, each assigned to a feature before a rule admits it.
- The transport to the host, two candidates: the sandbox's port published on the host's loopback,
  which the internal network may not allow; or a launcher-owned loopback listener that relays each
  connection through `podman exec code agent relay <instance-id>`. Neither transport is
  implemented. Record which works and what it exposes to other local users; the launcher
  generates the connection token per run.
- "Add Remote Agent Host..." against that endpoint, with the token.

The VS Code that attaches runs with a fresh `--user-data-dir`, no account signed in and no
extension installed, until the filtering relay of step 2 stands between them: step 2's source
pass finds no setting that stops a token push while keeping remote hosts, so an attachment with
an account before the relay is the forwarding the investigation exists to prevent. Where a token
is needed, in any step, it is the smoke-test driver's `chat.agentHost.unsafeTestToken` on the
routes that honor it and a throwaway account created for the test on the others, never the
user's session.

Measured on 2026-09-23: VS Code 1.138.0 on macOS attached to the host in a sandbox launched on the
default egress profile.

- Downloads. The CLI, installed under `~/.local/bin` for this measurement, comes from
  `https://update.code.visualstudio.com/latest/cli-linux-arm64/stable`; the host's server
  download from the same host's `/commit:<commit>/server-linux-arm64/stable`. Both answer with a
  redirect to `vscode.download.prss.microsoft.com`, so the feature "VS Code CLI and server
  download" needs `read` rules for both hosts. The server archive is 210 MB; the host is ready
  51 s after start when it downloads and 14 s when the server is cached. The image installs the CLI
  (Containerfile, "VS Code CLI"); the server is downloaded at first start through the proxy's
  default rules (`defaults/host`, "VS Code").
- Writes, discarded with the session: the server under `~/.vscode/cli/servers/`, server data,
  extensions and the supervisor log under `~/.vscode-server/`, the endpoint registry under
  `~/.config/Code/agent-host/`, a cache under `~/.cache/Microsoft/`, and three sockets in `/tmp`.
- Other destinations: the host POSTs telemetry to `mobile.events.data.microsoft.com`; the proxy
  refuses it and the host continues, so no rule admits it. The host also streams its log records
  to the client over the protocol (`otlp/exportLogs`).
- Listener: `127.0.0.1:31546` only, the port given with `--port`. The supervisor checks the
  connection token at the WebSocket handshake: `101` with `?tkn=<token>`, `403 Forbidden: missing
  or invalid connection token` without.
- Transport: the exec relay works with no launcher change. On the host, a loopback listener runs
  one relay per connection:

  ```sh
  socat TCP-LISTEN:31546,bind=127.0.0.1,reuseaddr,fork \
    EXEC:"podman exec -i <container> /home/nonroot/.local/bin/code agent relay \
      --user-data-dir /home/nonroot/.config/Code <instance-id>"
  ```

  The command above is tested with the CLI installed under `~/.local/bin`; with the image's CLI
  the path is `/usr/local/bin/code`, untested, as is the form without absolute paths.
  `code agent endpoints` in the sandbox prints the instance id and the token. The listener
  accepts any local process; the connection token is what refuses them, and VS Code keeps it in
  the profile's settings under `chat.remoteAgentHosts`. The published-port candidate is untried.
- Attachment: the Agents window opened with a fresh `--user-data-dir` and `--extensions-dir`,
  signed out, with `chat.agentHost.allowSignedOutWhenUsable` set beforehand; whether the window
  needs it is not measured. The command is a Command Palette entry of the Agents window, listed as
  "Agents: Add Remote Agent Host..."; it takes the `ws://` URL, then a display name, and connects
  at once. The workspace dropdown's Remote tab and "Agents: Manage Remote Agent Hosts..." list the
  host as Online, with a folder picker on the host.
- The protocol log under `~/.vscode-server/data/logs/<start>/ahp/` records the exchange. Over two
  and a half hours the client, `vscode-agents-window` on protocol 0.9.0, sent `initialize`,
  `listSessions`, two `subscribe` calls for the host's log channel and its automations, nine
  `dispatchAction` calls that push 35 VS Code settings as host configuration, among them the
  terminal auto-approve rules, workspace trust, the telemetry level and a `sandbox` block set to
  off with network allowed, and a ping every five seconds. That `sandbox` block is the Agent Host
  setting step 2 names. The host advertises `protectedResources` for both of its agents, GitHub
  required for Copilot and optional for Claude. The log holds no `authenticate` request, no
  `auth/required` notification and no `AuthRequired` error: no bearer token crossed in this
  signed-out attachment. No message carries the project path, and no session exists.

## Step 2: enforcement outside the sandbox

The deciding test. A hostile host, a script speaking AHP in place of `code agent host`, stands in
for the compromised sandbox and tries each client operation; what stops it must be VS Code or the
launcher's filter. Record, for each operation, what VS Code does by default, what a VS Code
setting prevents, and what remains:

- a bearer token requested by each route the host has: protected resources advertised in the
  agent list before any session is selected and again after one is, an `AuthRequired` error on
  an ordinary command, an `auth/required` notification, an `authRequired` MCP server and tool
  call, each also after a root-state update and after a reconnection, since the notification is
  not replayed and VS Code re-checks on reconnect. Each route needs a positive control, so that a
  signed-out client sending nothing cannot pass as enforcement. The decision rests on the
  connect-time route's control, the hostile host recording the test token without enforcement.
  The routes whose control needs an account are delivered in step 4's acceptance, behind the
  relay, where the evidence is the relay's report of the `authenticate` it refused on the client
  side and the hostile host's log holding no token;
- a client tool call, VS Code's own and an extension's;
- `browseDirectory` and `fetchContent` on host paths outside the project;
- a forwarded MCP server, and a tool call routed to it;
- every other client-executed operation the spec's channels define; the list above is what the
  source read so far shows, not the whole surface.

The hostile host is `src/probe/ahp-hostile-host.py`, run with `uv run --with websockets` and
attached through "Add Remote Agent Host...". It advertises two agents with protected resources.
After `initialize` it sends an `auth/required` notification and the reverse `resource*` requests
(`resourceResolve`, `resourceList`, `resourceRead`, `resourceWrite`, `resourceMkdir`,
`resourceDelete`, `createResourceWatch`) for host paths; write, mkdir and delete act only on a
probe file under the host's `/tmp`. It answers `createSession` for Copilot with `AuthRequired`.
It then broadcasts its agent list with one resource added, and with `--grant-path` it follows a
refused read with `resourceRequest` and reads again. When the operator starts a turn it sends a
client-contributed tool call naming a tool the client offered, and a URL-mode elicitation. It
serves the container's own files read-only for the Remote tab's folder picker, and records every
frame to a JSONL log.

Measured on 2026-09-23: VS Code 1.138.0 on macOS attached to the hostile host, signed out except
where the test token is named. Sessions were opened from the workspace dropdown's Remote tab on the
container's `/home/nonroot`; sessions on a Local folder sent the hostile host nothing.

- Reverse file operations returned `PermissionDenied` (-32009) carrying the grant request, with no
  content, for `/etc/passwd`, `/home/nonroot` (absent on macOS) and a `/tmp` file.
  `createResourceWatch` from the host is unhandled (-32000). When the host follows a refused read
  with `resourceRequest`, VS Code shows a banner naming the host and the full path, with Deny,
  Allow and the highlighted Always Allow. After the user chose Allow, the request returned `{}`.
  On the next connection to the same address in the same window, the same request returned `{}`
  within 4 ms with no banner, and a read then returned the file's bytes. The source says Allow
  lasts "for the lifetime of the connection"; what that covers is unverified.
- `createSession` for Copilot reached the host, which answered `AuthRequired`; no `authenticate`
  and no second `createSession` followed, in the signed-out runs and in the test-token runs. The
  request followed `resolveSessionConfig` and carries the argument set of the sessions provider's
  eager creation (`baseAgentHostSessionsProvider.ts`), which on an error logs a warning and stops.
  The chat handler's path, which resolves authentication and retries `createSession` once
  (`agentHostSessionHandler.ts`), was not reached, so these runs say nothing about it.
- `createSession` carried 15 client tools, the integrated-browser and automation set, and a synced
  customization that names a GitHub MCP server without its command, URL, environment or headers.
  Opening the session raised VS Code's workspace-trust prompt for the host folder.
- A `chat/inputRequested` with a `url` rendered an "Authorization Required" card showing the full
  URL with Open and Cancel. VS Code opened nothing; the user's Cancel reached the host as
  `chat/inputCompleted` with `decline`.
- A client-contributed tool call naming `toolSearch` rendered as a card; VS Code ran nothing and
  returned no result. The host sent only the call's start and ready actions.
- Signed out, no token crossed on the three token routes exercised: resources advertised at
  connect, the `auth/required` notification, and `AuthRequired` on `createSession`.
- With `--enable-smoke-test-driver` and `chat.agentHost.unsafeTestToken` set, VS Code pushed that
  token within 0.5 s of each `initialize` to both advertised resources, including the one marked
  optional, before any session and without a prompt. This held on four connections; on two,
  VS Code first sent `reconnect`, which the hostile host refuses, then a fresh `initialize`. It
  pushed for a new resource 3 ms after the host added one to its agent list
  (`root/agentsChanged`). This is the driver's test-token path; that a signed-in session's token is
  forwarded the same way is read from source (`agentHostAuth.ts`), not measured.

Not measured, assigned by the evidence each gives. The relay's design needs these first, since
what VS Code runs on a channel decides what the relay refuses there, and each is measured with
the hostile host and no account: a client tool call within a turn the host completes; a forwarded
MCP server with a tool call routed to it; the messages VS Code sends for an `authRequired` MCP
server, up to the sign-in it asks for; whether Always Allow persists a grant into the profile,
moot if the design refuses the reverse `resource*` requests; and a push after a `reconnect` the
host accepts, with the test token, since the connect-time route honors it. These are step 4's
acceptance stages, each with its credential: the `auth/required` notification, whose handler
resolves a real session, so a throwaway account; `AuthRequired` on `createSession` on the chat
handler's retry path, where interactive resolution takes the test token for the agent's advertised
resources, which the connect-time route has pushed and the token cache does not forward twice
(`AgentHostAuthTokenCache`), so a distinct push there needs a stage design of its own; the
`authRequired` MCP route's token,
which `resolveMcpServerAuthentication` takes from a real session, so a throwaway account; and a
real signed-in session's token on the connect-time route, so a throwaway account.

VS Code settings that bear on these operations, read in the 1.138.0 source. A setting counts only
if VS Code itself checks it; one it mirrors into the host's config, a hostile host ignores.

- Token push: no setting. `_authenticateWithConnection` (`remoteAgentHost.contribution.ts`) pushes
  the sessions it resolves for every advertised resource, checking only for the test token. VS
  Code sends nothing for a resource it resolves no session for, and `chat.remoteAgentHostsEnabled`
  off disables remote hosts altogether.
- Reverse file operations: `chat.agentHost.localFilePermissions` lists granted URIs per host, `r`
  or `rw`, each covering descendants; it has no deny entry. Outside a grant VS Code refuses, and the
  host can ask for the banner.
- Client tools: the list VS Code sends is filtered by a per-session-type tool enablement kept in
  profile storage and edited in the Tools section of Chat Customizations; every tool is on by
  default (`agentHostActiveClientService.ts`). The source comment names the Copilot CLI session
  type as that section's only target; whether it applies to a remote host's sessions is unverified.
- MCP: `chat.agentHost.githubMcpServer.enabled` is mirrored into the host's config, so the host
  decides. No setting gates the synced customizations.
- URL elicitation: no setting; VS Code opens the URL only on Open, with commands disallowed.

Decision: VS Code's own controls leave the credential route open, with no setting that closes it
short of disabling remote hosts, so the launcher-owned filtering relay below is needed. ACP stays
deferred provisionally: the operations the relay must refuse are ones this step names, but whether
sessions stay usable with them refused, without further protocol handling, is for the relay's
design and tests to establish. The operations under "Not measured" stay open where that list
assigns them.

The relay interprets the WebSocket frames, forwards state and chat, and refuses the named
operations. For credentials the enforcement is on the `authenticate` messages themselves: every one
refused, whatever the resource, because a resource name such as `https://api.github.com` says
nothing about which account, credential or scopes the user authorized. An exception is a
credential-selection decision of its own, outside this plan; the harness of step 3 authenticates
from the volume. Stripping `protectedResources` from the root state removes one of the four
asking routes, so it spares VS Code a refused push and enforces nothing. The relay gets a design
of its own before code. It is not a session server: AHP's state, reducers and reconciliation stay
the Agent Host's.

An Agent Host setting inside the sandbox is not enforcement in this step: the hostile host ignores
it.

## Step 3: one harness

For a harness with a credential the sandbox owns, the Claude harness on
`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`:

- the session "Add Remote Agent Host..." opens on the project, measured here rather than in
  step 1 because a session needs an agent with credentials in the host;
- authentication: the credential's source and place in the volume, whether the CLI's login there
  is reused, and what VS Code pushes although the credential is in the volume;
- which tools run inside the host process, and that none runs on the host;
- the destinations it opens, by observation, each assigned to a feature;
- what ends when VS Code disconnects, when the launcher exits, and when the sandbox is killed;
  the run removed as for a terminal session.

## Step 4: implement

Built only when steps 1 to 3 pass. The shape, to be settled then:

    java -jar ko-agent-sandbox.jar [options] --protocol=ahp -- code agent host ...

`--protocol` selects the transport, the token and the filter; the command selects the host. The
provider its egress admits needs a decision of its own: `EgressRules.AgentProviders` maps the
agent commands to their providers and `code` is not among them. Under `deny-unless-model` a
launch of `code agent host` therefore selects no provider and allows no host, project allow lines
included; under the default profile the defaults admit every supported provider, and the
project's file follows (egress-proxy.md, "Choosing an egress profile"). Neither the command nor
the harness determines the provider: the Claude harness offers Anthropic-native and
Copilot-routed models and switches between them within a session. Under `deny-unless-model` the
launch therefore names the permitted provider route or routes explicitly, in an option settled
in this step, and a harness's models on any other route fail at the proxy; under the default
profile the ruleset decides as it does for any agent. The destinations each route needs are step
3's measurement.

The launcher prints the address and token for "Add Remote Agent Host...", or writes the
`chat.remoteAgentHosts` entry when that is measured to be safe. The other session options keep
their meaning. The launcher stays resident, on the path Windows uses, for as long as it owns the
listener or the filter.

Acceptance: the hostile host of step 2 obtains nothing on the host through VS Code, in the
launch matrix of `--write=reject` and `live`, `--egress=deny-unless-model`, the protected `.git`
entries and `.ko-agent-sandbox`, `--run-on-host` and every ending of step 3. The token routes step 2
leaves without a positive control get one stage each, on a fresh connection, with the credential
step 2 names for it: a connection made while a throwaway account is signed in, for the
connect-time route; then one challenge per remaining route, fired alone, against a resource the
connection has not pushed, so that the relay's timestamped report of the `authenticate` it refused
belongs to that challenge. In every stage the hostile host's log holds no token. The stage for
`AuthRequired`, which must reach the chat handler's retry path and draw a push the token cache
does not suppress, is settled in the relay's tests. The exact VS Code and AHP versions tested are
recorded in the documentation.

## Phases

0. Step 1, measured above, and the hostile host of step 2 written against the spec's channels.
1. Step 2's measurements, recorded above, and the filtering relay's design, which they call for.
2. Step 3.
3. Step 4, with the documentation: a usage section in the README, the refused operations under a
   heading of their own in SECURITY.md, and `doc/vscode.md` for the setup.
4. Further harnesses, each through step 3.
5. ACP, on the conditions above, along "Deferred: ACP".

## Non-goals

- The IDE's file system, terminals, browser or MCP servers reachable from the sandbox.
- The IDE's credentials forwarded into the sandbox, on any route, without a credential-selection
  decision of its own.
- More than one project root, or a project other than the launch directory.
- An SSH daemon, a dev tunnel or a Dev Container conversion for IDE integration; the Dev Container
  path gets a design of its own if wanted, since VS Code would own the container's start.
- A session server written here.

## Deferred: ACP

The design as reviewed, for when the track is reopened.

### The interface

    java -jar ko-agent-sandbox.jar [options] --protocol=acp -- opencode acp
    java -jar ko-agent-sandbox.jar [options] --protocol=acp -- copilot --acp

The IDE's custom-agent entry runs one of these lines, with the project directory as the working
directory: the launcher takes the project from it, as for a terminal launch. `--protocol` selects
the transport and the relay's policy; the command after `--` selects the agent and, as for a
terminal launch, the provider its egress admits. The other session options keep their meaning.

There is no launcher-owned alias from an agent name to its ACP command line. The agent's own
documented invocation is what the user configures, its first word is what selects the provider,
and an alias would be a second place to keep both.

Sign-in stays a terminal launch: run the agent's documented sign-in from the README in an ordinary
session, and the protocol session finds the credential in the shared volume.

### What protocol mode changes in the launcher

- The container is created without `-t`; `-i` stays. Without a pseudo-terminal the agent's stdout
  reaches the IDE byte for byte, and the entrypoint skips its pause without a terminal.
- The launcher stays resident, on the path Windows uses, and relays between the IDE's pipes and
  podman's stdio instead of inheriting them. The relay lives on the host because every process in
  the sandbox is untrusted (design.md, "Services run as processes, not as multi-uid nested
  containers"); a filter inside the sandbox would be the agent's to bypass.
- End of file on the IDE's pipe ends the session as Ctrl-C ends a terminal one; the reaper removes
  the run as for a terminal session.
- `--run-on-host`'s offer to provision a launcher is a prompt; without a terminal it is declined.
- The launch lines and the relay's refusals go to stderr, which the IDE captures as the agent's
  log.

### The relay's policy

The relay forwards what is listed here and nothing else. The client is the trusted side, so a
message from it is forwarded after the field checks below; a message from the agent is forwarded
only when named, because only what the agent asks of the client can widen its authority.

From the client to the agent:

- `initialize`: `fs.readTextFile`, `fs.writeTextFile`, `terminal`, `auth.terminal` and
  `elicitation.url` set to false or removed; `elicitation.form` and the rest forwarded.
- `session/new`, `session/load` and `session/resume`: `cwd` checked and translated as "Paths"
  says; a non-empty `additionalDirectories` or `mcpServers` refused.
- `session/prompt`: paths in `resource_link` and `resource` content translated; the rest forwarded.
- Every other v1 method, every underscore-prefixed method, every notification, and every response
  to an agent's request: forwarded.

From the agent to the client:

- `initialize` result: `terminal`-type authentication methods and `_meta.terminal-auth` removed.
- `session/request_permission`: forwarded.
- `elicitation/create` with `mode: form`: forwarded. With `mode: url`: refused. The client shows
  the full URL and asks consent, but the browser is a host program opening a URL the agent
  composed, a request the ruleset never sees; the sign-ins that need a browser have their
  terminal launch.
- `fs/*`, `terminal/*`, underscore-prefixed and unknown requests: refused with a JSON-RPC error
  naming the relay, whatever the agent was told in `initialize`.
- `session/update`: forwarded, with the paths in tool call `locations` and in diff content
  translated. `elicitation/complete` and every other notification: dropped.
- Every response to a client's request: forwarded.
- `_meta`, on every message and nested object from the agent: removed, except the trace keys
  `traceparent`, `tracestate` and `baggage`. An agent's extension data is what a client acts on
  outside the reviewed surface, `terminal-auth` being the measured case.

Why each refusal:

- The client's file system and terminals are the host's. A `terminal/create` from the sandbox is
  the shortcut `--run-on-host` exists to prevent (SECURITY.md, "Run on host"): a host command with
  the IDE's authority, not a confined one.
- `additionalDirectories` widens the root set past the project, which only the mount decides.
- A stdio MCP entry names a host path and environment for the agent to run; an `http` entry
  carries the IDE's headers, so its credentials, to a host the ruleset may or may not admit. A
  sandbox-owned MCP configuration is `plan-executable-agent-configuration.md`'s subject, not the
  IDE's to supply.
- A `terminal` authentication method has the IDE run the launcher again with the method's `env`,
  which reaches the sandbox only through `--env`; the launcher cannot tell the method's variables
  from the IDE's. Copilot's `_meta.terminal-auth` names a path inside the image, which a client
  honoring it would run on the host.

The relay does not log message bodies. It forwards only a protocol version it has a policy for,
and refuses the `initialize` of any other, since a version whose client surface it does not know
is one it cannot filter. `--protocol=acp` stays version-neutral: ACP v2 is added as a second
policy as soon as Zed and one installed agent negotiate it end to end, whatever the release label,
and the policy is derived from v2's own client surface, not carried over from v1.

### Paths

The IDE spells paths as the host does; the sandbox spells them as the mount does. The relay
translates in the fields it knows and refuses what does not translate:

- Into the sandbox: `cwd`, and the paths in `session/prompt` content. Each is canonicalized on the
  host, must be the project directory or inside it, and is respelled with `mountPathOf` (identity
  on macOS and Linux, `C:\...` to `/mnt/c/...` on Windows). A path outside the project refuses the
  message with both spellings.
- Out of the sandbox: tool call `locations[].path` and diff `path` in `session/update`, respelled
  by the inverse. On macOS and Linux that is the real path, which differs from an IDE's symbolic
  spelling; the first phase measures whether Zed matches its buffers by it.
- A path in a field the relay does not know passes untranslated: the IDE then shows a wrong path,
  and gains nothing.

The test therefore expects `cwd` to equal the launch directory's sandbox mount path. Protocol mode
on native Windows is released only after the inverse translation is tested there; until then a
Windows launch with `--protocol` is refused with that reason.

### Tests

Each policy line above is a test, with a fake agent on the sandbox side and a scripted client on
the IDE side:

- capabilities rewritten in `initialize`, and `fs/*`, `terminal/*`, `elicitation/create` in URL
  mode, an underscore-prefixed and an unknown request each refused although the fake agent was
  told otherwise;
- `terminal` authentication methods and `_meta.terminal-auth` absent from the result the client
  sees, and `_meta` stripped from a `session/update` while its trace keys survive;
- `additionalDirectories` and `mcpServers` refused on each of `session/new`, `session/load` and
  `session/resume`; `cwd` outside the project refused; `cwd` inside it arriving as the mount path;
- a `session/update` path respelled for the IDE; an unknown notification dropped.

The fake agent, in the test sources and launched as the backend command, reports what each session
request carried and attempts the refused calls.

The launch matrix through the relay:

- `--write=reject` and `live`; a protected `.git` entry and `.ko-agent-sandbox` refused as in a
  terminal session;
- `--egress=deny-unless-model` with the backend's provider selected by the command's first word;
- a credential from a terminal-launch sign-in found by the protocol launch;
- `--run-on-host` through the relay, its provisioning offer declined without a terminal;
- end of file on stdin ending the session and the reaper removing the run; the IDE process killed
  with the launcher; the proxy or the backend dying;
- stdout parsing as JSON-RPC lines from its first byte.

Then by hand, recorded here: Zed with `opencode acp`, an edit, a command, cancel, restart, and a
Zed-configured MCP server refused visibly; then `copilot --acp`; then JetBrains with the same
command line, whose documentation is unread, so its behavior is measured, not assumed.

### Phases, when reopened

1. Measure Zed: the working directory it launches the command with, what its `session/new`
   carries, whether it sends `additionalDirectories` or its MCP servers, whether it starts one
   agent process per thread or per project, how it shows a refused request, and whether it
   matches buffers by real path.
2. `--protocol=acp` in the launcher: creation without `-t`, the resident relay, the reference text
   and the launch matrix.
3. The relay's policy, the path translation and the fake-agent tests.
4. Zed with `opencode acp`; then `copilot --acp`; documentation as for AHP, in `doc/acp.md`.
5. JetBrains.
6. Further backends as they appear in the image: Codex and Claude reach ACP through separate
   adapter programs, unverified.
7. ACP v2, once Zed and one installed agent negotiate it: read its client surface, write the
   second policy, extend the fake agent to v2, and keep v1 for the clients still on it.

## Sources

- https://github.com/microsoft/agent-host-protocol/blob/main/CHANGELOG.md
- https://github.com/microsoft/agent-host-protocol/tree/main/docs (`guide/ahp-and-acp`,
  `guide/terminals`, `guide/mcp`, `specification/transport`, `specification/authentication`)
- https://github.com/microsoft/vscode-docs/tree/main/docs/agents (`concepts/agent-host`,
  `run/agent-harnesses`, `run/remote-agent-sessions`)
- https://github.com/microsoft/vscode/tree/1.138.0/src/vs/sessions/contrib/providers/remoteAgentHost
  (`browser/remoteAgentHostActions.ts`, `browser/remoteAgentHost.contribution.ts`,
  `REMOTE_AGENT_HOST_SESSIONS_PROVIDER.md`)
- https://github.com/microsoft/vscode/tree/1.138.0/src/vs/platform/agentHost/common
  (`remoteAgentHostService.ts`, `agentHostClientFileSystemProvider.ts`)
- https://github.com/microsoft/vscode/blob/1.138.0/src/vs/workbench/contrib/chat/browser/agentSessions/agentHost/agentHostAuth.ts
- https://github.com/microsoft/vscode/tree/1.138.0/cli/src/commands (`args.rs`, `agent_host.rs`,
  `agent_relay.rs`)
- https://github.com/agentclientprotocol/agent-client-protocol/blob/main/CHANGELOG.md
- https://github.com/agentclientprotocol/agent-client-protocol/tree/main/docs/protocol/v1
  (`overview`, `transports`, `initialization`, `session-setup`, `file-system`, `terminals`,
  `authentication`, `elicitation`, `extensibility`)
- https://github.com/agentclientprotocol/rust-sdk/blob/main/md/protocol-v2.md
- https://github.com/zed-industries/zed/blob/main/docs/src/ai/external-agents.md
- https://www.jetbrains.com/help/ai-assistant/acp.html (unread)
