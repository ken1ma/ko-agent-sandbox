# Plan: IDE integration through VS Code's Agent Host Protocol

VS Code's Agents window drives an agent whose runtime, tools and credentials stay in the sandbox.
VS Code reaches the agent through the Agent Host Protocol (AHP):

- a host process owns the sessions;
- clients connect to the host over a WebSocket.

This plan investigates that integration in three steps, and implements it when the steps pass. The
Agent Client Protocol (ACP) connects one client and one agent over the agent's stdio. ACP is
deferred; "Deferred: ACP" keeps its design for when the ACP track is reopened.

Every step serves one requirement: a compromised process inside the sandbox cannot make VS Code
exercise host authority that the user did not grant.

- Every process in the sandbox is untrusted. Enforcement therefore lives in VS Code or in a
  launcher-owned filter on the host, never in a setting that the sandbox side honors.
- A host that ignores its configuration still sends protocol messages.

## What is read and measured

Read and measured on 2026-09-22 and 2026-09-23. The VS Code documents carry an approval date of
2026-09-16; the VS Code source is release 1.138.0.

VS Code and AHP:

- The spec release is 0.9.0 of 2026-08-28. Breaking changes may land in minor versions until 1.0.0.
- The user guide describes three ways for VS Code to reach a remote Agent Host:
  - through SSH, where VS Code installs its own CLI on the remote machine;
  - through a dev tunnel;
  - inside the workspace's Dev Container.
- The source has a fourth way, the Agents window's command "Add Remote Agent Host..."
  (`remoteAgentHostActions.ts`, `remoteAgentHost.contribution.ts`, `remoteAgentHostService.ts`):
  - the command takes a host, `host:port` or a WebSocket URL such as
    `ws://127.0.0.1:8080?tkn=abc-123`;
  - the command stores the address under the `chat.remoteAgentHosts` setting, with an optional
    `connectionToken`, and connects to it;
  - the command exists while `chat.remoteAgentHostsEnabled` is on, which it is by default;
  - the settings are tagged experimental.
- `code agent host` runs the host (`cli/src/commands/`):
  - by default it binds `localhost` on an ephemeral port;
  - it takes `--connection-token` or `--connection-token-file`, `--server-data-dir` and
    `--foreground`;
  - it downloads the VS Code server release when its data directory lacks it.
- `code agent relay <instance-id>` copies stdin and stdout to a running host's endpoint verbatim,
  and interprets nothing. The relay exists for use as an SSH `ProxyCommand`.
- The Dev Container path runs VS Code's bundled devcontainers CLI on the host
  (`REMOTE_AGENT_HOST_SESSIONS_PROVIDER.md`):
  - `devcontainer up`;
  - the VS Code remote CLI, installed inside the container;
  - the host's WebSocket, relayed over `devcontainer exec` stdio.
- What the host can ask of VS Code, the client surface found so far:
  - tools that a connected client contributes, VS Code's own and its extensions', which the host
    routes back to that client;
  - the read-only `vscode-agent-client://` filesystem, whose `browseDirectory` and `fetchContent`
    the connection proxies back to the client (`agentHostClientFileSystemProvider.ts`);
  - the MCP servers configured in the editor, which VS Code forwards to the host;
  - bearer tokens, in the next item.
- VS Code pushes bearer tokens, and the host has three further ways to ask for one
  (`agentHostAuth.ts`, `remoteAgentHost.contribution.ts`):
  - The push: on every connection change, and when the default account changes, VS Code resolves
    its existing sign-in sessions for each protected resource that the host's agents advertise.
    VS Code pushes the tokens with `authenticate`.
  - An `AuthRequired` error, code `-32007`, which any command may return with the resources in its
    data.
  - The `auth/required` notification, for an expired token or a new requirement. VS Code answers
    the notification by recovering a session for the named resource.
  - The `authRequired` state of an MCP server or a tool call.
  - The specification's example is a GitHub token for the Copilot agent.
  - With the smoke-test driver enabled and `chat.agentHost.unsafeTestToken` set, VS Code pushes
    that string instead of a real session on two paths: the discovery pass over the agent list,
    and interactive resolution. The `auth/required` handler recovers a real session regardless.
  - The connection token is separate from all of these.
- The host runs terminals as its own pseudo-terminals, so a host inside the sandbox would run them
  inside the sandbox.
- The Copilot harness uses VS Code's GitHub session. The Claude harness can instead read
  `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`. Codex on the Agent Host is experimental.
- The image installs the `code` CLI at `/usr/local/bin/code` (Containerfile, "VS Code CLI").

ACP, for the deferred track:

- The stable protocol version is 1. The changelog's release 1.9.1 of 2026-09-18 carries
  `unstable-v2` entries, so v2 is a draft.
- Over the stdio transport, the agent reads JSON-RPC from stdin, writes JSON-RPC to stdout and
  writes logs to stderr. The agent must write nothing else to stdout.
- What the agent may ask of the client, the v1 client surface:
  - `session/request_permission`, always;
  - `fs/read_text_file` and `fs/write_text_file` on the client's filesystem, including unsaved
    editor buffers;
  - `terminal/create`, `output`, `wait_for_exit`, `kill` and `release`, which run a command in the
    client's environment;
  - `elicitation/create`, either in form mode, where the user fills in a schema, or in URL mode,
    where the client shows the full URL, obtains consent and opens a browser on it.

  The client advertises each of these in `initialize`, with `auth.terminal` beside them. The
  agent's notifications to the client are `session/update` and `elicitation/complete`.
- Extensions go both ways: `_meta` on most request, response, notification and nested types, and
  methods named with a leading underscore. An unknown request is answered "method not found"; an
  unknown notification is ignored.
- `session/new`, `session/load` and `session/resume` carry an absolute `cwd` and an `mcpServers`
  list.
  - When the agent advertises `sessionCapabilities.additionalDirectories`, these requests also
    carry `additionalDirectories`, which widen the session's root set.
  - A stdio MCP entry names an absolute command path, arguments and environment for the agent to
    spawn. An `http` or `sse` entry names a URL and headers.
- A `terminal` authentication method makes the client launch the configured agent command again in
  an interactive terminal, with the method's `args` appended and its `env` applied.
- In the image, `copilot --acp` (Copilot CLI 1.0.87) and `opencode acp` (OpenCode 1.18.32) answer
  an `initialize` on stdout, with nothing on stderr.
  - Both advertise `loadSession`, and the `http` and `sse` MCP transports.
  - Copilot's authentication method carries a `_meta.terminal-auth` entry that names
    `/usr/local/bin/copilot login`.
  - `claude` 2.1.278 and `codex` 0.155.1 have no ACP mode of their own.
- Zed runs a custom agent from `agent_servers.<name>` in its settings: `type: custom`, `command`,
  `args`, `env`.
  - Zed's documentation says that Zed-configured MCP servers may be forwarded to the agent over
    ACP.
  - The same documentation says that Zed's `dev::OpenAcpLogs` action shows the messages exchanged.
- JetBrains' ACP documentation is unread; nothing here about JetBrains is verified.

The launcher:

- The launcher creates the container with `-it`. On POSIX it then execs
  `podman start --attach --interactive`. On Windows, and wherever exec is unavailable, the launcher
  stays resident and waits for podman (`SandboxLifecycle.handOver`).
- Every launch line goes to stderr, as do the entrypoint's warnings. The entrypoint's start pause
  needs a terminal on stdin.
- Under egress, the command's first word and `--model-provider` select the model providers that a
  launch admits (`EgressRules.selectedProvider`). `copilot` is recognized, and `opencode` is refused
  without the option.
- No host process accepts a connection from the sandbox: the clipboard relay and the runner read
  FIFOs through `podman exec` (SECURITY.md, "Clipboard" and "Run on host"). The listeners that
  SECURITY.md documents, the per-program egress proxy and the ports of the mill and Gradle daemons,
  serve host processes.
- The workspace root is mounted at its real path on macOS and Linux. On Windows the root is mounted
  at `/mnt/<drive>/...`, the spelling that `SandboxWorkspace.mountPathOf` derives from `C:\...`.
  - An IDE that opened the workspace through a symbolic link sees a different spelling from the
    sandbox's. design.md, "Prior-art references worth retaining", records that open item.

## Decision: AHP is the active investigation; ACP is deferred

The native VS Code panel is the integration wanted, and released source can attach it by address.
So the investigation that decides whether that outcome is practical comes first.

This order is sequencing, not a finding that ACP is the harder track:

- ACP's work is identified: the stdio lifecycle, the relay's policy, authentication handling and
  paths.
- AHP's harder questions stay open until step 2: how to stop client operations and credential
  pushes from a host treated as hostile.
- Implementing ACP first would spend the work before it is known whether ACP's editors are wanted.

ACP is the fallback, with its design kept under "Deferred: ACP". ACP is reopened, and its
identified work compared against AHP's measured cost, under either of these conditions:

- step 2 shows that AHP needs a filtering relay beyond refusing the named operations;
- step 3 shows that no harness authenticates from the volume.

ACP is also reopened on its own when Zed or JetBrains support is wanted.

## Step 1: attachment

What to run and record, on VS Code 1.138.0 or the release current at the time:

- `code agent host --foreground --connection-token-file ...` inside the image. Record:
  - the server download it needs, and so the image change and the destination to admit;
  - the paths it writes;
  - every other destination it opens, each assigned to a feature before a rule admits it.
- The transport to the host, with two candidates:
  - the sandbox's port published on the host's loopback, which the internal network may not allow;
  - a launcher-owned loopback listener that relays each connection through
    `podman exec code agent relay <instance-id>`.

  Neither transport is implemented. Record which one works and what it exposes to other local
  users. The launcher generates the connection token per run.
- "Add Remote Agent Host..." against that endpoint, with the token.

Until the filtering relay of step 2 stands between them, the VS Code that attaches runs with a fresh
`--user-data-dir`, no account signed in and no extension installed.

- Step 2's source pass finds no setting that stops a token push while keeping remote hosts. An
  attachment with an account before the relay is therefore the forwarding that the investigation
  exists to prevent.
- Where any step needs a token, the token is never the user's session. On the routes that honor the
  smoke-test driver's `chat.agentHost.unsafeTestToken`, the token is that string. On the other
  routes, the token comes from a throwaway account created for the test.

Measured on 2026-09-23: VS Code 1.138.0 on macOS attached to the host, in a sandbox launched on the
default egress profile.

- Downloads:
  - The CLI comes from `https://update.code.visualstudio.com/latest/cli-linux-arm64/stable`. For
    this measurement the CLI was installed under `~/.local/bin`.
  - The host's server download comes from the same host's
    `/commit:<commit>/server-linux-arm64/stable`.
  - Both answer with a redirect to `vscode.download.prss.microsoft.com`, so the feature "VS Code
    CLI and server download" needs `read` rules for both hosts.
  - The server archive is 210 MB. The host is ready 51 s after start when it downloads the server,
    and 14 s after start when the server is cached.
  - The image installs the CLI (Containerfile, "VS Code CLI"). The server is downloaded at first
    start, through the proxy's default rules (`defaults/host`, "VS Code").
- Writes, all discarded with the session:
  - the server under `~/.vscode/cli/servers/`;
  - server data, extensions and the supervisor log under `~/.vscode-server/`;
  - the endpoint registry under `~/.config/Code/agent-host/`;
  - a cache under `~/.cache/Microsoft/`;
  - three sockets in `/tmp`.
- Other destinations: the host POSTs telemetry to `mobile.events.data.microsoft.com`. The proxy
  refuses the telemetry and the host continues, so no rule admits it. The host also streams its log
  records to the client over the protocol (`otlp/exportLogs`).
- Listener: `127.0.0.1:31546` only, the port given with `--port`. The supervisor checks the
  connection token at the WebSocket handshake. The handshake answers `101` with `?tkn=<token>`, and
  `403 Forbidden: missing or invalid connection token` without it.
- Transport: the exec relay works with no launcher change. On the host, a loopback listener runs
  one relay per connection:

  ```sh
  socat TCP-LISTEN:31546,bind=127.0.0.1,reuseaddr,fork \
    EXEC:"podman exec -i <container> /home/nonroot/.local/bin/code agent relay \
      --user-data-dir /home/nonroot/.config/Code <instance-id>"
  ```

  - The command above is tested with the CLI installed under `~/.local/bin`. With the image's CLI
    the path is `/usr/local/bin/code`. That form is untested, as is the form without absolute
    paths.
  - A relay that the launcher runs adds `--detach-keys=`, which the launcher passes to every exec
    that attaches stdin (`HostCommands.ExecWithInput`).
  - `code agent endpoints` in the sandbox prints the instance id and the token.
  - The listener accepts any local process; the connection token is what refuses other processes.
    VS Code keeps the token in the profile's settings, under `chat.remoteAgentHosts`.
  - The published-port candidate is untried.
- Attachment:
  - The Agents window opened with a fresh `--user-data-dir` and `--extensions-dir`, signed out,
    with `chat.agentHost.allowSignedOutWhenUsable` set beforehand. Whether the window needs that
    setting is not measured.
  - The command is a Command Palette entry of the Agents window, listed as "Agents: Add Remote
    Agent Host...". The command takes the `ws://` URL, then a display name, and connects at once.
  - The workspace dropdown's Remote tab and "Agents: Manage Remote Agent Hosts..." list the host as
    Online, with a folder picker on the host.
- The protocol log under `~/.vscode-server/data/logs/<start>/ahp/` records the exchange. Over two
  and a half hours, the client, `vscode-agents-window` on protocol 0.9.0, sent these messages:
  - `initialize` and `listSessions`;
  - two `subscribe` calls, for the host's log channel and for its automations;
  - nine `dispatchAction` calls that push 35 VS Code settings as host configuration. Among them are
    the terminal auto-approve rules, workspace trust, the telemetry level, and a `sandbox` block
    set to off with network allowed. That `sandbox` block is the Agent Host setting that step 2
    names;
  - a ping every five seconds.
- The host advertises `protectedResources` for both of its agents: GitHub, required for Copilot and
  optional for Claude.
- The log holds no `authenticate` request, no `auth/required` notification and no `AuthRequired`
  error: no bearer token crossed in this signed-out attachment.
- No message carries the workspace root's path, and no session exists.

## Step 2: enforcement outside the sandbox

Step 2 is the deciding test. A hostile host, a script that speaks AHP in place of
`code agent host`, stands in for the compromised sandbox and tries each client operation. What
stops the hostile host must be VS Code or the launcher's filter. For each operation, record what
VS Code does by default, what a VS Code setting prevents, and what remains:

- a bearer token, requested by each route the host has:
  - protected resources advertised in the agent list, before any session is selected and again
    after one is;
  - an `AuthRequired` error on an ordinary command;
  - an `auth/required` notification;
  - an `authRequired` MCP server and tool call;
  - each of these again after a root-state update and after a reconnection, because the
    notification is not replayed and VS Code checks again on reconnect.

  Each route needs a positive control, so that a signed-out client that sends nothing cannot pass
  as enforcement.
  - The decision rests on the connect-time route's control: the hostile host records the test token
    when nothing enforces.
  - The routes whose control needs an account are delivered in step 4's acceptance, behind the
    relay. There the evidence is the relay's report of the `authenticate` it refused on the client
    side, and a hostile-host log that holds no token.
- a client tool call, VS Code's own and an extension's;
- `browseDirectory` and `fetchContent` on host paths outside the workspace;
- a forwarded MCP server, and a tool call routed to it;
- every other client-executed operation that the spec's channels define. The list above is what the
  source read so far shows, not the whole surface.

The hostile host is `src/probe/ahp-hostile-host.py`. The script runs with
`uv run --with websockets`, and VS Code attaches to it through "Add Remote Agent Host...". The
hostile host:

- advertises two agents with protected resources;
- after `initialize`, sends an `auth/required` notification and the reverse `resource*` requests
  for host paths: `resourceResolve`, `resourceList`, `resourceRead`, `resourceWrite`,
  `resourceMkdir`, `resourceDelete` and `createResourceWatch`. Write, mkdir and delete act only on
  a probe file under the host's `/tmp`;
- answers `createSession` for Copilot with `AuthRequired`;
- then broadcasts its agent list with one resource added;
- with `--grant-path`, follows a refused read with `resourceRequest`, and reads again;
- when the operator starts a turn, sends a client-contributed tool call that names a tool the client
  offered, and a URL-mode elicitation;
- serves the container's own files read-only, for the Remote tab's folder picker;
- records every frame to a JSONL log.

Measured on 2026-09-23: VS Code 1.138.0 on macOS attached to the hostile host, signed out except
where the test token is named. Sessions were opened from the workspace dropdown's Remote tab, on the
container's `/home/nonroot`. Sessions on a Local folder sent the hostile host nothing.

- Reverse file operations for `/etc/passwd`, `/home/nonroot` (absent on macOS) and a `/tmp` file
  returned `PermissionDenied` (-32009) carrying the grant request, with no content.
  - VS Code leaves `createResourceWatch` from the host unhandled (-32000).
  - When the host follows a refused read with `resourceRequest`, VS Code shows a banner that names
    the host and the full path, with Deny, Allow and the highlighted Always Allow. After the user
    chose Allow, the request returned `{}`.
  - On the next connection to the same address in the same window, the same request returned `{}`
    within 4 ms with no banner, and a read then returned the file's bytes.
  - The source says that Allow lasts "for the lifetime of the connection"; what that covers is
    unverified.
- `createSession` for Copilot reached the host, which answered `AuthRequired`. No `authenticate` and
  no second `createSession` followed, in the signed-out runs and in the test-token runs.
  - The request followed `resolveSessionConfig`. The request carries the argument set of the
    sessions provider's eager creation (`baseAgentHostSessionsProvider.ts`), which logs a warning
    on an error and stops.
  - These runs did not reach the chat handler's path, which resolves authentication and retries
    `createSession` once (`agentHostSessionHandler.ts`). So the runs say nothing about that path.
- `createSession` carried 15 client tools, the integrated-browser and automation set. The request
  also carried a synced customization that names a GitHub MCP server without its command, URL,
  environment or headers. Opening the session raised VS Code's workspace-trust prompt for the host
  folder.
- A `chat/inputRequested` with a `url` rendered an "Authorization Required" card, which showed the
  full URL with Open and Cancel. VS Code opened nothing. The user's Cancel reached the host as
  `chat/inputCompleted` with `decline`.
- A client-contributed tool call naming `toolSearch` rendered as a card. VS Code ran nothing and
  returned no result. The host sent only the call's start and ready actions.
- Signed out, no token crossed on the three token routes exercised: resources advertised at
  connect, the `auth/required` notification, and `AuthRequired` on `createSession`.
- With `--enable-smoke-test-driver` and `chat.agentHost.unsafeTestToken` set, VS Code pushed that
  token within 0.5 s of each `initialize`, to both advertised resources, including the one marked
  optional. VS Code pushed before any session existed and without a prompt.
  - The push held on four connections. On two of them, VS Code first sent `reconnect`, which the
    hostile host refuses, then a fresh `initialize`.
  - VS Code pushed for a new resource 3 ms after the host added the resource to its agent list
    (`root/agentsChanged`).
  - That push is the driver's test-token path. That VS Code forwards a signed-in session's token the
    same way is read from source (`agentHostAuth.ts`), not measured.

Not measured, assigned by the evidence each item gives:

- The relay's design needs these items first, because what VS Code runs on a channel decides what
  the relay refuses there. Each is measured with the hostile host and no account; the last also
  takes the test token, since the connect-time route honors it:
  - a client tool call within a turn that the host completes;
  - a forwarded MCP server, with a tool call routed to it;
  - the messages VS Code sends for an `authRequired` MCP server, up to the sign-in it asks for;
  - whether Always Allow persists a grant into the profile, which is moot if the design refuses the
    reverse `resource*` requests;
  - a push after a `reconnect` that the host accepts.
- These items are step 4's acceptance stages, each with its credential:
  - the `auth/required` notification: its handler resolves a real session, so the stage needs a
    throwaway account;
  - `AuthRequired` on `createSession`, on the chat handler's retry path: interactive resolution
    takes the test token for the agent's advertised resources. The connect-time route has already
    pushed those resources, and the token cache does not forward a token twice
    (`AgentHostAuthTokenCache`). So a distinct push there needs a stage design of its own;
  - the `authRequired` MCP route's token: `resolveMcpServerAuthentication` takes the token from a
    real session, so the stage needs a throwaway account;
  - a real signed-in session's token on the connect-time route, which needs a throwaway account.

VS Code settings that bear on these operations, read in the 1.138.0 source. A setting counts only
if VS Code itself checks it. A hostile host ignores a setting that VS Code mirrors into the host's
config.

- Token push: no setting.
  - `_authenticateWithConnection` (`remoteAgentHost.contribution.ts`) pushes the sessions it
    resolves for every advertised resource, and checks only for the test token.
  - VS Code sends nothing for a resource it resolves no session for.
  - `chat.remoteAgentHostsEnabled` set to off disables remote hosts altogether.
- Reverse file operations: `chat.agentHost.localFilePermissions` lists granted URIs per host, each
  `r` or `rw`, and each grant covers its descendants. The setting has no deny entry. Outside a grant
  VS Code refuses, and the host can ask for the banner.
- Client tools: a per-session-type tool enablement filters the list that VS Code sends
  (`agentHostActiveClientService.ts`).
  - The enablement is kept in profile storage and edited in the Tools section of Chat
    Customizations. Every tool is on by default.
  - The source comment names the Copilot CLI session type as that section's only target. Whether
    the section applies to a remote host's sessions is unverified.
- MCP: VS Code mirrors `chat.agentHost.githubMcpServer.enabled` into the host's config, so the host
  decides. No setting gates the synced customizations.
- URL elicitation: no setting. VS Code opens the URL only on Open, with commands disallowed.

Decision: VS Code's own controls leave the credential route open, and no setting closes it short of
disabling remote hosts. So the launcher-owned filtering relay below is needed.

- ACP stays deferred provisionally. Step 2 names the operations that the relay must refuse. Whether
  sessions stay usable with those operations refused, without further protocol handling, is for the
  relay's design and tests to establish.
- The operations under "Not measured" stay open where that list assigns them.

The relay interprets the WebSocket frames, forwards state and chat, and refuses the named
operations.

- For credentials, the relay enforces on the `authenticate` messages themselves: it refuses every
  one, whatever the resource. A resource name such as `https://api.github.com` says nothing about
  which account, credential or scopes the user authorized.
- An exception would need a credential-selection decision of its own, outside this plan. The harness
  of step 3 authenticates from the volume.
- Stripping `protectedResources` from the root state removes one of the four asking routes. The
  stripping spares VS Code a refused push, and enforces nothing.
- The relay gets a design of its own before code.
- The relay is not a session server: AHP's state, reducers and reconciliation stay the Agent
  Host's.

An Agent Host setting inside the sandbox is not enforcement in this step: the hostile host ignores
it.

## Step 3: one harness

For a harness with a credential that the sandbox owns, the Claude harness on
`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`, record:

- the session that "Add Remote Agent Host..." opens on the workspace. The session is measured here
  rather than in step 1, because a session needs an agent with credentials in the host;
- authentication: the credential's source and place in the volume, whether the CLI's login there
  is reused, and what VS Code pushes although the credential is in the volume;
- which tools run inside the host process, and that none runs on the host;
- the destinations the harness opens, by observation, each assigned to a feature;
- what ends when VS Code disconnects, when the launcher exits, and when the sandbox is killed, with
  the run removed as for a terminal session.

## Step 4: implement

Step 4 is built only when steps 1 to 3 pass. Step 4's shape, to be settled then:

    java -jar ko-agent-sandbox.jar [options] --protocol=ahp -- code agent host ...

`--protocol` selects the transport, the token and the filter; the command selects the host.

The providers that the launch's egress admits come from `--model-provider`:

- `EgressRules.AgentProviders` maps the agent commands to their providers, and `code` is not among
  them.
- A launch of `code agent host` without the option therefore selects no provider. That selection
  allows no host under `deny-unless-model`, and the catalog alone under the default profile
  (egress-proxy.md, "Choosing an egress profile").
- Neither the command nor the harness could determine the provider: the Claude harness offers
  Anthropic-native and Copilot-routed models, and switches between them within a session.
- The launch therefore names the permitted provider route or routes with the option. A harness's
  models on any other route fail at the proxy.
- This step settles whether to refuse `code agent host` without the option, as a providerless agent
  (`EgressRules.ProviderlessAgents`).
- The destinations each route needs are step 3's measurement.

The launcher prints the address and token for "Add Remote Agent Host...", or writes the
`chat.remoteAgentHosts` entry once writing it is measured to be safe. The other session options
keep their meaning. The launcher stays resident, on the path Windows uses, for as long as it owns
the listener or the filter.

Acceptance: the hostile host of step 2 obtains nothing on the host through VS Code, in this launch
matrix:

- `--workspace=read-only` and `live`;
- `--egress=deny-unless-model`;
- the protected `.git` entries and `.ko-agent-sandbox`;
- `--run-on-host`;
- every ending of step 3.

The token routes that step 2 leaves without a positive control get one stage each, on a fresh
connection, with the credential that step 2 names for the route:

- first, a connection made while a throwaway account is signed in, for the connect-time route;
- then one challenge per remaining route, fired alone, against a resource that the connection has
  not pushed, so that the relay's timestamped report of the `authenticate` it refused belongs to
  that challenge;
- in every stage, the hostile host's log holds no token;
- the stage for `AuthRequired` must reach the chat handler's retry path and draw a push that the
  token cache does not suppress. The relay's tests settle that stage.

The documentation records the exact VS Code and AHP versions tested.

## Phases

0. Step 1, measured above, and the hostile host of step 2, written against the spec's channels.
1. Step 2's measurements, recorded above, and the filtering relay's design, which they call for.
2. Step 3.
3. Step 4, with the documentation: a usage section in the README, the refused operations under a
   heading of their own in SECURITY.md, and `doc/vscode.md` for the setup.
4. Further harnesses, each through step 3.
5. ACP, on the conditions above, along "Deferred: ACP".

## Non-goals

- The IDE's filesystem, terminals, browser or MCP servers reachable from the sandbox.
- The IDE's credentials forwarded into the sandbox, on any route, without a credential-selection
  decision of its own.
- More than one workspace root, or a workspace root other than the launch directory.
- An SSH daemon, a dev tunnel or a Dev Container conversion for IDE integration. The Dev Container
  path gets a design of its own if wanted, since VS Code would own the container's start.
- A session server written here.

## Deferred: ACP

This section keeps the reviewed design for when the ACP track is reopened.

### The interface

    java -jar ko-agent-sandbox.jar [options] --protocol=acp -- opencode acp
    java -jar ko-agent-sandbox.jar [options] --protocol=acp -- copilot --acp

The IDE's custom-agent entry runs one of these lines, with the workspace root as the working
directory. The launcher takes the workspace from that directory, as for a terminal launch.

- `--protocol` selects the transport and the relay's policy.
- The command after `--` selects the agent. As for a terminal launch, the command also selects the
  providers that its egress admits, beside those that `--model-provider` names.
- The other session options keep their meaning.

The launcher keeps no alias from an agent name to its ACP command line.

- The user configures the agent's own documented invocation, and its first word selects the
  provider.
- An alias would be a second place to keep both.

Sign-in stays a terminal launch: run the agent's documented sign-in from the README in an ordinary
session, and the protocol session finds the credential in the shared volume.

### What protocol mode changes in the launcher

- The container is created without `-t`; `-i` stays.
  - Without a pseudo-terminal, the agent's stdout reaches the IDE byte for byte.
  - Without a terminal, the entrypoint skips its pause.
- The launcher stays resident, on the path Windows uses. The launcher relays between the IDE's pipes
  and podman's stdio instead of inheriting them.
  - The relay lives on the host because every process in the sandbox is untrusted (design.md,
    "Services run as processes, not as multi-uid nested containers").
  - A filter inside the sandbox would be the agent's to bypass.
- End of file on the IDE's pipe ends the session, as Ctrl-C ends a terminal session. The reaper
  removes the run as for a terminal session.
- `--run-on-host`'s offer to provision a launcher is a prompt. Without a terminal, the offer is
  declined.
- The launch lines and the relay's refusals go to stderr, which the IDE captures as the agent's
  log.

### The relay's policy

The relay forwards what this section lists and nothing else.

- The client is the trusted side, so the relay forwards a message from the client after the field
  checks below.
- The relay forwards a message from the agent only when this section names it, because only what
  the agent asks of the client can widen the agent's authority.

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
- `elicitation/create` with `mode: form`: forwarded. With `mode: url`: refused.
  - The client shows the full URL and asks consent. The browser, though, is a host program that
    opens a URL the agent composed, and the ruleset never sees that request.
  - The sign-ins that need a browser have their terminal launch.
- `fs/*`, `terminal/*`, underscore-prefixed and unknown requests: refused with a JSON-RPC error
  that names the relay, whatever the agent was told in `initialize`.
- `session/update`: forwarded, with the paths in tool call `locations` and in diff content
  translated. `elicitation/complete` and every other notification: dropped.
- Every response to a client's request: forwarded.
- `_meta`, on every message and nested object from the agent: removed, except the trace keys
  `traceparent`, `tracestate` and `baggage`. A client acts on an agent's extension data outside the
  reviewed surface; `terminal-auth` is the measured case.

Why each refusal:

- The client's filesystem and terminals are the host's. A `terminal/create` from the sandbox is the
  shortcut that `--run-on-host` exists to prevent: a host command with the IDE's authority, not a
  confined one (SECURITY.md, "Run on host").
- `additionalDirectories` widens the root set past the workspace, which only the mount decides.
- A stdio MCP entry names a host path and environment for the agent to run.
- An `http` MCP entry carries the IDE's headers, and so the IDE's credentials, to a host the ruleset
  may or may not admit.
- A sandbox-owned MCP configuration is `plan-executable-agent-configuration.md`'s subject, not the
  IDE's to supply.
- A `terminal` authentication method has the IDE run the launcher again with the method's `env`.
  That `env` reaches the sandbox only through `--env`, and the launcher cannot tell the method's
  variables from the IDE's.
- Copilot's `_meta.terminal-auth` names a path inside the image, which a client that honors the
  entry would run on the host.

The relay does not log message bodies.

The relay forwards only a protocol version it has a policy for, and refuses the `initialize` of any
other version: the relay cannot filter a version whose client surface it does not know.

`--protocol=acp` stays version-neutral. ACP v2 is added as a second policy as soon as Zed and one
installed agent negotiate v2 end to end, whatever the release label. The v2 policy is derived from
v2's own client surface, not carried over from v1.

### Paths

The IDE spells paths as the host does; the sandbox spells them as the mount does. The relay
translates the fields it knows, and refuses what does not translate:

- Into the sandbox: `cwd`, and the paths in `session/prompt` content.
  - The relay canonicalizes each path on the host. The path must be the workspace root or inside
    it.
  - The relay respells the path with `mountPathOf`: identity on macOS and Linux, `C:\...` to
    `/mnt/c/...` on Windows.
  - A path outside the workspace refuses the message, and the refusal names both spellings.
- Out of the sandbox: tool call `locations[].path` and diff `path` in `session/update`, respelled
  by the inverse.
  - On macOS and Linux the inverse yields the real path, which differs from an IDE's symbolic
    spelling.
  - The first phase measures whether Zed matches its buffers by the real path.
- A path in a field the relay does not know passes untranslated. The IDE then shows a wrong path,
  and gains nothing.

The test therefore expects `cwd` to equal the launch directory's sandbox mount path.

Protocol mode on native Windows is released only after the inverse translation is tested there.
Until then, a Windows launch with `--protocol` is refused with that reason.

### Tests

Each policy line above is a test, with a fake agent on the sandbox side and a scripted client on
the IDE side:

- capabilities rewritten in `initialize`;
- `fs/*`, `terminal/*`, `elicitation/create` in URL mode, an underscore-prefixed request and an
  unknown request each refused, although the fake agent was told otherwise;
- `terminal` authentication methods and `_meta.terminal-auth` absent from the result the client
  sees;
- `_meta` stripped from a `session/update`, while its trace keys survive;
- `additionalDirectories` and `mcpServers` refused on each of `session/new`, `session/load` and
  `session/resume`;
- `cwd` outside the workspace refused, and `cwd` inside it arriving as the mount path;
- a `session/update` path respelled for the IDE;
- an unknown notification dropped.

The fake agent lives in the test sources and is launched as the backend command. The fake agent
reports what each session request carried, and attempts the refused calls.

The launch matrix through the relay:

- `--workspace=read-only` and `live`; a protected `.git` entry and `.ko-agent-sandbox` refused as
  in a terminal session;
- `--egress=deny-unless-model` with the backend's providers named by `--model-provider`;
- a credential from a terminal-launch sign-in, found by the protocol launch;
- `--run-on-host` through the relay, with its provisioning offer declined without a terminal;
- end of file on stdin ending the session, and the reaper removing the run;
- the IDE process killed together with the launcher;
- the proxy or the backend dying;
- stdout parsing as JSON-RPC lines from its first byte.

Then test by hand, and record the results here:

- Zed with `opencode acp`: an edit, a command, cancel, restart, and a Zed-configured MCP server
  refused visibly;
- then `copilot --acp`;
- then JetBrains with the same command line. JetBrains' documentation is unread, so its behavior is
  measured, not assumed.

### Phases, when reopened

1. Measure Zed:
   - the working directory it launches the command with;
   - what its `session/new` carries;
   - whether it sends `additionalDirectories` or its MCP servers;
   - whether it starts one agent process per thread or per project;
   - how it shows a refused request;
   - whether it matches buffers by real path.
2. `--protocol=acp` in the launcher: creation without `-t`, the resident relay, the reference text
   and the launch matrix.
3. The relay's policy, the path translation and the fake-agent tests.
4. Zed with `opencode acp`, then `copilot --acp`. Documentation as for AHP, in `doc/acp.md`.
5. JetBrains.
6. Further backends as they appear in the image. Claude and Codex reach ACP through separate
   adapter programs (unverified).
7. ACP v2, once Zed and one installed agent negotiate it: read its client surface, write the second
   policy, extend the fake agent to v2, and keep v1 for the clients still on it.

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
