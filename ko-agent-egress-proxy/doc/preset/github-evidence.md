# Evidence for preset/github

[The defaults file](../../app/src/main/resources/defaults/preset/github) inspects
Copilot CLI's hosts on this evidence.
[`doc/agent-measurement.md`](../../../doc/agent-measurement.md) says how a client is measured,
and how much a report establishes.

## Copilot CLI

`copilot` 1.0.111, the image's version on 2026-11-11, at `api.githubcopilot.com` and the three plan
hosts. The "Documented" pages were read on 2026-09-28, and the issues under "Reported" on
2026-11-11, with each state as of that day.

- Documented: `proxyUrl` in the CLI's configuration reference, overridden by `HTTP_PROXY` or
  `HTTPS_PROXY`
  (https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference).
- The changelog lists:
  - the proxy variables from 0.0.336;
  - custom CA certificates loaded at startup from 1.0.40;
  - HTTP/1.1 as the default transport from 1.0.57, with `COPILOT_ENABLE_HTTP2=1` as the opt-in;
  - mTLS to an HTTPS proxy from 1.0.83.

  The changelog does not say how the CA is configured.
- Copilot's network troubleshooting page says that on Linux Copilot reads
  `/etc/ssl/certs/ca-certificates.crt`, the file the launch mounts its bundle over. The page does
  not say whether that covers the CLI
  (https://docs.github.com/en/copilot/how-tos/troubleshoot-copilot/troubleshoot-network-errors).
- Session sync is on by default. With `remote` "on" and `remoteExport` true in the configuration
  reference, Copilot sends the session to the user's GitHub account. The session-data page says
  what a session holds. SECURITY.md covers the export and `--no-remote-export` ("Not defended").
- Reported:
  - A model call is `POST /chat/completions` on the plan's host,
    `api.individual.githubcopilot.com` for one plan (github/copilot-cli #454).
  - The built-in GitHub MCP server is `/mcp/readonly` on the same plan host (github/copilot-cli
    #4408).
  - Under inspection, the two are distinct lines.
- The measurement below put the hosts under inspection by default. The client trusted the launch
  CA, and every request went over HTTP/1.1 with `COPILOT_ENABLE_HTTP2` unset.
  - The model path is `POST /responses` on `api.individual.githubcopilot.com`, and the GitHub MCP
    server is `POST /mcp/readonly` there.
- Still to measure: session sync, which waits for an account whose organization allows it, and
  the business and enterprise hosts, which wait for an account on those plans.

## Measured with copilot 1.0.111 on 2026-11-14

Signed in on an individual plan, under `deny-unless-allowed`.

- Modes: `copilot -p` with a shell call and a subagent that makes its own shell call;
  `copilot --resume -p` with a shell call; `copilot -p` with a read through the built-in GitHub MCP
  server; the interactive TUI in this repository, with three turns and a compaction, then `/login`
  and a message; the TUI with a turn under `deny-unless-selected`.
- Within each sign-in, every request to the plan host and `api.github.com` carried the same
  credential index: the token that `api.github.com` accepts also reaches the model host. The token
  from `/login` shows as a new index. No mode called the token exchange that the defaults allow.
- The TUI reads the repository's issues and pull requests, and its embeddings index, from
  `api.github.com`.
- The device code login polls `/login/oauth/access_token` until the user approves. Its codes and
  tokens travel in bodies, so its lines carry no `cred=`.
- `/logout` fails in the sandbox before any request: the client deletes the token through the
  Secret Service, and the container has no D-Bus session ("Failed to connect to address
  `unix:path=/run/user/<uid>/bus`").
- Under `deny-unless-selected` with only the token exchange granted on `api.github.com`, the refused
  `/copilot_internal/user` left every message refused: "Authentication token found but could not be
  validated". With the defaults' three reads, the turn completed, and `api.github.com` refused the
  TUI's repository reads, its release check and `/graphql`.
- Every request body declared a `Content-Length`.
- A task subagent asked for a model of its own, which the origin answered with
  `400 model_not_supported` for this plan. A general-purpose subagent, which takes the session's
  model, completed.
- The refusals:
  - the WebSocket upgrade at `/responses`, answered 403: the client tries once per turn, a
    subagent's included, and sends the turn's `POST /responses` at once;
  - the catalog's read-only `api.github.com` refuses `POST /graphql`, and the `POST` that indexes
    the repository. The TUI continues after both;
  - `telemetry.individual.githubcopilot.com` (telemetry), `exp.individual.githubcopilot.com`
    (experiments) and `cafe.github.com` (metrics), once or twice at each process start. Copilot
    works without them, and they are absent.
- The errors: at each process start, one `CONNECT` to each host that sent no byte before closing.
- No mode or turn failed. `/chat/completions` was called once, in the TUI session with the
  compaction.
- Unmeasured: the business and enterprise hosts, and session sync, which the account's organization
  policy turns off.

### The lines that MeasurementReport accepts for Copilot CLI

`MeasurementReport` reads this block (`doc/agent-measurement.md`, "The measurement suite").
Each `<...>` stands for one segment.

```measurement-report
path api.individual.githubcopilot.com /responses /chat/completions /auto /models /meta
path api.individual.githubcopilot.com /mcp/readonly
path api.individual.githubcopilot.com /agents/swe/internal/memory/v0/enabled
path api.individual.githubcopilot.com /agents/swe/custom-agents/<owner>/<repo>
path api.github.com /copilot_internal/user /copilot_internal/managed_settings
path api.github.com /copilot_internal/team_customizations /repos/github/copilot-cli/releases
path api.github.com /repos/<owner>/<repo>/issues /repos/<owner>/<repo>/pulls
path api.github.com /repos/<owner>/<repo>/copilot_internal/embeddings_index
path github.com /login/device/code /login/oauth/access_token
refused api.individual.githubcopilot.com GET /responses
refused api.github.com POST /graphql
refused api.github.com POST /repos/<owner>/<repo>/copilot_internal/embeddings_index
refused api.github.com GET /repos/<owner>/<repo>/issues
refused api.github.com GET /repos/<owner>/<repo>/pulls
refused api.github.com GET /repos/<owner>/<repo>/copilot_internal/embeddings_index
refused api.github.com GET /repos/github/copilot-cli/releases
refused telemetry.individual.githubcopilot.com CONNECT
refused exp.individual.githubcopilot.com CONNECT
refused cafe.github.com CONNECT
error api.individual.githubcopilot.com tunnel: expected 5 bytes, got 0
error api.github.com tunnel: expected 5 bytes, got 0
error github.com tunnel: expected 5 bytes, got 0
```

## OpenCode signed in to GitHub Copilot

Observed with opencode 1.19.5 on 2026-11-14, after its device-code sign-in to GitHub Copilot on the
account above. No OpenCode turn ran on Copilot: OpenCode lists only the models that `/models` marks
for the model picker, and the account's answer marked none.
[`openai-evidence.md`](openai-evidence.md) has OpenCode's documentation and its ChatGPT measurement.

- The sign-in sent the device code requests that the defaults allow. OpenCode stores the GitHub
  token itself, and sends it to the generic host's `/models` at each start.
- A launch that does not name github refuses that request, and OpenCode's turns on another
  provider complete.

### The lines that MeasurementReport accepts for OpenCode

```measurement-report
path api.githubcopilot.com /models
refused api.githubcopilot.com CONNECT
```

## References

- github/copilot-cli `changelog.md`; #454, #4408 — proxy, CA and mTLS entries by version; a
  model path and the built-in MCP server's path on a plan host
