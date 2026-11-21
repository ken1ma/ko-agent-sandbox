# Agent measurement

The defaults inspect each agent's model and login hosts once a measurement shows that the agent's
client works over an inspected connection. `design.md` records the decision and its costs ("Model
hosts inspected by default"). This document says how to measure a client release. Each provider's
evidence file holds its agents' measurements ("The agents, in order").

## Rules

1. A model or login host moves from `tunnel` to inspected only after the measurement below has
   passed for one version of the agent's client.
   - The provider's evidence file holds the measurement's record ("Measurement", "The agents, in
     order"). The defaults file names its evidence file in its last line.
   - The image installs every agent at its latest release (`Containerfile`), so a build can
     install a client newer than the measured one, and runs that client unmeasured.
   - A client at another version is measured again before its lines record that version. A client
     that fails returns its lines to `tunnel`.
   - `TODO.md` has the check for a newer client: CI's repeat of the measurement ("Before the first
     release — continuous integration").
2. An inspected model or login host grants `read` and every `method=` word at the root. The
   treatment still fails requests that a tunnel carries, and a client that meets such a failure
   stays a tunnel. "Measurement" says how each failure shows.
   - The defaults grant `upgrade=websocket` at a path, never at a root, and only where a
     measurement shows that a feature, or the client's turn, fails without the WebSocket.
     `design.md` has the reason ("WebSocket only at a path that a line names").
3. A host whose client sends its credential in the query stays a tunnel: the audit line prints the
   request target whole (`design.md`, "Model hosts inspected by default").

## The measurement suite

Each new client release needs the measurement again ("Rules"), several times before CI repeats
it (`TODO.md`, "Before the first release — continuous integration"). So a driver runs the parts
that need no person, and a reader compares a run's log with the records. Both assume that the
agents are signed in in the session's persistent volume. CI later adds the sign-in.

For a release:

1. In a session, from the repository root, run the driver. Each mode prints its UTC start and end,
   and the driver exits 1 when a mode does not complete.

   ```sh
   scala $KO_AGENT_SANDBOX_JAVA_OPTS run --workspace ~/.cache/measure-agents \
       src/test/measurement/MeasureAgents.scala -- [claude] [codex] [agy] [kiro-cli] [copilot] \
       [opencode]
   ```

   - Claude Code: `claude -p` with a Bash call and a subagent that makes its own Bash call.
   - Codex: `codex exec` and `codex exec resume`, each with a shell command, and a turn whose
     subagent answers.
   - agy: `agy -p` with a shell call and a subagent that makes its own, and `agy --conversation -p`
     with a shell call. The subagent's calls are read from its transcript, which the stream names.
   - Kiro: `kiro-cli chat --v3 --no-interactive` with a shell call and a subagent that makes its
     own, and `--resume-id` with a shell call.
   - Copilot: `copilot -p` with a shell call and a subagent that makes its own, a resumed turn
     with a shell call, and a read through the built-in GitHub MCP server.
   - OpenCode: `opencode run` on the ChatGPT sign-in with a shell call and a subagent that makes
     its own, and `--session` with a shell call. The subagent's calls are read from its session,
     which `opencode export` prints.
   - For each: a `curl` upload under a foreign key to the model host, whole, and chunked and cut
     short. OpenCode's goes to `chatgpt.com`, which Codex's upload to `api.openai.com` misses.
   - A mode completes only when each of its calls succeeded and `curl` held the cut upload open
     until the cut (`AgentEvents.scala`, held to recorded events by `AgentEventsTest`). After a
     failed mode, the driver keeps the turns' event files and prints their directory.
1. Do the manual items that the driver lists: interactive turns, a compaction, `/voice`, a
   sign-out and sign-in, and a token refresh.
1. On the host, run the command that the driver prints last:
   `sbt "Test/runMain agentsandbox.launcher.MeasurementReport --since=<the first mode's start>"`.
   It reads the workspace's latest run, or the `proxy.log` it is given, and exits 1 when a line
   matches no record. It writes the report to `log/measurement-report.log`, where the session's
   agent reads it.
   - `--since` leaves out what came before the first mode: Scala CLI's downloads for compiling
     the driver, which belong to no agent.

The reader (`MeasurementReport.scala`):

- It lists each recorded host's methods and paths with their counts, `cred=` indexes and framing,
  and the recorded paths that the run did not call. A record with no `path` line is unmeasured.
- It counts the requests to every other host by method, such as an unmeasured record's hosts.
- A finding is a path on a recorded host that no record naming the host lists, or a `deny` or
  `error` line that no record accepts.
  - A record names the hosts of its `allow` and `path` lines. A host can belong to two records:
    agy reads a repository on `github.com`, where the `github` record has Copilot's sign-in.
  - A `refused` line accepts a refusal without naming its host. OpenCode is refused at
    `registry.npmjs.org`, where the packages that a session installs stay unjudged.
- `curl`'s requests and `ko-sandbox-egress-check`'s `HEAD` are probes. The report lists each probe
  with its framing, credential index and body end, and never judges them. A refusal of the check's
  `CONNECT` names no client, so it stays a finding.
- Each evidence file holds the reader's lines in fenced `measurement-report` blocks:
  `path <host> </path>...`, `refused <host> <method> [</path>]` and `error <host> <reason prefix>`.
  - A `<name>` stands for one segment, part of one, or one label of a host.
  - A block line in none of the three forms, or a block without its closing fence, fails the
    reader.

`sbt "testWithPodman *AgentMeasurementTest"` runs the driver and the reader per agent. A test
fails on a turn that did not complete, on a finding, or when a probe's whole or cut upload is
missing from the log. The suite's header says which session and accounts the turns run on, when a
test skips, and where each report goes (`AgentMeasurementTest.scala`).

## Measurement

Each agent gets one launch with the agent's model hosts inspected. Its session exercises tool
calls, a subagent where the agent has one, and a compaction or a long turn.

- A host that the defaults do not name gets this line in the launch's workspace rule file. A host
  that the defaults inspect needs none.

  ```text
  allow https://HOST/ read method=POST,PUT,PATCH,DELETE
  ```

  An agent whose entry names an `upgrade=websocket` line adds that line too.

- Every launch writes the proxy's log. `--egress-log` prints it after the session.

Read from the log:

- every host the client called, login and refresh included, and every path on an inspected host.
  - The hosts and paths show that the inspected hosts are the complete set, and that nothing moved
    to a host the defaults do not name.
  - A tunnel shows its host alone.
- no `deny` line on a model host, except refusals that the agent's record accepts. A `deny`
  line names the rule that the request broke (SECURITY.md, "The audit line grammar").
- no `error` line on a model host. Each of these is a way the client could fail:
  - a connection whose origin sends nothing for 300 seconds ends
    (`InspectedIdleTimeoutMillis`). A non-streaming request whose answer takes longer is the
    case to look for;
  - a server-sent-event stream that the origin's side cuts shows as a `relay:` line without
    `client:`. The stream must survive a whole long turn;
  - a client that does not trust the launch CA, or that offers HTTP/2 alone, shows as a handshake
    error, and an origin failure as an `origin:` line.
- whether the client sends a `Content-Length` or a chunked body. The framing decides whether a
  request's size is on its `allow` line or on a `chunked-end` line.
- whether a model request's target holds a credential in its query, and whether the request's
  line has `cred=`.
  - A line without the field, on a request that the provider accepted, means a credential that
    the index does not count: another header, or a signing scheme.
  - The log names neither. The client's documentation or source does, and the index gains a
    header only from that reading.
- a line for each model request sent over HTTP, by its path, beside the completed turn.
  - The sandbox has no route but the proxy, so a transport that ignores `HTTPS_PROXY` fails rather
    than escapes. The log then shows what did connect.
- for a client whose model traffic runs in a granted WebSocket: each stream's handshake line and
  its `websocket-end` line with the byte totals, beside the completed turns. One stream carries
  several requests, and the log has no line for each.

The log misses one failure, which shows as the client's own error. A client that sends a second
request on a connection meets the closed socket, and can lose the end of the first response
(`HTTPHelper.toClientBytes`).

Each result is recorded in the provider's evidence file:

- the client's exact version and the date;
- the mode, interactive or headless, and any child process the mode spawns;
- the hosts and paths the client called, and the refusals accepted. The next measurement compares
  its own with these.

The record holds paths, not log lines as printed: a printed line holds the whole target, query
included.

A pass in one mode is no evidence for another mode where the client has a second transport or a
child of its own (agy's model transport, Kiro's `acp`).

A feature that opens a transport of its own is measured as a mode: the agent's `/voice` under
`--audio=mic` (`mic.md`), and a remote-session feature.

A measurement that fails on a protocol rule leaves the agent a tunnel, and the record names the
failing rule. `design.md` says why the relay does not change ("Model hosts inspected by default").

## The agents, in order

The agents are measured in the README's order. Each provider's evidence file holds what its agents'
documentation and reported issues say, and the agents' measurement records:

- `claude`: [`anthropic-evidence.md`](../ko-agent-egress-proxy/doc/preset/anthropic-evidence.md)
- `codex`: [`openai-evidence.md`](../ko-agent-egress-proxy/doc/preset/openai-evidence.md)
- `agy`: [`google-evidence.md`](../ko-agent-egress-proxy/doc/preset/google-evidence.md)
- `kiro-cli`: [`aws-evidence.md`](../ko-agent-egress-proxy/doc/preset/aws-evidence.md)
- `copilot`: [`github-evidence.md`](../ko-agent-egress-proxy/doc/preset/github-evidence.md)
- `opencode`: [`openai-evidence.md`](../ko-agent-egress-proxy/doc/preset/openai-evidence.md),
  and for its Copilot sign-in
  [`github-evidence.md`](../ko-agent-egress-proxy/doc/preset/github-evidence.md)

A report establishes a transport that differed in the named release on the named platform. A
report does not establish the installed client's behavior.

A login or token host is inspected once the measurement covers the agent's sign-in and a token
refresh.
- The log then shows every request to them by path, so a request that no sign-in makes stands out.
- The proxy then holds the sign-in's codes and tokens in plaintext, refresh tokens included, which
  outlive the access tokens it sees on the model hosts.
- `auth.openai.com`, `platform.claude.com`, `oauth2.googleapis.com` and Kiro's
  `prod.us-east-1.auth.desktop.kiro.dev` are inspected. `claude.ai` and `accounts.google.com` are
  absent, since Claude Code and agy send them no request (`defaults/preset/anthropic` and
  `google`). `cognito-identity.us-east-1.amazonaws.com` is absent too: Kiro's Google sign-in sent
  it nothing, and Kiro's turns complete with the host refused (`defaults/preset/aws`).
- `oidc.us-east-1.amazonaws.com`, for Kiro's Builder ID and Identity Center sign-ins, is inspected
  unmeasured, on the evidence of kiro-cli's AWS SDK at `management.us-east-1.kiro.dev`.

## References

- https://embracethered.com/blog/posts/2025/claude-abusing-network-access-and-anthropic-api-for-data-exfiltration/
- https://www.promptarmor.com/resources/claude-cowork-exfiltrates-files
