# Evidence for model-provider/aws

[The defaults file](../../app/src/main/resources/defaults/model-provider/aws) inspects
Kiro CLI's hosts on this evidence.
[`doc/agent-measurement.md`](../../../doc/agent-measurement.md) says how a client is measured,
and how much a report establishes.

## Kiro CLI

`kiro-cli` 3.1.0, the image's version on 2026-11-11, at `runtime.us-east-1.kiro.dev` and
`management.us-east-1.kiro.dev`, each also in `eu-central-1`. The "Documented" pages were read on
2026-09-28, and the issues under "Reported" on 2026-11-11, with each state as of that day.

- Documented: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from v1.8.0
  (https://kiro.dev/docs/cli/quick-start, "Proxy configuration"). Neither that page nor the
  firewall page has a CA setting.
- The firewall page names the `runtime` and `q` hosts "Kiro service", and the `management` hosts
  "Configuration, access management". The page says that CLI application traffic, chat and
  completions included, follows the proxy settings
  (https://kiro.dev/docs/privacy-and-security/firewalls).
- Reported:
  - 2.8.1 on Windows spawned the `acp` child of interactive `chat` without the parent's proxy and
    certificate variables (kirodotdev/Kiro #9608, closed as completed).
  - 2.10.0 under WSL failed behind a TLS-inspecting proxy in its v3 harness, while v2 worked
    (#9860, closed as completed).
- The measurement below put the hosts under inspection by default, with the sign-in hosts.
  - Every mode ran the V3 engine, in a Node child that kept the proxy and CA variables.
  - Every request to `runtime` and `management` carried `cred=`: a bearer token, not a SigV4
    signature.
  - V3's model calls are `POST /v1/responses` on `runtime`, and its other calls are `POST /`.
  - Under `deny-unless-model`, which admits the provider file alone, a TUI turn completed.
- The V2 engine, kiro-cli's own `acp` child, sends its model calls to
  `q.us-east-1.amazonaws.com`, and its turns completed under inspection. Kiro removes V2 in
  January, so `q` has no line, and a workspace that runs V2 adds it (README, `kiro-cli`).

## Measured with kiro-cli 3.3.0 on 2026-11-14

Signed in with a Google account in us-east-1, under `deny-unless-allowed`.

- Modes: `kiro-cli chat --v3 --no-interactive` with a shell call and a subagent that makes its own
  shell call; `--resume-id` with a shell call; the V3 TUI in this repository, with two turns,
  `/compact` and a message; `kiro-cli logout`, `kiro-cli login --use-device-flow` and a turn; a
  token refresh at the token's expiry; the TUI with a turn under `deny-unless-model`.
- Each mode ran in a Node child of kiro-cli, which sent the model calls as `KiroCLI/3.3.0` and the
  rest as `aws-sdk-js`. kiro-cli itself sent the sign-in requests as `Kiro-CLI`, and read the
  profile at `management` as `aws-sdk-rust`. Every client negotiated HTTP/1.1 and trusted the
  launch CA.
- Within each sign-in, every request to `runtime` and `management` carried the same credential
  index. The sign-in host's codes and tokens travel in bodies, so its lines carry no `cred=`.
- Every body declared a `Content-Length`; `/v1/responses` bodies held 54 to 63 KB. No query held a
  credential.
- A request to `/` names its operation in a header, as AWS's JSON protocol does, so its line does
  not.
- `management`'s query names the Kiro profile's ARN, which holds an AWS account number.
- The sign-in polled `/oauth/device/poll` every five seconds until the browser approved the code.
  The logout sent `/logout`.
- The refusals: telemetry every few seconds while Kiro runs; `app.kiro.dev` twice at each start;
  the update host at the TUI's start.
- The error: once, at a V3 start, a `CONNECT` to `management` sent no byte before closing, and the
  turn completed.
- Signed out, `kiro-cli whoami` sent `cognito-identity` two requests without a credential. With the
  host refused, kiro-cli tried it three to six times at each start, and the turns completed.
- At the token's expiry, kiro-cli refreshed the token at `/refreshToken`, and the turn completed. A
  refresh forced by moving the stored expiry 50 minutes early was answered 401 there instead, and
  kiro-cli deleted the token.
- A token from a sign-in three minutes after that 401 was rejected from its first use: "The bearer
  token included in the request is invalid", in Kiro's log, under both profiles. The next sign-in's
  token worked and refreshed.
- Unmeasured: eu-central-1; the Builder ID and Identity Center sign-ins at `oidc`; the GitHub
  sign-in.

### The lines that MeasurementReport accepts

`MeasurementReport` reads this block (`doc/agent-measurement.md`, "The measurement suite").

```measurement-report
path runtime.us-east-1.kiro.dev / /v1/responses
path management.us-east-1.kiro.dev /
path prod.us-east-1.auth.desktop.kiro.dev /oauth/device/authorization /oauth/device/poll /logout
path prod.us-east-1.auth.desktop.kiro.dev /refreshToken
refused telemetry.us-east-1.kiro.dev CONNECT
refused client-telemetry.us-east-1.amazonaws.com CONNECT
refused app.kiro.dev CONNECT
refused prod.download.cli.kiro.dev CONNECT
refused cognito-identity.us-east-1.amazonaws.com CONNECT
error management.us-east-1.kiro.dev tunnel: expected 5 bytes, got 0
```

## References

- kirodotdev/Kiro #9608, #9860 — a child process without the proxy variables; a harness that
  failed behind a TLS-inspecting proxy
