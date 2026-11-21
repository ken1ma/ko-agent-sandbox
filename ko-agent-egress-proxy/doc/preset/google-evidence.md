# Evidence for preset/google

[The defaults file](../../app/src/main/resources/defaults/preset/google) inspects
Antigravity's hosts on this evidence.
[`doc/agent-measurement.md`](../../../doc/agent-measurement.md) says how a client is measured,
and how much a report establishes.

## Antigravity

`agy` 1.5.3, the image's version on 2026-11-11, at `cloudcode-pa.googleapis.com`,
`daily-cloudcode-pa.googleapis.com`, `generativelanguage.googleapis.com`, and the `businessaicode`
and `aiplatform` hosts. The "Documented" pages were read on 2026-09-28, and the issues under
"Reported" on 2026-11-11, with each state as of that day.

- `aicode.googleapis.com` has no line: `/voice` streams there over gRPC, which needs HTTP/2, so a
  workspace adds the host as a tunnel (the defaults file; `doc/TODO.md`, "Deferred — an HTTP/2
  relay for gRPC hosts"). Without the host, agy falls back for its flags, and its turns complete.
- Documented: nothing on a proxy or a CA in the 28 CLI pages under
  https://antigravity.google/docs/cli.
- Reported:
  - 1.0.2 on Windows sent `loadCodeAssist` past `HTTPS_PROXY`
    (google-antigravity/antigravity-cli #181, closed as a duplicate).
  - 1.1.21 on Windows sent `loadCodeAssist` through the proxy, and the model calls,
    `streamGenerateContent`, directly (#875, open).
- The measurement below put `daily-cloudcode-pa.googleapis.com` under inspection by default, with
  `cloudcode-pa.googleapis.com` and `oauth2.googleapis.com`. Every model call went to
  `daily-cloudcode-pa.googleapis.com`, as `POST /v1internal:<method>`.
- The API-key and Business modes' hosts have no line, and a workspace adds them as tunnels (the
  defaults file). Still to measure: the GCP-licensed accounts on `cloudcode-pa`, the Business
  sign-in, which waits for such an account, and where a `GEMINI_API_KEY` session sends the key,
  which waits for a key. A key in the query, `?key=`, keeps `generativelanguage.googleapis.com` out
  of inspection (`doc/agent-measurement.md`, "Rules").

## Measured with agy 1.5.8 on 2026-11-14

Signed in with a consumer account, under `deny-unless-allowed`.

- Modes: `agy -p` with a shell call and a subagent that makes its own shell call;
  `agy --conversation -p` with a shell call; the interactive TUI in this repository, with two turns
  and `/compact`, a sign-out, a sign-in and a message, then `/voice` under `--audio=mic`; a token
  refresh, forced by moving the token file's expiry into the past; the TUI with a turn under
  `deny-unless-selected`.
- The client negotiated HTTP/1.1 and trusted the launch CA. The language server sends the model
  requests as `antigravity/cli/1.5.8`; the sign-in, userinfo and picture requests are
  `Go-http-client/1.1`.
- Within each sign-in, the model host's requests and the userinfo read carried the same credential
  index. The token endpoint's codes and tokens travel in bodies, so its lines carry no `cred=`.
- `streamGenerateContent` bodies are chunked, with `?alt=sse` in the query; every other body
  declared a `Content-Length`. No query held a credential.
- After each turn, `recordTrajectoryAnalytics` uploaded 37 to 208 KB to the model host.
- In this repository, the TUI sent `github.com` a `HEAD` of the repository's own path, without a
  credential, after a turn. Under `deny-unless-selected`, which admits no catalog host, the proxy
  refused that `CONNECT`, and the turn completed.
- The sign-out sent no request. The sign-in exchanged its code at `oauth2.googleapis.com/token`;
  without a D-Bus session, agy keeps the token in
  `~/.gemini/antigravity-cli/antigravity-oauth-token`.
- Other Google clients in a session, such as gcloud, exchange their tokens at
  `oauth2.googleapis.com` too. Only agy's exchange and refresh are measured.
- The refusals: `play.googleapis.com` (telemetry), every few seconds while agy runs;
  `www.gstatic.com` (the plugin marketplace), at the TUI's start; `aicode.googleapis.com` (the
  flags), at each start. agy works without them.
- The errors, each at a process's exit: a connection that agy closed or reset without a request,
  once (agy 1.5.9) before its TLS handshake; and the response to a `recordTrajectoryAnalytics`
  upload that agy abandoned ("context canceled" in agy's log), whose relay to agy failed with
  Broken pipe.
- `/voice` and `fetchConfig` went through a tunnel to `aicode.googleapis.com`, which the
  measurement allowed. No mode or turn failed.
- Unmeasured: the GCP-licensed accounts on `cloudcode-pa`, inspected on this client's evidence; the
  Business sign-in; `GEMINI_API_KEY`, whose key may travel in the query.

### The lines that MeasurementReport accepts

`MeasurementReport` reads this block (`doc/agent-measurement.md`, "The measurement suite").
Each `<...>` stands for one segment.

```measurement-report
path daily-cloudcode-pa.googleapis.com /v1internal:loadCodeAssist /v1internal:fetchAvailableModels
path daily-cloudcode-pa.googleapis.com /v1internal:fetchAdminControls /v1internal:fetchUserInfo
path daily-cloudcode-pa.googleapis.com /v1internal:retrieveUserQuotaSummary
path daily-cloudcode-pa.googleapis.com /v1internal:listExperiments
path daily-cloudcode-pa.googleapis.com /v1internal:streamGenerateContent
path daily-cloudcode-pa.googleapis.com /v1internal:writeTrajectoryAcls
path daily-cloudcode-pa.googleapis.com /v1internal:recordTrajectoryAnalytics
path daily-cloudcode-pa.googleapis.com /v1internal/cascadeNuxes
path oauth2.googleapis.com /token
path www.googleapis.com /oauth2/v2/userinfo
path lh3.googleusercontent.com /a/<picture>
path github.com /<owner>/<repo>
refused play.googleapis.com CONNECT
refused www.gstatic.com CONNECT
refused github.com CONNECT
refused aicode.googleapis.com CONNECT
error daily-cloudcode-pa.googleapis.com tunnel: Connection reset
error daily-cloudcode-pa.googleapis.com client closed before sending a request
error daily-cloudcode-pa.googleapis.com relay: client: Broken pipe
error daily-cloudcode-pa.googleapis.com tunnel: expected 5 bytes, got 0
```

## References

- google-antigravity/antigravity-cli #181, #875 — request paths that ignored `HTTPS_PROXY` in
  released versions
