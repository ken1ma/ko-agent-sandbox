# Plan: measurements for the credential plans

Step 1 of `plan-preset-credential-proxy.md` and of `plan-login-brokering.md`, step 2 of the
brokering plan, and the brokering plan's open questions that a session settles, run on the host.

- Record each result in the provider's evidence file, with the client's version and the date
  (`agent-measurement.md`, "Measurement"), and settle the plan item that it answers.
- Delete this file once both plans and the evidence files hold the results, and
  `agent-measurement.md` holds the per-release checks (`plan-preset-credential-proxy.md`, step 4).

## Before you start

- Launch every session from an empty directory, such as `~/measure-ws`. Some items write a rule to
  its `.ko-agent-sandbox/egress/rule`, which must not reach a real workspace.
- Give each item the volume that it names with `--persistent-volume=`, so that no existing sign-in
  takes part. `--reset` leaves these volumes; "After the session" removes them.
  - Before the first launch, check that none of them exists, so that no earlier login takes part
    and the cleanup removes only this session's volumes. Launch only when the check prints nothing:
    for a volume that exists, give that item another name in this check, in its launch and in the
    cleanup, or remove the old volume; after a failed check, run it again.

    ```sh
    for v in measure-claude-key measure-claude-oat measure-claude-login measure-claude-console \
        measure-claude-rotation measure-claude-rc measure-claude-rc-oat \
        measure-codex-key measure-codex-login measure-codex-tui measure-copilot; do
        podman volume exists "$v"
        case $? in
            0) echo "$v exists" ;;
            1) ;;
            *) echo "$v: the check failed" ;;
        esac
    done
    ```
- Start each session with `bash` as the command, and run the agent inside it. Only the command's
  first word selects a preset (`egress-proxy.md`, "Choosing an egress profile"), so each launch
  names its provider's preset with `--egress-preset=`.
- After each session, `<launcher> --egress-log` prints the proxy's log:
  - `inject=NAME` on a line: the binding's value replaced its placeholder in that request;
  - `cred=N`: the request carried a credential, and the same `N` means the same credential;
  - the log names no header. A binding shows the header instead: `inject=` appears only when the
    client puts the placeholder in the binding's place (`egress-proxy.md`, "Where the value goes").
- Print a credentials file's shape, never its values: each item's `jq` command prints each field's
  path and type.

## Claude Code

1. The API key's header, and its approval prompt (preset plan):

   ```sh
   ANTHROPIC_API_KEY=<Console key> <launcher> --egress-preset=anthropic \
       --persistent-volume=measure-claude-key \
       --egress-cred=ANTHROPIC_API_KEY@api.anthropic.com:x-api-key bash
   ```

   - In the sandbox, run `claude`, approve the key, send a message and quit. Expect `inject=` on
     `/v1/messages`. Without it, repeat with `--egress-cred=ANTHROPIC_API_KEY@api.anthropic.com`,
     which binds `Authorization`.
   - Launch again the same way, which issues a new placeholder, and run `claude`. Record whether it
     asks to approve the key again.
   - Record the requests to `api.anthropic.com` without `cred=`.
2. The `setup-token` token's header and format (preset plan):

   ```sh
   CLAUDE_CODE_OAUTH_TOKEN=<claude setup-token's output> <launcher> --egress-preset=anthropic \
       --persistent-volume=measure-claude-oat \
       --egress-cred=CLAUDE_CODE_OAUTH_TOKEN@api.anthropic.com bash
   ```

   - Run `claude -p "say ok"`. The placeholder is 22 random letters and digits, since the launcher
     recognizes no `sk-ant-oat01-` prefix.
   - Expect `inject=` on `/v1/messages`. A failed turn whose request carries `cred=` without
     `inject=` sent the placeholder elsewhere, perhaps in `x-api-key` after reading its prefix:
     record it, since the placeholder then has to keep `sk-ant-oat01-`.
3. The sign-in and a refresh (brokering plan):
   - Launch with `--egress-preset=anthropic --persistent-volume=measure-claude-login bash`, run
     `claude`, sign in with `/login`, and quit.
   - Record the shapes of `~/.claude/.credentials.json` and of `oauthAccount` in
     `~/.claude/.claude.json`, which name the account:

     ```sh
     jq '[paths(scalars) as $p
         | {path: ($p | map(tostring) | join(".")), type: (getpath($p) | type)}]' \
       ~/.claude/.credentials.json
     jq '.oauthAccount' ~/.claude/.claude.json | jq '[paths(scalars) as $p
         | {path: ($p | map(tostring) | join(".")), type: (getpath($p) | type)}]' -
     ```

   - Set the expiry, `claudeAiOauth.expiresAt` in 2.1.326, to a time in the past. Writing through
     `cat` keeps the file's permissions:

     ```sh
     f=~/.claude/.credentials.json
     jq '.claudeAiOauth.expiresAt = 0' "$f" > /tmp/c.json &&
       cat /tmp/c.json > "$f" && rm /tmp/c.json
     ```

   - Run `claude -p "say ok"`, and record the `POST /v1/oauth/token` line and the new `cred=` index
     after it, as the earlier measurement did (`anthropic-evidence.md`).
4. A sign-out whose revocation fails (brokering plan):
   - Add `deny https://platform.claude.com/ method=POST` to the rule file, and launch as in
     item 3. Save the credentials on the volume, so that a later sign-out can revoke this login:
     `cp ~/.claude/.credentials.json ~/persistent-volume/signed-in.json`. Run `/logout` in
     `claude`, and quit.
   - Record the refused `POST /v1/oauth/token/revoke`, and the credentials file's shape after the
     sign-out, with item 3's first command. A missing file means that Claude Code deleted it.
   - Remove the line, launch again, and put the saved file back:
     `cp ~/persistent-volume/signed-in.json ~/.claude/.credentials.json`. Run `/logout`,
     record the allowed revoke request, and delete `signed-in.json`.
5. The keyless Console sign-in, a refresh, its placeholders and a sign-out (brokering plan):
   - Launch with `--egress-preset=anthropic --persistent-volume=measure-claude-console bash`, run
     `claude`, and sign in with `/login`, "Anthropic Console account" and "Sign in with your Console
     account (recommended)". A claude.ai login on the volume would outrank the profile.
   - Record whether the log has `POST /api/oauth/claude_cli/create_api_key`, which only the legacy
     sign-in sends, and the profile's shape:

     ```sh
     f=$(echo ~/.config/anthropic/credentials/*.json)
     jq '[paths(scalars) as $p
         | {path: ($p | map(tostring) | join(".")), type: (getpath($p) | type)}]' "$f"
     ```

   - Force a refresh, and record the token `POST` and the new `cred=` index after it:

     ```sh
     jq '.expires_at = 0' "$f" > /tmp/p.json && cat /tmp/p.json > "$f" && rm /tmp/p.json
     claude -p "say ok"
     ```

   - Put 22 random letters and digits in `access_token`, run `claude -p "say ok"`, and record
     whether a request carries a new `cred=` index:

     ```sh
     p=$(python3 -c 'import secrets, string
     print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(22)))')
     jq --arg p "$p" '.access_token = $p' "$f" > /tmp/p.json &&
       cat /tmp/p.json > "$f" && rm /tmp/p.json
     claude -p "say ok"
     ```

   - Save the profile, whose refresh token is the sign-in's last real one:
     `cp "$f" ~/persistent-volume/profile.json`. Repeat the trial with `refresh_token` and
     `expires_at` set to `0` (`jq --arg p "$p" '.refresh_token = $p | .expires_at = 0'`), record
     whether a token `POST` goes out, and put the saved profile back with
     `cp ~/persistent-volume/profile.json "$f"` instead of signing in again.
   - Sign out as in item 4, with `profile.json` as the saved file, and record the revoke requests
     and `ls -la ~/.config/anthropic/credentials ~/.config/anthropic/configs` after each. Claude
     Code prints the same success after a refused revoke as after an allowed one.
6. Whether a refresh retires the old refresh token, and how soon (brokering plan, "The store"):
   - Launch as in item 3 with `--persistent-volume=measure-claude-rotation`, sign in, and quit.
   - Save the credentials on the volume, since a new launch discards the rest of `~`, and hash the
     refresh token, which shows a change without the value:

     ```sh
     f=~/.claude/.credentials.json
     cp "$f" ~/persistent-volume/r0.json
     jq -r .claudeAiOauth.refreshToken "$f" | sha256sum
     ```

   - Force a refresh as in item 3, hash again, and run `cp "$f" ~/persistent-volume/r1.json`.
     Another hash means that the refresh token rotated.
   - Put the old file back with an expiry in the past, and run `claude -p "say ok"`. A completed
     turn means that the provider still accepted the old refresh token:

     ```sh
     f=~/.claude/.credentials.json
     jq '.claudeAiOauth.expiresAt = 0' ~/persistent-volume/r0.json > /tmp/c.json &&
       cat /tmp/c.json > "$f" && rm /tmp/c.json
     ```

   - Do the same with `r1.json`. A failure means that reusing the old token retired the new one.
   - If the old token was accepted, repeat with 60 minutes between the refresh and the reuse.
   - Record the `POST /v1/oauth/token` lines of each run, and delete `r0.json` and `r1.json`.
7. Remote Control (brokering plan, "Open questions"; preset plan, the `setup-token` entry):
   - Launch as in item 3 with `--persistent-volume=measure-claude-rc`, sign in, and quit.
   - Run `claude remote-control`, open the URL that it prints in a browser or the Claude app, send
     "say ok", wait for the answer, and stop it.
   - Record each `api.anthropic.com` request with its method, path and `cred=` index, and every
     refusal. `/v1/messages` carries the OAuth token's index; another index is a per-session token.
   - When a refusal stops Remote Control, add an `allow` line for the refused URL to the rule file,
     with `upgrade=websocket` for a WebSocket, and launch again. Record both runs.
   - Repeat item 2's launch with `--persistent-volume=measure-claude-rc-oat`, and record whether
     `claude remote-control` starts.

## Codex

8. `CODEX_API_KEY` under `codex exec` (preset plan):

   ```sh
   CODEX_API_KEY=<API key> <launcher> --egress-preset=openai \
       --persistent-volume=measure-codex-key --egress-cred=CODEX_API_KEY@api.openai.com bash
   ```

   - Run `codex exec --skip-git-repo-check "say ok"`: without the flag, Codex exits before any
     request in a directory it does not trust (`codex-rs/exec/src/lib.rs`), and
     `MeasureAgents.scala` passes it too.
     Expect `inject=` on `/v1/responses`.
   - Expect `chatgpt.com`'s `/backend-api/codex/models` to get the placeholder unsubstituted, since
     one binding names one host: record its `cred=` line and whether the turn completes.
9. `CODEX_ACCESS_TOKEN` (preset plan): measured after the preset plan's step 2, with a token from
   a ChatGPT Business or Enterprise workspace (`TODO.md`). A binding cannot measure it now: its
   placeholder lacks `at-`, so Codex reads it as an agent identity JWT.
10. The sign-in, a refresh and a stored synthetic ID token (brokering plan):
    - Launch with `--egress-preset=openai --persistent-volume=measure-codex-login bash`, sign in
      with `codex login --device-auth`, and record the shape of `~/.codex/auth.json` and of the ID
      token's claims, which name the account. The decoded claims hold your email address, so the
      second command pipes them straight into the shape:

      ```sh
      jq '[paths(scalars) as $p
          | {path: ($p | map(tostring) | join(".")), type: (getpath($p) | type)}]' \
        ~/.codex/auth.json
      python3 -c 'import json, base64, sys
      part = json.load(open(sys.argv[1]))["tokens"]["id_token"].split(".")[1]
      print(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode())' ~/.codex/auth.json |
        jq '[paths(scalars) as $p
            | {path: ($p | map(tostring) | join(".")), type: (getpath($p) | type)}]' -
      ```

    - Replace `tokens.access_token` in `~/.codex/auth.json` with `invalid`. The earlier measurement
      forced its refresh with a rejected access token (`openai-evidence.md`).

      ```sh
      f=~/.codex/auth.json
      jq '.tokens.access_token = "invalid"' "$f" > /tmp/a.json &&
        cat /tmp/a.json > "$f" && rm /tmp/a.json
      ```

      Run `codex exec --skip-git-repo-check "say ok"`. Record the `POST /oauth/token` line, which
      the item requires, and the new `cred=` index after it.
      - Moving `last_refresh` alone forces nothing while the access token is a readable, unexpired
        JWT: Codex checks the token's expiry first (`codex-rs/login/src/auth/manager.rs`,
        `proactive_refresh_reason`).
    - Copy the sign-in to a scratch home, keep its claims, and replace the ID token's signature:

      ```sh
      mkdir -p /tmp/codex-a && cp ~/.codex/auth.json /tmp/codex-a/
      python3 - <<'EOF'
      import json, pathlib
      path = pathlib.Path("/tmp/codex-a/auth.json")
      auth = json.loads(path.read_text())
      header, payload, _ = auth["tokens"]["id_token"].split(".")
      auth["tokens"]["id_token"] = f"{header}.{payload}.c2lnbmF0dXJl"
      path.write_text(json.dumps(auth))
      EOF
      CODEX_HOME=/tmp/codex-a codex exec --skip-git-repo-check "say ok"
      ```

    - Repeat with an empty payload, `e30` in place of `{payload}`. Record which ID token Codex
      accepts from storage. The sign-in also checks the token's account claim before it stores the
      token (`codex-rs/login/src/device_code_auth.rs`), so only the brokered sign-in in step 3 of
      the brokering plan tests that path.
    - A refresh in the scratch home can retire the volume's refresh token: sign in again if the
      volume's login stops working.
11. A sign-out whose revocation fails (brokering plan): as item 4, with
    `deny https://auth.openai.com/ method=POST`, `~/.codex/auth.json` saved and restored,
    `codex logout`, the refused `POST /oauth/revoke`, and the shape of `~/.codex/auth.json` with
    item 10's first command.
12. The TUI with a stored synthetic ID token (brokering plan, "One placeholder per token kind"):
    - Launch with `--egress-preset=openai --persistent-volume=measure-codex-tui bash`, and sign in
      with `codex login --device-auth`.
    - Copy the sign-in to `/tmp/codex-a` with a fake ID token signature: run item 10's script
      without its last line. The ID token is a JWT, `header.payload.signature`, and the script
      keeps the header and the claims.
    - Run `CODEX_HOME=/tmp/codex-a codex`, send "say ok", run `/status`, and quit.
    - Record whether the turn completes, the account and plan that `/status` shows, and any
      `POST /oauth/token`. Repeat with the claims emptied: `e30` in place of `{payload}`.

## Copilot CLI

13. The format-kept placeholder (preset plan):

    ```sh
    COPILOT_GITHUB_TOKEN=<fine-grained PAT with Copilot Requests> <launcher> \
        --egress-preset=github --persistent-volume=measure-copilot \
        --egress-cred=COPILOT_GITHUB_TOKEN@api.github.com bash
    ```

    - Run `copilot -p "say ok"`. Copilot sends nothing for a token that fails its local check
      (github/copilot-cli #2431).
    - A line with `inject=` on `api.github.com` means that Copilot accepted the placeholder. Record
      every host whose lines carry `cred=`. The plan host gets the placeholder unsubstituted, so the
      turn may fail there.
    - If Copilot sends nothing: on the host, outside any sandbox, run `copilot -p "say ok"` with the
      real token, one letter after `github_pat_` changed to another letter of the same case. An
      error before any request means a check beyond the structure, likely a checksum; a 401 means
      no such check.

## The store's lock (brokering plan, step 2)

14. On macOS, Windows and Linux, in the podman that the launcher uses. On macOS and Linux, save
    the script as a file and run it with `sh FILE`: pasted into a shell, its `set -eu` and its
    `trap` stay in that shell, and the cleanup waits until the shell exits.

    ```sh
    set -eu
    image=docker.io/library/alpine
    volume=$(podman volume create)
    holder=
    cleanup() {
        if [ -n "$holder" ]; then podman rm -f "$holder" >/dev/null; fi
        podman volume rm "$volume" >/dev/null
    }
    trap cleanup EXIT
    holder=$(podman run -d -v "$volume:/s" "$image" \
        flock /s/l sh -c 'touch /s/held; exec sleep 120')
    tries=0
    until podman exec "$holder" test -e /s/held; do
        tries=$((tries + 1))
        if [ "$tries" -ge 30 ]; then echo "the holder never took the lock"; exit 1; fi
        sleep 1
    done
    set +e
    podman run --rm -v "$volume:/s" "$image" flock -n /s/l true; echo "while held: exit $?"
    set -e
    podman kill "$holder" >/dev/null
    podman wait "$holder" >/dev/null
    set +e
    podman run --rm -v "$volume:/s" "$image" flock -n /s/l true; echo "after the kill: exit $?"
    ```

    On Windows, paste this into PowerShell:

    ```powershell
    $image = 'docker.io/library/alpine'
    $volume = podman volume create
    if ($LASTEXITCODE -ne 0) { throw 'podman volume create failed' }
    $holder = $null
    try {
        $holder = podman run -d -v "${volume}:/s" $image `
            flock /s/l sh -c 'touch /s/held; exec sleep 120'
        if ($LASTEXITCODE -ne 0) { throw 'the holder did not start' }
        $tries = 0
        while ($true) {
            podman exec $holder test -e /s/held
            if ($LASTEXITCODE -eq 0) { break }
            $tries++
            if ($tries -ge 30) { throw 'the holder never took the lock' }
            Start-Sleep -Seconds 1
        }
        podman run --rm -v "${volume}:/s" $image flock -n /s/l true
        "while held: exit $LASTEXITCODE"
        podman kill $holder | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'podman kill failed' }
        podman wait $holder | Out-Null
        podman run --rm -v "${volume}:/s" $image flock -n /s/l true
        "after the kill: exit $LASTEXITCODE"
    } finally {
        if ($holder) { podman rm -f $holder | Out-Null }
        podman volume rm $volume | Out-Null
    }
    ```

    - Expect exit 1 while the holder holds the lock, and exit 0 after it is killed.
    - Podman's own errors exit with 125 or higher, so they do not read as either result.
    - The script names its volume and container by the ids that podman returns, gives the holder
      30 seconds to take the lock, stops if setting up or the kill fails, and removes both on
      every exit.

## After the session

1. Sign out of each login that a volume still holds, so that the provider revokes it before the
   volume goes: launch on the volume, and run `/logout` in `claude` or `codex logout`. Items 6, 7
   and 12 end with one.
2. From the measurement directory, run `<launcher> --reset`. It removes that workspace's
   containers, volume, CA and logs, and leaves the named volumes.
3. Remove the named volumes:

   ```sh
   podman volume rm measure-claude-key measure-claude-oat measure-claude-login \
       measure-claude-console measure-claude-rotation measure-claude-rc measure-claude-rc-oat \
       measure-codex-key measure-codex-login measure-codex-tui measure-copilot
   ```

4. Remove the measurement directory.
5. Unset the credentials in the host shell, or close it:

   ```sh
   unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN CODEX_API_KEY COPILOT_GITHUB_TOKEN
   ```

6. Revoke what stays valid at the provider:
   - a subscription login that a step left signed in: https://claude.ai/settings/claude-code lists
     each with its last activity. Codex names no such page, and no page documents a revoke for
     Claude Code's Console sign-in, so items 4, 5 and 11 restore each refused sign-out's file and
     sign out again;
   - the `claude setup-token` token, which lasts a year. The same page lists it as a Claude Code
     token with its sign-in time. To check it, run `claude -p` with `CLAUDE_CODE_OAUTH_TOKEN` set
     and `ANTHROPIC_API_KEY` unset: a set API key outranks the token, and the run then succeeds
     whatever the token's state;
   - any key or token created only for the session.
