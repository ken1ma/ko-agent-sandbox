# Cloud credentials in a session

The launcher forwards nothing from a cloud CLI's configuration directory, including the tokens a
login caches there. Using the credentials a login produced takes the same steps for every cloud:

1. Log in on the host, never in the sandbox: inside, the login's token, which obtains credentials
   for every account and role you hold, would be readable by every program in the session.
1. Export into the launching shell the short-lived credentials the login resolves, then forward
   each name with `--env=<name>`.
1. Grant each endpoint the session calls as a `tunnel` line, one host per service and region.
1. The sandbox holds the real values, usable by every program in it, until they expire
   ([SECURITY.md](../SECURITY.md#defended), "Credential theft"). Forward a read-only role's
   credentials when the session reviews or previews.
1. Refresh stays on the host: when the credentials expire, log in and export again, then relaunch.

## AWS

`aws login` and `aws sso login` cache their tokens under `~/.aws`. Either resolves to a set of
three values, and exporting fixes the set the CLI would otherwise refresh:

- `aws sso login` resolves role credentials valid for the role's session duration, up to twelve
  hours.
- `aws login` resolves credentials that expire fifteen minutes after issue; the automatic refresh
  that extends a login to twelve hours needs the refresh token, which stays on the host
  (https://docs.aws.amazon.com/sdkref/latest/guide/feature-login-credentials.html). An exported
  set fits a session of minutes; a longer one takes `aws sso login`, or a relaunch with a fresh
  export.

The export and the launch:

    aws sso login --profile my-profile        # or: aws login --profile my-profile
    eval "$(aws configure export-credentials --profile my-profile --format env)"
    java -jar "<path-to-jar>/ko-agent-sandbox.jar" \
        --env=AWS_ACCESS_KEY_ID --env=AWS_SECRET_ACCESS_KEY --env=AWS_SESSION_TOKEN claude

[egress-rule-example/pulumi-aws/rule](egress-rule-example/pulumi-aws/rule) is a complete rule
file for a session that runs Pulumi against AWS.

A Bedrock API key is not one of these values: it is a bearer token, forwarded as
`--env=AWS_BEARER_TOKEN_BEDROCK`, the variable the Bedrock SDKs read. No default names a Bedrock
host; the region's `bedrock-runtime` host is the project's own `tunnel` line in
`.ko-agent-sandbox/egress/rule`:

    allow https://bedrock-runtime.us-east-1.amazonaws.com/      tunnel   # N. Virginia
    allow https://bedrock-runtime.ap-northeast-1.amazonaws.com/ tunnel   # Tokyo
