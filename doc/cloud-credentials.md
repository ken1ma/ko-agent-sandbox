# Cloud credentials in a session

The launcher forwards nothing from a cloud CLI's configuration directory, including the tokens a
login caches there. To use the credentials a login produced, take the same steps for every cloud:

1. Log in on the host, never in the sandbox. The login's token obtains credentials for every account
   and role you hold, and inside the sandbox every program in the session could read the token.
1. Export into the launching shell the short-lived credentials the login resolves, then forward
   each name with `--env=<name>`. For AWS, `--env-aws-cred` does this step ("AWS", below).
1. Grant each endpoint the session calls, one host per service and region, with the methods its
   SDK sends. Use `read` and the `method=` writes, which the proxy inspects and logs, or a `tunnel`
   where inspection fails.
1. The sandbox holds the real values, usable by every program in it, until they expire
   ([SECURITY.md](../SECURITY.md#defended), "Credential theft"). Forward a read-only role's
   credentials when the session reviews or previews.
1. Refresh stays on the host: when the credentials expire, log in and export again, then relaunch.

## AWS

`aws login` and `aws sso login` cache their tokens under `~/.aws`. Either login resolves to a set
of three values. `--env-aws-cred[=<profile>]` exports that set on the host and forwards each name,
as `--env=<name>` does. The option reads the profile it names, else `AWS_PROFILE`. Exporting fixes
the set, which the CLI would otherwise refresh:

- `aws sso login` resolves role credentials valid for the role's session duration, up to twelve
  hours.
- `aws login` resolves credentials that expire fifteen minutes after issue. The automatic refresh
  that extends a login to twelve hours needs the refresh token, which stays on the host
  (https://docs.aws.amazon.com/sdkref/latest/guide/feature-login-credentials.html).
  - An exported set fits a session of minutes.
  - A longer session takes `aws sso login`, or a relaunch with a fresh export.

The login and the launch:

    aws sso login --profile my-profile        # or: aws login --profile my-profile
    java -jar "<path-to-jar>/ko-agent-sandbox.jar" --env-aws-cred=my-profile claude

The launch prints the three names and the time left. What `--env-aws-cred` does and refuses:

- The option refuses the launch when the login has expired or the host's `PATH` holds no `aws`.
- The option runs `aws configure export-credentials --profile <profile>`.
- The option refuses a profile that resolves a static key. A key without an expiry is not a login's
  credential, and forwarding one gives the session an authority that no relaunch ends. Forward a
  static key with its own `--env=<name>`.
- The option forwards the profile's `region` as `AWS_REGION`, since the sandbox has no
  `~/.aws/config`. The option forwards no region when `--env=AWS_REGION` names one or the profile
  has none.

Under `egress-rule-example`:

- [pulumi-s3-backend-us-east-1/rule](egress-rule-example/pulumi-s3-backend-us-east-1/rule) is a
  complete rule file for a session that runs Pulumi against AWS with its state in S3.
- [pulumi-s3-backend-ap-northeast-1/rule](egress-rule-example/pulumi-s3-backend-ap-northeast-1/rule)
  is the same stack in Tokyo, where CloudFront, Route 53 and the certificate's ACM stay in
  us-east-1.
- [pulumi-cloud-backend/rule](egress-rule-example/pulumi-cloud-backend/rule) names the variables
  that a Google Cloud access token and an Azure service principal travel in.

A Bedrock API key is not one of the three values. The key is a bearer token: forward it as
`--env=AWS_BEARER_TOKEN_BEDROCK`, the variable the Bedrock SDKs read. No default rule names a
Bedrock host, so grant the region's `bedrock-runtime` host with a `tunnel` line in the workspace's
`.ko-agent-sandbox/egress/rule`:

    allow https://bedrock-runtime.us-east-1.amazonaws.com/      tunnel   # N. Virginia
    allow https://bedrock-runtime.ap-northeast-1.amazonaws.com/ tunnel   # Tokyo
