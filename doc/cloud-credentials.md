# Cloud credentials in a session

The launcher forwards nothing from a cloud CLI's configuration directory, including the tokens a
login caches there. Using the credentials a login produced takes the same steps for every cloud:

1. Log in on the host, never in the sandbox: inside, the login's token, which obtains credentials
   for every account and role you hold, would be readable by every program in the session.
1. Export into the launching shell the short-lived credentials the login resolves, then forward
   each name with `--env=<name>`. For AWS, `--env-aws-cred` does this step ("AWS", below).
1. Grant each endpoint the session calls, one host per service and region, with the methods its
   SDK sends: `read` and the `method=` writes, inspected and logged, or a `tunnel` where
   inspection fails.
1. The sandbox holds the real values, usable by every program in it, until they expire
   ([SECURITY.md](../SECURITY.md#defended), "Credential theft"). Forward a read-only role's
   credentials when the session reviews or previews.
1. Refresh stays on the host: when the credentials expire, log in and export again, then relaunch.

## AWS

`aws login` and `aws sso login` cache their tokens under `~/.aws`. Either resolves to a set of
three values, which `--env-aws-cred[=<profile>]` exports on the host and forwards by name, as
`--env=<name>` does, for the profile named, else for `AWS_PROFILE`. Exporting fixes the set the
CLI would otherwise refresh:

- `aws sso login` resolves role credentials valid for the role's session duration, up to twelve
  hours.
- `aws login` resolves credentials that expire fifteen minutes after issue; the automatic refresh
  that extends a login to twelve hours needs the refresh token, which stays on the host
  (https://docs.aws.amazon.com/sdkref/latest/guide/feature-login-credentials.html). An exported
  set fits a session of minutes; a longer one takes `aws sso login`, or a relaunch with a fresh
  export.

The login and the launch:

    aws sso login --profile my-profile        # or: aws login --profile my-profile
    java -jar "<path-to-jar>/ko-agent-sandbox.jar" --env-aws-cred=my-profile claude

The launch prints the three names and the time left; an expired login, or no `aws` on the host's
`PATH`, refuses the launch. The option runs `aws configure export-credentials --profile <profile>`
and refuses a profile that resolves a static key: a key without an expiry is not a login's
credential, and forwarding one gives the session an authority no relaunch ends. A static key is its
own `--env=<name>` forward. The region travels with the credentials: the sandbox has no
`~/.aws/config`, so the option forwards the profile's `region` as `AWS_REGION`, unless
`--env=AWS_REGION` names one or the profile has none.

Under `egress-rule-example`,
[pulumi-s3-backend-us-east-1/rule](egress-rule-example/pulumi-s3-backend-us-east-1/rule) is a
complete rule file for a session that runs Pulumi against AWS with its state in S3;
[pulumi-s3-backend-ap-northeast-1/rule](egress-rule-example/pulumi-s3-backend-ap-northeast-1/rule)
is the same stack in Tokyo, where CloudFront, Route 53 and the certificate's ACM stay in us-east-1;
[pulumi-cloud-backend/rule](egress-rule-example/pulumi-cloud-backend/rule) names the variables
a Google Cloud access token and an Azure service principal travel in.

A Bedrock API key is not one of these values: it is a bearer token, forwarded as
`--env=AWS_BEARER_TOKEN_BEDROCK`, the variable the Bedrock SDKs read. No default names a Bedrock
host; the region's `bedrock-runtime` host is the project's own `tunnel` line in
`.ko-agent-sandbox/egress/rule`:

    allow https://bedrock-runtime.us-east-1.amazonaws.com/      tunnel   # N. Virginia
    allow https://bedrock-runtime.ap-northeast-1.amazonaws.com/ tunnel   # Tokyo
