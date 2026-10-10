package agentsandbox.launcher

import java.nio.file.{Path, Paths}
import java.time.Instant

import AwsCredential.*
import CommandLine.*
import HostCommands.Run

class AwsCredentialTest extends munit.FunSuite:

  private val now = Instant.parse("2026-10-08T10:00:00Z")
  private val aws = Paths.get("/usr/local/bin/aws")
  private val output =
    """AWS_ACCESS_KEY_ID=ASIAEXAMPLE
      |AWS_SECRET_ACCESS_KEY=secret/with+symbols=
      |AWS_SESSION_TOKEN=token==
      |AWS_CREDENTIAL_EXPIRATION=2026-10-08T21:58:30+00:00
      |""".stripMargin
  private val values = Vector(
    "AWS_ACCESS_KEY_ID" -> "ASIAEXAMPLE", "AWS_SECRET_ACCESS_KEY" -> "secret/with+symbols=",
    "AWS_SESSION_TOKEN" -> "token==",
  )

  /** The host's `aws`: the export's result, and the profile's region, none when `region` is None. */
  private def host(exit: Int, out: String, err: String = "", region: Option[String] = Some("ap-northeast-1")) =
    (args: Seq[String]) =>
      if args.contains("export-credentials") then Run(exit, out.getBytes("UTF-8"), err)
      else region.fold(Run(1, Array.emptyByteArray, ""))(value => Run(0, s"$value\n".getBytes("UTF-8"), ""))

  test("option parsing: --env-aws-cred names a profile or takes AWS_PROFILE, once, and never beside its names"):
    assertEquals(
      parseCommandLine(List("--env-aws-cred=team", "claude")).map(_.awsCredential),
      Right(Some(Request(Some("team")))),
    )
    assertEquals(parseCommandLine(List("--env-aws-cred", "claude")).map(_.awsCredential), Right(Some(Request(None))))
    assert(parseCommandLine(List("--env-aws-cred=", "claude")).swap.exists(_.contains("name the profile")))
    assert(parseCommandLine(List("--env-aws-cred", "--env-aws-cred=team")).swap.exists(_.contains("twice")))
    // The names it forwards are its own: a second route for one of them is a refusal, not a race.
    assert(
      parseCommandLine(List("--env-aws-cred", "--env=AWS_SESSION_TOKEN")).swap
        .exists(_.contains("--env=AWS_SESSION_TOKEN and --env-aws-cred")),
    )
    assert(
      parseCommandLine(List("--egress-cred=AWS_ACCESS_KEY_ID@a.example", "--env-aws-cred=team")).swap
        .exists(_.contains("--egress-cred=AWS_ACCESS_KEY_ID@a.example:Authorization and --env-aws-cred")),
    )
    // The region is the user's to name beside the option, which then leaves it alone (resolve).
    assert(parseCommandLine(List("--env-aws-cred", "--env=AWS_REGION=us-east-1", "claude")).isRight)
    // Without the option, the names are the user's to forward as any other.
    assert(parseCommandLine(List("--env=AWS_SESSION_TOKEN", "claude")).isRight)
    // After the command, it is the command's.
    assertEquals(parseCommandLine(List("claude", "--env-aws-cred")).map(_.awsCredential), Right(None))

  test("the commands name the profile as an argument: one line per value, then the region"):
    assertEquals(
      command(aws, "team"),
      Vector("/usr/local/bin/aws", "configure", "export-credentials", "--profile", "team", "--format", "env-no-export"),
    )
    assertEquals(
      regionCommand(aws, "team"),
      Vector("/usr/local/bin/aws", "configure", "get", "region", "--profile", "team"),
    )

  test("the values are read by name, in the order the sandbox lists them, with the expiry and the region"):
    var ran = Vector.empty[Seq[String]]
    val resolved = resolve(
      Request(None), Map("AWS_PROFILE" -> "team").get, _ => Some(aws),
      args => { ran :+= args; host(0, output)(args) }, now,
    )
    assertEquals(resolved, Right(Resolved("team", values, "2026-10-08T21:58:30+00:00", Some("ap-northeast-1"))))
    assertEquals(ran, Vector(command(aws, "team"), regionCommand(aws, "team")))
    assertEquals(resolved.map(_.names), Right(Names :+ "AWS_REGION"))
    assertEquals(resolved.map(_.environment), Right(values.toMap + ("AWS_REGION" -> "ap-northeast-1")))
    assertEquals(resolved.map(_.forwards.map(_.name).sorted), Right((Names :+ "AWS_REGION").sorted))
    assertEquals(
      resolved.map(bannerLine(_, now)),
      Right(
        "aws credential: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN from profile team, " +
          "expire in 11h 58m; AWS_REGION=ap-northeast-1",
      ),
    )
    // A profile named on the option wins over the host's.
    assertEquals(
      resolve(Request(Some("other")), Map("AWS_PROFILE" -> "team").get, _ => Some(aws), host(0, output), now)
        .map(_.profile),
      Right("other"),
    )

  test("a profile without a region forwards none, and --env=AWS_REGION keeps the region command from running"):
    val none = resolve(Request(Some("team")), Map.empty, _ => Some(aws), host(0, output, region = None), now)
    assertEquals(none.map(_.region), Right(None))
    assertEquals(none.map(_.names), Right(Names))
    assertEquals(none.map(bannerLine(_, now)).map(_.endsWith("; the profile names no region")), Right(true))
    var ran = Vector.empty[Seq[String]]
    val skipped = resolve(
      Request(Some("team")), Map.empty, _ => Some(aws), args => { ran :+= args; host(0, output)(args) }, now,
      forwardRegion = false,
    )
    assertEquals(skipped.map(_.region), Right(None))
    assertEquals(ran, Vector(command(aws, "team")))

  test("a refusal names what is missing and what to do: the profile, the CLI, the login, the expiry"):
    def refusal(
      request: Request, hostEnv: Map[String, String], locate: String => Option[Path], run: Seq[String] => Run,
    ): String =
      resolve(request, hostEnv.get, locate, run, now).swap.getOrElse(fail("resolved"))
    assert(refusal(Request(None), Map.empty, _ => Some(aws), host(0, output)).contains("AWS_PROFILE is not set"))
    assert(refusal(Request(None), Map("AWS_PROFILE" -> ""), _ => Some(aws), host(0, output)).contains("not set"))
    assert(refusal(Request(Some("team")), Map.empty, _ => None, host(0, output)).contains("not on the host's PATH"))
    val expired = refusal(Request(Some("team")), Map.empty, _ => Some(aws), host(255, "", "Error loading SSO Token"))
    assert(expired.contains("Error loading SSO Token"), expired)
    assert(expired.contains("aws sso login --profile team"), expired)
    // A static key has no expiration line: not a login's credential, and never forwarded by this option.
    val static = refusal(
      Request(Some("team")), Map.empty, _ => Some(aws),
      host(0, "AWS_ACCESS_KEY_ID=AKIAEXAMPLE\nAWS_SECRET_ACCESS_KEY=secret\n"),
    )
    assert(static.contains("static key"), static)
    assert(static.contains("--env=<name>"), static)
    val past = refusal(
      Request(Some("team")), Map.empty, _ => Some(aws),
      host(0, output.replace("2026-10-08T21:58:30+00:00", "2026-10-08T09:59:00+00:00")),
    )
    assert(past.contains("expired at 2026-10-08T09:59:00Z"), past)
    val partial = refusal(
      Request(Some("team")), Map.empty, _ => Some(aws), host(0, output.replace("AWS_SESSION_TOKEN=token==\n", "")),
    )
    assert(partial.contains("printed no AWS_SESSION_TOKEN"), partial)
    // No value in any refusal.
    Vector(expired, static, past, partial).foreach: message =>
      assert(!message.contains("secret"), message)
      assert(!message.contains("token=="), message)

  test("an expiry the CLI prints in a form OffsetDateTime does not read stays on the line as printed"):
    val resolved = parse(Request(Some("team")), "team", output.replace("+00:00", ""), now)
    assertEquals(resolved.map(_.expiration), Right("2026-10-08T21:58:30"))
    assertEquals(
      resolved.map(bannerLine(_, now)).map(_.contains("expire at 2026-10-08T21:58:30; the profile")),
      Right(true),
    )
    val line = bannerLine(Resolved("team", Vector.empty, "2026-10-08T10:14:00Z", None), now)
    assert(line.contains(", expire in 14m;"), line)

  test("a set that expires while the launch waits at the prompt is refused at the create"):
    val resolved = parse(Request(Some("team")), "team", output, now).fold(fail(_), identity)
    assertEquals(expiredSince(resolved, now), None)
    val atExpiry = expiredSince(resolved, Instant.parse("2026-10-08T21:58:30Z"))
    assertEquals(atExpiry.map(_.contains("expired at")), Some(true))
    val late = expiredSince(resolved, Instant.parse("2026-10-09T00:00:00Z")).getOrElse(fail("not refused"))
    assert(late.contains("--env-aws-cred; the credentials of profile team expired at 2026-10-08T21:58:30Z"), late)
    assert(late.contains("aws sso login --profile team"), late)
    assert(!late.contains("token=="), late)
    // An expiry OffsetDateTime does not read is never refused here, as it is not at resolution.
    val unread = resolved.copy(expiration = "2026-10-08T21:58:30")
    assertEquals(expiredSince(unread, Instant.parse("2026-10-09T00:00:00Z")), None)

