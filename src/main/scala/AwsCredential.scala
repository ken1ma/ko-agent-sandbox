// --env-aws-cred: the AWS CLI's temporary credentials for one profile, resolved on the host at
// launch and forwarded by name, as --env=NAME is, with the profile's region when it has one.

package agentsandbox.launcher

import java.nio.file.Path
import java.time.{Duration, Instant, OffsetDateTime}
import java.time.format.DateTimeParseException

import HostCommands.Run

object AwsCredential:

  val OptionName = "--env-aws-cred"
  val ProfileVariable = "AWS_PROFILE"
  val Names = Vector("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
  val ExpirationName = "AWS_CREDENTIAL_EXPIRATION"
  val RegionName = "AWS_REGION"
  val Executable = "aws"
  val InstallUrl = "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"

  /** `--env-aws-cred` as parsed: the profile named, else the host's `AWS_PROFILE`. */
  case class Request(profile: Option[String]):
    def spelled: String = profile.fold(OptionName)(name => s"$OptionName=$name")

  /**
   * The three values for the profile, each under the name the SDKs read, when they expire, and
   * the profile's region, forwarded as `AWS_REGION` since the sandbox has no `~/.aws/config`.
   */
  case class Resolved(profile: String, values: Vector[(String, String)], expiration: String, region: Option[String]):
    def environment: Map[String, String] = values.toMap ++ region.map(RegionName -> _)
    def names: Vector[String] = values.map(_._1) ++ region.map(_ => RegionName)
    def forwards: Vector[CommandLine.EnvForward] =
      environment.toVector.map((name, value) => CommandLine.EnvForward(name, Some(value)))

  /**
   * `--profile` on the command line even when the name came from `AWS_PROFILE`: botocore leaves the
   * launching shell's `AWS_ACCESS_KEY_ID` out of its chain only for a profile given as an argument
   * (`create_credential_resolver`, `disable_env_vars`), so a stale export cannot be what is resolved.
   * `env-no-export` prints one `NAME=VALUE` line per value and the expiration line for temporary
   * credentials alone (`awscli/customizations/configure/exportcreds.py`, `BasePerLineFormatter`).
   */
  def command(aws: Path, profile: String): Vector[String] =
    Vector(aws.toString, "configure", "export-credentials", "--profile", profile, "--format", "env-no-export")

  /** Prints the profile's `region` from the config file alone, and exits 1 when the profile has none. */
  def regionCommand(aws: Path, profile: String): Vector[String] =
    Vector(aws.toString, "configure", "get", "region", "--profile", profile)

  /**
   * The values the AWS CLI on the host resolves for the request, or why there are none to forward.
   * Refusals name the profile and the command, never a value.
   *
   * @param locate        the executable on the host's PATH
   * @param run           the command, with its exit, output and error text
   * @param forwardRegion false when `--env=AWS_REGION` is given, which then names the region itself
   */
  def resolve(
    request: Request,
    hostEnv: String => Option[String],
    locate: String => Option[Path],
    run: Seq[String] => Run,
    now: Instant,
    forwardRegion: Boolean = true,
  ): Either[String, Resolved] =
    for
      profile <- request.profile.orElse(hostEnv(ProfileVariable).filter(_.nonEmpty)).toRight(
        s"error: $OptionName names no profile and $ProfileVariable is not set on the host; " +
          s"pass $OptionName=<profile>",
      )
      aws <- locate(Executable).toRight(
        s"error: ${request.spelled}; $Executable is not on the host's PATH; install the AWS CLI ($InstallUrl)",
      )
      output <- {
        val result = run(command(aws, profile))
        if result.ok then Right(result.text)
        else
          Left(
            s"error: ${request.spelled}; aws configure export-credentials --profile $profile failed:\n${result.err}\n" +
              s"Log in on the host (aws sso login --profile $profile, or aws login --profile $profile), then relaunch.",
          )
      }
      resolved <- parse(request, profile, output, now)
    yield
      val region = Option.when(forwardRegion)(run(regionCommand(aws, profile))).filter(_.ok).map(_.text.trim)
      resolved.copy(region = region.filter(_.nonEmpty))

  /** `env-no-export` output to the values, refusing a set that is not a login's: no expiration, or one passed. */
  def parse(request: Request, profile: String, output: String, now: Instant): Either[String, Resolved] =
    val lines = output.linesIterator.map(_.span(_ != '=')).collect {
      case (name, value) if value.startsWith("=") => name -> value.drop(1)
    }.toMap
    for
      expiration <- lines.get(ExpirationName).toRight(
        s"error: ${request.spelled}; profile $profile resolved a static key, which never expires; the option " +
          "forwards a login's temporary credentials alone (doc/cloud-credentials.md). Forward a static key with " +
          "--env=<name>.",
      )
      _ <- expiry(expiration).filter(!_.isAfter(now)).toLeft(()).left.map(expiredMessage(request.spelled, profile, _))
      values <- Names.foldLeft[Either[String, Vector[(String, String)]]](Right(Vector.empty)): (done, name) =>
        done.flatMap: taken =>
          lines.get(name).filter(_.nonEmpty).toRight(
            s"error: ${request.spelled}; aws configure export-credentials --profile $profile printed no $name",
          ).map(value => taken :+ (name -> value))
    yield Resolved(profile, values, expiration, None)

  private def expiredMessage(spelled: String, profile: String, expired: Instant): String =
    s"error: $spelled; the credentials of profile $profile expired at $expired; " +
      s"log in on the host (aws sso login --profile $profile, or aws login --profile $profile), then relaunch."

  /**
   * The refusal for a set that expired after its resolution: the start prompt waits without bound,
   * and `aws login` resolves a set that lasts fifteen minutes.
   */
  def expiredSince(resolved: Resolved, now: Instant): Option[String] =
    expiry(resolved.expiration).filter(!_.isAfter(now)).map(expiredMessage(OptionName, resolved.profile, _))

  /** The expiration as an instant, when the CLI printed one `OffsetDateTime` reads. */
  def expiry(expiration: String): Option[Instant] =
    try Some(OffsetDateTime.parse(expiration).toInstant)
    catch case _: DateTimeParseException => None

  /**
   * The launch's line for the forward: the credential names, since the values are secrets, how long
   * they serve, and the region, which is no secret.
   */
  def bannerLine(resolved: Resolved, now: Instant): String =
    val expires = expiry(resolved.expiration).map(instant => Duration.between(now, instant)).fold(
      s"expire at ${resolved.expiration}",
    ): duration =>
      val minutes = duration.toMinutes
      if minutes >= 60 then s"expire in ${minutes / 60}h ${minutes % 60}m" else s"expire in ${minutes}m"
    val region = resolved.region.fold(s"; the profile names no region")(value => s"; $RegionName=$value")
    s"aws credential: ${resolved.values.map(_._1).mkString(", ")} from profile ${resolved.profile}, $expires$region"
