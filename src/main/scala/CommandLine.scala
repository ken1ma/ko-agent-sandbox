// The launcher's command line: the session options, a management action with its operands, or the
// command forwarded verbatim (parseCommandLine), and the --env forwards resolved against the host.
// --env-aws-cred's resolution is AwsCredential.scala.

package agentsandbox.launcher

import agentsandbox.egress.{CredentialBinding, CredentialGrammar}

import AgentSandboxLauncher.*

object CommandLine:

  /**
   * The independent session options, selected on every launch and never persisted by a
   * stage or an agent resume. The writable default is `live` (doc/plan-staged.md has the staged
   * mode and the default flip that follow it); no distributable build may make launches with no
   * `--write` option read-only before the staged workflow is usable.
   */
  val WriteModes = Vector("reject", "live")
  val DefaultWriteMode = "live"
  val EgressProfiles = Vector("deny-all", "deny-unless-model", "deny-unless-allowed")
  val DefaultEgressProfile = "deny-unless-allowed"

  /** The programs `--run-on-host` can name. Available on macOS only, which
    * AgentSandboxLauncher.launchSettings enforces: the parser stays pure over
    * the arguments. */
  val RunOnHostPrograms = RunOnHostPrereqs.Program.values.toVector.map(_.name)

  def parseRunOnHost(value: String): Either[String, Vector[String]] =
    val names = value.split(",", -1).toVector
    names.find(name => !RunOnHostPrograms.contains(name)) match
      case Some(bad) =>
        Left(s"error: --run-on-host=$bad; the programs are ${RunOnHostPrograms.mkString(", ")}, exactly")
      case None if names.distinct != names => Left(s"error: --run-on-host=$value names a program twice")
      case None                            => Right(names)

  /** `--env=NAME` (value: the host's, read at launch) or `--env=NAME=VALUE`. */
  case class EnvForward(name: String, value: Option[String])

  /**
   * The only names `--env` refuses: the launcher's own KO_AGENT_SANDBOX_* variables, which are how
   * it tells the sandbox what is in force — the egress ruleset, the nesting, clipboard and
   * session-start modes. Forwarded, one would make what the agent is told differ from what is
   * enforced, the drift the launcher exists to rule out. Every other variable the launcher or the
   * image sets (the proxy and CA-bundle variables, TZ, PAGER) is forwardable: the network has no
   * route but the proxy whatever the environment says, so an override can only fail, visibly,
   * under a name the launch printed — and overriding a default is what a forward is for.
   */
  val RefusedForwardPrefix = LauncherVariablePrefix

  /**
   * The `--env` arguments for the forwards, or why one cannot be made. A name unset on the host
   * is an error, not an empty variable: a forward that configures nothing is the silent failure
   * the KO_AGENT_SANDBOX_* typo warning exists for. A forward is how a secret gets in (SECURITY.md,
   * "Credential theft"), so a value the host holds travels as `--env=NAME`, which podman fills from
   * this process's environment: the value is in no podman argument and not in the create command
   * podman records for the container. An explicit value is on the launch command line already, so
   * its argument carries `NAME=VALUE`. An empty host value uses `--env=NAME=` because it contains
   * no secret and avoids relying on podman's handling of empty host variables. The launcher's own
   * output carries names alone.
   */
  def forwardedEnvironment(
    forwards: Vector[EnvForward],
    hostEnv: String => Option[String],
  ): Either[String, Vector[String]] =
    forwards.map(_.name).find(_.startsWith(RefusedForwardPrefix)) match
      case Some(name) =>
        Left(s"error: --env=$name; the launcher sets $RefusedForwardPrefix* itself, and a forward would replace it")
      case None => resolve(forwards, hostEnv)

  private def resolve(forwards: Vector[EnvForward], hostEnv: String => Option[String]): Either[String, Vector[String]] =
    val resolved = forwards.map: forward =>
      forward.value match
        case Some(value) => Right(s"--env=${forward.name}=$value")
        case None =>
          hostEnv(forward.name).toRight(forward.name).map: value =>
            if value.isEmpty then s"--env=${forward.name}=" else s"--env=${forward.name}"
    resolved.collectFirst { case Left(name) => name } match
      case Some(name) =>
        Left(s"error: --env=$name; the variable is not set on the host, so there is nothing to forward")
      case None => Right(resolved.collect { case Right(arg) => arg })

  /** Parsed launcher invocation: the session options as given (None when defaulted), then
    * either one management action with its operands, or the command forwarded verbatim. */
  case class ParsedCommandLine(
    write: Option[String],
    egress: Option[String],
    action: Option[(String, List[String])],
    command: List[String],
    env: Vector[EnvForward] = Vector.empty,
    runOnHost: Option[Vector[String]] = None,
    credentialBindings: Vector[CredentialBinding] = Vector.empty,
    awsCredential: Option[AwsCredential.Request] = None,
  ):
    def writeMode: String = write.getOrElse(DefaultWriteMode)
    def egressProfile: String = egress.getOrElse(DefaultEgressProfile)

  val ManagementActions: Set[String] =
    Set(
      "--help", "--build", "--update", "--reset", "--reset-run-on-host", "--reset-all", "--stats",
      "--egress-log", "--egress-effective", "--self-test",
    )

  /**
   * Outside a management action's documented operands, the first non-option is the command and
   * ends launcher parsing; everything after it is passed verbatim. `--` is an optional escape
   * for a command that could look like a launcher option; no launcher option is parsed after
   * the command. An option this launcher does not parse refuses the launch rather than passing
   * through — authority is never configured by a spelling that is not read.
   */
  def parseCommandLine(args: List[String]): Either[String, ParsedCommandLine] =
    def choose(option: String, value: String, choices: Vector[String]): Either[String, String] =
      if choices.contains(value) then Right(value)
      else Left(s"error: $option=$value; the values are ${choices.mkString(", ")}, exactly")

    var bindings = Vector.empty[CredentialBinding]
    var awsCredential = Option.empty[AwsCredential.Request]

    def loop(
      rest: List[String],
      write: Option[String],
      egress: Option[String],
      env: Vector[EnvForward],
      runOnHost: Option[Vector[String]],
    ): Either[String, ParsedCommandLine] =
      rest match
        case Nil =>
          Right(ParsedCommandLine(write, egress, None, Nil, env, runOnHost))
        case "--" :: command =>
          Right(ParsedCommandLine(write, egress, None, command, env, runOnHost))

        case arg :: tail if arg.startsWith(EgressCredentials.OptionPrefix) =>
          EgressCredentials.parseOption(arg.stripPrefix(EgressCredentials.OptionPrefix), RefusedForwardPrefix)
            .flatMap: binding =>
              if bindings.exists(_.name == binding.name) then
                Left(s"error: --egress-cred=${binding.spelled}; ${binding.name} is bound twice; one name, one host")
              else
                bindings :+= binding
                loop(tail, write, egress, env, runOnHost)

        case arg :: tail if arg == AwsCredential.OptionName || arg.startsWith(AwsCredential.OptionName + "=") =>
          val profile = arg.drop(AwsCredential.OptionName.length).stripPrefix("=")
          if awsCredential.isDefined then Left(s"error: ${AwsCredential.OptionName} is given twice")
          else if arg != AwsCredential.OptionName && profile.isEmpty then
            Left(
              s"error: ${AwsCredential.OptionName}=; name the profile, or drop the = to use " +
                s"${AwsCredential.ProfileVariable}",
            )
          else
            awsCredential = Some(AwsCredential.Request(Option.when(profile.nonEmpty)(profile)))
            loop(tail, write, egress, env, runOnHost)

        case arg :: tail if arg.startsWith("--write=") =>
          if write.isDefined then Left("error: --write is given twice")
          else choose("--write", arg.stripPrefix("--write="), WriteModes)
            .flatMap(value => loop(tail, Some(value), egress, env, runOnHost))

        case arg :: tail if arg.startsWith("--egress=") =>
          if egress.isDefined then Left("error: --egress is given twice")
          else choose("--egress", arg.stripPrefix("--egress="), EgressProfiles)
            .flatMap(value => loop(tail, write, Some(value), env, runOnHost))

        case arg :: tail if arg.startsWith("--run-on-host=") =>
          if runOnHost.isDefined then Left("error: --run-on-host is given twice")
          else parseRunOnHost(arg.stripPrefix("--run-on-host="))
            .flatMap(programs => loop(tail, write, egress, env, Some(programs)))

        case arg :: tail if arg.startsWith("--env=") =>
          val (name, value) = arg.stripPrefix("--env=").span(_ != '=')
          if !CredentialGrammar.environmentName(name) then
            Left(s"error: --env=$name; a variable is named [A-Za-z_][A-Za-z0-9_]*")
          else if env.exists(_.name == name) then Left(s"error: --env=$name is given twice")
          else
            loop(
              tail, write, egress,
              env :+ EnvForward(name, Option.when(value.nonEmpty)(value.drop(1))), runOnHost,
            )

        case ("--write" | "--egress" | "--env" | "--run-on-host" | "--egress-cred") :: _ =>
          Left(
            "error: the launch options are spelled --write=<mode>, --egress=<profile>, " +
              "--env=<name>[=<value>], --env-aws-cred[=<profile>], --egress-cred=<name>@<host> and " +
              "--run-on-host=<programs>",
          )

        case arg :: tail if arg.startsWith("--egress-check=") =>
          Right(
            ParsedCommandLine(
              write, egress,
              Some(("--egress-check", arg.stripPrefix("--egress-check=") :: tail)),
              Nil, env, runOnHost,
            ),
          )

        case action :: tail if ManagementActions(action) =>
          Right(ParsedCommandLine(write, egress, Some((action, tail)), Nil, env, runOnHost))

        case arg :: _ if arg.startsWith("--") =>
          Left(s"error: unknown option $arg\nRun --help for the launcher actions.")

        case command =>
          Right(ParsedCommandLine(write, egress, None, command, env, runOnHost))

    loop(args, None, None, Vector.empty, None).flatMap: parsed =>
      val awsNames = awsCredential.map(_ => AwsCredential.Names).getOrElse(Vector.empty)
      parsed.env.find(forward => bindings.exists(_.name == forward.name)) match
        case Some(forward) =>
          val name = forward.name
          Left(s"error: --env=$name and --egress-cred=$name@…; pass $name to one of them")
        case None if bindings.size > CredentialGrammar.MaxBindings =>
          Left(
            s"error: ${bindings.size} --egress-cred options; a launch takes at most ${CredentialGrammar.MaxBindings}",
          )
        case None =>
          (parsed.env.map(forward => s"--env=${forward.name}" -> forward.name)
            ++ bindings.map(binding => s"--egress-cred=${binding.spelled}" -> binding.name))
            .find((_, name) => awsNames.contains(name)) match
            case Some((option, name)) =>
              Left(s"error: $option and ${AwsCredential.OptionName}; the option forwards $name itself")
            case None => Right(parsed.copy(credentialBindings = bindings, awsCredential = awsCredential))
