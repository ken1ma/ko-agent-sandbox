// The launcher's command line: the session options, a management action with its operands, or the
// command forwarded verbatim (parseArguments); the merge of the options file's options under the
// command line's (merge); and the --env forwards resolved against the host. The file's location and
// syntax are OptionsFile.scala, --env-aws-cred's resolution AwsCredential.scala, --claude-plugin-dir's
// ClaudePlugins.scala.

package agentsandbox.launcher

import agentsandbox.egress.{CredentialBinding, CredentialGrammar}

import AgentSandboxLauncher.*

object CommandLine:

  /**
   * The independent session options, selected on every launch and never persisted by a
   * stage or an agent resume. The writable default is `live` (doc/plan-staged.md has the staged
   * mode and the default flip that follow it); no distributable build may make launches with no
   * `--workspace` option read-only before the staged workflow is usable.
   */
  val WorkspaceModes = Vector("read-only", "live")
  val DefaultWorkspaceMode = "live"

  /**
   * `--workspace`'s other values, beside the mode, in any order, each at most once: the backend that
   * holds the workspace's protections, `fuse`, the ko-agent-fs filter, the default of both modes
   * until the release decision, or `bpf`, the cgroup-LSM policy of doc/plan-bpf-lsm-cgroup.md
   * ("Phases", 6); and `unix-socket`, which allows Unix sockets in the workspace and beneath the
   * persistent volume at the cost of the policy's ninth hook, and so needs `bpf`: the filter cannot
   * honor it. On Windows the share refuses every socket bind itself (`ENOTSUP`), so there the value
   * reaches the volume alone (doc/plan-bpf-lsm-cgroup.md, "What is gained and what is lost").
   */
  val WorkspaceBackends = Vector("fuse", "bpf")
  val DefaultWorkspaceBackend = "fuse"
  val UnixSocketValue = "unix-socket"

  /** The settings `--workspace` selects, as parseWorkspace reads them. */
  final case class WorkspaceSettings(mode: String, backend: String, unixSocket: Boolean):
    def bpf: Boolean = backend == "bpf"
    def live: Boolean = mode == "live"
    def readOnly: Boolean = mode == "read-only"
    /** The filter mounts the workspace: a live session under the `fuse` backend. */
    def filtered: Boolean = live && !bpf

    /** The launch line uses commas without spaces to match the `--workspace` command-line value
      * and the container label (KoAgentBpf.SettingsLabel): the mode, the backend, then `unix-socket`
      * when set. The backend is always spelled, so a launch line reads the same once another backend
      * is the default. */
    def spelled: String = s"$mode,$backend" + (if unixSocket then s",$UnixSocketValue" else "")

  object WorkspaceSettings:
    val Default: WorkspaceSettings =
      WorkspaceSettings(DefaultWorkspaceMode, DefaultWorkspaceBackend, unixSocket = false)

  /**
   * `--workspace=<mode>[,<backend>][,unix-socket]`, the values in any order and each once; an
   * unclear value refuses the launch rather than being read as either side of a choice (design.md,
   * "Security configuration must fail closed").
   */
  def parseWorkspace(value: String): Either[String, WorkspaceSettings] =
    val values = value.split(",", -1).toVector
    val grammar =
      s"the values are a mode, ${WorkspaceModes.mkString(" or ")}, a backend, " +
        s"${WorkspaceBackends.mkString(" or ")}, and $UnixSocketValue, separated by commas, each at most once"
    val modes = values.filter(WorkspaceModes.contains)
    val backends = values.filter(WorkspaceBackends.contains)
    val sockets = values.filter(_ == UnixSocketValue)
    val unknown = values.filterNot(value =>
      WorkspaceModes.contains(value) || WorkspaceBackends.contains(value) || value == UnixSocketValue,
    )
    if unknown.nonEmpty || modes.size != 1 || backends.size > 1 || sockets.size > 1 then
      Left(s"error: --workspace=$value; $grammar")
    else
      val settings =
        WorkspaceSettings(modes.head, backends.headOption.getOrElse(DefaultWorkspaceBackend), sockets.nonEmpty)
      if settings.unixSocket && !settings.bpf then
        Left(
          s"error: --workspace=$value; $UnixSocketValue needs the bpf backend: the fuse filter cannot allow Unix " +
            s"sockets in the workspace (--workspace=${settings.mode},bpf,$UnixSocketValue)",
        )
      else Right(settings)
  val EgressProfiles = Vector("deny-all", "deny-unless-model", "deny-unless-allowed")
  val DefaultEgressProfile = "deny-unless-allowed"

  /**
   * Each grant of a host resource comes from a launcher option, on the command line or in the
   * options file, never from a variable a shell profile exports to every process; every launch
   * prints each grant. The clipboard: off by default, and `paste` before `bidirectional`, because
   * each step hands the agent more of the host: reading what the user last copied, then writing
   * what the user will next paste (ClipboardRelay). `--audio=mic` grants the host microphone for
   * the session (MicrophoneRelay).
   */
  val ClipboardModes = Vector("off", "paste", "bidirectional")
  val DefaultClipboardMode = "off"

  /**
   * The devices `--audio` grants, each alone: doc/microphone.md records that the microphone and a
   * speaker together close a loop from the host's speaker back into the sandbox, and leaves the
   * speaker out ("No playback to the host").
   */
  final val AudioOption = "--audio"
  val AudioDevices = Vector("mic")
  val MicOption = s"$AudioOption=mic"

  def parseAudio(value: String): Either[String, Vector[String]] =
    if value == "off" then Right(Vector.empty)
    else
      val devices = value.split(",", -1).toVector
      devices.find(device => !AudioDevices.contains(device)) match
        case Some(_) =>
          Left(s"error: $AudioOption=$value; the values are off, or ${AudioDevices.mkString(", ")} separated by commas")
        case None if devices.distinct != devices => Left(s"error: $AudioOption=$value names a device twice")
        case None                                => Right(devices)

  /** `--nesting` (AgentSandboxLauncher.NestingVariable has what each value allows) and
    * `--session-start` (SessionStartVariable has why the launch pauses). */
  val NestingModes = Vector("none", "user-namespace", "same-uid")
  val DefaultNestingMode = "none"
  val SessionStartModes = Vector("pause", "immediate")
  val DefaultSessionStartMode = "pause"

  /**
   * `--model-provider=<names>` adds model providers to the one the command's name selects for the
   * session's egress (EgressRules.selectedProvider). It is repeatable, so the command line adds to
   * the options file's names rather than replacing them. The names go to the proxy as written: the
   * proxy image defines the provider names, and its refusal of a name it does not define fails the
   * launch (EgressRules.rulesetRefusal). The launcher keeps no list of providers.
   */
  final val ModelProviderOption = "--model-provider"

  final val PersistentVolumeOption = "--persistent-volume"
  final val ProxyImageOption = "--proxy-image"

  /** Skips the options file for one launch or action; on the command line alone (OptionsFile). */
  final val NoOptionsFileOption = "--no-options-file"

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
   * session-start modes, the microphone. Forwarded, one would make what the agent is told differ from what is
   * enforced, the drift the launcher exists to rule out. Every other variable the launcher or the
   * image sets (the proxy and CA-bundle variables, TZ, PAGER) is forwardable: the network has no
   * route but the proxy whatever the environment says, so an override can only fail, visibly,
   * under a name the launch printed — and overriding a default is what a forward is for.
   */
  val RefusedForwardPrefix = LauncherVariablePrefix

  /**
   * The `--env` arguments for the forwards, or why one cannot be made. A name unset on the host
   * is an error, not an empty variable: a forward that configures nothing would fail silently. A
   * forward is how a secret gets in (SECURITY.md, "Credential theft"), so a value the host holds
   * travels as `--env=NAME`, which podman fills from this process's environment: the value is in
   * no podman argument and not in the create command podman records for the container. An
   * explicit value is on the launch command line or in the options file already, so its argument
   * carries `NAME=VALUE`. An empty host value uses `--env=NAME=` because it contains no secret and
   * avoids relying on podman's handling of empty host variables. The launcher's own output
   * carries names alone.
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

  /**
   * Parsed launcher invocation: the session options as given (None when defaulted), then either
   * one management action with its operands, or the command forwarded verbatim. As one source
   * gives them (parseArguments), an option other than a closed choice holds its empty value, and
   * `dropped` names the repeatable options whose empty value dropped the entries before it; the
   * merge (merge, parseCommandLine) reads both and returns each option's value in force, where an
   * empty value has become the default.
   */
  case class ParsedCommandLine(
    workspace: Option[String],
    egress: Option[String],
    action: Option[(String, List[String])],
    command: List[String],
    env: Vector[EnvForward] = Vector.empty,
    runOnHost: Option[Vector[String]] = None,
    credentialBindings: Vector[CredentialBinding] = Vector.empty,
    /** `--env-aws-cred=`, as one source gives it, is `Request(Some(""))`. */
    awsCredential: Option[AwsCredential.Request] = None,
    clipboard: Option[String] = None,
    /** `--audio=off` is `Some(Vector.empty)`. */
    audio: Option[Vector[String]] = None,
    claudePlugins: Vector[String] = Vector.empty,
    modelProviders: Vector[String] = Vector.empty,
    nesting: Option[String] = None,
    sessionStart: Option[String] = None,
    memory: Option[String] = None,
    persistentVolume: Option[String] = None,
    image: Option[String] = None,
    proxyImage: Option[String] = None,
    noOptionsFile: Boolean = false,
    dropped: Set[String] = Set.empty,
  ):
    /** The settings of `workspace`, which parseArguments stored in its one spelling (parseWorkspace). */
    def workspaceSettings: WorkspaceSettings =
      workspace.fold(WorkspaceSettings.Default)(spelled =>
        parseWorkspace(spelled).fold(reason => throw IllegalStateException(reason), identity),
      )
    def workspaceMode: String = workspaceSettings.mode
    def egressProfile: String = egress.getOrElse(DefaultEgressProfile)
    def clipboardMode: String = clipboard.getOrElse(DefaultClipboardMode)
    def nestingMode: String = nesting.getOrElse(DefaultNestingMode)
    def sessionStartMode: String = sessionStart.getOrElse(DefaultSessionStartMode)
    def microphone: Boolean = audio.exists(_.contains("mic"))

  /** An option the options file supplied to a launch or an action, as the startup line spells it. */
  case class FileSupplied(option: String, spelled: String)

  /**
   * A single-valued option: one value per source, the command line's replacing the file's. `empty`
   * is the value that, in force after the merge, means the default; a closed choice has none.
   */
  private case class Single[A](
    name: String,
    get: ParsedCommandLine => Option[A],
    set: (ParsedCommandLine, Option[A]) => ParsedCommandLine,
    spelled: A => String,
    empty: Option[A] = None,
  ):
    def isGiven(parsed: ParsedCommandLine): Boolean = get(parsed).isDefined
    def cleared(parsed: ParsedCommandLine): ParsedCommandLine = set(parsed, None)
    def merged(file: ParsedCommandLine, commandLine: ParsedCommandLine, into: ParsedCommandLine): ParsedCommandLine =
      set(into, get(commandLine).orElse(get(file)).filterNot(empty.contains))
    def supplied(file: ParsedCommandLine, commandLine: ParsedCommandLine): Vector[FileSupplied] =
      if isGiven(commandLine) then Vector.empty else get(file).map(value => FileSupplied(name, spelled(value))).toVector

  /** A repeatable option, merged by `key`: the command line's entry replaces the file's of the same key,
    * and the command line's empty value drops the file's entries. */
  private case class Repeated[A](
    name: String,
    get: ParsedCommandLine => Vector[A],
    set: (ParsedCommandLine, Vector[A]) => ParsedCommandLine,
    key: A => String,
    spelled: A => String,
  ):
    def isGiven(parsed: ParsedCommandLine): Boolean = get(parsed).nonEmpty || parsed.dropped(name)
    def cleared(parsed: ParsedCommandLine): ParsedCommandLine = set(parsed, Vector.empty)
    private def kept(file: ParsedCommandLine, commandLine: ParsedCommandLine): Vector[A] =
      if commandLine.dropped(name) then Vector.empty
      else get(file).filterNot(entry => get(commandLine).exists(key(_) == key(entry)))
    def merged(file: ParsedCommandLine, commandLine: ParsedCommandLine, into: ParsedCommandLine): ParsedCommandLine =
      set(into, kept(file, commandLine) ++ get(commandLine))
    def supplied(file: ParsedCommandLine, commandLine: ParsedCommandLine): Vector[FileSupplied] =
      kept(file, commandLine).map(entry => FileSupplied(name, spelled(entry)))

  private val Singles: Vector[Single[?]] = Vector(
    Single[String]("--workspace", _.workspace, (p, v) => p.copy(workspace = v), v => s"--workspace=$v"),
    Single[String]("--egress", _.egress, (p, v) => p.copy(egress = v), v => s"--egress=$v"),
    Single[String]("--clipboard", _.clipboard, (p, v) => p.copy(clipboard = v), v => s"--clipboard=$v"),
    Single[Vector[String]](
      AudioOption, _.audio, (p, v) => p.copy(audio = v),
      v => s"$AudioOption=${if v.isEmpty then "off" else v.mkString(",")}",
    ),
    Single[String]("--nesting", _.nesting, (p, v) => p.copy(nesting = v), v => s"--nesting=$v"),
    Single[String]("--session-start", _.sessionStart, (p, v) => p.copy(sessionStart = v), v => s"--session-start=$v"),
    Single[String]("--memory", _.memory, (p, v) => p.copy(memory = v), v => s"--memory=$v", Some("")),
    Single[String](
      PersistentVolumeOption, _.persistentVolume, (p, v) => p.copy(persistentVolume = v),
      v => s"$PersistentVolumeOption=$v", Some(""),
    ),
    Single[String]("--image", _.image, (p, v) => p.copy(image = v), v => s"--image=$v", Some("")),
    Single[String](
      ProxyImageOption, _.proxyImage, (p, v) => p.copy(proxyImage = v), v => s"$ProxyImageOption=$v", Some(""),
    ),
    Single[Vector[String]](
      "--run-on-host", _.runOnHost, (p, v) => p.copy(runOnHost = v), v => s"--run-on-host=${v.mkString(",")}",
      Some(Vector.empty),
    ),
    Single[AwsCredential.Request](
      AwsCredential.OptionName, _.awsCredential, (p, v) => p.copy(awsCredential = v), _.spelled,
      Some(AwsCredential.Request(Some(""))),
    ),
  )

  private val Repeateds: Vector[Repeated[?]] = Vector(
    // The name alone: a value may be a secret (forwardedEnvironment).
    Repeated[EnvForward]("--env", _.env, (p, v) => p.copy(env = v), _.name, forward => s"--env=${forward.name}"),
    Repeated[CredentialBinding](
      "--egress-cred", _.credentialBindings, (p, v) => p.copy(credentialBindings = v), _.name,
      binding => s"--egress-cred=${binding.spelled}",
    ),
    Repeated[String](
      ClaudePlugins.OptionName, _.claudePlugins, (p, v) => p.copy(claudePlugins = v), identity,
      directory => s"${ClaudePlugins.OptionName}=$directory",
    ),
    Repeated[String](
      ModelProviderOption, _.modelProviders, (p, v) => p.copy(modelProviders = v), identity,
      name => s"$ModelProviderOption=$name",
    ),
  )

  /** Every option the options file can hold, by name. */
  val FileOptionNames: Vector[String] = Singles.map(_.name) ++ Repeateds.map(_.name)

  /** The options among FileOptionNames that `parsed` gives, as the action refusals read one source. */
  def givenOptions(parsed: ParsedCommandLine): Vector[String] =
    Singles.filter(_.isGiven(parsed)).map(_.name) ++ Repeateds.filter(_.isGiven(parsed)).map(_.name)

  /** `parsed` with only the options named in `used`: what an action reads of the options file. */
  def restrictedTo(parsed: ParsedCommandLine, used: Set[String]): ParsedCommandLine =
    val singles = Singles.filterNot(option => used(option.name)).foldLeft(parsed)((p, option) => option.cleared(p))
    Repeateds.filterNot(option => used(option.name)).foldLeft(singles)((p, option) => option.cleared(p))
      .copy(dropped = parsed.dropped.filter(used))

  /**
   * The options in force for a launch or an action: the command line's over the file's, as
   * Single and Repeated merge them, with the action, the command and `--no-options-file` the
   * command line's. Then the checks across options run on the merged set, so an `--env` and an
   * `--egress-cred` of one name fail whichever source each comes from. Also gives the options the
   * file supplied, for the startup lines.
   */
  def merge(
    file: ParsedCommandLine,
    commandLine: ParsedCommandLine,
  ): Either[String, (ParsedCommandLine, Vector[FileSupplied])] =
    val base = commandLine.copy(dropped = Set.empty)
    val singles = Singles.foldLeft(base)((into, option) => option.merged(file, commandLine, into))
    val merged = Repeateds.foldLeft(singles)((into, option) => option.merged(file, commandLine, into))
    val supplied = Singles.flatMap(_.supplied(file, commandLine)) ++ Repeateds.flatMap(_.supplied(file, commandLine))
    checkedAcross(merged).map(_ -> supplied)

  val NoOptions: ParsedCommandLine = ParsedCommandLine(None, None, None, Nil)

  /** One source's arguments merged over no file: the options in force when the file is skipped. */
  def parseCommandLine(args: List[String]): Either[String, ParsedCommandLine] =
    parseArguments(args).flatMap(merge(NoOptions, _)).map(_._1)

  private def checkedAcross(parsed: ParsedCommandLine): Either[String, ParsedCommandLine] =
    val bindings = parsed.credentialBindings
    val awsNames = parsed.awsCredential.map(_ => AwsCredential.Names).getOrElse(Vector.empty)
    parsed.env.find(forward => bindings.exists(_.name == forward.name)) match
      case Some(forward) =>
        val name = forward.name
        Left(s"error: --env=$name and --egress-cred=$name@...; pass $name to one of them")
      case None if bindings.size > CredentialGrammar.MaxBindings =>
        Left(s"error: ${bindings.size} --egress-cred options; a launch takes at most ${CredentialGrammar.MaxBindings}")
      case None =>
        (parsed.env.map(forward => s"--env=${forward.name}" -> forward.name)
          ++ bindings.map(binding => s"--egress-cred=${binding.spelled}" -> binding.name))
          .find((_, name) => awsNames.contains(name)) match
          case Some((option, name)) =>
            Left(s"error: $option and ${AwsCredential.OptionName}; the option forwards $name itself")
          case None => Right(parsed)

  val ManagementActions: Set[String] =
    Set(
      "--help", "--build", "--update", "--reset", "--reset-run-on-host", "--reset-all", "--stats",
      "--egress-log", "--egress-effective", "--self-test",
    )

  /** The options that take a value, with what the value is; each is refused spelled without its `=`. */
  val ValuedOptions: Map[String, String] = Map(
    "--workspace" -> "<mode>[,<backend>][,unix-socket]", "--egress" -> "<profile>", ModelProviderOption -> "<names>",
    "--clipboard" -> "<mode>", AudioOption -> "off|<devices>", "--nesting" -> "none|user-namespace|same-uid",
    "--session-start" -> "pause|immediate", "--memory" -> "<size>", PersistentVolumeOption -> "<name>",
    "--image" -> "<reference>", ProxyImageOption -> "<reference>", "--env" -> "<name>[=<value>]",
    "--egress-cred" -> "<name>@<host>", "--run-on-host" -> "<programs>", ClaudePlugins.OptionName -> "<dir>",
  )

  private val SpelledOptions: String =
    Vector(
      "--workspace", "--egress", ModelProviderOption, "--clipboard", AudioOption, "--nesting", "--session-start",
      "--memory", PersistentVolumeOption, "--image", ProxyImageOption, "--env",
    ).map(option => s"$option=${ValuedOptions(option)}").mkString(", ") +
      s", ${AwsCredential.OptionName}[=<profile>], --egress-cred=<name>@<host>, --run-on-host=<programs> and " +
      s"${ClaudePlugins.OptionName}=<dir>"

  /**
   * One source's arguments, as given. Outside a management action's documented operands, the first
   * non-option is the command and ends launcher parsing; everything after it is passed verbatim.
   * `--` is an optional escape for a command that could look like a launcher option; no launcher
   * option is parsed after the command. An option this launcher does not parse refuses the launch
   * rather than passing through — authority is never configured by a spelling that is not read.
   * Within one source, a single-valued option is given once and an entry of a repeatable option
   * once; an empty value of a repeatable option drops its entries before it.
   */
  def parseArguments(args: List[String]): Either[String, ParsedCommandLine] =
    // A closed choice takes exactly one of its values, case-sensitive, and an empty value is none of
    // them: an unclear value refuses the launch rather than being read as either side of the choice
    // (design.md, "Security configuration must fail closed"). Its default weakens nothing.
    def choose(option: String, value: String, choices: Vector[String]): Either[String, String] =
      if choices.contains(value) then Right(value)
      else Left(s"error: $option=$value; the values are ${choices.mkString(", ")}, exactly")

    var parsed = NoOptions

    /** A single-valued option's value, given once. */
    def once[A](option: String, current: Option[A], value: Either[String, A])(
      set: Option[A] => ParsedCommandLine,
    ): Either[String, Unit] =
      if current.isDefined then Left(s"error: $option is given twice")
      else value.map(chosen => parsed = set(Some(chosen)))

    def update(next: ParsedCommandLine): Either[String, Unit] =
      parsed = next
      Right(())

    /** A repeatable option's empty value: the entries before it are dropped. */
    def drop(option: String)(set: ParsedCommandLine => ParsedCommandLine): Either[String, Unit] =
      update(set(parsed).copy(dropped = parsed.dropped + option))

    def option(arg: String): Option[Either[String, Unit]] =
      def valueOf(name: String): Option[String] = Option.when(arg.startsWith(name + "="))(arg.drop(name.length + 1))
      def single(name: String, current: Option[String], set: (ParsedCommandLine, Option[String]) => ParsedCommandLine)(
        value: String => Either[String, String],
      ): Option[Either[String, Unit]] =
        valueOf(name).map(spelled => once(name, current, value(spelled))(set(parsed, _)))
      Vector(
        () =>
          single("--workspace", parsed.workspace, (p, v) => p.copy(workspace = v))(
            parseWorkspace(_).map(_.spelled),
          ),
        () => single("--egress", parsed.egress, (p, v) => p.copy(egress = v))(choose("--egress", _, EgressProfiles)),
        () =>
          single("--clipboard", parsed.clipboard, (p, v) => p.copy(clipboard = v))(
            choose("--clipboard", _, ClipboardModes),
          ),
        () => single("--nesting", parsed.nesting, (p, v) => p.copy(nesting = v))(choose("--nesting", _, NestingModes)),
        () =>
          single("--session-start", parsed.sessionStart, (p, v) => p.copy(sessionStart = v))(
            choose("--session-start", _, SessionStartModes),
          ),
        () => single("--memory", parsed.memory, (p, v) => p.copy(memory = v))(Right(_)),
        () => single(PersistentVolumeOption, parsed.persistentVolume, (p, v) => p.copy(persistentVolume = v))(Right(_)),
        () => single("--image", parsed.image, (p, v) => p.copy(image = v))(Right(_)),
        () => single(ProxyImageOption, parsed.proxyImage, (p, v) => p.copy(proxyImage = v))(Right(_)),
        () =>
          valueOf(AudioOption).map: value =>
            once(AudioOption, parsed.audio, parseAudio(value))(v => parsed.copy(audio = v)),
        () =>
          valueOf("--run-on-host").map: value =>
            val programs = if value.isEmpty then Right(Vector.empty) else parseRunOnHost(value)
            once("--run-on-host", parsed.runOnHost, programs)(v => parsed.copy(runOnHost = v)),
        () =>
          Option.when(arg == AwsCredential.OptionName || arg.startsWith(AwsCredential.OptionName + "=")):
            val profile = Option.when(arg != AwsCredential.OptionName)(arg.drop(AwsCredential.OptionName.length + 1))
            once(AwsCredential.OptionName, parsed.awsCredential, Right(AwsCredential.Request(profile)))(v =>
              parsed.copy(awsCredential = v),
            ),
        () =>
          valueOf("--egress-cred").map {
            case "" => drop("--egress-cred")(_.copy(credentialBindings = Vector.empty))
            case value =>
              EgressCredentials.parseOption(value, RefusedForwardPrefix).flatMap: binding =>
                if parsed.credentialBindings.exists(_.name == binding.name) then
                  Left(s"error: --egress-cred=${binding.spelled}; ${binding.name} is bound twice; one name, one host")
                else update(parsed.copy(credentialBindings = parsed.credentialBindings :+ binding))
          },
        // Spelled paths only here; ClaudePlugins.resolve reads them against the host at launch.
        () =>
          valueOf(ClaudePlugins.OptionName).map {
            case ""        => drop(ClaudePlugins.OptionName)(_.copy(claudePlugins = Vector.empty))
            case directory if parsed.claudePlugins.contains(directory) =>
              Left(s"error: ${ClaudePlugins.OptionName}=$directory is given twice")
            case directory => update(parsed.copy(claudePlugins = parsed.claudePlugins :+ directory))
          },
        () =>
          valueOf(ModelProviderOption).map {
            case "" => drop(ModelProviderOption)(_.copy(modelProviders = Vector.empty))
            case spelled =>
              val names = spelled.split(",", -1).toVector
              val selected = parsed.modelProviders ++ names
              if names.contains("") then
                Left(s"error: $ModelProviderOption=$spelled; the value is provider names separated by commas")
              else
                selected.diff(selected.distinct).headOption match
                  case Some(name) => Left(s"error: $ModelProviderOption=$name is given twice")
                  case None       => update(parsed.copy(modelProviders = selected))
          },
        () =>
          valueOf("--env").map {
            case "" => drop("--env")(_.copy(env = Vector.empty))
            case spelled =>
              val (name, value) = spelled.span(_ != '=')
              if !CredentialGrammar.environmentName(name) then
                Left(s"error: --env=$name; a variable is named [A-Za-z_][A-Za-z0-9_]*")
              else if parsed.env.exists(_.name == name) then Left(s"error: --env=$name is given twice")
              else update(parsed.copy(env = parsed.env :+ EnvForward(name, Option.when(value.nonEmpty)(value.drop(1)))))
          },
        () =>
          Option.when(arg == NoOptionsFileOption || arg.startsWith(NoOptionsFileOption + "=")):
            if arg != NoOptionsFileOption then Left(s"error: $arg; $NoOptionsFileOption takes no value")
            else if parsed.noOptionsFile then Left(s"error: $NoOptionsFileOption is given twice")
            else update(parsed.copy(noOptionsFile = true))
      ).iterator.map(_()).collectFirst { case Some(outcome) => outcome }

    @scala.annotation.tailrec
    def loop(rest: List[String]): Either[String, ParsedCommandLine] =
      rest match
        case Nil             => Right(parsed)
        case "--" :: command => Right(parsed.copy(command = command))
        case arg :: _ if ValuedOptions.contains(arg) =>
          Left(s"error: the launch options are spelled $SpelledOptions")
        case arg :: tail if arg.startsWith("--egress-check=") =>
          Right(parsed.copy(action = Some(("--egress-check", arg.stripPrefix("--egress-check=") :: tail))))
        case action :: tail if ManagementActions(action) => Right(parsed.copy(action = Some((action, tail))))
        case arg :: tail if arg.startsWith("--") =>
          option(arg) match
            case Some(Left(refusal)) => Left(refusal)
            case Some(Right(()))     => loop(tail)
            case None                => Left(s"error: unknown option $arg\nRun --help for the launcher actions.")
        case command => Right(parsed.copy(command = command))

    loop(args)
