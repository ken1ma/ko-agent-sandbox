// The launcher's command line:
// - the session options, then a management action with its operands or the command forwarded verbatim
//   (parseArguments);
// - the merge that puts the command line's options over the options file's (merge);
// - the --env forwards, resolved against the host.
// OptionsFile.scala holds the options file's location and syntax. AwsCredential.scala resolves --env-aws-cred, and
// ClaudePlugins.scala resolves --claude-plugin-dir.

package agentsandbox.launcher

import agentsandbox.egress.{CredentialBinding, CredentialGrammar, RulesetHelper}

import AgentSandboxLauncher.*

object CommandLine:

  /**
   * The independent session options. Every launch selects them, and neither a stage nor an agent resume persists
   * them.
   * - The writable default is `live`. doc/plan-staged.md has the staged mode and the default flip that follow `live`.
   * - No distributable build may make a launch without a `--workspace` option read-only before the staged workflow is
   *   usable.
   */
  val WorkspaceModes = Vector("read-only", "live")
  val DefaultWorkspaceMode = "live"

  /**
   * `--workspace` takes up to three parts, in any order, each at most once per source, in one value or across several
   * `--workspace` options (joinWorkspace):
   * - the mode (WorkspaceModes);
   * - the backend that holds the workspace's protections:
   *   - `bpf`, the BPF backend, the default of both modes (doc/bpf-lsm-cgroup.md, "Launches");
   *   - `fuse`, the FUSE backend;
   * - the socket setting: `unix-socket` allows Unix sockets in the workspace and beneath the persistent volume at the
   *   cost of the BPF backend's ninth hook, and `no-unix-socket`, the default, does not. `unix-socket` needs `bpf`,
   *   because the FUSE backend cannot honor the value.
   *   - On Windows the share itself refuses every socket bind (`ENOTSUP`), so the value reaches only the volume there
   *     (doc/bpf-lsm-cgroup.md, "What is gained and what is lost").
   *
   * Each part has a value for every setting, defaults included, so a command line can state any part over the options
   * file's (WorkspaceValue.over).
   */
  val WorkspaceBackends = Vector("bpf", "fuse")
  val DefaultWorkspaceBackend = "bpf"
  val UnixSocketValue = "unix-socket"
  val NoUnixSocketValue = "no-unix-socket"

  /** The settings in force once the sources' `--workspace` values are merged. */
  final case class WorkspaceSettings(mode: String, backend: String, unixSocket: Boolean):
    def bpf: Boolean = backend == "bpf"
    def live: Boolean = mode == "live"
    def readOnly: Boolean = mode == "read-only"
    /** Whether the FUSE backend mounts the workspace, which happens in a live session under the `fuse` backend. */
    def fuseMounted: Boolean = live && !bpf

    /** The mode, the backend, then `unix-socket` when set. The launch line uses commas without spaces to match the
      * `--workspace` command-line value and the container label (KoAgentBpf.SettingsLabel). The launch line always
      * spells the backend, the default included. */
    def spelled: String = s"$mode,$backend" + (if unixSocket then s",$UnixSocketValue" else "")

  object WorkspaceSettings:
    val Default: WorkspaceSettings = WorkspaceValue.Unstated.settings

  /**
   * The parts that one source's `--workspace` states. A source parses alone, and the merge then puts the command
   * line's parts over the file's (CommandLine.merge), so the merge knows where each part came from.
   */
  final case class WorkspaceValue(mode: Option[String], backend: Option[String], unixSocket: Option[Boolean]):
    def parts: Vector[String] =
      mode.toVector ++ backend ++ unixSocket.map(if _ then UnixSocketValue else NoUnixSocketValue)
    def spelled: String = parts.mkString(",")

    /** This value's parts, with `file`'s for the parts this value does not state. */
    def over(file: WorkspaceValue): WorkspaceValue =
      WorkspaceValue(mode.orElse(file.mode), backend.orElse(file.backend), unixSocket.orElse(file.unixSocket))

    /** `file`'s parts that this value does not state, which the startup line credits to the file; None for none. */
    def leftOf(file: WorkspaceValue): Option[WorkspaceValue] =
      val left = WorkspaceValue(
        file.mode.filter(_ => mode.isEmpty),
        file.backend.filter(_ => backend.isEmpty),
        file.unixSocket.filter(_ => unixSocket.isEmpty),
      )
      Option.when(left.parts.nonEmpty)(left)

    def settings: WorkspaceSettings = WorkspaceSettings(
      mode.getOrElse(DefaultWorkspaceMode),
      backend.getOrElse(DefaultWorkspaceBackend),
      unixSocket.contains(true),
    )

  object WorkspaceValue:
    val Unstated: WorkspaceValue = WorkspaceValue(None, None, None)

  /**
   * One source's `--workspace` value, with the parts in any order and each part once. An unclear value
   * refuses the launch rather than being read as either side of a choice (design.md, "Security configuration must fail
   * closed").
   */
  def parseWorkspace(value: String): Either[String, WorkspaceValue] =
    val values = value.split(",", -1).toVector
    val grammar =
      s"the parts are a mode, ${WorkspaceModes.mkString(" or ")}, a backend, ${WorkspaceBackends.mkString(" or ")}, " +
        s"and a socket setting, $UnixSocketValue or $NoUnixSocketValue, separated by commas, each at most once"
    val sockets = Vector(UnixSocketValue, NoUnixSocketValue)
    val modes = values.filter(WorkspaceModes.contains)
    val backends = values.filter(WorkspaceBackends.contains)
    val socketValues = values.filter(sockets.contains)
    val unknown = values.filterNot(value =>
      WorkspaceModes.contains(value) || WorkspaceBackends.contains(value) || sockets.contains(value),
    )
    if unknown.nonEmpty || modes.size > 1 || backends.size > 1 || socketValues.size > 1 then
      Left(s"error: --workspace=$value; $grammar")
    else
      val unixSocket = socketValues.headOption.map(_ == UnixSocketValue)
      val parsed = WorkspaceValue(modes.headOption, backends.headOption, unixSocket)
      unixSocketRefusal(parsed.settings).map(reason => s"error: --workspace=$value; $reason").toLeft(parsed)

  /** Why `settings` cannot hold, or None: the FUSE backend cannot honor `unix-socket`. */
  def unixSocketRefusal(settings: WorkspaceSettings): Option[String] =
    Option.when(settings.unixSocket && !settings.bpf)(
      s"$UnixSocketValue needs the BPF backend: the FUSE backend cannot allow Unix sockets in the workspace " +
        s"(--workspace=...,bpf or --workspace=...,$NoUnixSocketValue)",
    )

  /** One source's later `--workspace` value joined to its earlier ones. A part stated twice is refused, as within one
    * value, and so is a join the FUSE backend cannot honor. */
  def joinWorkspace(earlier: WorkspaceValue, later: WorkspaceValue): Either[String, WorkspaceValue] =
    val repeated = WorkspaceValue(
      earlier.mode.filter(_ => later.mode.isDefined),
      earlier.backend.filter(_ => later.backend.isDefined),
      earlier.unixSocket.filter(_ => later.unixSocket.isDefined),
    )
    val joined = later.over(earlier)
    if repeated.parts.nonEmpty then
      Left(
        s"error: --workspace=${later.spelled}; an earlier --workspace already states ${repeated.spelled}; " +
          "give one value from each pair",
      )
    else
      unixSocketRefusal(joined.settings).map(reason => s"error: --workspace=${joined.spelled}; $reason").toLeft(joined)

  /** Why the two sources' `--workspace` values cannot hold together once merged, or None. Each source alone passed
    * parseWorkspace, so only parts from both sources can conflict. */
  def workspaceMergeRefusal(file: Option[WorkspaceValue], commandLine: Option[WorkspaceValue]): Option[String] =
    for
      fromFile <- file
      stated <- commandLine
      merged = stated.over(fromFile).settings
      reason <- unixSocketRefusal(merged)
    yield s"error: the options file's --workspace=${fromFile.spelled} and the command line's " +
      s"--workspace=${stated.spelled} merge to ${merged.spelled}; $reason"

  /**
   * Each grant of a host resource comes from a launcher option, on the command line or in the options file. A grant
   * never comes from a variable that a shell profile exports to every process. Every launch prints each grant.
   * - The clipboard is off by default, and `paste` comes before `bidirectional`, because each step hands the agent
   *   more of the host. `paste` reads what the user last copied, and `bidirectional` also writes what the user will
   *   next paste (ClipboardRelay).
   * - `--audio=mic` grants the host microphone for the session (MicRelay).
   */
  val ClipboardModes = Vector("off", "paste", "bidirectional")
  val DefaultClipboardMode = "off"

  /**
   * The devices that `--audio` grants, each alone. The microphone and a speaker together would close a loop from the
   * host's speaker back into the sandbox, so doc/mic.md leaves the speaker out ("No playback to the host").
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

  /** `--nesting` (AgentSandboxLauncher.NestingVariable says what each value allows) and
    * `--session-start` (SessionStartVariable says why the launch pauses). */
  val NestingModes = Vector("none", "user-namespace", "same-uid")
  val DefaultNestingMode = "none"
  val SessionStartModes = Vector("pause", "immediate")
  val DefaultSessionStartMode = "pause"

  /**
   * `--model-provider=<names>` adds model providers to the provider that the command's name selects for the session's
   * egress (EgressRules.selectedProvider).
   * - The option is repeatable, so the command line adds to the options file's names rather than replacing them.
   * - The names go to the proxy as written. The proxy image defines the provider names, and the proxy's refusal of a
   *   name it does not define fails the launch (EgressRules.rulesetRefusal). The launcher keeps no list of providers.
   */
  final val ModelProviderOption = "--model-provider"

  final val PersistentVolumeOption = "--persistent-volume"
  final val ProxyImageOption = "--proxy-image"

  /** Skips the options file for one launch or action. Only the command line takes this option (OptionsFile). */
  final val NoOptionsFileOption = "--no-options-file"

  /** The programs that `--run-on-host` can name. The option is available on macOS only.
    * AgentSandboxLauncher.launchSettings enforces that limit, so the parser stays pure over the arguments. */
  val RunOnHostPrograms = RunOnHostPrereqs.Program.values.toVector.map(_.name)

  def parseRunOnHost(value: String): Either[String, Vector[String]] =
    val names = value.split(",", -1).toVector
    names.find(name => !RunOnHostPrograms.contains(name)) match
      case Some(bad) =>
        Left(s"error: --run-on-host=$bad; the programs are ${RunOnHostPrograms.mkString(", ")}, exactly")
      case None if names.distinct != names => Left(s"error: --run-on-host=$value names a program twice")
      case None                            => Right(names)

  /** `--env=NAME`, whose value is the host's, read at launch, or `--env=NAME=VALUE`. */
  case class EnvForward(name: String, value: Option[String])

  /**
   * The only names that `--env` refuses: the launcher's own KO_AGENT_SANDBOX_* variables.
   * - The launcher tells the sandbox what is in force through these variables: the egress ruleset, the nesting,
   *   clipboard and session-start modes, and the microphone.
   * - A forwarded KO_AGENT_SANDBOX_* variable would make what the agent is told differ from what is enforced. The
   *   launcher exists to rule out that drift.
   * - Every other variable that the launcher or the image sets is forwardable: the proxy and CA-bundle variables, TZ
   *   and PAGER. The network has no route but the proxy, whatever the environment says. An override can therefore only
   *   fail, visibly, under a name that the launch printed, and overriding a default is what a forward is for.
   */
  val RefusedForwardPrefix = LauncherVariablePrefix

  /**
   * The `--env` arguments for the forwards, or the reason a forward cannot be made.
   * - A name unset on the host is an error, not an empty variable, because a forward that configures nothing would
   *   fail silently.
   * - A forward is how a secret gets in (SECURITY.md, "Credential theft"). A value that the host holds therefore
   *   travels as `--env=NAME`, which podman fills from this process's environment. The value is in no podman argument
   *   and not in the create command that podman records for the container.
   * - An explicit value is already on the launch command line or in the options file, so the value's argument carries
   *   `NAME=VALUE`.
   * - An empty host value uses `--env=NAME=`, because the empty value contains no secret, and the argument avoids
   *   relying on podman's handling of empty host variables.
   * - The launcher's own output carries names alone.
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
   * The parsed launcher invocation: the session options as given (None when defaulted), then either one management
   * action with its operands, or the command forwarded verbatim.
   * - As one source gives the options (parseArguments), an option other than a closed choice holds its empty value.
   *   `dropped` names the repeatable options whose empty value dropped the entries before that value.
   * - The merge (merge, parseCommandLine) reads the empty values and `dropped`, and returns each option's value in
   *   force, where the default replaces an empty value.
   */
  case class ParsedCommandLine(
    workspace: Option[WorkspaceValue],
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
    /** The settings of `workspace`, with the defaults for the parts no source stated. */
    def workspaceSettings: WorkspaceSettings = workspace.fold(WorkspaceSettings.Default)(_.settings)
    def workspaceMode: String = workspaceSettings.mode
    def egressProfile: String = egress.getOrElse(RulesetHelper.DefaultProfile)
    def clipboardMode: String = clipboard.getOrElse(DefaultClipboardMode)
    def nestingMode: String = nesting.getOrElse(DefaultNestingMode)
    def sessionStartMode: String = sessionStart.getOrElse(DefaultSessionStartMode)
    def mic: Boolean = audio.exists(_.contains("mic"))

  /** An option that the options file supplied to a launch or an action, as the startup line spells the option. */
  case class FileSupplied(option: String, spelled: String)

  /**
   * A single-valued option: one value per source.
   * - By default the command line's value replaces the file's. An option of parts, `--workspace`, gives `over`, which
   *   puts the command line's parts over the file's, and `leftOf`, the file's parts that stay in force.
   * - `empty` is the value that means the default when the value is in force after the merge. A closed choice has no
   *   `empty`.
   */
  private case class Single[A](
    name: String,
    get: ParsedCommandLine => Option[A],
    set: (ParsedCommandLine, Option[A]) => ParsedCommandLine,
    spelled: A => String,
    empty: Option[A] = None,
    over: (A, A) => A = (stated: A, _: A) => stated,
    leftOf: (A, A) => Option[A] = (_: A, _: A) => None,
  ):
    def isGiven(parsed: ParsedCommandLine): Boolean = get(parsed).isDefined
    def cleared(parsed: ParsedCommandLine): ParsedCommandLine = set(parsed, None)
    def merged(file: ParsedCommandLine, commandLine: ParsedCommandLine, into: ParsedCommandLine): ParsedCommandLine =
      val inForce = (get(commandLine), get(file)) match
        case (Some(stated), Some(fromFile)) => Some(over(stated, fromFile))
        case (stated, fromFile)             => stated.orElse(fromFile)
      set(into, inForce.filterNot(empty.contains))
    def supplied(file: ParsedCommandLine, commandLine: ParsedCommandLine): Vector[FileSupplied] =
      val fromFile = (get(commandLine), get(file)) match
        case (Some(stated), Some(value)) => leftOf(stated, value)
        case (stated, value)             => value.filter(_ => stated.isEmpty)
      fromFile.map(value => FileSupplied(name, spelled(value))).toVector

  /** A repeatable option, merged by `key`. The command line's entry replaces the file's entry of the same key, and the
    * command line's empty value drops the file's entries. */
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
    Single[WorkspaceValue](
      "--workspace", _.workspace, (p, v) => p.copy(workspace = v), v => s"--workspace=${v.spelled}",
      over = _.over(_), leftOf = _.leftOf(_),
    ),
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
    // The startup line spells the name alone, because a value may be a secret (forwardedEnvironment).
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

  /** The options among FileOptionNames that `parsed` gives. The action refusals read one source with this method. */
  def givenOptions(parsed: ParsedCommandLine): Vector[String] =
    Singles.filter(_.isGiven(parsed)).map(_.name) ++ Repeateds.filter(_.isGiven(parsed)).map(_.name)

  /** `parsed` with only the options named in `used`, which is what an action reads of the options file. */
  def restrictedTo(parsed: ParsedCommandLine, used: Set[String]): ParsedCommandLine =
    val singles = Singles.filterNot(option => used(option.name)).foldLeft(parsed)((p, option) => option.cleared(p))
    Repeateds.filterNot(option => used(option.name)).foldLeft(singles)((p, option) => option.cleared(p))
      .copy(dropped = parsed.dropped.filter(used))

  /**
   * The options in force for a launch or an action, and the options that the file supplied, for the startup lines.
   * - The command line's options go over the file's options, as Single and Repeated merge them. The action, the
   *   command and `--no-options-file` come from the command line.
   * - A `--workspace` part from each source can conflict once merged, which refuses the launch
   *   (workspaceMergeRefusal).
   * - The checks across options then run on the merged set, so an `--env` and an `--egress-cred` of one name fail
   *   whichever source each option comes from.
   */
  def merge(
    file: ParsedCommandLine,
    commandLine: ParsedCommandLine,
  ): Either[String, (ParsedCommandLine, Vector[FileSupplied])] =
    val base = commandLine.copy(dropped = Set.empty)
    val singles = Singles.foldLeft(base)((into, option) => option.merged(file, commandLine, into))
    val merged = Repeateds.foldLeft(singles)((into, option) => option.merged(file, commandLine, into))
    val supplied = Singles.flatMap(_.supplied(file, commandLine)) ++ Repeateds.flatMap(_.supplied(file, commandLine))
    workspaceMergeRefusal(file.workspace, commandLine.workspace).toLeft(()).flatMap(_ => checkedAcross(merged))
      .map(_ -> supplied)

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

  /** The options that take a value, with what the value is. Each option is refused when spelled without its `=`. */
  val ValuedOptions: Map[String, String] = Map(
    "--workspace" -> "read-only|live|bpf|fuse|unix-socket|no-unix-socket[,...]", "--egress" -> "<profile>",
    ModelProviderOption -> "<names>",
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
   * One source's arguments, as given.
   * - Outside a management action's documented operands, the first non-option is the command and ends launcher
   *   parsing. Everything after the command is passed verbatim, and no launcher option is parsed there.
   * - `--` is an optional escape for a command that could look like a launcher option.
   * - An option that this launcher does not parse refuses the launch rather than passing through, so a spelling that
   *   is not read never configures authority.
   * - Within one source, a single-valued option is given once, and each entry of a repeatable option is given once.
   *   `--workspace` may repeat, with each part given once (joinWorkspace).
   *   An empty value of a repeatable option drops the option's entries before that value.
   */
  def parseArguments(args: List[String]): Either[String, ParsedCommandLine] =
    // A closed choice takes exactly one of its values, case-sensitive, and an empty value is none of them. An unclear
    // value refuses the launch rather than being read as either side of the choice (design.md, "Security configuration
    // must fail closed"). A closed choice's default weakens nothing.
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

    /** A repeatable option's empty value, which drops the entries before that value. */
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
          valueOf("--workspace").map: value =>
            parseWorkspace(value)
              .flatMap(stated => parsed.workspace.fold(Right(stated))(joinWorkspace(_, stated)))
              .flatMap(joined => update(parsed.copy(workspace = Some(joined)))),
        () =>
          single("--egress", parsed.egress, (p, v) => p.copy(egress = v))(
            choose("--egress", _, RulesetHelper.Profiles),
          ),
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
                  Left(s"error: --egress-cred=${binding.spelled}; ${CredentialGrammar.boundTwice(binding.name)}")
                else update(parsed.copy(credentialBindings = parsed.credentialBindings :+ binding))
          },
        // The parser keeps the paths as spelled. ClaudePlugins.resolve reads the paths against the host at launch.
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
                Left(s"error: --env=$name; a variable name is ${CredentialGrammar.EnvironmentNameForm}")
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
