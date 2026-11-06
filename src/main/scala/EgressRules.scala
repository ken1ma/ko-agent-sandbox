// The launcher's side of the egress proxy:
//
// - reading this workspace's rules;
// - asking the proxy image what the rules resolve to;
// - keeping the audit log;
// - the actions that report on the rules and the log (--egress-log, --egress-effective, --egress-check).
//
// This file does not start a session's proxy *container*. AgentSandboxLauncher.prepareRunFiles starts the
// container with a dozen flags, and moving that code here would drag the launch with it.
//
// The proxy owns the defaults, the profile equations and the rule resolution (container/ko-agent-egress-proxy).
// Nothing here re-implements any of them, so there is no second opinion about what is allowed.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import agentsandbox.egress.{CredentialBinding, RulesetHelper}

import AgentSandboxLauncher.*
import HostCommands.*
import FileHelper.*
import LauncherState.*
import SandboxWorkspace.*

object EgressRules:

  /**
   * The rule text with comments stripped and whitespace collapsed, one line per rule line: the format
   * that the environment variable holds.
   *
   * - A rule is a multi-token line (`allow https://x/ read`), so the line breaks separate the rules and
   *   must stay.
   * - A comment starts at the start of a line or after whitespace.
   * - A `#` inside a token stays, so the proxy's parser sees and refuses the token. Stripping the `#`
   *   here would turn `https://x/a/#b/` into the wider `https://x/a/`.
   * - The proxy says what is in force: a rule file's ruleset is not this text.
   */
  def normalizeRuleText(text: String): String =
    text.linesIterator
      .map(RulesetHelper.ruleTokens(_).mkString(" "))
      .filter(_.nonEmpty)
      .mkString("\n")

  def lineSummary(normalized: String): String =
    normalized.linesIterator.mkString("; ")

  /**
   * The rule lines that the ruleset reports as granting beyond the defaults. The method reads them from
   * the ruleset's `widening lines (N): ...` line, which puts `; ` between rule lines.
   *
   * - The launch prints the lines under an `<file>: N widening lines` heading. A file that only removes
   *   or narrows grants prints no such report, so the report is a signal rather than a habit.
   * - The proxy classifies against the defaults it ships (resolveRuleset has the classes), so a custom
   *   image reports against its own defaults.
   * - An image that prints no such line reports nothing, never a classification against defaults the
   *   image does not have.
   */
  def wideningLines(resolved: String): Vector[String] =
    resolved.linesIterator.find(_.startsWith(RulesetHelper.WideningLineHead)).toVector.flatMap: line =>
      line.drop(line.indexOf("):") + 2).trim.split("; ").toVector.filter(_.nonEmpty)

  private val WholeHostRule = """allow https://([^/ ]+)/ (.+)""".r

  /** Joins whole-host rules (`allow https://<host>/ <words>`) that share their grant words into one
    * line, `allow <words>: <host>, <host>`, at the first rule's place. A report that lists many hosts
    * then stays short. A rule with no such partner, and any other line, stays as written. */
  def groupedByHost(rules: Seq[String]): Vector[String] =
    val hostsOf = rules
      .collect { case WholeHostRule(host, words) => words -> host }
      .groupMap((words, _) => words)((_, host) => host)
      .map((words, hosts) => words -> hosts.distinct)
      .filter((_, hosts) => hosts.size > 1)
    // Every rule of a group maps to the same line, and distinct keeps that line at the first rule's place.
    rules.toVector
      .map:
        case WholeHostRule(_, words) if hostsOf.contains(words) => s"allow $words: ${hostsOf(words).mkString(", ")}"
        case rule => rule
      .distinct

  /** The prefixes of the lines that the proxy prints after the ruleset lines: the summary line, then the
    * widening line. These lines describe the ruleset's size and the workspace's file rather than the
    * ruleset. Everything from the first of them on is metadata (RulesetHelper.metadataLines). */
  val MetadataPrefixes: Vector[String] = Vector(RulesetHelper.SummaryLineHead, RulesetHelper.WideningLineHead)

  /** Removes the metadata about the workspace's file from the resolved rules. The launcher exports the
    * result in `KO_AGENT_SANDBOX_EGRESS_RULESET`, and selects the inspection certificate's hosts from it. */
  def rulesetLinesOf(resolved: String): String =
    resolved.linesIterator.takeWhile(line => !MetadataPrefixes.exists(line.startsWith)).mkString("\n")

  /**
   * The launch banner's one-line summary of the ruleset: the profile as the ruleset's first line spells
   * it, then the counts of the summary line, which say how wide the ruleset is. Neither source alone is
   * enough.
   *
   * - The banner leaves out the full lines. The lines are one `--egress-effective` away, and the proxy
   *   writes them into this session's own log.
   * - A thousand characters of hostnames in the banner make a line that people learn to skip. A ruleset
   *   that nobody expected then goes unnoticed.
   * - The method refuses a dry run that lacks the profile line, the summary's counts, or the provider
   *   field that every profile but deny-all carries (RulesetHelper.rulesetLines). No launch therefore
   *   starts without this line stating its egress.
   *
   * @param profileSource what the line adds after the profile when the options file supplied `--egress`
   *   (OptionsInForce.from). `providerSource` is what the line adds after the provider selection when
   *   the options file supplied provider names (OptionsInForce.providersFrom).
   * @param color tints the profile in the shade of `profileFrom` (HostCommands.stated), and the provider selection as
   *   chosen, in the file's shade for each provider in `providersFromFile` (HostCommands.chosen). The command's own
   *   provider counts as the command line's, since the user typed the command. `no provider` is a default: no source
   *   named one.
   */
  def egressBanner(
    resolved: String,
    profileSource: String = "",
    providerSource: String = "",
    color: Boolean = colorStderr,
    providersFromFile: Set[String] = Set.empty,
    profileFrom: ValueSource,
  ): Either[String, String] =
    val lines = resolved.linesIterator.toVector

    val counts: Map[String, Int] =
      lines.find(_.startsWith(RulesetHelper.SummaryLineHead)).toVector
        .flatMap(_.stripPrefix(RulesetHelper.SummaryLineHead).split(";").toVector)
        .flatMap: field =>
          field.trim.split(" ", 2) match
            case Array(count, name) => count.toIntOption.map(name -> _)
            case _                  => None
        .toMap

    for
      head <- lines.headOption.filter(_.startsWith(RulesetHelper.ProfileLineHead)).toRight(NoProfileLine)
      profile = head.stripPrefix(RulesetHelper.ProfileLineHead).takeWhile(_ != ';')
      provider = head.split(RulesetHelper.ModelProviderLabel, 2).lift(1).map(_.trim).filter(_.nonEmpty)
      _ <- Either.cond(profile == "deny-all" || provider.nonEmpty, (), noProviderField(profile))
      inspected <- counts.get("inspected hosts").toRight(NoSummaryCounts)
      tunnel <- counts.get("tunnel hosts").toRight(NoSummaryCounts)
    yield
      def named(name: String) = chosen(name, color, providersFromFile(name))
      val selected = provider.map:
        case "none"                       => s"${defaulted("no provider", color)} selected"
        case names if names.contains(",") => s"model providers ${names.split(",").map(named).mkString(", ")}"
        case name                         => s"model provider ${named(name)}"
      val profileLine = s"egress: ${stated(profile, profileFrom, color)}$profileSource"
      (Vector(profileLine) ++ selected.map(_ + providerSource)
        :+ s"$inspected inspected, $tunnel tunnel")
        .mkString("; ")

  /**
   * Which of `names`, the entries of the workspace's log directory, to delete.
   *
   * - The method deletes every run directory (runLogDir) except the newest retain-1, so `retain`
   *   directories remain, counting the new run's. A run directory's name sorts chronologically by its
   *   UTC stamp.
   * - The method never prunes a live run's directory, however old. The run's proxy, runner and relay
   *   append to the directory's files. Unlinking the files would leave the session writing where nothing
   *   can read, and the whole record would be lost at exit.
   *   - A retention rule that counts sessions rather than liveness does this to a workspace that runs
   *     more than `retain` sessions at once.
   *   - More than `retain` directories can remain while their runs are live.
   * - The method also deletes the flat files of the layout before run directories, unless their run is
   *   live. That branch can go after 2026-12-17, two months after run directories replaced the flat files.
   */
  def runLogDirsToPrune(names: Seq[String], retain: Int, liveRuns: Set[String]): Seq[String] =
    val runDirs = names.filter(_.matches(RunLogDirPattern)).sorted
      .dropRight((retain - 1).max(0))
      .filterNot(name => liveRuns.exists(run => name.endsWith(s"-$run")))
    val flatLogs = names.filter(_.matches("(proxy|run-on-host|microphone)-.*\\.log"))
      .filterNot(name => liveRuns.exists(run => name.endsWith(s"-$run.log")))
    runDirs ++ flatLogs

  val RetainedRuns = 20

  val RuleFiles: Vector[(String, String)] = Vector(RulesetHelper.RuleFile -> RulesetHelper.RuleVariable)

  /**
   * The egress rule files that are present, as (name, normalized text) pairs, under the refusals that
   * SandboxWorkspace.readBoundaryRuleFiles lists.
   */
  def readRuleFiles(egressDir: Path): Either[String, Vector[(String, String)]] =
    SandboxWorkspace.readBoundaryRuleFiles(egressDir, RuleFiles.map(_(0)), "doc/egress-proxy.md", normalizeRuleText)

  /**
   * The model provider of each agent command, keyed by the basename of the directly launched command.
   *
   * - The launcher classifies only that basename. The launcher does not inspect a script's arguments
   *   or guess what the script may later execute.
   * - A script that starts an agent therefore selects no provider, and gets the startup warning instead
   *   of a guessed grant, unless the launch names its providers (selectedProvider).
   * - The provider names are the proxy's (RulesetHelper.ModelProviders). The proxy checks them, so this
   *   file keeps no list of providers.
   */
  val AgentProviders: Map[String, String] =
    Map(
      "codex" -> "openai",
      "claude" -> "anthropic",
      "agy" -> "google",
      "kiro-cli" -> "aws",
      "copilot" -> "github",
    )

  /** The agents that run against any provider, so no classification can stand in for a choice. A launch
    * of such an agent names its providers or is refused. */
  val ProviderlessAgents: Set[String] = Set("opencode")

  private def commandName(command: Option[String]): Option[String] = command.map(_.split("[/\\\\]").last)

  def commandProvider(command: Option[String]): Option[String] = commandName(command).flatMap(AgentProviders.get)

  /**
   * The provider selection that a launch hands the proxy (RulesetHelper.selectedProviders): the
   * command's classification, followed by the `--model-provider` names that the classification does
   * not repeat. The proxy would refuse a repeated name as named twice.
   *
   * - An options file's `--model-provider` applies to every agent. A selection that replaced the
   *   classification would cut each other agent off from its own provider.
   * - The method refuses the option under deny-all, where the option would select nothing.
   * - Under the other profiles, the method refuses a providerless agent without the option. Every
   *   other agent's launch selects a provider there, and the providerless agent's launch would
   *   silently select none.
   */
  def selectedProvider(
    named: Vector[String],
    command: Option[String],
    profile: String,
  ): Either[String, Option[String]] =
    val name = commandName(command)
    if profile == "deny-all" && named.nonEmpty then
      Left(s"error: ${CommandLine.ModelProviderOption} selects no host under --egress=deny-all; drop it")
    else
      val own = commandProvider(command)
      val selected = own.toVector ++ named.filterNot(own.contains)
      Option.when(selected.nonEmpty)(selected.mkString(",")) match
        case None if profile != "deny-all" && name.exists(ProviderlessAgents) =>
          Left(
            s"error: ${name.get} has no fixed model provider; name the session's providers with " +
              s"${CommandLine.ModelProviderOption}=<names>, separated by commas",
          )
        case selected => Right(selected)

  /** The launch's warning that no provider is selected, under a profile where a provider could be. The
    * proxy never sees the command or the option, so the warning cannot come from the proxy's resolution.
    * `command` is the command's first word; a launch without a command runs the image's default. */
  def noProviderLine(command: Option[String], profile: String): Option[String] =
    Option.when(profile != "deny-all"):
      val subject = command.fold("no command is given")(name => s"'$name' is not a recognized agent command")
      val effect =
        if profile == "deny-unless-model" then "allows no host"
        else "starts from the catalog alone; the workspace's rule file applies after it"
      s"$subject and no ${CommandLine.ModelProviderOption} is given, so $profile selects no model provider and $effect"

  /** The launch's failure when the dry run refuses. The proxy names the variable it refused, and the
    * launcher names the option or file that the variable carries. */
  def rulesetRefusal(err: String): String =
    val subject =
      if err.contains(RulesetHelper.ModelProviderVariable) then s"${CommandLine.ModelProviderOption} is not valid"
      else "this workspace's egress rules are not valid"
    s"error: $subject\n$err"

  /**
   * A --print-ruleset dry run of the proxy image (--rm, --network=none, nothing mounted): the ruleset,
   * or the reason the ruleset is invalid.
   *
   * - The proxy combines its defaults, the profile and the workspace's rules.
   * - --egress-effective and every launch use this dry run's result, for the banner and for the leaf
   *   certificate's names alike.
   * - `provenance` also reports every line's sources (--egress-effective's view).
   */
  def resolvedRuleset(
    podman: String,
    proxyImage: String,
    profile: String,
    provider: Option[String],
    ruleFiles: Vector[(String, String)],
    provenance: Boolean = false,
  ): Run =
    run(
      (Vector(podman, "run", "--rm", "--pull=never", "--network=none")
        ++ rulesetEnvArgs(profile, provider, ruleFiles)
        ++ Vector(proxyImage, "--print-ruleset")
        ++ Option.when(provenance)("--provenance"))*
    )

  /**
   * The upstream proxy that HTTPS_PROXY names, handed to the proxy container as the variable itself,
   * with no value.
   *
   * - podman fills a value-less `--env` from this process's environment. The URL, userinfo included,
   *   therefore appears in no argument and no process listing.
   * - The proxy is the URL's one parser (TransportHelper.UpstreamEndpoint).
   * - The method selects the variable as the proxy selects it, and returns no argument for a direct
   *   run.
   */
  def upstreamProxyArgs(read: String => Option[String]): Vector[String] =
    agentsandbox.egress.TransportHelper.upstreamProxyVariable(read).map((name, _) => s"--env=$name").toVector

  /** The proxy's transport line from its log, without the instant stamp. The proxy writes the line
    * before the ready line (AgentEgressProxy.serve), so the line is there once the launch is. */
  def transportLineOf(log: String): Option[String] =
    log.linesIterator.map(_.dropWhile(_ != ' ').drop(1))
      .find(_.startsWith(agentsandbox.egress.TransportHelper.TransportLineHead))

  /** The --env arguments that pass the selected profile, provider and rule files to the proxy. The dry
    * run and the real container get identical arguments, so the proxy enforces what the dry run vetted. */
  def rulesetEnvArgs(
    profile: String,
    provider: Option[String],
    ruleFiles: Vector[(String, String)],
  ): Vector[String] =
    Vector(
      s"--env=${RulesetHelper.ProfileVariable}=$profile",
      s"--env=${RulesetHelper.ModelProviderVariable}=${provider.getOrElse("")}",
    ) ++ ruleFiles.map: (name, text) =>
      val variable = RuleFiles.find(_(0) == name).fold(fail(s"error: no rule file $name"))(_(1))
      s"--env=$variable=$text"

  /** The run directories (runLogDir) in the workspace's log directory, oldest first. */
  def runLogDirs(logDir: Path): Vector[Path] =
    if !Files.isDirectory(logDir) then Vector.empty
    else
      directoryEntries(logDir)
        .filter(path => path.getFileName.toString.matches(RunLogDirPattern) && Files.isDirectory(path))
        .sortBy(_.getFileName.toString)

  /** A run directory's proxy audit logs: the container proxy's `proxy.log` first, then the host
    * proxies' (RunOnHostProxy.workspaceAuditLog) in name order. */
  def proxyLogsOf(runLogs: Path): Vector[Path] =
    val (container, host) = directoryEntries(runLogs)
      .filter(path => path.getFileName.toString.matches("proxy.*\\.log"))
      .sortBy(_.getFileName.toString)
      .partition(_.getFileName.toString == "proxy.log")
    container ++ host

  /** What `--egress-log` prints with no arguments: each run's proxy audit logs, oldest run first. */
  def retainedProxyLogs(logDir: Path): Vector[Path] = runLogDirs(logDir).flatMap(proxyLogsOf)

  private val OtherFormat = "An image built by another launcher version prints another format; rebuild with --build."
  private val NoProfileLine = s"error: the proxy image's --print-ruleset has no 'egress profile' line\n$OtherFormat"
  private def noProviderField(profile: String): String =
    s"error: the proxy image's --print-ruleset names no model provider under the $profile profile\n$OtherFormat"
  private val NoSummaryCounts =
    s"error: the proxy image's --print-ruleset has no '${RulesetHelper.SummaryLineHead}' line with both host counts\n" +
      OtherFormat

  /**
   * The inspected hosts in a --print-ruleset answer: the hosts of its `allow https://` lines, one line
   * per resolved scope. A `tunnel` line is never among them.
   *
   * - The host is the URL's part between the scheme and its first `/`. A host under several scopes
   *   counts as one name.
   * - The launcher learns from this list which names the leaf certificate must list. The list is the
   *   proxy image's own answer under this workspace's rules, so no second copy of any list exists to
   *   drift. A proxy image or rules of the user's choosing get a matching leaf too.
   * - An empty list means that the ruleset inspects nothing. The launcher then issues no leaf and hands
   *   the proxy no inspection material.
   * - The method refuses a resolution without its profile line, which is another launcher version's
   *   format.
   */
  def inspectedHostsOf(dryRunOutput: String): Either[String, Vector[String]] =
    val lines = dryRunOutput.linesIterator.toVector
    if !lines.headOption.exists(_.startsWith(RulesetHelper.ProfileLineHead)) then Left(NoProfileLine)
    else
      Right(allowedHostsOf(dryRunOutput, tunnel = false))

  /** The hosts the dry run's ruleset tunnels, whose traffic stays opaque: no credential is substituted there. */
  def tunnelHostsOf(dryRunOutput: String): Vector[String] = allowedHostsOf(dryRunOutput, tunnel = true)

  private def allowedHostsOf(dryRunOutput: String, tunnel: Boolean): Vector[String] =
    rulesetLinesOf(dryRunOutput).linesIterator
      .filter(line => line.startsWith("allow https://") && line.endsWith(" tunnel") == tunnel)
      .map(_.stripPrefix("allow https://").takeWhile(_ != '/'))
      .toVector
      .distinct
      .sorted

  /**
   * - Without arguments, the action prints the retained host files, oldest first. The listing works
   *   after every container is gone.
   * - With arguments, the action passes them to `podman logs` on the running proxies, which shows the
   *   live view of the same lines.
   */
  def egressLog(os: Os, extra: List[String]): Nothing =
    val workspaceRoot = resolveWorkspaceRoot(os)
    requireStateRootOutside(os, workspaceRoot)
    val id = workspaceIdOf(workspaceRoot, os)
    val logDir = logStateRoot(os).resolve(id)

    if extra.isEmpty then
      val files = retainedProxyLogs(logDir)
      if files.isEmpty then fail("no proxy logs for this workspace\n" + pathLine("egress log dir", logDir, os))
      files.foreach: file =>
        System.err.println(pathLine("==>", file, os, separator = " "))
        Files.copy(file, System.out)
      System.out.flush()
      sys.exit(0)
    else
      requirePodman(os)
      val running = run(podman, "ps", "--format", "{{.Names}}")
      if !running.ok then
        fail(s"error: could not list the running containers\n${running.err}")
      val proxies = running.text.linesIterator
        .map(_.trim)
        .filter(isRunNamed(proxyRunContainer, id))
        .toList
      if proxies.isEmpty then
        fail(
          s"""no running egress proxy for this workspace; each run's proxy is
             |removed when its sandbox exits. Its retained logs are files:
             |run --egress-log without arguments, or read files under:
             |${pathLine("egress log dir", logDir, os)}""".stripMargin,
        )
      val command = List(podman, "logs") ++ extra ++ proxies
      sys.exit(if stepOk(command*) then 0 else 1)

  /** The front half that the egress preflights share: this workspace's vetted rule files, the provider
    * that the given command selects, and the Id of the proxy image to consult. The proxy image is under
    * the same version lock as a launch (proxyImageLock). The method prints the command-selection notes
    * that a launch would print. `operands` is the action's optional `[--] [command [arguments...]]`,
    * which the action accepts without launching anything. */
  private def egressPreflight(
    os: Os,
    profile: String,
    modelProviders: Vector[String],
    proxyImageOption: Option[String],
    operands: List[String],
  ): (String, String, Vector[(String, String)], Option[String]) =
    val command = operands match
      case "--" :: rest => rest
      case rest         => rest
    val workspaceRoot = resolveWorkspaceRoot(os)
    requireStateRootOutside(os, workspaceRoot)
    val workspaceId = workspaceIdOf(workspaceRoot, os)
    val (proxyImage, proxyImageOverridden) = proxyImageChoice(proxyImageOption)

    val proxyInspected = inspectProxyImage(proxyImage)
    if !proxyInspected.ok then
      fail(
        s"""error: egress proxy image not found: $proxyImage
           |
           |Build it first: run this launcher with --build.""".stripMargin,
      )
    val proxyImageId = versionLockedProxyImageId(proxyImage, proxyImageOverridden, proxyInspected.text)

    val boundaryDir = boundaryDirOf(workspaceRoot)
    boundaryDirRefusal(boundaryDir).foreach(fail(_))
    val ruleFiles = readRuleFiles(boundaryDir.resolve("egress")).fold(fail(_), identity)

    val provider = selectedProvider(modelProviders, command.headOption, profile).fold(fail(_), identity)
    if provider.isEmpty then
      noProviderLine(command.headOption, profile).foreach(line => System.err.println(s"egress: $line"))

    if ruleFiles.nonEmpty then printRuleFiles(ruleFiles)
    else System.err.println("egress rules: no workspace rule file; the launcher-owned defaults")

    (workspaceId, proxyImageId, ruleFiles, provider)

  private def ruleFileSource(name: String): String = s".ko-agent-sandbox/egress/$name"

  /** Prints the workspace's rule file as written, on one line. The egress actions print this line and
    * report no widening on stderr; a launch prints launchLines instead. */
  def printRuleFiles(ruleFiles: Vector[(String, String)]): Unit =
    ruleFiles.foreach: (name, text) =>
      System.err.println(s"${ruleFileSource(name)}: ${lineSummary(text)}")

  /** A launch's lines about the workspace's rule file, once the dry run has answered.
    *
    * - The lines that the dry run reports as granting beyond the defaults (wideningLines) come first,
    *   tinted as a weakened boundary and grouped by host (groupedByHost).
    * - The file's other lines follow (HostCommands.ruleFileReport).
    *
    * The proxy reads one rule file (RuleFiles), so every widening line belongs to that file. */
  def launchLines(
    ruleFiles: Vector[(String, String)],
    rulesetText: String,
    color: Boolean = colorStderr,
  ): Vector[String] =
    val widens = wideningLines(rulesetText)
    ruleFiles.flatMap: (name, text) =>
      ruleFileReport(ruleFileSource(name), text.linesIterator.toVector, widens, color, groupedByHost)

  /**
   * Prints the ruleset this workspace would apply, without a session. The action uses the same
   * readRuleFiles and resolvedRuleset as a launch, under the accompanying --egress=<profile>, and adds
   * per-line provenance. Data goes to stdout and context to stderr, so the effective lists pipe cleanly.
   */
  def egressEffective(
    os: Os,
    profile: String,
    modelProviders: Vector[String],
    proxyImage: Option[String],
    operands: List[String],
    bindings: Vector[CredentialBinding] = Vector.empty,
  ): Nothing =
    val (workspaceId, proxyImageId, ruleFiles, provider) =
      egressPreflight(os, profile, modelProviders, proxyImage, operands)

    val resolved = resolvedRuleset(podman, proxyImageId, profile, provider, ruleFiles, provenance = true)
    System.out.write(resolved.out)
    System.out.flush()
    if !resolved.ok then
      fail(rulesetRefusal(resolved.err))
    val inspected = inspectedHostsOf(resolved.text).fold(fail(_), identity).toSet
    EgressCredentials.effectiveLines(bindings, inspected, tunnelHostsOf(resolved.text).toSet).foreach(println)
    resolved.err.linesIterator.filter(_.startsWith("warning:")).foreach(line => System.err.println(emphasized(line)))

    val caCert = tlsStateRoot(os).resolve(workspaceId).resolve("ca.crt")
    if Files.isRegularFile(caCert) then System.err.println(pathLine("egress tls ca", caCert, os))
    System.err.println(pathLine("egress log dir", logStateRoot(os).resolve(workspaceId), os))
    sys.exit(0)

  /**
   * Reports one host's ruleset decision and current DNS resolution. A one-shot proxy container answers
   * on a per-run network built like a session's egress network. AgentEgressProxy.checkHost explains why the
   * two answers are reported apart, and why the resolver must be the one that enforcement uses.
   */
  def egressCheck(
    os: Os,
    profile: String,
    modelProviders: Vector[String],
    proxyImage: Option[String],
    host: String,
    operands: List[String],
  ): Nothing =
    val (workspaceId, proxyImageId, ruleFiles, provider) =
      egressPreflight(os, profile, modelProviders, proxyImage, operands)

    val network = egressRunNetwork(workspaceId, newRunSuffix())
    createNetwork(network, internal = false)
    val checked =
      try
        run(
          (Vector(podman, "run", "--rm", "--pull=never", s"--network=$network")
            ++ rulesetEnvArgs(profile, provider, ruleFiles) ++ upstreamProxyArgs(env)
            ++ Vector(proxyImageId, "--check-host", host))*
        )
      finally
        if !runOk(podman, "network", "rm", network) then
          System.err.println(s"note: could not remove the check network $network")

    System.out.write(checked.out)
    System.out.flush()
    if !checked.ok then fail(s"error: the egress check failed\n${checked.err}")
    sys.exit(0)
