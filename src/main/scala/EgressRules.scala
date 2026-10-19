// The egress proxy as the launcher deals with it: reading this workspace's rules, asking the proxy
// image what they resolve to, keeping the audit log, and the actions that report on them
// (--egress-log, --egress-effective, --egress-check). A session's proxy *container* is not
// started here — it is a dozen flags in AgentSandboxLauncher.prepareRunFiles, and moving it would
// drag the launch with it.
//
// The proxy owns the defaults, the profile equations and the rule resolution; nothing here
// re-implements any of them, so there is no second opinion about what is allowed. See
// container/ko-agent-egress-proxy.

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
   * Comment-stripped, whitespace-collapsed rule text, one line per line — the format the
   * environment variable holds. A rule is a multi-token line (`allow https://x/ read`), so line
   * structure is what separates them and must be preserved. A comment starts at the start of a
   * line or after whitespace; a `#` inside a token is kept, so the proxy's parser sees and
   * refuses it rather than this pass turning `https://x/a/#b/` into the wider `https://x/a/`.
   * What is in force is the proxy's to say — a rule file's ruleset is not this text.
   */
  def normalizeRuleText(text: String): String =
    text.linesIterator
      .map(RulesetHelper.ruleTokens(_).mkString(" "))
      .filter(_.nonEmpty)
      .mkString("\n")

  def lineSummary(normalized: String): String =
    normalized.linesIterator.mkString("; ")

  /**
   * The rule lines the ruleset reports as granting beyond the defaults, read from its
   * `widening lines (N): ...` line, `; ` between rule lines. The launch prints them under an
   * `<file>: N widening lines` heading, so that a file which only removes or narrows grants
   * prints no such report and the report is a signal rather than a habit. The proxy classifies
   * against the defaults it ships (resolveRuleset has the classes), so a custom image reports
   * against its own; an image printing no such line reports nothing, never a classification
   * against defaults it does not have.
   */
  def wideningLines(resolved: String): Vector[String] =
    resolved.linesIterator.find(_.startsWith(RulesetHelper.WideningLineHead)).toVector.flatMap: line =>
      line.drop(line.indexOf("):") + 2).trim.split("; ").toVector.filter(_.nonEmpty)

  private val WholeHostRule = """allow https://([^/ ]+)/ (.+)""".r

  /** Whole-host rules sharing their grant words, `allow https://<host>/ <words>`, joined into one
    * line `allow <words>: <host>, <host>` at the first one's place, so that a report listing many
    * hosts stays short. A rule with no such partner, and any other line, stays as written. */
  def groupedByHost(rules: Seq[String]): Vector[String] =
    val hostsOf = rules
      .collect { case WholeHostRule(host, words) => words -> host }
      .groupMap((words, _) => words)((_, host) => host)
      .map((words, hosts) => words -> hosts.distinct)
      .filter((_, hosts) => hosts.size > 1)
    // Every rule of a group maps to the same line; distinct keeps it at the first one's place.
    rules.toVector
      .map:
        case WholeHostRule(_, words) if hostsOf.contains(words) => s"allow $words: ${hostsOf(words).mkString(", ")}"
        case rule => rule
      .distinct

  /** The lines the proxy prints after the ruleset lines, describing the ruleset's size and the
    * workspace's file rather than the ruleset: the summary line, then the widening line. Everything
    * from the first of them on is metadata (RulesetHelper.metadataLines). */
  val MetadataPrefixes: Vector[String] = Vector(RulesetHelper.SummaryLineHead, RulesetHelper.WideningLineHead)

  /** Exclude metadata about the workspace's file from the resolved rules exported in
    * `KO_AGENT_SANDBOX_EGRESS_RULESET` and used to select the inspection certificate's hosts. */
  def rulesetLinesOf(resolved: String): String =
    resolved.linesIterator.takeWhile(line => !MetadataPrefixes.exists(line.startsWith)).mkString("\n")

  /**
   * The launch banner's one-line summary of the ruleset: the profile as the ruleset's
   * first line spells it, then the counts of the summary line, which say how wide it is — each
   * source alone insufficient. The full lines are one `--egress-effective` away, and the proxy
   * writes them into this session's own log; a thousand characters of hostnames in the banner is
   * a line people learn to skip, and skipping it is how a ruleset nobody expected goes unnoticed.
   * A dry run without the profile line, the provider field every profile but deny-all carries
   * (RulesetHelper.rulesetLines) or the summary's counts is refused, so no launch starts without
   * this line stating its egress.
   *
   * @param profileSource follows the profile, and `providerSource` the provider selection: what the
   *   line adds when the options file supplied `--egress` or `--model-provider` (OptionsInForce.from).
   * @param color tints the profile and the provider selection (HostCommands.chosen).
   */
  def egressBanner(
    resolved: String, profileSource: String = "", providerSource: String = "", color: Boolean = colorStderr,
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
      val selected = provider.map:
        case "none"                       => s"${chosen("no provider", color)} selected"
        case names if names.contains(",") => s"model providers ${chosen(names.replace(",", ", "), color)}"
        case name                         => s"model provider ${chosen(name, color)}"
      (Vector(s"egress: ${chosen(profile, color)}$profileSource") ++ selected.map(_ + providerSource)
        :+ s"$inspected inspected, $tunnel tunnel")
        .mkString("; ")

  /**
   * Which of `names`, the entries of the workspace's log directory, to delete: every run directory
   * (runLogDir) but the newest retain-1, so `retain` remain with the new run's. A run directory's
   * name sorts chronologically by its UTC stamp.
   *
   * A live run's directory is never pruned, however old: its proxy, runner and relay are appending
   * to its files, and unlinking them would leave the session writing where nothing can read, losing
   * the whole record at exit — which is what a retention rule counting sessions rather than
   * liveness does to a workspace running more than `retain` of them at once. More than `retain`
   * directories can remain while their runs are live.
   *
   * Also the flat files of the layout before run directories, unless their run is live. That branch
   * can go after the first release.
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
   * Present egress rule files as (name, normalized text), under the refusals
   * SandboxWorkspace.readBoundaryRuleFiles lists.
   */
  def readRuleFiles(egressDir: Path): Either[String, Vector[(String, String)]] =
    SandboxWorkspace.readBoundaryRuleFiles(egressDir, RuleFiles.map(_(0)), "doc/egress-proxy.md", normalizeRuleText)

  /**
   * Only the basename of the directly launched command is classified; the launcher does not inspect
   * a script's arguments or guess what it may later execute — a script that starts an agent selects
   * no provider and gets the startup warning instead of a guessed grant, unless the launch names
   * its providers (selectedProvider). The names are the proxy's (RulesetHelper.ModelProviders), and
   * the proxy checks them, so this file keeps no list of providers.
   */
  val AgentProviders: Map[String, String] =
    Map(
      "codex" -> "openai",
      "claude" -> "anthropic",
      "agy" -> "google",
      "kiro-cli" -> "aws",
      "copilot" -> "github",
    )

  /** The agents that run against any provider, so no classification stands for a choice: a
    * launch of one names its providers or is refused. */
  val ProviderlessAgents: Set[String] = Set("opencode")

  private def commandName(command: Option[String]): Option[String] = command.map(_.split("[/\\\\]").last)

  def commandProvider(command: Option[String]): Option[String] = commandName(command).flatMap(AgentProviders.get)

  /**
   * The provider selection a launch hands the proxy (RulesetHelper.selectedProviders): the
   * command's classification, followed by the `--model-provider` names it does not repeat, which
   * the proxy would refuse as named twice. An options file's `--model-provider` applies to every
   * agent, so a selection that replaced the classification would cut each other agent off from its
   * own provider. The option is refused under deny-all, where it would select nothing; a
   * providerless agent without it is refused under the other profiles, where every other agent's
   * launch selects a provider and that one's would silently select none.
   */
  def selectedProvider(
    option: Option[String],
    command: Option[String],
    profile: String,
  ): Either[String, Option[String]] =
    val name = commandName(command)
    if profile == "deny-all" && option.isDefined then
      Left(s"error: ${CommandLine.ModelProviderOption} selects no host under --egress=deny-all; drop it")
    else
      val own = commandProvider(command)
      val named = option.toVector.flatMap(_.split(",", -1)).filterNot(own.contains)
      Option.when(own.nonEmpty || named.nonEmpty)((own.toVector ++ named).mkString(",")) match
        case None if profile != "deny-all" && name.exists(ProviderlessAgents) =>
          Left(
            s"error: ${name.get} has no fixed model provider; name the session's providers with " +
              s"${CommandLine.ModelProviderOption}=<names>, separated by commas",
          )
        case selected => Right(selected)

  /** The launch's warning that no provider is selected, under a profile where one could be: the
    * proxy never sees the command or the option, so the line cannot come from its resolution.
    * `command` is the command's first word; a launch with none runs the image's default. */
  def noProviderLine(command: Option[String], profile: String): Option[String] =
    Option.when(profile != "deny-all"):
      val subject = command.fold("no command is given")(name => s"'$name' is not a recognized agent command")
      val effect =
        if profile == "deny-unless-model" then "allows no host"
        else "starts from the catalog alone; the workspace's rule file applies after it"
      s"$subject and no ${CommandLine.ModelProviderOption} is given, so $profile selects no model provider and $effect"

  /** The launch's failure when the dry run refuses: the proxy names the variable it refused, and
    * the launcher names the option or file that variable carries. */
  def rulesetRefusal(err: String): String =
    val subject =
      if err.contains(RulesetHelper.ModelProviderVariable) then s"${CommandLine.ModelProviderOption} is not valid"
      else "this workspace's egress rules are not valid"
    s"error: $subject\n$err"

  /**
   * A --print-ruleset dry run of the proxy image (--rm, --network=none,
   * nothing mounted): the ruleset, or the reason it is invalid. The
   * proxy combines its defaults, the profile and the workspace's rules; both
   * --egress-effective and every launch use this one dry run's result — for
   * the banner and for the leaf certificate's names alike. `provenance`
   * additionally reports every line's sources (--egress-effective's view).
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
   * The upstream proxy HTTPS_PROXY names, handed to the proxy container as the variable itself,
   * with no value: podman fills a value-less `--env` from this process's environment, so the URL
   * — its userinfo included — is in no argument and no process listing, and the proxy is its one
   * parser (TransportHelper.UpstreamEndpoint). Selected as the proxy selects it.
   * Empty for a direct run.
   */
  def upstreamProxyArgs(read: String => Option[String]): Vector[String] =
    agentsandbox.egress.TransportHelper.upstreamProxyVariable(read).map((name, _) => s"--env=$name").toVector

  /** The proxy's transport line out of its log, the instant stamp removed. Written before the
    * ready line (AgentEgressProxy.serve), so it is there once the launch is. */
  def transportLineOf(log: String): Option[String] =
    log.linesIterator.map(_.dropWhile(_ != ' ').drop(1))
      .find(_.startsWith(agentsandbox.egress.TransportHelper.TransportLineHead))

  /** The --env arguments passing the selected profile, provider and rule files to the proxy — the
    * dry run and the real container get identical ones, so what was vetted is what is enforced. */
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
   * The inspected hosts out of a --print-ruleset answer: the hosts of its `allow https://` lines,
   * one line per resolved scope, a `tunnel` line never among them — the host is the URL's part
   * between the scheme and its first `/`, and a host under several scopes is one name. This is
   * how the launcher learns which names the leaf certificate must list — the proxy image's own
   * answer under this workspace's rules, so no second copy of any list exists to drift, and a proxy
   * image or rules of the user's choosing get a matching leaf too. Empty means the ruleset
   * inspects nothing; the launcher then issues no leaf and hands the proxy no inspection material.
   * A resolution without its profile line is another launcher version's format, refused.
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
   * No arguments: the retained host files, oldest first — works after every
   * container is gone. With arguments: passed through to `podman logs` on
   * the running proxies, the live view of the same lines.
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

  /** The shared front half of the egress preflights: this workspace's vetted rule files,
    * the provider the given command selects, and the Id of the proxy image to consult, under the
    * same version lock as a launch (proxyImageLock) — with the command-selection notes a launch
    * would print. `operands` is the action's optional `[--] [command [arguments...]]`, accepted
    * without launching anything. */
  private def egressPreflight(
    os: Os,
    profile: String,
    modelProvider: Option[String],
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

    val provider = selectedProvider(modelProvider, command.headOption, profile).fold(fail(_), identity)
    if provider.isEmpty then
      noProviderLine(command.headOption, profile).foreach(line => System.err.println(s"egress: $line"))

    if ruleFiles.nonEmpty then printRuleFiles(ruleFiles)
    else System.err.println("egress rules: no workspace rule file; the launcher-owned defaults")

    (workspaceId, proxyImageId, ruleFiles, provider)

  private def ruleFileSource(name: String): String = s".ko-agent-sandbox/egress/$name"

  /** The workspace's rule file as written, one line. Printed by the egress actions, which report no
    * widening on stderr; a launch prints launchLines. */
  def printRuleFiles(ruleFiles: Vector[(String, String)]): Unit =
    ruleFiles.foreach: (name, text) =>
      System.err.println(s"${ruleFileSource(name)}: ${lineSummary(text)}")

  /** A launch's lines about the workspace's rule file, once the dry run has answered: the lines it
    * reports as granting beyond the defaults (wideningLines) tinted as a weakened boundary and
    * grouped by host (groupedByHost), the file's other lines after them (HostCommands.ruleFileReport).
    * The proxy reads one rule file (RuleFiles), so every widening line is that file's. */
  def launchLines(
    ruleFiles: Vector[(String, String)],
    rulesetText: String,
    color: Boolean = colorStderr,
  ): Vector[String] =
    val widens = wideningLines(rulesetText)
    ruleFiles.flatMap: (name, text) =>
      ruleFileReport(ruleFileSource(name), text.linesIterator.toVector, widens, color, groupedByHost)

  /**
   * The ruleset this workspace would apply, without a session: the same readRuleFiles +
   * resolvedRuleset a launch uses, under the accompanying --egress=<profile>, plus per-line
   * provenance. Data to stdout, context to stderr, so the effective lists pipe cleanly.
   */
  def egressEffective(
    os: Os,
    profile: String,
    modelProvider: Option[String],
    proxyImage: Option[String],
    operands: List[String],
    bindings: Vector[CredentialBinding] = Vector.empty,
  ): Nothing =
    val (workspaceId, proxyImageId, ruleFiles, provider) =
      egressPreflight(os, profile, modelProvider, proxyImage, operands)

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
   * One host's ruleset decision and current DNS resolution, through a one-shot proxy container on a
   * per-run network built like a session's egress network (AgentEgressProxy.checkHost has why the
   * two are reported apart and why the resolver must be enforcement's).
   */
  def egressCheck(
    os: Os,
    profile: String,
    modelProvider: Option[String],
    proxyImage: Option[String],
    host: String,
    operands: List[String],
  ): Nothing =
    val (workspaceId, proxyImageId, ruleFiles, provider) =
      egressPreflight(os, profile, modelProvider, proxyImage, operands)

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
