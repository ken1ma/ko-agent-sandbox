// The egress proxy as the launcher deals with it: reading this project's rules, asking the proxy
// image what they resolve to, keeping the audit log, and the actions that report on them
// (--egress-log, --egress-effective, --egress-check). A session's proxy *container* is not
// started here — it is a dozen flags in AgentSandboxLauncher.launch, and moving it would drag the
// launch with it.
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
import SandboxProject.*

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
   * `egress rules widen:` heading, so that a file which only removes or narrows grants prints no
   * such report and the report is a signal rather than a habit. The proxy classifies against the
   * defaults it ships (resolveRuleset has the classes), so a custom image reports against its
   * own; an image printing no such line reports nothing, never a classification against defaults
   * it does not have.
   */
  def wideningLines(resolved: String): Vector[String] =
    resolved.linesIterator.find(_.startsWith(RulesetHelper.WideningLineHead)).toVector.flatMap: line =>
      line.drop(line.indexOf("):") + 2).trim.split("; ").toVector.filter(_.nonEmpty)

  /** The lines the proxy prints after the ruleset lines, describing the ruleset's size and the
    * project's file rather than the ruleset: the summary line, then the widening line. Everything
    * from the first of them on is metadata (RulesetHelper.metadataLines). */
  val MetadataPrefixes: Vector[String] = Vector(RulesetHelper.SummaryLineHead, RulesetHelper.WideningLineHead)

  /** Exclude metadata about the project file from the resolved rules exported in
    * `KO_AGENT_SANDBOX_EGRESS_RULESET` and used to select the inspection certificate's hosts. */
  def rulesetLinesOf(resolved: String): String =
    resolved.linesIterator.takeWhile(line => !MetadataPrefixes.exists(line.startsWith)).mkString("\n")

  /**
   * The launch banner's one-line summary of the ruleset: the profile as the ruleset's
   * first line spells it, then the counts of the summary line, which say how wide it is — each
   * source alone insufficient. The full lines are one `--egress-effective` away, and the proxy
   * writes them into this session's own log; a thousand characters of hostnames in the banner is
   * a line people learn to skip, and skipping it is how a ruleset nobody expected goes unnoticed.
   * On parse failure, show only the first line to avoid dumping the resolved host list.
   *
   * @param color tints the profile (HostCommands.chosen).
   */
  def egressBanner(resolved: String, color: Boolean = colorStderr): String =
    val lines = resolved.linesIterator.toVector

    val counts: Map[String, Int] =
      lines.find(_.startsWith(RulesetHelper.SummaryLineHead)).toVector
        .flatMap(_.stripPrefix(RulesetHelper.SummaryLineHead).split(";").toVector)
        .flatMap: field =>
          field.trim.split(" ", 2) match
            case Array(count, name) => count.toIntOption.map(name -> _)
            case _                  => None
        .toMap

    val parsed =
      for
        head <- lines.headOption.filter(_.startsWith(RulesetHelper.ProfileLineHead))
        inspected <- counts.get("inspected hosts")
        tunnel <- counts.get("tunnel hosts")
      yield
        val profile = head.stripPrefix(RulesetHelper.ProfileLineHead).takeWhile(_ != ';')
        profile match
          case "deny-unless-model" =>
            val provider = head
              .split(RulesetHelper.ModelProviderLabel, 2)
              .lift(1)
              .map(_.trim)
              .filter(_.nonEmpty)
              .getOrElse("none")
            val selected = provider match
              case "none" => "no provider selected"
              case "all"  => "every model provider"
              case name   => s"model provider $name"
            s"egress: ${chosen(profile, color)}; $selected; $inspected inspected, $tunnel tunnel"
          case _ =>
            s"egress: ${chosen(profile, color)}; $inspected inspected, $tunnel tunnel"

    parsed.getOrElse(s"egress: ${lines.headOption.getOrElse("(empty resolution)")}")

  /**
   * Everything but the newest retain-1, so the new file makes retain; names
   * embed a UTC stamp and sort chronologically.
   *
   * A run still holding its log open is never pruned, however old the file
   * is: its proxy is appending to that inode, and unlinking it would leave
   * the session writing where nothing can read, losing the whole record at
   * exit — which is what a retention rule counting sessions rather than
   * liveness does to a project running more than `retain` of them at once.
   * More than `retain` logs can remain while their runs are live.
   */
  def logsToPrune(names: Seq[String], retain: Int, liveRuns: Set[String]): Seq[String] =
    names.sorted
      .dropRight((retain - 1).max(0))
      .filterNot(name => liveRuns.exists(run => name.endsWith(s"-$run.log")))

  val RetainedProxyLogs = 20

  val RuleFiles: Vector[(String, String)] = Vector(RulesetHelper.RuleFile -> RulesetHelper.RuleVariable)

  /**
   * Present egress rule files as (name, normalized text), under the refusals
   * SandboxProject.readBoundaryRuleFiles lists.
   */
  def readRuleFiles(egressDir: Path): Either[String, Vector[(String, String)]] =
    SandboxProject.readBoundaryRuleFiles(egressDir, RuleFiles.map(_(0)), "doc/egress-proxy.md", normalizeRuleText)

  /**
   * Only the basename of the directly launched command is classified; the launcher does not inspect
   * a script's arguments or guess what it may later execute — a script that starts an agent selects
   * no provider and, under deny-unless-model, gets the startup warning instead of a guessed grant.
   * opencode has no fixed provider and selects `all`, the proxy's word for every provider it
   * defines (RulesetHelper.AllProviders); the proxy expands it, so this file keeps no list of
   * providers.
   */
  val AgentProviders: Map[String, String] =
    Map(
      "codex" -> "openai",
      "claude" -> "anthropic",
      "agy" -> "google",
      "kiro-cli" -> "aws",
      "copilot" -> "github",
      "opencode" -> "all",
    )

  def commandProvider(command: Option[String]): Option[String] =
    command.map(name => name.split("[/\\\\]").last).flatMap(AgentProviders.get)

  /**
   * A --print-ruleset dry run of the proxy image (--rm, --network=none,
   * nothing mounted): the ruleset, or the reason it is invalid. The
   * proxy combines its defaults, the profile and the project's rules; both
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
      s"--env=${RulesetHelper.ModelProviderVariable}=${provider.getOrElse("none")}",
    ) ++ ruleFiles.map: (name, text) =>
      val variable = RuleFiles.find(_(0) == name).fold(fail(s"error: no rule file $name"))(_(1))
      s"--env=$variable=$text"

  def retainedLogs(logDir: Path, prefix: String = "proxy-"): Vector[Path] =
    if !Files.isDirectory(logDir) then Vector.empty
    else
      directoryEntries(logDir)
        .filter(p => p.getFileName.toString.startsWith(prefix))
        .filter(p => p.getFileName.toString.endsWith(".log"))
        .sortBy(_.getFileName.toString)

  /**
   * The inspected hosts out of a --print-ruleset answer: the hosts of its `allow https://` lines,
   * one line per resolved scope, a `tunnel` line never among them — the host is the URL's part
   * between the scheme and its first `/`, and a host under several scopes is one name. This is
   * how the launcher learns which names the leaf certificate must list — the proxy image's own
   * answer under this project's rules, so no second copy of any list exists to drift, and a proxy
   * image or rules of the user's choosing get a matching leaf too. Empty means the ruleset
   * inspects nothing; the launcher then issues no leaf and hands the proxy no inspection material.
   * A resolution without its profile line is another launcher version's format, refused.
   */
  def inspectedHostsOf(dryRunOutput: String): Either[String, Vector[String]] =
    val lines = dryRunOutput.linesIterator.toVector
    if !lines.headOption.exists(_.startsWith(RulesetHelper.ProfileLineHead)) then
      Left(
        "error: the proxy image's --print-ruleset has no 'egress profile' line\n" +
          "An image built by another launcher version prints another format; rebuild with --build.",
      )
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
    val projectDir = resolveProjectDir(os)
    requireStateRootOutside(os, projectDir)
    val id = projectIdOf(projectDir, os)
    val logDir = logStateRoot(os).resolve(id)

    if extra.isEmpty then
      val files = retainedLogs(logDir)
      if files.isEmpty then fail("no proxy logs for this project\n" + pathLine("egress log dir", logDir, os))
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
          s"""no running egress proxy for this project; each run's proxy is
             |removed when its sandbox exits. Its retained logs are files:
             |run --egress-log without arguments, or read files under:
             |${pathLine("egress log dir", logDir, os)}""".stripMargin
        )
      val command = List(podman, "logs") ++ extra ++ proxies
      sys.exit(if stepOk(command*) then 0 else 1)

  /** The shared front half of the egress preflights: this project's vetted rule files,
    * the provider the given command selects, and the proxy image to consult — with the
    * command-selection notes a launch would print. `operands` is the action's optional
    * `[--] [command [arguments...]]`, accepted without launching anything. */
  private def egressPreflight(
    os: Os,
    operands: List[String],
  ): (String, String, Vector[(String, String)], Option[String]) =
    val command = operands match
      case "--" :: rest => rest
      case rest         => rest
    val projectDir = resolveProjectDir(os)
    requireStateRootOutside(os, projectDir)
    val projectId = projectIdOf(projectDir, os)
    val proxyImage = proxyImageChoice._1

    if !runOk(podman, "image", "exists", proxyImage) then
      fail(
        s"""error: egress proxy image not found: $proxyImage
           |
           |Build it first: run this launcher with --build.""".stripMargin
      )

    val boundaryDir = boundaryDirOf(projectDir)
    boundaryDirRefusal(boundaryDir).foreach(fail(_))
    val ruleFiles = readRuleFiles(boundaryDir.resolve("egress")).fold(fail(_), identity)

    val provider = commandProvider(command.headOption)
    command.headOption match
      case None       => System.err.println("egress: no command given, so no model provider is selected")
      case Some(name) if provider.isEmpty =>
        System.err.println(s"egress: '$name' is not a recognized agent command; it selects no model provider")
      case Some(_) => ()

    if ruleFiles.nonEmpty then printRuleFiles(ruleFiles)
    else System.err.println("egress rules: no project rule file; the launcher-owned defaults")

    (projectId, proxyImage, ruleFiles, provider)

  /** The project's rule file as written, one line. Printed by a launch and by the egress actions
    * alike; the launch follows it with the widening report once the dry run has answered
    * (printWidening). */
  def printRuleFiles(ruleFiles: Vector[(String, String)]): Unit =
    ruleFiles.foreach: (name, text) =>
      System.err.println(s"egress rules (.ko-agent-sandbox/egress/$name): ${lineSummary(text)}")

  /** The lines the dry run reports as granting beyond the defaults (EgressRules.wideningLines),
    * once more, alone, tinted as a weakened boundary (HostCommands.wideningReport): the lines as
    * written print at every launch and are read as a habit; the report appears only when the
    * file widens. */
  def printWidening(rulesetText: String): Unit =
    val widens = wideningLines(rulesetText)
    if widens.nonEmpty then wideningReport("egress rules", widens).foreach(System.err.println)

  /**
   * The ruleset this project would apply, without a session: the same readRuleFiles +
   * resolvedRuleset a launch uses, under the accompanying --egress=<profile>, plus per-line
   * provenance. Data to stdout, context to stderr, so the effective lists pipe cleanly.
   */
  def egressEffective(
    os: Os,
    profile: String,
    operands: List[String],
    bindings: Vector[CredentialBinding] = Vector.empty,
  ): Nothing =
    val (projectId, proxyImage, ruleFiles, provider) = egressPreflight(os, operands)

    val resolved = resolvedRuleset(podman, proxyImage, profile, provider, ruleFiles, provenance = true)
    System.out.write(resolved.out)
    System.out.flush()
    if !resolved.ok then
      fail(s"error: this project's egress rules are not valid\n${resolved.err}")
    val inspected = inspectedHostsOf(resolved.text).fold(fail(_), identity).toSet
    EgressCredentials.effectiveLines(bindings, inspected, tunnelHostsOf(resolved.text).toSet).foreach(println)
    resolved.err.linesIterator.filter(_.startsWith("warning:")).foreach(line => System.err.println(emphasized(line)))

    val caCert = tlsStateRoot(os).resolve(projectId).resolve("ca.crt")
    if Files.isRegularFile(caCert) then System.err.println(pathLine("egress tls ca", caCert, os))
    System.err.println(pathLine("egress log dir", logStateRoot(os).resolve(projectId), os))
    sys.exit(0)

  /**
   * One host's ruleset decision and current DNS resolution, through a one-shot proxy container on a
   * per-run network built like a session's egress network (AgentEgressProxy.checkHost has why the
   * two are reported apart and why the resolver must be enforcement's).
   */
  def egressCheck(os: Os, profile: String, host: String, operands: List[String]): Nothing =
    val (projectId, proxyImage, ruleFiles, provider) = egressPreflight(os, operands)

    val network = egressRunNetwork(projectId, newRunSuffix())
    createNetwork(network, internal = false)
    val checked =
      try
        run(
          (Vector(podman, "run", "--rm", "--pull=never", s"--network=$network")
            ++ rulesetEnvArgs(profile, provider, ruleFiles) ++ upstreamProxyArgs(env)
            ++ Vector(proxyImage, "--check-host", host))*
        )
      finally
        if !runOk(podman, "network", "rm", network) then
          System.err.println(s"note: could not remove the check network $network")

    System.out.write(checked.out)
    System.out.flush()
    if !checked.ok then fail(s"error: the egress check failed\n${checked.err}")
    sys.exit(0)
