// The egress proxy as the launcher deals with it: reading this project's rules, asking the proxy
// image what they resolve to, and keeping the audit log. The proxy *container's* lifecycle
// is not here — it is a dozen flags in AgentSandboxLauncher.launch, and moving it would drag the
// launch with it.
//
// The proxy owns the defaults, the profile equations and the rule resolution; nothing here
// re-implements any of them, so there is no second opinion about what is allowed. See
// container/ko-agent-egress-proxy.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import FileHelper.*

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
      .map(_.trim.split("\\s+").filter(_.nonEmpty).takeWhile(!_.startsWith("#")).mkString(" "))
      .filter(_.nonEmpty)
      .mkString("\n")

  def lineSummary(normalized: String): String =
    normalized.linesIterator.mkString("; ")

  /**
   * The rule lines the ruleset reports as granting beyond the defaults for their host —
   * its `widening lines (N): ...` line, `; ` between lines — printed on a line of their own at
   * launch, so that a file which only takes or narrows prints nothing extra and the line is a
   * signal rather than a habit. The proxy classifies against the defaults it ships (resolveRuleset
   * has the classes), so a custom image reports against its own; an image printing no such line
   * reports nothing, never a classification against defaults it does not have.
   */
  def wideningLines(resolved: String): Vector[String] =
    resolved.linesIterator.find(_.startsWith("widening lines (")).toVector.flatMap: line =>
      line.drop(line.indexOf("):") + 2).trim.split("; ").toVector.filter(_.nonEmpty)

  /** The lines the proxy prints after the ruleset lines, describing the ruleset's size and the
    * project's file rather than the ruleset: the summary line, then the widening line. Everything
    * from the first of them on is metadata (RulesetHelper.metadataLines). */
  val MetadataPrefixes: Vector[String] = Vector("ruleset summary:", "widening lines (")

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
   * @param color tints the profile, except under the permissive one, where the caller tints the
   *              whole line.
   */
  def egressBanner(resolved: String, color: Boolean = colorStderr): String =
    val lines = resolved.linesIterator.toVector

    val counts: Map[String, Int] =
      lines.find(_.startsWith("ruleset summary:")).toVector
        .flatMap(_.stripPrefix("ruleset summary:").split(";").toVector)
        .flatMap: field =>
          field.trim.split(" ", 2) match
            case Array(count, name) => count.toIntOption.map(name -> _)
            case _                  => None
        .toMap

    val parsed =
      for
        head <- lines.headOption.filter(_.startsWith("egress profile: "))
        inspected <- counts.get("inspected hosts")
        tunnel <- counts.get("tunnel hosts")
        denied <- counts.get("denial patterns")
      yield
        val profile = head.stripPrefix("egress profile: ").takeWhile(_ != ';')
        profile match
          case "allow-unless-denied" =>
            // Plain: the caller tints this line whole, and a word tinted inside it would end that
            // colour at its own reset. The tunnel hosts are the exception set; the inspected count
            // says nothing where every unlisted host is inspected too.
            s"egress: $profile; public HTTPS read; $tunnel tunnel, $denied denied"
          case "deny-unless-model" =>
            val provider = head
              .split("model provider: ", 2)
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

  /** The one profile weaker than the launcher's default — public HTTPS to whatever is not
    * denied — and so the one banner line a terminal has reason to tint. */
  def permissiveProfile(resolved: String): Boolean =
    resolved.linesIterator.nextOption().exists(_.startsWith("egress profile: allow-unless-denied"))

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

  val RuleFiles: Vector[(String, String)] = Vector("rule" -> "EGRESS_RULE")

  /** Retired rule filenames are refused with migration advice: the workspace guard prevents
    * a session from correcting them, so the launcher must report that their rules are unread. */
  val RetiredRuleFiles: Vector[String] = Vector("allowed", "denied")

  /**
   * Present egress rule files as (name, normalized text). Refuse forms that could hide or
   * misread configuration:
   * - A file at egress/ would leave its rules unread because the reader expects a directory.
   * - An unknown filename could be a typo that leaves intended rules unread.
   * - A symlink at egress/ or a rule file could redirect the host read. Podman resolves mount
   *   sources on the host, so this read must see the bytes the mounted directory would show.
   * - An entry with a rule filename that is not a regular file would be skipped by the reader.
   * - A present but empty rule file is more likely a forgotten edit than a deliberate no-op;
   *   an intentionally empty rule file is absent.
   * Entries inside egress/ follow SandboxProject.isMetadataEntry's metadata exemption.
   */
  def readRuleFiles(egressDir: Path): Either[String, Vector[(String, String)]] =
    def symlinkRefusal(path: Path): String =
      s"error: $path must not be a symlink\nRefusing to read this project's egress rules through one."

    if Files.isSymbolicLink(egressDir) then Left(symlinkRefusal(egressDir))
    else if !Files.exists(egressDir) then Right(Vector.empty)
    else if !Files.isDirectory(egressDir) then
      Left(
        s"""error: $egressDir is a file
           |egress is a directory holding the rule file ${RuleFiles.map(_(0)).mkString(", ")}. Move the
           |lines there and remove the file; doc/egress-proxy.md has the grammar.""".stripMargin
      )
    else
      val entries = directoryEntries(egressDir)
        .filterNot(entry => SandboxProject.isMetadataEntry(entry.getFileName.toString))
        .sortBy(_.getFileName.toString)

      val refusal = entries
        .collectFirst:
          case entry if RetiredRuleFiles.contains(entry.getFileName.toString) =>
            s"error: $entry is a file of the retired grammar\nThe rules are one file, egress/rule, " +
              "in the rule grammar; doc/egress-proxy.md has it. Rewrite the lines there and delete this file."
          case entry if !RuleFiles.exists(_(0) == entry.getFileName.toString) =>
            s"error: $entry is not a rule file\negress/ holds only " +
              s"${RuleFiles.map(_(0)).mkString(", ")}; a stray name would be ignored config."
          case entry if Files.isSymbolicLink(entry) => symlinkRefusal(entry)
          case entry if !Files.isRegularFile(entry) =>
            s"error: $entry is not a regular file\negress/ holds a text file per rule file; " +
              "anything else would leave this file silently unread."
        .orElse:
          RuleFiles
            .map(_(0))
            .collectFirst:
              case name if readIfPresent(egressDir.resolve(name)).map(normalizeRuleText).contains("") =>
                s"error: ${egressDir.resolve(name)} lists no lines\n" +
                  "Delete the file; an intentionally empty rule file is an absent file."

      refusal.toLeft(
        RuleFiles.flatMap: (name, _) =>
          readIfPresent(egressDir.resolve(name)).map(normalizeRuleText).map(name -> _),
      )

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
   * proxy owns the defaults and the profile arithmetic; this one dry run is
   * the authority both --egress-effective and every launch consult — for
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
   * parser (TransportHelper.UpstreamEndpoint). Uppercase then lowercase, the proxy's own order.
   * Empty for a direct run.
   */
  def upstreamProxyArgs(read: String => Option[String]): Vector[String] =
    agentsandbox.egress.TransportHelper.UpstreamProxyVariables
      .find(name => read(name).exists(_.nonEmpty))
      .map(name => s"--env=$name")
      .toVector

  /** The proxy's transport line out of its log, the instant stamp removed. Written before the
    * ready line (AgentEgressProxy.serve), so it is there once the launch is. */
  def transportLineOf(log: String): Option[String] =
    log.linesIterator.map(_.dropWhile(_ != ' ').drop(1)).find(_.startsWith("egress transport: "))

  /** The --env arguments passing the selected profile, provider and rule files to the proxy — the
    * dry run and the real container get identical ones, so what was vetted is what is enforced. */
  def rulesetEnvArgs(
    profile: String,
    provider: Option[String],
    ruleFiles: Vector[(String, String)],
  ): Vector[String] =
    Vector(
      s"--env=EGRESS_PROFILE=$profile",
      s"--env=EGRESS_MODEL_PROVIDER=${provider.getOrElse("none")}",
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
   * Under allow-unless-denied no leaf is issued at all: the proxy issues its own from the run CA.
   * A resolution without its profile line is another launcher version's format, refused.
   */
  def inspectedHostsOf(dryRunOutput: String): Either[String, Vector[String]] =
    val lines = dryRunOutput.linesIterator.toVector
    if !lines.headOption.exists(_.startsWith("egress profile: ")) then
      Left(
        "error: the proxy image's --print-ruleset has no 'egress profile' line\n" +
          "An image built by another launcher version prints another format; rebuild with --build.",
      )
    else
      Right(
        rulesetLinesOf(dryRunOutput).linesIterator
          .filter(line => line.startsWith("allow https://") && !line.endsWith(" tunnel"))
          .map(_.stripPrefix("allow https://").takeWhile(_ != '/'))
          .toVector
          .distinct
          .sorted,
      )
