// The egress proxy as the launcher deals with it: reading this project's policy, asking the proxy
// image what that policy resolves to, and keeping the audit log. The proxy *container's* lifecycle
// is not here — it is a dozen flags in AgentSandboxLauncher.launch, and moving it would drag the
// launch with it.
//
// The proxy owns the baseline, the profile equations and the delta arithmetic; nothing here
// re-implements any of them, so there is no second opinion about what is allowed. See
// container/ko-agent-egress-proxy.

package agentsandbox.launcher

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*

import HostCommands.*

object EgressProxyPolicy:

  /**
   * Comment-stripped, whitespace-collapsed policy text, one entry per line — the format the
   * environment variables carry. Entries are multi-token lines (`+host x`), so line
   * structure is what separates them and must be preserved. A comment starts at the start of a
   * line or after whitespace; a `#` inside a token is kept, so the proxy's parser sees and
   * refuses it rather than this pass turning `path=/a/#b/` into the wider `path=/a/`. What is
   * in force is the proxy's to say — a delta file's resolved policy is not this text.
   */
  def normalizePolicyText(text: String): String =
    text.linesIterator
      .map(_.trim.split("\\s+").filter(_.nonEmpty).takeWhile(!_.startsWith("#")).mkString(" "))
      .filter(_.nonEmpty)
      .mkString("\n")

  def entriesSummary(normalized: String): String =
    normalized.linesIterator.mkString("; ")

  /**
   * The `allowed` entries the resolved policy reports as reaching past the baseline — its
   * `widening entries (N): ...` line, `; ` between entries — printed on a line of their own at
   * launch, so that a policy which only removes or narrows prints nothing extra and the line is a
   * signal rather than a habit. The proxy classifies against the baseline it ships (resolvePolicy
   * has the classes), so a custom image reports against its own; an image printing no such line
   * reports nothing, never a classification against a baseline it does not have.
   */
  def wideningEntries(resolved: String): Vector[String] =
    resolved.linesIterator.find(_.startsWith("widening entries (")).toVector.flatMap: line =>
      line.drop(line.indexOf("):") + 2).trim.split("; ").toVector.filter(_.nonEmpty)

  /** The lines the proxy prints after the policy lines, describing the project's file rather than
    * the policy: today the widening line; a summary line joins it. Everything from the first of
    * them on is metadata. */
  val MetadataPrefixes: Vector[String] = Vector("widening entries (")

  /** The dry run's text up to its first metadata line — the policy alone — for the consumers that
    * carry nothing else: the agent's authority section and `KO_AGENT_SANDBOX_EGRESS_POLICY`. */
  def policyLinesOf(resolved: String): String =
    resolved.linesIterator.takeWhile(line => !MetadataPrefixes.exists(line.startsWith)).mkString("\n")

  /**
   * The launch banner's one-line summary of the resolved policy: the profile as the policy spells
   * it, then the counts that say how wide it is. The full host lists are one `--egress-effective`
   * away, and the proxy writes them into this session's own log; a thousand characters of
   * hostnames in the banner is a line people learn to skip, and skipping it is how a policy nobody
   * expected goes unnoticed. An unparseable resolution is printed whole rather than guessed at.
   *
   * @param color tints the profile, except under the permissive one, where the caller tints the
   *              whole line.
   */
  def egressBanner(resolved: String, color: Boolean = colorStderr): String =
    val lines = resolved.linesIterator.toVector

    def countOf(prefix: String): Option[Int] =
      lines.find(_.startsWith(prefix)).flatMap: line =>
        val open = line.indexOf('(')
        val close = line.indexOf(')')
        Option.when(open >= 0 && close > open)(line.substring(open + 1, close).toIntOption).flatten

    // The restricted line counts scopes; the banner counts hosts, as the leaf does.
    val parsed =
      for
        head <- lines.headOption.filter(_.startsWith("egress profile: "))
        restricted <- lines.find(_.startsWith("restricted hosts (")).flatMap(restrictedHostsOf(_).toOption).map(_.size)
        denied <- countOf("denied rules (")
      yield
        val profile = head.stripPrefix("egress profile: ").takeWhile(_ != ';')
        val effective = restricted + countOf("unrestricted hosts (").getOrElse(0)
        profile match
          case "allow-unless-denied" =>
            // Plain: the caller tints this line whole, and a word tinted inside it would end that
            // colour at its own reset.
            s"egress: $profile; public HTTPS; $restricted restricted, $denied denied"
          case "deny-unless-model" =>
            val provider = head
              .split("model provider: ", 2)
              .lift(1)
              .map(_.trim)
              .filter(_.nonEmpty)
              .getOrElse("none")
            val selected =
              if provider == "none" then "no provider selected" else s"model provider $provider"
            s"egress: ${statedMode(profile, color)}; $selected; $effective effective hosts"
          case _ =>
            s"egress: ${statedMode(profile, color)}; $effective effective hosts"

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
   * So `retain` is a floor on what is kept, not a ceiling.
   */
  def logsToPrune(names: Seq[String], retain: Int, liveRuns: Set[String]): Seq[String] =
    names.sorted
      .dropRight((retain - 1).max(0))
      .filterNot(name => liveRuns.exists(run => name.endsWith(s"-$run.log")))

  val RetainedProxyLogs = 20

  val PolicyFiles: Vector[(String, String)] = Vector(
    "allowed" -> "EGRESS_ALLOWED",
    "denied" -> "EGRESS_DENIED",
  )

  /**
   * The policy directory's files as (name, normalized text), present files
   * only. Refused forms, each of which would otherwise be silently ignored
   * or misread config: egress as a regular file rather than a directory,
   * fatal so a policy written that way is never skipped unseen; a filename
   * that is no policy file (a typo'd name configures nothing); a symlinked
   * policy file (podman resolves mount sources on the host, and this read
   * must see the bytes a mounted-back directory would show); a policy name
   * that is not a regular file, which would leave its file silently unread;
   * a present-but-empty file, more likely a forgotten edit than a
   * deliberate no-op — an intentionally empty policy is an absent file.
   * Dot-named metadata is exempt from all of it (SandboxProject.isMetadataEntry).
   */
  def readPolicyFiles(egressDir: Path): Either[String, Vector[(String, String)]] =
    def symlinkRefusal(path: Path): String =
      s"error: $path must not be a symlink\nRefusing to read this project's egress policy through one."

    if Files.isSymbolicLink(egressDir) then Left(symlinkRefusal(egressDir))
    else if !Files.exists(egressDir) then Right(Vector.empty)
    else if !Files.isDirectory(egressDir) then
      Left(
        s"""error: $egressDir is a file
           |egress is a directory of policy files:
           |${PolicyFiles.map(_(0)).mkString(", ")}. Split the entries and remove the
           |file; README ("Modifying the egress policy") has the grammar.""".stripMargin
      )
    else
      val entries = Files
        .list(egressDir)
        .iterator()
        .asScala
        .filterNot(entry => SandboxProject.isMetadataEntry(entry.getFileName.toString))
        .toVector
        .sortBy(_.getFileName.toString)

      val refusal = entries
        .collectFirst:
          case entry if !PolicyFiles.exists(_(0) == entry.getFileName.toString) =>
            s"error: $entry is not a policy file\negress/ holds only " +
              s"${PolicyFiles.map(_(0)).mkString(", ")}; a stray name would be ignored config."
          case entry if Files.isSymbolicLink(entry) => symlinkRefusal(entry)
          // The one stray form the name check cannot see: a policy file's own name on something
          // the read below skips, which would leave that file silently unread.
          case entry if !Files.isRegularFile(entry) =>
            s"error: $entry is not a regular file\negress/ holds a text file per policy; " +
              "anything else would leave this file silently unread."
        .orElse:
          PolicyFiles
            .map(_(0))
            .collectFirst:
              case name if readIfPresent(egressDir.resolve(name)).map(normalizePolicyText).contains("") =>
                s"error: ${egressDir.resolve(name)} lists no entries\n" +
                  "Delete the file; an intentionally empty policy is an absent file."

      refusal.toLeft(
        PolicyFiles.flatMap: (name, _) =>
          readIfPresent(egressDir.resolve(name)).map(normalizePolicyText).map(name -> _),
      )

  /**
   * Only the basename of the directly launched command is classified; the launcher does not
   * inspect a wrapper's arguments or guess what it may later execute — a wrapper script selects
   * no provider and, under deny-unless-model, gets the startup warning instead of a guessed grant.
   */
  val AgentProviders: Map[String, String] =
    Map("codex" -> "openai", "claude" -> "anthropic", "agy" -> "google", "copilot" -> "github")

  def commandProvider(command: Option[String]): Option[String] =
    command.map(name => name.split("[/\\\\]").last).flatMap(AgentProviders.get)

  /**
   * A --print-policy dry run of the proxy image (--rm, --network=none,
   * nothing mounted): the resolved policy, or the reason it is invalid. The
   * proxy owns the baseline and the profile arithmetic; this one dry run is
   * the authority both --egress-effective and every launch consult — for
   * the banner and for the leaf certificate's names alike. `provenance`
   * additionally reports every entry's source (--egress-effective's view).
   */
  def resolvedPolicy(
    podman: String,
    proxyImage: String,
    profile: String,
    provider: Option[String],
    policyFiles: Vector[(String, String)],
    provenance: Boolean = false,
  ): Run =
    run(
      (Vector(podman, "run", "--rm", "--pull=never", "--network=none")
        ++ policyEnvArgs(profile, provider, policyFiles)
        ++ Vector(proxyImage, "--print-policy")
        ++ Option.when(provenance)("--provenance"))*
    )

  /** The --env arguments carrying the authority selection and policy files to the proxy — the
    * dry run and the real container get identical ones, so what was vetted is what is enforced. */
  def policyEnvArgs(
    profile: String,
    provider: Option[String],
    policyFiles: Vector[(String, String)],
  ): Vector[String] =
    Vector(
      s"--env=EGRESS_PROFILE=$profile",
      s"--env=EGRESS_MODEL_PROVIDER=${provider.getOrElse("none")}",
    ) ++ policyFiles.map: (name, text) =>
      val variable = PolicyFiles.find(_(0) == name).fold(fail(s"error: no policy file $name"))(_(1))
      s"--env=$variable=$text"

  def retainedLogs(logDir: Path, prefix: String = "proxy-"): Vector[Path] =
    if !Files.isDirectory(logDir) then Vector.empty
    else
      Files
        .list(logDir)
        .iterator()
        .asScala
        .filter(p => p.getFileName.toString.startsWith(prefix))
        .filter(p => p.getFileName.toString.endsWith(".log"))
        .toVector
        .sortBy(_.getFileName.toString)

  /**
   * The inspected hosts out of a --print-policy answer: its `restricted
   * hosts (N): ...` line, which names every inspected scope and nothing else
   * (the allowances have lines of their own) — a token per scope, `host` or
   * `host/prefix/` for an entry narrowed by `path=`, so the host is the token
   * up to its first `/`, and a host under several prefixes is one name. This
   * is how the launcher learns which names the leaf certificate must carry —
   * the proxy image's own answer under this project's policy, so no second
   * copy of any list exists to drift, and a proxy image or policy of the
   * user's choosing gets a matching leaf too. Empty means the policy inspects
   * nothing; the launcher then mints no leaf and hands the proxy no
   * inspection material.
   */
  def inspectedHostsOf(printPolicyOutput: String): Either[String, Vector[String]] =
    printPolicyOutput.linesIterator.find(_.startsWith("restricted hosts (")) match
      case None =>
        Left(
          "error: the proxy image's --print-policy has no 'restricted hosts' line\n" +
            "An image built by another launcher version prints another format; rebuild with --build.",
        )
      case Some(line) => restrictedHostsOf(line)

  /** The distinct hosts of one policy line's tokens, sorted; Left for a line without its `):`. */
  private def restrictedHostsOf(line: String): Either[String, Vector[String]] =
    line.indexOf("):") match
      case -1 =>
        Left(
          s"error: unparseable policy line: $line\n" +
            "An image built by another launcher version prints another format; rebuild with --build.",
        )
      case at =>
        Right(
          line
            .drop(at + 2)
            .trim
            .split(" ")
            .toVector
            .filter(_.nonEmpty)
            .map(_.takeWhile(_ != '/'))
            .distinct
            .sorted,
        )
