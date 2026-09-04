// The egress proxy as the launcher deals with it: reading this project's policy, asking the proxy
// image what that policy resolves to, and keeping the audit log. The proxy *container's* lifecycle
// is not here — it is a dozen flags in AgentSandboxLauncher.launch, and moving it would drag the
// launch with it.
//
// The proxy owns the defaults, the profile equations and the rule resolution; nothing here
// re-implements any of them, so there is no second opinion about what is allowed. See
// container/ko-agent-egress-proxy.

package agentsandbox.launcher

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*

import HostCommands.*

object EgressProxyPolicy:

  /**
   * Comment-stripped, whitespace-collapsed rule text, one line per line — the format the
   * environment variable holds. A rule is a multi-token line (`allow https://x/ read`), so line
   * structure is what separates them and must be preserved. A comment starts at the start of a
   * line or after whitespace; a `#` inside a token is kept, so the proxy's parser sees and
   * refuses it rather than this pass turning `https://x/a/#b/` into the wider `https://x/a/`.
   * What is in force is the proxy's to say — a rule file's resolved policy is not this text.
   */
  def normalizePolicyText(text: String): String =
    text.linesIterator
      .map(_.trim.split("\\s+").filter(_.nonEmpty).takeWhile(!_.startsWith("#")).mkString(" "))
      .filter(_.nonEmpty)
      .mkString("\n")

  def entriesSummary(normalized: String): String =
    normalized.linesIterator.mkString("; ")

  /**
   * The rule lines the resolved policy reports as granting beyond the defaults for their host —
   * its `widening lines (N): ...` line, `; ` between lines — printed on a line of their own at
   * launch, so that a file which only takes or narrows prints nothing extra and the line is a
   * signal rather than a habit. The proxy classifies against the defaults it ships (resolvePolicy
   * has the classes), so a custom image reports against its own; an image printing no such line
   * reports nothing, never a classification against defaults it does not have.
   */
  def wideningEntries(resolved: String): Vector[String] =
    resolved.linesIterator.find(_.startsWith("widening lines (")).toVector.flatMap: line =>
      line.drop(line.indexOf("):") + 2).trim.split("; ").toVector.filter(_.nonEmpty)

  /** The lines the proxy prints after the policy lines, describing the policy's size and the
    * project's file rather than the policy: the summary line, then the widening line. Everything
    * from the first of them on is metadata (PolicyHelper.metadataLines). */
  val MetadataPrefixes: Vector[String] = Vector("policy summary:", "widening lines (")

  /** The dry run's text up to its first metadata line — the policy alone — for the consumers that
    * hold nothing else: the agent's authority section and `KO_AGENT_SANDBOX_EGRESS_POLICY`. */
  def policyLinesOf(resolved: String): String =
    resolved.linesIterator.takeWhile(line => !MetadataPrefixes.exists(line.startsWith)).mkString("\n")

  /**
   * The launch banner's one-line summary of the resolved policy: the profile as the policy's
   * first line spells it, then the counts of the summary line, which say how wide it is — each
   * source alone insufficient. The full lines are one `--egress-effective` away, and the proxy
   * writes them into this session's own log; a thousand characters of hostnames in the banner is
   * a line people learn to skip, and skipping it is how a policy nobody expected goes unnoticed.
   * An unparseable resolution is printed whole rather than guessed at.
   *
   * @param color tints the profile, except under the permissive one, where the caller tints the
   *              whole line.
   */
  def egressBanner(resolved: String, color: Boolean = colorStderr): String =
    val lines = resolved.linesIterator.toVector

    val counts: Map[String, Int] =
      lines.find(_.startsWith("policy summary:")).toVector
        .flatMap(_.stripPrefix("policy summary:").split(";").toVector)
        .flatMap: field =>
          field.trim.split(" ", 2) match
            case Array(count, name) => count.toIntOption.map(name -> _)
            case _                  => None
        .toMap

    val parsed =
      for
        head <- lines.headOption.filter(_.startsWith("egress profile: "))
        inspected <- counts.get("inspected hosts")
        opaque <- counts.get("opaque hosts")
        denied <- counts.get("denial patterns")
      yield
        val profile = head.stripPrefix("egress profile: ").takeWhile(_ != ';')
        profile match
          case "allow-unless-denied" =>
            // Plain: the caller tints this line whole, and a word tinted inside it would end that
            // colour at its own reset. The opaque hosts are the exception set; the inspected count
            // says nothing where every unlisted host is inspected too.
            s"egress: $profile; public HTTPS read; $opaque opaque, $denied denied"
          case "deny-unless-model" =>
            val provider = head
              .split("model provider: ", 2)
              .lift(1)
              .map(_.trim)
              .filter(_.nonEmpty)
              .getOrElse("none")
            val selected =
              if provider == "none" then "no provider selected" else s"model provider $provider"
            s"egress: ${statedMode(profile, color)}; $selected; $inspected inspected, $opaque opaque"
          case _ =>
            s"egress: ${statedMode(profile, color)}; $inspected inspected, $opaque opaque"

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

  val PolicyFiles: Vector[(String, String)] = Vector("rule" -> "EGRESS_RULE")

  /** The two files of the grammar `rule` replaced, refused by name with the pointer: the guard
    * freezes the directory, so nothing else tells a project its policy went unread. */
  val RetiredPolicyFiles: Vector[String] = Vector("allowed", "denied")

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
           |egress is a directory holding the policy file ${PolicyFiles.map(_(0)).mkString(", ")}. Move the
           |lines there and remove the file; doc/egress-proxy.md has the grammar.""".stripMargin
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
          case entry if RetiredPolicyFiles.contains(entry.getFileName.toString) =>
            s"error: $entry is a file of the retired grammar\nThe policy is one file, egress/rule, " +
              "in the rule grammar; doc/egress-proxy.md has it. Rewrite the lines there and delete this file."
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
   * proxy owns the defaults and the profile arithmetic; this one dry run is
   * the authority both --egress-effective and every launch consult — for
   * the banner and for the leaf certificate's names alike. `provenance`
   * additionally reports every line's sources (--egress-effective's view).
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

  /** The --env arguments passing the authority selection and policy files to the proxy — the
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
   * The inspected hosts out of a --print-policy answer: the hosts of its `allow https://` lines,
   * one line per resolved scope, a `tunnel` line never among them — the host is the URL's part
   * between the scheme and its first `/`, and a host under several scopes is one name. This is
   * how the launcher learns which names the leaf certificate must list — the proxy image's own
   * answer under this project's policy, so no second copy of any list exists to drift, and a proxy
   * image or policy of the user's choosing gets a matching leaf too. Empty means the policy
   * inspects nothing; the launcher then mints no leaf and hands the proxy no inspection material.
   * Under allow-unless-denied no leaf is minted at all: the proxy mints its own from the run CA.
   * A resolution without its profile line is another launcher version's format, refused.
   */
  def inspectedHostsOf(printPolicyOutput: String): Either[String, Vector[String]] =
    val lines = printPolicyOutput.linesIterator.toVector
    if !lines.headOption.exists(_.startsWith("egress profile: ")) then
      Left(
        "error: the proxy image's --print-policy has no 'egress profile' line\n" +
          "An image built by another launcher version prints another format; rebuild with --build.",
      )
    else
      Right(
        policyLinesOf(printPolicyOutput).linesIterator
          .filter(line => line.startsWith("allow https://") && !line.endsWith(" tunnel"))
          .map(_.stripPrefix("allow https://").takeWhile(_ != '/'))
          .toVector
          .distinct
          .sorted,
      )
