// `--egress-cred`: the bindings the command line names, the values read from the host environment,
// the placeholders the sandbox and host commands see instead, which proxy of the launch is given
// each, and keeping the values out of what the launcher's children inherit (doc/egress-proxy.md,
// "Brokered credentials"). The grammar is the proxy's own (CredentialGrammar).

package agentsandbox.launcher

import java.security.SecureRandom

import agentsandbox.egress.{BrokeredCredential, CredentialBinding, CredentialGrammar}

object EgressCredentials:

  val OptionPrefix = "--egress-cred="

  /** Token prefixes programs check for: a placeholder keeps the prefix and the length, so a format check
    * still passes. */
  val RecognizedPrefixes: Vector[String] = Vector("github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-")

  private val Digits = '0' to '9'
  private val Uppers = 'A' to 'Z'
  private val Lowers = 'a' to 'z'

  /** RFC 3986's unreserved punctuation: kept in place, it reads the same in a header and a query. */
  private val KeptSeparators = "-._~"

  /**
   * One `--egress-cred=` value, or why it is refused. The refusal for a value on the command line names
   * the variable alone: whatever follows its `=` may be the secret.
   */
  def parseOption(spelled: String, refusedPrefix: String): Either[String, CredentialBinding] =
    val shown = if spelled.takeWhile(_ != '@').contains('=') then s"${spelled.takeWhile(_ != '=')}=…" else spelled
    CredentialGrammar.parseBinding(spelled) match
      case Left(reason) => Left(s"error: --egress-cred=$shown; $reason")
      case Right(binding) if binding.name.startsWith(refusedPrefix) =>
        Left(s"error: --egress-cred=$shown; the launcher sets $refusedPrefix* itself")
      case Right(binding) => Right(binding)

  /**
   * The values, each read from the environment variable its binding names and checked against the grammar, each
   * with a placeholder of its own. Refusals name the variable, never its value.
   */
  def resolve(
    bindings: Vector[CredentialBinding],
    hostEnv: String => Option[String],
    random: SecureRandom = SecureRandom(),
  ): Either[String, Vector[BrokeredCredential]] =
    bindings.foldLeft[Either[String, Vector[BrokeredCredential]]](Right(Vector.empty)): (resolved, binding) =>
      resolved.flatMap: done =>
        hostEnv(binding.name) match
          case None =>
            Left(s"error: --egress-cred=${binding.spelled}; ${binding.name} is not set on the host")
          case Some(value) =>
            CredentialGrammar.valueProblem(binding.name, value) match
              case Some(problem) => Left(s"error: --egress-cred=${binding.spelled}; $problem")
              case None if placeholderBits(value) < MinimumPlaceholderBits =>
                Left(
                  s"error: --egress-cred=${binding.spelled}; value of ${binding.name} is too short to be " +
                    s"replaced by an unguessable placeholder, which needs $MinimumPlaceholderBits random bits; " +
                    s"if the sandbox may hold it, forward it with --env=${binding.name}",
                )
              case None =>
                val taken = done.map(_.placeholder).toSet + value
                Right(done :+ BrokeredCredential(binding, placeholderFor(value, taken, random), value))

  /**
   * The floor on a placeholder's randomness. The project sees the placeholder once the session runs, so
   * randomness guards against a coincidence before it: an application's own token, or a string written
   * into the repository in advance, equal to the placeholder, which the proxy would then replace.
   */
  val MinimumPlaceholderBits = 64

  /** The random bits of `value`'s placeholder (placeholderFor): the recognized prefix and the kept separators
    * add none. */
  def placeholderBits(value: String): Double =
    val prefix = recognizedPrefix(value)
    value.drop(prefix.length).filterNot(KeptSeparators.contains(_)).map: char =>
      val choices =
        if Digits.contains(char) then Digits.size
        else if Uppers.contains(char) || Lowers.contains(char) then Uppers.size
        else Digits.size + Uppers.size + Lowers.size
      math.log(choices.toDouble) / math.log(2)
    .sum

  private def recognizedPrefix(value: String): String =
    RecognizedPrefixes.find(known => value.startsWith(known) && value.length > known.length).getOrElse("")

  /**
   * Fresh random characters in the value's format, so a program checking a token's syntax
   * before sending it still sends it: a recognized prefix and the length kept, `-`, `.`, `_` and `~` kept
   * in place — GitHub's `ghs_APPID_JWT` installation tokens separate their parts with them — and each
   * other character replaced at random within its class, a digit for a digit, a letter of the same case for a
   * letter.
   * Other punctuation becomes a letter or a digit: `&`, `=`, `#` and `%` would split or re-parse the query
   * a `?PARAM` placeholder is composed into.
   */
  def placeholderFor(value: String, taken: Set[String], source: SecureRandom): String =
    val prefix = recognizedPrefix(value)
    def replaced(char: Char): Char =
      def from(alphabet: IndexedSeq[Char]) = alphabet(source.nextInt(alphabet.size))
      if KeptSeparators.contains(char) then char
      else if Digits.contains(char) then from(Digits)
      else if Uppers.contains(char) then from(Uppers)
      else if Lowers.contains(char) then from(Lowers)
      else from(Digits ++ Uppers ++ Lowers)
    val placeholder = prefix + value.drop(prefix.length).map(replaced)
    if taken.contains(placeholder) then placeholderFor(value, taken, source) else placeholder

  /**
   * Refuses a binding no proxy of the launch would substitute: the session's proxy inspects
   * `sessionInspected`, a host proxy each host of its program's rules. A tunnel host no proxy inspects
   * is refused by name, since no substitution can happen inside it.
   */
  def checkHosts(
    bindings: Vector[CredentialBinding],
    sessionInspected: Set[String],
    sessionTunnels: Set[String],
    programHosts: Map[String, Set[String]],
  ): Either[String, Unit] =
    bindings.collectFirst(Function.unlift(binding =>
      val host = binding.host
      if sessionInspected(host) || programHosts.values.exists(_(host)) then None
      else if sessionTunnels(host) then
        Some(
          s"error: --egress-cred=${binding.spelled}; $host is an opaque tunnel, where nothing can be substituted; " +
            s"bind to an inspected host or forward the value itself with --env=${binding.name}",
        )
      else
        val programFiles = programHosts.keys.toVector.sorted
          .map(program => s" or to .ko-agent-sandbox/run-on-host/$program/egress/rule")
          .mkString
        Some(
          s"error: --egress-cred=${binding.spelled}; no proxy of this launch allows $host; add " +
            s"`allow https://$host/ read` to .ko-agent-sandbox/egress/rule$programFiles",
        ),
    )).toLeft(())

  /** What a proxy inspecting `inspected` is given: the bindings for those hosts, and no other. */
  def bindingsFor(credentials: Seq[BrokeredCredential], inspected: String => Boolean): Vector[BrokeredCredential] =
    credentials.filter(credential => inspected(credential.binding.host)).toVector

  /** The banner's line per binding: the variable as the sandbox sees it, where its value goes, and the
    * placeholder, which is in the sandbox anyway. */
  def bannerLines(credentials: Seq[BrokeredCredential]): Vector[String] =
    credentials.toVector.map: credential =>
      val binding = credential.binding
      s"brokered credential: ${binding.name} → ${binding.target} (${binding.place.shown}), " +
        s"placeholder ${credential.placeholder}"

  /** `--egress-effective`'s line per binding: where its value would go under this ruleset. A binding the
    * session's proxy does not inspect is refused at launch unless a selected program's rules allow it;
    * the action does not read those rules. */
  def effectiveLines(
    bindings: Seq[CredentialBinding],
    sessionInspected: Set[String],
    sessionTunnels: Set[String],
  ): Vector[String] =
    bindings.toVector.map: binding =>
      val where =
        if sessionInspected(binding.host) then "substituted by the session's proxy"
        else if sessionTunnels(binding.host) then "a tunnel here: refused unless a run-on-host program's rules allow it"
        else "not allowed here: refused unless a run-on-host program's rules allow it"
      s"brokered credential: ${binding.name} → ${binding.target} (${binding.place.shown}); $where"

  val SubstitutionNote = "brokered values are substituted in the bound header or parameter only"

  // ---------------------------------------------------------------------------
  // The launcher's own environment
  // ---------------------------------------------------------------------------

  /**
   * Removes the names from the environment every process this launcher starts inherits: `podman`, the
   * runner, the reaper, the handover's exec. A child started without a changed environment inherits
   * the process's current one, so removing them there reaches every start; one whose environment a
   * ProcessBuilder edits starts from the JVM's copy taken at start, which still has them (`scrub`).
   */
  def withhold(names: Seq[String], os: HostCommands.Os): Unit =
    withheldNames = withheldNames ++ names
    names.foreach: name =>
      if os == HostCommands.Os.Windows then FFMHelper.kernel32.clearEnvironmentVariable(name)
      else FFMHelper.libc.unsetenv(name)

  @volatile private var withheldNames: Set[String] = Set.empty

  /** For a ProcessBuilder whose environment is edited: the withheld names removed from its copy. */
  def scrub(builder: ProcessBuilder): ProcessBuilder =
    withheldNames.foreach(builder.environment.remove)
    builder
