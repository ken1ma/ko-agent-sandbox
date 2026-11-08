// `--egress-cred` brokers credentials (doc/egress-proxy.md, "Brokered credentials"). This file handles:
//
// - the bindings that the command line names;
// - the values, which the launcher reads from the host environment;
// - the placeholders that the sandbox and host commands see instead of the values;
// - which proxy of the launch receives each binding;
// - keeping the values out of what the launcher's children inherit.
//
// The binding grammar is the proxy's own (CredentialGrammar).

package agentsandbox.launcher

import java.security.SecureRandom

import agentsandbox.egress.{BrokeredCredential, CredentialBinding, CredentialGrammar, RulesetHelper}

import HostCommands.{chosen, colorStderr}

object EgressCredentials:

  val OptionPrefix = "--egress-cred="

  /** Token prefixes that programs check for. A value that starts with one of them gets a placeholder in
    * the value's format, so the check still passes (placeholderFor). */
  val RecognizedPrefixes: Vector[String] = Vector("github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-")

  private val Digits = '0' to '9'
  private val Uppers = 'A' to 'Z'
  private val Lowers = 'a' to 'z'
  private val LettersAndDigits = Digits ++ Uppers ++ Lowers

  /** RFC 3986's unreserved punctuation. A placeholder keeps these characters in place, because they read
    * the same in a header and in a query. */
  private val KeptSeparators = "-._~"

  /**
   * One `--egress-cred=` value, or why the launcher refuses the value. A refusal for a value on the
   * command line names only the variable, because whatever follows the variable's `=` may be the secret.
   */
  def parseOption(spelled: String, refusedPrefix: String): Either[String, CredentialBinding] =
    val shown = if spelled.takeWhile(_ != '@').contains('=') then s"${spelled.takeWhile(_ != '=')}=..." else spelled
    CredentialGrammar.parseBinding(spelled) match
      case Left(reason) => Left(s"error: --egress-cred=$shown; $reason")
      case Right(binding) if binding.name.startsWith(refusedPrefix) =>
        Left(s"error: --egress-cred=$shown; the launcher sets $refusedPrefix* itself")
      case Right(binding) => Right(binding)

  /**
   * The values, each with a placeholder of its own. The launcher reads each value from the environment
   * variable that its binding names, and checks the value against the grammar. Refusals name the
   * variable, never its value.
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
              case None =>
                val taken = done.map(_.placeholder).toSet + value
                Right(done :+ BrokeredCredential(binding, placeholderFor(value, taken, random), value))

  /**
   * The minimum randomness of a placeholder in its value's format. Code in the workspace sees the
   * placeholder once the session runs, so the randomness guards against a coincidence before then. An
   * application's own token, or a string written into the repository in advance, could equal the
   * placeholder, and the proxy would then replace that string.
   */
  val MinimumPlaceholderBits = 64

  /** The randomness of a placeholder that does not take its value's length, so no format limits the
    * randomness. */
  val UnformattedPlaceholderBits = 128

  private def bits(choices: Int): Double = math.log(choices.toDouble) / math.log(2)

  /** The fewest letters and digits that hold UnformattedPlaceholderBits. */
  val UnformattedPlaceholderLength: Int =
    math.ceil(UnformattedPlaceholderBits / bits(LettersAndDigits.size)).toInt

  /** The random bits of a placeholder in `value`'s format. The recognized prefix and the kept separators
    * add no bits. */
  def formatBits(value: String): Double =
    val prefix = recognizedPrefix(value)
    value.drop(prefix.length).filterNot(KeptSeparators.contains(_)).map: char =>
      if Digits.contains(char) then bits(Digits.size)
      else if Uppers.contains(char) || Lowers.contains(char) then bits(Uppers.size)
      else bits(LettersAndDigits.size)
    .sum

  /** Whether `value`'s placeholder takes the value's format. The placeholder does when the value starts
    * with a recognized prefix and the format leaves the placeholder MinimumPlaceholderBits. */
  def keepsFormat(value: String): Boolean =
    recognizedPrefix(value).nonEmpty && formatBits(value) >= MinimumPlaceholderBits

  private def recognizedPrefix(value: String): String =
    RecognizedPrefixes.find(known => value.startsWith(known) && value.length > known.length).getOrElse("")

  /**
   * A fresh random placeholder for `value` that equals none of `taken`.
   *
   *   - A value whose format is kept (keepsFormat) gets a placeholder in that format. A program that
   *     checks a token's syntax before sending the token then still sends it.
   *     - The prefix and the length stay.
   *     - `-`, `.`, `_` and `~` stay in place, because GitHub's `ghs_APPID_JWT` installation tokens
   *       separate their parts with these characters.
   *     - Each other character is replaced at random within its class: a digit for a digit, and a letter
   *       of the same case for a letter.
   *     - Other punctuation becomes a letter or a digit, because `&`, `=`, `#` and `%` would split or
   *       re-parse the query that a `?PARAM` placeholder is composed into.
   *   - Any other value gets UnformattedPlaceholderLength letters and digits.
   *     - A placeholder in the value's format shows the sandbox the value's length, where its separators
   *       are, and each other character's class. For a password that a person chose, this narrows the
   *       guesses.
   *     - A short value's format leaves too few random bits.
   */
  def placeholderFor(value: String, taken: Set[String], source: SecureRandom): String =
    def from(alphabet: IndexedSeq[Char]) = alphabet(source.nextInt(alphabet.size))
    def replaced(char: Char): Char =
      if KeptSeparators.contains(char) then char
      else if Digits.contains(char) then from(Digits)
      else if Uppers.contains(char) then from(Uppers)
      else if Lowers.contains(char) then from(Lowers)
      else from(LettersAndDigits)
    val placeholder =
      if keepsFormat(value) then
        val prefix = recognizedPrefix(value)
        prefix + value.drop(prefix.length).map(replaced)
      else String(Array.fill(UnformattedPlaceholderLength)(from(LettersAndDigits)))
    if taken.contains(placeholder) then placeholderFor(value, taken, source) else placeholder

  /**
   * Refuses a binding that no proxy of the launch would substitute. The session's proxy inspects
   * `sessionInspected`, and a host proxy inspects each host of its program's rules. A tunnel host that
   * no proxy inspects gets a refusal that names the tunnel, because no substitution can happen inside a
   * tunnel.
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
          .map(program => s" or to ${RunOnHostPrereqs.programRuleFileShown(program)}")
          .mkString
        Some(
          s"error: --egress-cred=${binding.spelled}; no proxy of this launch allows $host; add " +
            s"`${RulesetHelper.hostReadLine(host)}` to ${RulesetHelper.WorkspaceRuleFile}$programFiles",
        ),
    )).toLeft(())

  /** What a proxy inspecting `inspected` is given: the bindings for those hosts, and no other. */
  def bindingsFor(credentials: Seq[BrokeredCredential], inspected: String => Boolean): Vector[BrokeredCredential] =
    credentials.filter(credential => inspected(credential.binding.host)).toVector

  /** The banner's line per binding: the variable as the sandbox sees it, where its value goes, and the
    * placeholder, which is in the sandbox anyway. The line tints the variable and its target as what the
    * user chose (HostCommands.chosen). `source` is what the line adds when the options file supplied the
    * binding (OptionsInForce.from). */
  def bannerLines(
    credentials: Seq[BrokeredCredential],
    source: BrokeredCredential => String = _ => "",
    color: Boolean = colorStderr,
  ): Vector[String] =
    credentials.toVector.map: credential =>
      val binding = credential.binding
      val fromFile = source(credential).nonEmpty
      s"brokered credential: ${chosen(binding.name, color, fromFile)} -> ${chosen(binding.target, color, fromFile)} " +
        s"(${binding.place.shown}), " +
        s"placeholder ${credential.placeholder}${source(credential)}"

  /** `--egress-effective`'s line per binding: where its value would go under this ruleset. A launch
    * refuses a binding that the session's proxy does not inspect, unless a selected program's rules allow
    * the binding. The action does not read those rules. */
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
      s"brokered credential: ${binding.name} -> ${binding.target} (${binding.place.shown}); $where"

  val SubstitutionNote = "brokered values are substituted in the bound header or parameter only"

  // ---------------------------------------------------------------------------
  // The launcher's own environment
  // ---------------------------------------------------------------------------

  /**
   * Removes the names from the environment that every process this launcher starts inherits: `podman`,
   * the runner, the reaper and the handover's exec.
   *
   * - A child started without a changed environment inherits the process's current environment, so
   *   removing the names there reaches every such start.
   * - A child whose environment a ProcessBuilder edits starts from the JVM's copy, taken at JVM start,
   *   which still has the names (`scrub`).
   */
  def withhold(names: Seq[String], os: HostCommands.Os): Unit =
    withheldNames = withheldNames ++ names
    names.foreach: name =>
      if os == HostCommands.Os.Windows then FFMHelper.kernel32.clearEnvironmentVariable(name)
      else FFMHelper.libc.unsetenv(name)

  @volatile private var withheldNames: Set[String] = Set.empty

  /** Removes the withheld names from a ProcessBuilder's copy of the environment, for a builder whose
    * environment the code edits. */
  def scrub(builder: ProcessBuilder): ProcessBuilder =
    withheldNames.foreach(builder.environment.remove)
    builder
