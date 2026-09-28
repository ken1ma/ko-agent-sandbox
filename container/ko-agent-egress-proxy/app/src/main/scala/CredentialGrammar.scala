// What a brokered credential may be (doc/egress-proxy.md, "Where the value goes"), the binding
// that says where it goes, and the lines a proxy reads its bindings from. The launcher's jar compiles
// this file too (build.sbt), so `--egress-cred` and the proxy's start-up run the same checks.

package agentsandbox.egress

import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.Locale
import scala.annotation.tailrec

import IPAddrHelper.{isIpLiteral, normalizeHost}

/** Where a binding's value is substituted. */
enum CredentialPlace:
  case Header(name: String)
  case Parameter(name: String)

  /** As a binding spells it after the host: `:HEADER` or `?PARAM`. */
  def spelled: String = this match
    case Header(name)    => s":$name"
    case Parameter(name) => s"?$name"

  /** As the launch banner shows it: `Authorization` or `?sig`. */
  def shown: String = this match
    case Header(name)    => name
    case Parameter(name) => s"?$name"

/** `NAME@HOST[/PREFIX/][:HEADER|?PARAM]`, with `/` as the prefix of a binding naming none. */
case class CredentialBinding(name: String, host: String, prefix: String, place: CredentialPlace):
  def spelled: String = s"$name@$target${place.spelled}"

  /** The host and the prefix a binding names, as it spells them: `api.github.com`, `h.example/owner/`. */
  def target: String = if prefix == RulePath.Root then host else s"$host$prefix"

  /** Whether a request to `host` at `path` is one this binding's value may go with. Under a prefix the
    * path must be literal, as under a rule's own path: a spelling the origin decodes could leave it. */
  def covers(requestHost: String, path: String): Boolean =
    requestHost == host
      && (prefix == RulePath.Root || RulePath.literalPathProblem(path).isEmpty && RulePath.contains(prefix, path))

/** A binding with what the sandbox holds for it and what the origin receives in its place. */
case class BrokeredCredential(binding: CredentialBinding, placeholder: String, value: String):
  override def toString: String = s"BrokeredCredential(${binding.spelled})"

object CredentialGrammar:

  /** A value at its longest: it travels in a request head, and the proxy reads no head longer than this.
    * doc/egress-proxy.md, "Where the value goes", has the tokens and the origins' limits it is set against. */
  val MaxValueBytes: Int = AgentEgressProxy.MaxHttpHeaderBytes

  /** The headers this proxy reads or removes: a value bound to one would never reach the origin as that header,
    * and Host, the framing pair and Upgrade route or frame the request. */
  val RefusedHeaders: Set[String] = HTTPHelper.ConnectionProtectedHeaders ++ HTTPHelper.HopByHopHeaders

  val DefaultPlace: CredentialPlace = CredentialPlace.Header("Authorization")

  val MaxBindings = 256

  /** A binding as `CredentialBinding.spelled` writes it, at its longest: the head of a request a binding
    * applies to holds its host, its prefix and its header or parameter name, and is no longer than this. */
  val MaxBindingBytes: Int = AgentEgressProxy.MaxHttpHeaderBytes

  /** A binding, a placeholder and a value at their longest, and the two spaces between them. */
  private val MaxLineBytes = MaxBindingBytes + 2 * MaxValueBytes + 2

  /** Set to StdinValue in a proxy's environment, tells it its bindings follow on its standard input; without it,
    * the proxy reads nothing there. */
  val StdinVariable = "EGRESS_CREDS"
  val StdinValue = "stdin"

  /** A value is 1 to MaxValueBytes bytes of visible ASCII, so it cannot end a field, start another, or alter framing.
    * `subject` names the value in the refusal, which never contains the value itself. */
  def valueProblem(subject: String, value: String): Option[String] =
    if value.isEmpty then Some(s"$subject is empty")
    else
      value.indexWhere(char => char < 0x21 || char > 0x7e) match
        // Every char before the first refused one is ASCII, so its index is its byte offset.
        case -1 if value.length > MaxValueBytes => Some(s"$subject is longer than $MaxValueBytes bytes")
        case -1                                 => None
        case offset => Some(s"$subject contains a byte a header cannot carry, at offset $offset")

  /** The launcher's one test of a variable name, for `--env` as for a binding. */
  def environmentName(name: String): Boolean = name.matches("[A-Za-z_][A-Za-z0-9_]*")

  /** A parameter frames nothing, so its name is free within the value grammar, but for what would split or
    * end the query, and `+`, which a form parser reads as a space: the origin would read `a+b` as `a b`. */
  def parameterProblem(name: String): Option[String] =
    Option.when(name.isEmpty || name.exists(char => char < 0x21 || char > 0x7e || "&=#+".contains(char)))(
      s"'$name' is not a query parameter name: visible ASCII without &, =, # or +",
    )

  /**
   * Parses `NAME@HOST[/PREFIX/][:HEADER|?PARAM]`. The host ends at the first `/`, `:` or `?`; a prefix
   * runs to its last `/`, and the place follows it. A refusal says what is wrong and what a binding is
   * instead; a name the caller restricts further, as the launcher does `KO_AGENT_SANDBOX_*`, is its own.
   */
  def parseBinding(spelled: String): Either[String, CredentialBinding] =
    spelled.indexOf('@') match
      case -1 =>
        Left("a credential needs a host; to set the value itself in the sandbox, use --env=NAME")
      case at =>
        val name = spelled.take(at)
        if name.contains('=') then
          Left(
            "a credential's value is not given on the command line; set the variable for the launch and pass NAME@HOST",
          )
        else if !environmentName(name) then
          Left(s"'$name' is not an environment variable name: a letter or _, then letters, digits and _")
        else
          val rest = spelled.drop(at + 1)
          val hostEnd = rest.indexWhere(char => char == '/' || char == ':' || char == '?') match
            case -1    => rest.length
            case index => index
          val (prefix, placeText) =
            if rest.lift(hostEnd).contains('/') then
              val lastSlash = rest.lastIndexOf('/')
              (rest.substring(hostEnd, lastSlash + 1), rest.drop(lastSlash + 1))
            else (RulePath.Root, rest.drop(hostEnd))
          for
            host <- bindingHost(rest.take(hostEnd))
            _ <- prefixProblem(prefix).toLeft(())
            place <- parsePlace(placeText)
            binding = CredentialBinding(name, host, prefix, place)
            // Every character of a parsed binding is ASCII, so its length is its bytes.
            _ <- Either.cond(
              binding.spelled.length <= MaxBindingBytes, (),
              s"a binding is at most $MaxBindingBytes bytes; this one is ${binding.spelled.length}, written " +
                "with its host normalized and its place named",
            )
          yield binding

  private def bindingHost(spelled: String): Either[String, String] =
    if spelled.isEmpty then Left("a credential needs a host after @")
    else
      try
        val host = normalizeHost(spelled)
        if isIpLiteral(host) then Left(s"'$spelled' is an IP literal; a credential is bound to a hostname")
        else Right(host)
      catch case ex: BadRequest => Left(s"'$spelled' is not a hostname: ${ex.getMessage}")

  /** A rule's path in canonical form, and a tree: the prefix names the requests under it. */
  private def prefixProblem(prefix: String): Option[String] =
    if prefix == RulePath.Root then None
    else if prefix.contains('?') then Some("a prefix ends at its last /, before ?PARAM")
    else
      RulePath.literalPathProblem(prefix)
        .map(problem => s"a prefix has $problem; it is written in canonical form, as a rule's path is")

  private def parsePlace(text: String): Either[String, CredentialPlace] =
    if text.isEmpty then Right(DefaultPlace)
    else if text.contains(':') && text.contains('?') then Left("a binding names one place: :HEADER or ?PARAM, not both")
    else if text.startsWith(":") then headerPlace(text.drop(1))
    else if text.startsWith("?") then
      val name = text.drop(1)
      parameterProblem(name).toLeft(CredentialPlace.Parameter(name))
    else Left(s"'$text' follows the host; a binding is NAME@HOST[/PREFIX/][:HEADER|?PARAM]")

  /** Any header name but those the proxy reads or removes, as the user spells it; `Authorization` is the
    * default place, whose token the rewrite finds after the scheme. */
  private def headerPlace(name: String): Either[String, CredentialPlace] =
    val folded = name.toLowerCase(Locale.ROOT)
    if name.nonEmpty && name.forall(_.isDigit) then
      Left(s"'$name' is a port, not a header name; a credential is bound to a hostname, reached on port 443 only")
    else if name.isEmpty || !name.forall(HTTPHelper.isHttpTokenChar) then
      Left(s"'$name' is not a header name: only letters, digits and !#$$%&'*+-.^_`|~")
    else if RefusedHeaders(folded) then
      Left(s"$name is read or removed by the proxy; bind the header the service authenticates with")
    else if folded == "authorization" then Right(DefaultPlace)
    else Right(CredentialPlace.Header(name))

  /** One binding's line: the binding, the placeholder and the value, each without a space. */
  def bindingLine(credential: BrokeredCredential): String =
    s"${credential.binding.spelled} ${credential.placeholder} ${credential.value}"

  /** The whole input a proxy reads: a count line, then one line per binding, nothing after them. */
  def bindingInput(credentials: Seq[BrokeredCredential]): String =
    (credentials.size.toString +: credentials.map(bindingLine)).map(_ + "\n").mkString

  /** bindingInput as written to a pipe: every byte is ASCII, which the value grammar guarantees. */
  def bindingBytes(credentials: Seq[BrokeredCredential]): Array[Byte] =
    bindingInput(credentials).getBytes(StandardCharsets.US_ASCII)

  /**
   * Reads what bindingInput wrote, a byte at a time and no further, so the read neither waits for the
   * end of input nor takes a byte that is not its own. Every binding passes the checks the launcher made,
   * again; a refusal names the binding, never the value.
   */
  def readBindings(in: InputStream): Either[String, Vector[BrokeredCredential]] =
    readLine(in).flatMap: countText =>
      HTTPHelper.parseDecimal(countText).filter(_ <= MaxBindings).map(_.toInt) match
        case None => Left(s"the bindings' count line is '$countText', not a count up to $MaxBindings")
        case Some(count) =>
          val read = (1 to count).foldLeft[Either[String, Vector[BrokeredCredential]]](Right(Vector.empty)):
            (credentials, _) => credentials.flatMap(done => readLine(in).flatMap(parseBindingLine).map(done :+ _))
          read.flatMap(checkDistinct)

  private def readLine(in: InputStream): Either[String, String] =
    val bytes = java.io.ByteArrayOutputStream()
    @tailrec
    def loop(): Either[String, String] =
      in.read() match
        case -1                              => Left("the bindings ended before their count")
        case 0x0a                            => Right(String(bytes.toByteArray, StandardCharsets.ISO_8859_1))
        case _ if bytes.size >= MaxLineBytes => Left("a binding line is longer than a binding can be")
        case byte =>
          bytes.write(byte)
          loop()
    loop()

  private def parseBindingLine(line: String): Either[String, BrokeredCredential] =
    line.split(" ", -1) match
      case Array(spelled, placeholder, value) =>
        for
          binding <- parseBinding(spelled)
          _ <- valueProblem(s"the placeholder of ${binding.name}", placeholder).toLeft(())
          _ <- valueProblem(binding.name, value).toLeft(())
        yield BrokeredCredential(binding, placeholder, value)
      case _ => Left("a binding line is not <binding> <placeholder> <value>")

  private def checkDistinct(credentials: Vector[BrokeredCredential]): Either[String, Vector[BrokeredCredential]] =
    val names = credentials.map(_.binding.name)
    val placeholders = credentials.map(_.placeholder)
    names.diff(names.distinct).headOption match
      case Some(duplicate) => Left(s"$duplicate is bound twice; one name, one host")
      case None if placeholders.distinct.size != placeholders.size => Left("two bindings share a placeholder")
      case None => Right(credentials)
