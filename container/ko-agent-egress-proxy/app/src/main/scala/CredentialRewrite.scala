// The brokered credential's rewrite of a request head (doc/egress-proxy.md, "Where the value goes"):
// the value in place of its placeholder in the one place a binding names, and the target as the
// audit line prints it. Pure, so it is tested on heads alone; AgentEgressProxy applies it before a
// request is authorized.

package agentsandbox.egress

import java.nio.charset.StandardCharsets
import scala.annotation.tailrec

import HTTPHelper.HttpRequestHead

/** A head with brokered values substituted, the names of the bindings whose value it carries, and its
  * target as the audit line prints it. */
case class Substituted(head: HttpRequestHead, injected: Vector[String], printedTarget: String)

object CredentialRewrite:

  extension (head: HttpRequestHead)
    /**
     * The head with each brokered value in place of its placeholder, for a request to `host`. A
     * credential is substituted only where its binding covers the request and the whole token in its
     * one place equals its placeholder: the token of `Bearer`, `token`, or `Basic`'s password half in
     * `Authorization`, the whole value of another bound header, or the percent-decoded value of a
     * bound query parameter. Each occurrence of the place is rewritten on its own, so a header or
     * parameter sent twice keeps one meaning whichever occurrence the origin reads. A placeholder
     * anywhere else is forwarded as it is: it authenticates nothing.
     */
    def withCredentials(host: String, credentials: Seq[BrokeredCredential]): Substituted =
      val bound = credentials.filter(_.binding.covers(host, head.path))
      def boundTo(fitsPlace: CredentialPlace => Boolean) =
        bound.filter(credential => fitsPlace(credential.binding.place))

      val headerResults = head.headers.map: (spelledName, value) =>
        val candidates = boundTo:
          case CredentialPlace.Header(name) => name.equalsIgnoreCase(spelledName)
          case _                            => false
        val replaced =
          if candidates.isEmpty then None
          else if spelledName.equalsIgnoreCase("Authorization") then authorizationWith(value, candidates)
          else candidates.find(_.placeholder == value).map(credential => (credential.value, credential))
        replaced match
          case Some((newValue, credential)) => (spelledName -> newValue, Some(credential.binding.name))
          case None                         => (spelledName -> value, None)

      val parameterResults = head.query.split("&", -1).toVector.map: piece =>
        val (spelledName, value) = piece.span(_ != '=')
        val candidates = boundTo:
          case CredentialPlace.Parameter(name) => name == percentDecoded(spelledName)
          case _                               => false
        candidates.find(credential => value.nonEmpty && credential.placeholder == percentDecoded(value.drop(1))) match
          case Some(credential) =>
            (s"$spelledName=${percentEncoded(credential.value)}", Some(credential.binding.name))
          case None => (piece, None)
      val rewrittenQuery = parameterResults.map(_(0)).mkString("&")

      val rewrittenTarget = if head.target.contains('?') then s"${head.path}?$rewrittenQuery" else head.target
      Substituted(
        head.copy(target = rewrittenTarget, headers = headerResults.map(_(0))),
        (headerResults ++ parameterResults).flatMap(_(1)).distinct,
        head.printedTarget(credentials),
      )

    /** The target as the audit line prints it: each parameter whose value is a placeholder, and each
      * placeholder spelled out anywhere else, as its binding's name, so no placeholder spelled as the launch
      * issued it reaches the log; a percent-escaped spelling prints as sent. */
    def printedTarget(credentials: Seq[BrokeredCredential]): String =
      def named(text: String): String =
        credentials.foldLeft(text)((printed, credential) =>
          printed.replace(credential.placeholder, credential.binding.name),
        )
      if !head.target.contains('?') then named(head.target)
      else
        val pieces = head.query.split("&", -1).toVector.map: piece =>
          val (name, value) = piece.span(_ != '=')
          val decoded = Option.when(value.nonEmpty)(percentDecoded(value.drop(1)))
          credentials.find(credential => decoded.contains(credential.placeholder)) match
            case Some(credential) => s"$name=${credential.binding.name}"
            case None             => named(piece)
        s"${named(head.path)}?${pieces.mkString("&")}"

  /** `Bearer` or `token` and the token, or `Basic` and its password half, replaced when it is a placeholder;
    * any other scheme is left as sent. The scheme's spelling and the spaces after it are kept. */
  private def authorizationWith(
    value: String,
    candidates: Seq[BrokeredCredential],
  ): Option[(String, BrokeredCredential)] =
    val scheme = value.takeWhile(_ != ' ')
    val separator = value.drop(scheme.length).takeWhile(_ == ' ')
    val token = value.drop(scheme.length + separator.length)
    if scheme.isEmpty || separator.isEmpty || token.isEmpty then None
    else if scheme.equalsIgnoreCase("Bearer") || scheme.equalsIgnoreCase("token") then
      candidates.find(_.placeholder == token).map(credential => (s"$scheme$separator${credential.value}", credential))
    else if scheme.equalsIgnoreCase("Basic") then
      val decoded =
        try Some(String(java.util.Base64.getDecoder.decode(token), StandardCharsets.ISO_8859_1))
        catch case _: IllegalArgumentException => None
      decoded.flatMap: pair =>
        val (user, password) = pair.span(_ != ':')
        candidates.find(credential => password.nonEmpty && credential.placeholder == password.drop(1)).map:
          credential =>
            val encoded = java.util.Base64.getEncoder.encodeToString(
              s"$user:${credential.value}".getBytes(StandardCharsets.ISO_8859_1),
            )
            (s"$scheme$separator$encoded", credential)
    else None

  /**
   * One decode pass, a malformed escape kept as is: whichever way the sandbox spelled a bound parameter,
   * the origin reads its name and value decoded. GitHelper keeps a decoder of its own, deny-side, and
   * gives why none is shared. This one decides a substitution, and that is safe to decide on one pass:
   * an origin decoding otherwise reads a name or a value this pass did not match, so the value is not
   * substituted and the origin answers the placeholder with 401.
   */
  private def percentDecoded(text: String): String =
    val out = StringBuilder()
    @tailrec
    def loop(index: Int): String =
      if index >= text.length then out.toString
      else if text.charAt(index) == '%' && index + 2 < text.length
        && Character.digit(text.charAt(index + 1), 16) >= 0 && Character.digit(text.charAt(index + 2), 16) >= 0
      then
        out.append(Integer.parseInt(text.substring(index + 1, index + 3), 16).toChar)
        loop(index + 3)
      else
        out.append(text.charAt(index))
        loop(index + 1)
    loop(0)

  /** RFC 3986's unreserved characters as they are, every other byte as `%XX`: the value grammar admits
    * `&`, `=`, `#` and `%`, which raw would split or re-parse the query. */
  private def percentEncoded(value: String): String =
    value.getBytes(StandardCharsets.UTF_8).map: byte =>
      val char = (byte & 0xff).toChar
      if char.isLetterOrDigit && char < 0x80 || "-._~".contains(char) then char.toString
      else f"%%${byte & 0xff}%02X"
    .mkString
