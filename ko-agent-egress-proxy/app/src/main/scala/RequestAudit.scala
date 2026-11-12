// The fields of an inspected request's audit lines past the target: its framing, its client and its credential's
// index on the `allow` line, and the `chunked-end` line that ends a chunked body (SECURITY.md, "The audit line
// grammar").
//
// The names:
// - `cred` is short for credential, since every inspected line can carry it and developers read the log.
// - `content-length=` is named after the header, not `send=`: the line prints before the relay sends the body, so the
//   value is the declared upper bound, not a count. It is lower case, as HTTP/2 and HTTP/3 require field names to be
//   on the wire (RFC 9113, 8.2.1).
// - `send=` on the `chunked-end` line, and the planned `recv=` for a WebSocket's other direction, count from the
//   client's side. A size named after a direction does not read as a second reference beside `id=`.
// - The line is `chunked-end`, one token so that the host stays the third field. It names the framing, as the planned
//   `websocket-end` will. Not `close`: it prints when the last chunk passes, while the connection still carries the
//   response.

package agentsandbox.egress

import java.util.Locale
import java.util.concurrent.atomic.AtomicLong
import scala.collection.mutable

import HTTPHelper.{BodyFraming, HttpRequestHead}
import LogHelper.auditLine

/** What one request's `allow` line adds after `inject=`, each field followed by a space, and the `id=` that its
  * `chunked-end` line repeats. */
final case class AllowFields(text: String, id: Option[Long])

/** A request body's end: the payload bytes written to the origin, and whether the whole body reached the origin. */
final case class BodyRelayed(payloadBytes: Long, complete: Boolean)

/** The counters behind `id=` and `cred=`. One instance serves one proxy run (AgentEgressProxy.Run). */
final class RequestAudit:
  private val lastId = AtomicLong(0)
  // Digests, never values (SECURITY.md, "The audit line grammar").
  private val credentialIndexes = mutable.HashMap.empty[String, Int]

  /** The fields of the `allow` line for `asSent`, the head as the client sent it, before any brokered value replaced
    * a placeholder. `framing` is the framing that the relay forwards. */
  def allowFields(asSent: HttpRequestHead, framing: BodyFraming): AllowFields =
    val id = Option.when(framing == BodyFraming.Chunked)(lastId.incrementAndGet())
    val framingField = framing match
      case BodyFraming.Length(count) => Some(s"content-length=$count")
      case BodyFraming.Chunked       => Some("chunked")
      case _                         => None
    val credential = RequestAudit.staticCredential(asSent).map: value =>
      s"cred=${credentialIndex(value).fold("?")(_.toString)}"
    val fields =
      Vector(framingField, id.map(number => s"id=$number"), RequestAudit.client(asSent).map(token => s"client=$token"),
        credential).flatten
    AllowFields(fields.map(field => s"$field ").mkString, id)

  /** The 1-based index of `credential` in order of first sight, or None for a new credential past
    * RequestAudit.MaxCredentials. */
  def credentialIndex(credential: String): Option[Int] =
    val digest = LogHelper.sha256Hex(credential)
    synchronized:
      credentialIndexes.get(digest).orElse:
        Option.when(credentialIndexes.size < RequestAudit.MaxCredentials):
          val index = credentialIndexes.size + 1
          credentialIndexes(digest) = index
          index

object RequestAudit:
  val MaxCredentials = 1024
  val MaxClientChars = 128

  /** The characters that `client=` keeps. `=` and the space stay out, so the field never reads as two fields. */
  private def isClientChar(char: Char): Boolean =
    char < 0x80 && (char.isLetterOrDigit || "._:/-".contains(char))

  /** The start of the first `User-Agent`, as far as its characters are client characters, at most MaxClientChars of
    * them. None when nothing qualifies. */
  def client(head: HttpRequestHead): Option[String] =
    head.values("User-Agent").headOption.map(_.takeWhile(isClientChar).take(MaxClientChars)).filter(_.nonEmpty)

  private val KeyHeaders = Set("x-api-key", "x-goog-api-key")

  /** The first credential in the head that stays the same across requests: the value of a key header, or the token of
    * an `Authorization` under a scheme that CredentialRewrite substitutes. A signing scheme such as SigV4 sends a new
    * value every request, and each would count as a new credential. */
  def staticCredential(head: HttpRequestHead): Option[String] =
    head.headers.iterator.flatMap: (name, value) =>
      val folded = name.toLowerCase(Locale.ROOT)
      if KeyHeaders.contains(folded) then Option.when(value.nonEmpty)(value)
      else if folded == "authorization" then
        CredentialRewrite.authorizationParts(value).collect:
          case (scheme, _, token) if CredentialRewrite.SubstitutedSchemes.exists(_.equalsIgnoreCase(scheme)) => token
      else None
    .nextOption()

  /** The line that ends a chunked body, after its `allow` line with the same `id=`. */
  def chunkedEndLine(host: String, method: String, target: String, id: Long, relayed: BodyRelayed): String =
    val incomplete = if relayed.complete then "" else " incomplete"
    auditLine("chunked-end", host, method, target, s"id=$id send=${relayed.payloadBytes}$incomplete")
