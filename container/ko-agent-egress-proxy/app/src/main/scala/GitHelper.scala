package agentsandbox.egress

import java.util.Locale
import scala.annotation.tailrec

import HTTPHelper.HttpRequestHead

/**
 * What requests mean in git's smart-HTTP protocol. The decisions about them
 * — what is allowed to reach a forge — stay in
 * RulesetHelper.authorizeInspectedRequest; this file only names the
 * requests.
 */
object GitHelper:

  /**
   * Where `clone` and `fetch` POST after ref discovery. A whole-path match,
   * never a suffix match — that would leave the proxy relying on the origin
   * router to agree where the path ends. `{2,}`: GitHub and Codeberg are
   * exactly owner/repo, gitlab.com nests subgroups deeper; a single segment
   * is a repository nowhere. requireUnambiguousPath has already rejected
   * percent-encoding and dot segments.
   */
  private val UploadPackPath = "(/[^/]+){2,}/git-upload-pack".r

  def isUploadPack(path: String): Boolean =
    UploadPackPath.matches(path)

  /**
   * `git push`'s first request: GET .../info/refs?service=git-receive-pack.
   * Classified on a once-percent-decoded spelling — the decode a forge's
   * router applies — so an encoded spelling cannot slip past. Deny-side
   * only: decoding here can widen a refusal, never a grant.
   */
  def isReceivePackDiscovery(head: HttpRequestHead): Boolean =
    percentDecoded(head.path).endsWith("/info/refs") &&
      head.query
        .split("&", -1)
        .exists(param => percentDecoded(param).toLowerCase(Locale.ROOT) == "service=git-receive-pack")

  /**
   * `git fetch`'s first request: GET .../info/refs?service=git-upload-pack, classified as
   * receive-pack's is. It is the `git-fetch` grant's own request, not `read`'s
   * (RulesetHelper.authorizeInspectedRequest); the decode can only widen that refusal.
   */
  def isUploadPackDiscovery(head: HttpRequestHead): Boolean =
    percentDecoded(head.path).endsWith("/info/refs") &&
      head.query
        .split("&", -1)
        .exists(param => percentDecoded(param).toLowerCase(Locale.ROOT) == "service=git-upload-pack")

  /**
   * One decode pass — the forge router's semantics, not HTTP's, which
   * assigns no meaning to %-escapes in a target; the forwarded bytes stay
   * as sent. Private and deny-side on purpose: in HTTPHelper as a reusable
   * decoder it would invite allow-side use and recreate the
   * parser-disagreement problem requireUnambiguousPath refuses. A malformed
   * escape is kept as is — the most an origin would make of it.
   */
  private def percentDecoded(value: String): String =
    val out = StringBuilder()

    @tailrec
    def loop(i: Int): String =
      if i >= value.length then out.toString
      else if value.charAt(i) == '%' && i + 2 < value.length
        && Character.digit(value.charAt(i + 1), 16) >= 0
        && Character.digit(value.charAt(i + 2), 16) >= 0
      then
        val hi = Character.digit(value.charAt(i + 1), 16)
        val lo = Character.digit(value.charAt(i + 2), 16)
        out.append(((hi << 4) | lo).toChar)
        loop(i + 3)
      else
        out.append(value.charAt(i))
        loop(i + 1)

    loop(0)

  /**
   * The spellings a forge's router decodes before routing, so that a ruleset
   * comparing the path as sent would disagree with the origin about which
   * path it names. Forge names never need escaping, so neither is a request
   * git would make.
   */
  private val DecodedSpellings: Vector[(String, String => Boolean)] = Vector(
    "percent-encoding" -> (_.contains('%')),
    "a dot segment" -> (_.split("/", -1).exists(segment => segment == "." || segment == "..")),
  )

  /**
   * The further spellings an origin may fold onto another path — a
   * backslash, which a Windows-hosted or lenient server reads as `/`, and an
   * empty segment, which many collapse — refused wherever the path is
   * compared to a reviewed prefix.
   */
  private val FoldedSpellings: Vector[(String, String => Boolean)] = Vector(
    "a backslash" -> (_.contains('\\')),
    "an empty segment" -> (_.contains("//")),
  )

  private def problemOf(path: String, spellings: Vector[(String, String => Boolean)]): Option[String] =
    spellings.collectFirst { case (name, present) if present(path) => name }

  /** Why `path` cannot be compared literally to a rule's path, or None: the one
    * rule for a rule's path at launch and for a request under one. */
  def literalPathProblem(path: String): Option[String] =
    problemOf(path, DecodedSpellings ++ FoldedSpellings)

  private def requireSpelledPlainly(path: String, spellings: Vector[(String, String => Boolean)]): Unit =
    problemOf(path, spellings).foreach: problem =>
      throw Refusal(s"$problem in the path", RefusalAdvice.ambiguousPath)

  /** A write-capable method's path, refused rather than normalized when a
    * forge would decode it first. */
  def requireUnambiguousPath(path: String): Unit =
    requireSpelledPlainly(path, DecodedSpellings)

  /** A path whose longest match is a line other than the root, on every
    * method: refused for any spelling literalPathProblem names. */
  def requireLiteralPath(path: String): Unit =
    requireSpelledPlainly(path, DecodedSpellings ++ FoldedSpellings)
