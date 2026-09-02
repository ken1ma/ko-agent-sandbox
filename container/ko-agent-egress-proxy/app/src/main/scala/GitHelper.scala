package agentsandbox.egress

import java.util.Locale
import scala.annotation.tailrec

import HTTPHelper.HttpRequestHead

/**
 * What requests mean in git's smart-HTTP protocol. The decisions about them
 * — what is allowed to reach a forge — stay in
 * AgentEgressProxy.authorizeInspectedRequest; this file only names the
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
   * Forge names never need escaping, so a percent-encoded or dot-segmented
   * path on the one write-capable method is not a request git would make;
   * refused rather than normalized.
   */
  def requireUnambiguousPath(path: String): Unit =
    if path.contains('%') then
      throw PolicyViolation("percent-encoding is not allowed in this path", RefusalAdvice.ambiguousPath)

    if path.split("/", -1).exists(segment => segment == "." || segment == "..") then
      throw PolicyViolation("dot segments are not allowed in this path", RefusalAdvice.ambiguousPath)
