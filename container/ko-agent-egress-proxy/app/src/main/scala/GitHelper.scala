package agentsandbox.egress

import java.util.Locale
import scala.annotation.tailrec

import HTTPHelper.HttpRequestHead

/**
 * What requests mean in git's smart-HTTP protocol. RulesetHelper.authorizeInspectedRequest decides what may reach a
 * forge; this file only names the requests.
 */
object GitHelper:

  /**
   * Where `clone` and `fetch` POST after ref discovery.
   *
   * - The pattern matches the whole path, never a suffix. A suffix match would leave the proxy relying on the
   *   origin's router to agree where the path ends.
   * - `{2,}`: GitHub and Codeberg paths are exactly owner/repo, and gitlab.com nests subgroups deeper. A single
   *   segment is a repository nowhere.
   * - RulePath.requireUnambiguousPath has already refused percent-encoding and dot segments.
   * - A segment holds no `#`. The target is forwarded as sent, and an origin whose parser cuts the path at `#`
   *   routes `/o/r/git-receive-pack#/git-upload-pack` to the push.
   */
  private val UploadPackPath = "(/[^/#]+){2,}/git-upload-pack".r

  def isUploadPack(path: String): Boolean =
    UploadPackPath.matches(path)

  /** `git push`'s first request: GET .../info/refs?service=git-receive-pack. */
  def isReceivePackDiscovery(head: HttpRequestHead): Boolean = isDiscovery(head, "git-receive-pack")

  /**
   * `git fetch`'s first request: GET .../info/refs?service=git-upload-pack. This request belongs to the
   * `git-fetch` grant, not to `read` (RulesetHelper.authorizeInspectedRequest). The decode can only widen the
   * refusal of this request under `read`.
   */
  def isUploadPackDiscovery(head: HttpRequestHead): Boolean = isDiscovery(head, "git-upload-pack")

  /**
   * The check runs on a spelling decoded once, as a forge's router decodes it, so an encoded spelling cannot slip
   * past. The check is deny-side only: decoding here can widen a refusal, never a grant.
   */
  private def isDiscovery(head: HttpRequestHead, service: String): Boolean =
    percentDecoded(head.path).endsWith("/info/refs") &&
      head.query.split("&", -1).exists(param => percentDecoded(param).toLowerCase(Locale.ROOT) == s"service=$service")

  /**
   * One decode pass, as the forge's router decodes. HTTP assigns no meaning to %-escapes in a target, and the
   * forwarded bytes stay as sent. A malformed escape is kept as it is, which is the most an origin would make of it.
   *
   * - The decoder is private and deny-side on purpose. As a reusable decoder in HTTPHelper, it would invite use on
   *   the allow side and recreate the parser disagreement that RulePath.requireUnambiguousPath refuses.
   * - CredentialRewrite keeps its own decoder for the substitution, and says why one pass is safe there.
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
