// What the proxy tells a refused or failed connection, and the typed reasons that the handlers sort by. This file
// holds the exception for each stage and RefusalAdvice's table of next steps.

package agentsandbox.egress

import java.io.IOException
import java.net.SocketException
import java.nio.charset.StandardCharsets

case class BadRequest(message: String) extends RuntimeException(message)

/** A connection that closed after zero bytes. Pooled clients close routinely this way after the ruleset allowed
  * the connection. The proxy logs such a close as `error`, since the ruleset refused nothing (SECURITY.md, "The
  * audit line grammar"). */
case class ClosedWithoutRequest() extends RuntimeException("closed without sending a request")

/** A response-body framing or I/O failure after the proxy forwarded the response head. Unlike an IOException, this
  * failure requires an abortive close of the client: a 502 would land inside the response body, and a clean TLS
  * shutdown would make a close-delimited body appear complete. */
case class TruncatedResponse(message: String) extends RuntimeException(message)

/** A refusal that the ruleset made. The refused party receives the refusal as a 403 body of two lines
  * (Refusals.refusalBody).
  *
  * - `message` is the audit line's `<why>`, and `advice` is RefusalAdvice's next step. Both are required, so no
  *   refusal site can ship without its step.
  * - `proxyError` is the response's RFC 9209 proxy error type (Refusals.proxyStatus). The type is the ruleset's
  *   refusal unless the site has a more specific registered type. */
case class Refusal(message: String, advice: String, proxyError: String = "http_request_denied")
    extends RuntimeException(message)

/**
 * The next step that each refusal names for the agent reading the 403 body inside the sandbox. The step is one the
 * agent can take there, or the one instruction to pass to the user.
 *
 * - A step never names a way around the ruleset, and never a host that this session's ruleset does not allow.
 *   forRefusedPost checks before naming a host.
 * - A host command's proxy sends these bodies too (doc/run-on-host-internals.md, "The command's egress proxy"). So a
 *   step that is the user's says "outside the sandbox": a refused host command already runs on the host.
 * - A body holds fixed text plus what the request itself named, so a body never carries workspace data or a
 *   credential.
 * - This object is the whole table, with one member per refusal. The audit line keeps the short reason alone.
 */
object RefusalAdvice:
  /** The step depends on why the host is refused.
    *
    * - The rule file's allow lines count under deny-unless-allowed alone (resolveRuleset). So under deny-all or
    *   deny-unless-model, the step is a relaunch, named as necessary and never as sufficient. This session's
    *   resolution says nothing about what that profile would apply from the workspace's file, a denial of this
    *   very host included.
    * - Under the default profile, a defaults host reaches this refusal only through `deny defaults`, so the step
    *   names `deny defaults`. A host that a deny line emptied is refused as denied instead, and that refusal names
    *   the line. */
  def hostNotAllowed(host: String, profile: String): String =
    val default = RulesetHelper.DefaultProfile
    val defaults = RulesetHelper.DefaultHosts.contains(host)
    val addition = s"'${RulesetHelper.hostReadLine(host)}' in ${RulesetHelper.WorkspaceRuleFile}"
    if profile == default then
      if defaults then
        "This workspace's rule file starts from deny defaults and does not allow it. Ask the user; do not look " +
          "for another route."
      else s"Not in this session's egress rules. Ask the user to add $addition on the host."
    else
      s"This session's egress profile, $profile, allows no workspace hosts. Ask the user; a relaunch under " +
        (if defaults then s"$default can allow it." else s"$default with $addition can allow it.")

  // The body's first line already names the deny line (`host denied (<line>)`). A `**.domain` pattern repeated here
  // would name a host that the ruleset does not allow.
  val hostDenied = "Denied by this workspace's rules. Ask the user; do not look for another route."

  val port = "Only port 443 is reachable."

  // The step names the directory, not the file: a host command's proxy sends this body too, and that proxy's log
  // has its session's name.
  val auditLog =
    "This proxy serves no new connection for the rest of the session. Tell the user: this proxy's audit log " +
      "is in the directory on the launch's `log dir` line; make it writable again, then relaunch."

  val ipLiteral = "Connect by hostname; addresses are refused."

  val nonPublicAddress = "This name resolves to an address the sandbox never reaches. Ask the user."

  val gitPush = "Push is refused in the sandbox. Leave the commits; the user pushes outside the sandbox."

  val gitFetch = "Clone and fetch are refused here: no git-fetch grant. Ask the user; do not look for another route."

  val noRead = "No read grant covers this path. Ask the user; do not look for another route."

  val graphql = "This GraphQL POST is refused. Read through the REST API."

  /** Where GitHub serves LFS file contents read-only, one URL per file (SECURITY.md, "Reading without being able
    * to write"). Advice names this host only while the ruleset allows the host. */
  val LfsContentHost = "media.githubusercontent.com"

  val lfsBatchGithub =
    s"LFS batch is refused. Read one file from https://$LfsContentHost/media/<owner>/<repo>/<ref>/<path>."

  val lfsBatch = "LFS batch is refused. Ask the user to fetch the content outside the sandbox."

  val methodNotGranted =
    "This HTTP method is not granted here. Ask the user to run the command themselves, outside the sandbox."

  val bodyFramingHeader = "GET and HEAD must omit Content-Length and Transfer-Encoding here. Remove those headers."

  val upgrade = "Only a WebSocket GET can upgrade, at a path a line grants. Use a plain request."

  /** The line names the refused path whole, so the user reads the one path it opens. */
  def webSocketNotGranted(host: String, path: String): String =
    s"No line grants a WebSocket here. Use a plain request; if the work needs this WebSocket, ask the user to add " +
      s"'${RulesetHelper.allowLine(host, path, RulesetHelper.Grant.WebSocket)}' to ${RulesetHelper.WorkspaceRuleFile}."

  val originForm = "Send the path, not the absolute URL."

  val hostHeader = "The Host header must name the host the tunnel was opened to."

  /** The agent instructions state the same RulePath checks in shorter words (LaunchMessages.appendedSection, "Egress");
    * a change to RulePath changes both texts. */
  val ambiguousPath =
    "Spell the path in printable ASCII without dot segments, backslashes, semicolons, # or empty segments. " +
      "Percent-encode only non-ASCII text and spaces, and nothing at all in a POST, PUT, PATCH or DELETE."

  /** The paths are the ruleset's own words for this host, so naming them names nothing new. */
  def pathOutside(paths: Set[String]): String =
    s"This host is allowed under ${paths.toVector.sorted.mkString(" and ")} only. " +
      "Ask the user; do not look for another route."

  /** The ClientHello stage answers after the 200, so this step reaches no client; the agent instructions carry the
    * sentence. The step exists all the same, because the constructor requires one. */
  val clientHello = "Send SNI naming the CONNECT host, without Encrypted ClientHello."

  /**
   * The step of a refusal that the requester answers by changing the request, else None. This method serves a
   * reader of the audit log who has the line's `<why>` and no 403 body: the run-on-host supervisor, reporting for a
   * program that printed none.
   * The match uses the reasons that authorizeInspectedRequest and RulePath throw with; the refusal table's test
   * holds the two together.
   */
  def requestStep(reason: String): Option[String] =
    if reason == "only origin-form request targets are allowed" then Some(originForm)
    else if reason == "HTTP Upgrade is not allowed" then Some(upgrade)
    else if reason.startsWith("Host header ") then Some(hostHeader)
    else if reason == "request body framing header" then Some(bodyFramingHeader)
    else if reason.endsWith(" in the path") then Some(ambiguousPath)
    else None

  /** Whether `reason` is a refusal for want of a grant, which no change to the request answers. */
  def grantRefused(reason: String): Boolean =
    reason.endsWith(" not granted") || reason == "path under no line" || reason.endsWith(" ref discovery")

  /** Chosen by the path that the request named, which this proxy parsed and never read from a body. The two POSTs
    * whose refusal costs a read get the read's other route: GraphQL (`/graphql` on GitHub, `/api/graphql` on
    * GitLab) and the LFS batch endpoint. */
  def forRefusedPost(host: String, path: String, allowed: String => Boolean): String =
    if path.endsWith("/graphql") then graphql
    else if path.endsWith("/info/lfs/objects/batch") then
      if host == "github.com" && allowed(LfsContentHost) then lfsBatchGithub else lfsBatch
    else methodNotGranted

case class BadTls(message: String) extends RuntimeException(message)

object Refusals:

  /** The refusal's body: the audit line's tail, and under the tail the next step when the refusal is the ruleset's
    * (Refusal.advice). Each part takes one line, so a client that prints the body also prints the step. curl prints the
    * body as it is, and git prints the body as `remote:` lines, since the type is text/plain. */
  def refusalBody(detail: String, advice: Option[String]): Array[Byte] =
    (s"ko-agent-egress-proxy: $detail\n" + advice.map(_ + "\n").getOrElse(""))
      .getBytes(StandardCharsets.UTF_8)

  /** This proxy's member of the Proxy-Status field. */
  val ProxyStatusMember = "ko-agent-egress-proxy"

  /**
   * RFC 9209's response field, on every response that this proxy generates itself and on none that it relays.
   *
   * - `error` is the registered proxy error type, which also tells a client that the origin did not send this
   *   response. `details` is the audit line's `<why>`.
   * - The status goes in a header, because clients that discard a failed CONNECT's body still show its header
   *   section (`curl -v`). The run-on-host supervisor reads the header too (RunOnHostProxy.unwritableProxyLog).
   * - A Structured Fields String holds printable ASCII alone, so any other character is sent as `?`.
   */
  def proxyStatus(proxyError: String, detail: Option[String]): String =
    val details = detail.map: text =>
      val printable = text.map(char => if char >= ' ' && char <= '~' then char else '?')
      "; details=\"" + printable.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    s"$ProxyStatusMember; error=$proxyError${details.getOrElse("")}"

  /** The `details` of a Proxy-Status line proxyStatus wrote, unescaped, or None for any other line. */
  def proxyStatusDetails(line: String): Option[String] =
    line match
      case ProxyStatusDetails(details) => Some(details.replaceAll(raw"\\(.)", "$1"))
      case _                           => None

  private val ProxyStatusDetails = raw"""(?i)Proxy-Status:.*; details="((?:[^"\\]|\\.)*)".*""".r

  /** The RFC 9209 proxy error type of a failure on the origin leg of an inspected connection,
    * after the origin's address accepted the connection. */
  def originProxyError(ex: IOException): String =
    def certificate(cause: Throwable): Boolean =
      cause != null && (cause.isInstanceOf[java.security.cert.CertificateException] || certificate(cause.getCause))
    ex match
      case _: javax.net.ssl.SSLException if certificate(ex) => "tls_certificate_error"
      case _: javax.net.ssl.SSLException                    => "tls_protocol_error"
      case _: java.net.SocketTimeoutException               => "http_response_timeout"
      case _: SocketException                               => "connection_terminated"
      case _                                                => "http_protocol_error"

  /** Starts the reason of every refusal after a failed log write; the run-on-host supervisor looks for it. */
  val AuditLogUnwritable = "audit log cannot be written"

  def auditLogFailure(ex: IOException): String = s"$AuditLogUnwritable: ${ex.getMessage}"
