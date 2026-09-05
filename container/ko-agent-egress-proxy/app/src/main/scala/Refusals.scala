// What a refused or failed connection is told, and the typed reasons the handlers sort by: the
// exception per stage, and RefusalAdvice's table of next steps.

package agentsandbox.egress

case class BadRequest(message: String) extends RuntimeException(message)

/** A connection that closed after zero bytes: routine pooled-client behavior after admission,
  * logged as `error`; the ruleset refused nothing (SECURITY.md, "The audit line grammar"). */
case class ClosedWithoutRequest() extends RuntimeException("closed without sending a request")

/** An origin EOF where response framing promised more. Distinct from IOException because the
  * response head has already been forwarded by then: no 502 can follow, and the handler must end
  * the client connection abortively so the stump cannot read as a completed response. */
case class TruncatedResponse(message: String) extends RuntimeException(message)

/** A refusal the ruleset made, told to the refused party as a 403 body of two lines
  * (HTTPHelper.refusalBody): `message` is the audit line's `<why>`, `advice` the next step,
  * RefusalAdvice's. Both are required, so no refusal site can ship without its step. */
case class Refusal(message: String, advice: String) extends RuntimeException(message)

/**
 * The next step each refusal names for the agent reading the 403 body inside the sandbox: a step it
 * can take there, or the one thing to tell the user. Never a way around the ruleset, and never a
 * host this session's ruleset does not admit — forRefusedPost checks before naming one. Fixed text
 * plus what the request itself named, so a body never carries project data or a credential. This
 * object is the whole table, one member per refusal; the audit line keeps the short reason alone.
 */
object RefusalAdvice:
  /** The step depends on why the host is refused. The rule file's allow lines count under
    * deny-unless-allowed alone (resolveRuleset), so under deny-all or deny-unless-model the step is
    * a relaunch — named as necessary, never as sufficient: this session's resolution says nothing
    * about what that profile would apply from the project's file, a denial of this very host
    * included. A defaults host reaches this refusal under the default profile only through `deny
    * defaults` — a host a deny line emptied is refused as denied, naming the line — so the step
    * names that. allow-unless-denied never reaches this refusal. */
  def hostNotAllowed(host: String, profile: String): String =
    val default = RulesetHelper.DefaultProfile
    val defaults = RulesetHelper.DefaultHosts.contains(host)
    val addition = s"'allow https://$host/ read' in .ko-agent-sandbox/egress/rule"
    if profile == default then
      if defaults then
        "This project's rule file starts from deny defaults and does not allow it. Ask the user; do not look " +
          "for another route."
      else s"Not in this session's egress rules. Ask the user to add $addition on the host."
    else
      s"This session's egress profile, $profile, admits no project hosts. Ask the user; a relaunch under " +
        (if defaults then s"$default can admit it." else s"$default with $addition can admit it.")

  // The line is on the body's first line already (`host denied (<line>)`); a `**.domain` pattern
  // repeated here would name a host the ruleset does not admit.
  val hostDenied = "Denied by this project's rules. Ask the user; do not look for another route."

  val port = "Only port 443 is reachable."

  val ipLiteral = "Connect by hostname; addresses are refused."

  val nonPublicAddress = "This name resolves to an address the sandbox never reaches. Ask the user."

  val gitPush = "Push is refused in the sandbox. Leave the commits; the user pushes on the host."

  val gitFetch = "Clone and fetch are refused here: no git-fetch grant. Ask the user; do not look for another route."

  val noRead = "This host is not readable here: no read grant. Ask the user; do not look for another route."

  val graphql = "GraphQL is a POST. Read through the REST API."

  /** Where GitHub serves LFS file contents read-only, one URL per file (SECURITY.md, "Reading
    * without being able to write"). Named in advice only while the ruleset admits it. */
  val LfsContentHost = "media.githubusercontent.com"

  val lfsBatchGithub =
    s"LFS batch is refused. Read one file from https://$LfsContentHost/media/<owner>/<repo>/<ref>/<path>."

  val lfsBatch = "LFS batch is refused, and no admitted host serves this forge's LFS content. Ask the user."

  val readOnly = "This host grants no such write here. Do the write on the host."

  val requestBody = "A read carries no body. Send the request without one."

  val upgrade = "WebSockets and HTTP/2 upgrades are refused. Use a plain request."

  val originForm = "Send the path, not the absolute URL."

  val hostHeader = "The Host header must name the host the tunnel was opened to."

  val ambiguousPath = "Spell the path without percent-encoding, dot segments, backslashes or empty segments."

  /** The paths are the ruleset's own words for this host, so naming them names nothing new. */
  def pathOutside(paths: Set[String]): String =
    s"This host is admitted under ${paths.toVector.sorted.mkString(" and ")} only. " +
      "Ask the user; do not look for another route."

  /** The ClientHello stage answers after the 200, so this reaches no client; the agent
    * instructions have the sentence. Given all the same: the constructor requires a step. */
  val clientHello = "Send SNI naming the CONNECT host, without Encrypted ClientHello."

  /** Chosen by the path the request named — parsed by this proxy, never read from a body — so the
    * two POSTs whose refusal costs a read get the read's other route: GraphQL (`/graphql` on
    * GitHub, `/api/graphql` on GitLab) and the LFS batch endpoint. */
  def forRefusedPost(host: String, path: String, admitted: String => Boolean): String =
    if path.endsWith("/graphql") then graphql
    else if path.endsWith("/info/lfs/objects/batch") then
      if host == "github.com" && admitted(LfsContentHost) then lfsBatchGithub else lfsBatch
    else readOnly

case class BadTls(message: String) extends RuntimeException(message)
