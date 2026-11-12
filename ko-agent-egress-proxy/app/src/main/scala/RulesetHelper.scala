// The egress rules. This file holds:
//
// - the grammar and the launcher-owned defaults;
// - the ordered resolution that turns them into the ruleset a profile enforces;
// - the lines that print the ruleset;
// - the decisions made against the ruleset, at the CONNECT and inside an inspected tunnel.
//
// Everything here is pure: nothing reads a socket or the environment. So the launcher runs the same code for its dry
// run (--print-ruleset), and the tests resolve rulesets by the thousand.

package agentsandbox.egress

import GitHelper.*
import HTTPHelper.*
import IPAddrHelper.*

object RulesetHelper:
  /*
   * A rule is a line of the workspace's `rule` file. The ruleset is what a launch enforces: the defaults, the
   * profile and the file resolved together (resolveRuleset).
   *
   * - A line grants exactly its words, under the path it names, and nothing else on the host.
   * - The lines apply in the order written over the defaults, as in PF's and relayd's model:
   *   - an `allow` adds its grants at its path;
   *   - a `deny` takes the grants it names from every scope on the hosts it matches;
   *   - for each grant, the last applicable line decides.
   * - A `deny` names a host or a subtree, never a path. A grant by path needs one spelling that works, while a
   *   denial by path needs every spelling that reaches the tenant, and a proxy that compares literally cannot know
   *   them all (SECURITY.md, "Adding hosts, not patterns"). The restrictive ordering therefore puts a host-wide
   *   deny before the narrower allow, which fails closed.
   *
   * An allowed request can carry sandbox data: even a permitted GET carries its URL. A host gets one of two
   * treatments:
   *
   * - `tunnel`: the application traffic stays opaque after the TLS identity check;
   * - inspected: TLS is terminated, and each request is decided against the resolved scope of its longest literal
   *   match (authorizeInspectedRequest).
   *
   * SECURITY.md defines the handshake checks and the audit events for both treatments.
   *
   * The selected profile decides which lines count (resolveRuleset): the defaults, modified by the workspace's
   * file. The defaults are every provider's default rules plus the inspected catalog. The proxy prints the ruleset
   * in force at startup and logs every denial, which is how you find out what an agent actually wanted.
   *
   * The launcher supplies the inspection material. AgentEgressProxy.loadInspection defines the standalone image's
   * requirements and refusals (SECURITY.md, "Who holds the CA key").
   */

  /** The grant words: what a line says after its URL. A method is its own word in the set, and `method=POST,PUT`
    * expands to two words. */
  object Grant:
    val Read = "read"
    val GitFetch = "git-fetch"
    val Tunnel = "tunnel"
    val Methods: Vector[String] = Vector("POST", "PUT", "PATCH", "DELETE")
    // A WebSocket handshake at the line's path, and the stream after a checked 101 (relayInspected). `websocket` is
    // the only value: cleartext HTTP/2 would turn the one request into requests that the proxy does not read.
    val WebSocket = "upgrade=websocket"
    val Forms = "read, git-fetch, method=M,..., upgrade=websocket, tunnel"

    def isInspected(grants: Set[String]): Boolean = grants.exists(_ != Tunnel)

    /** The words after the URL, in the grammar's order: read, git-fetch, method=…, upgrade=websocket, tunnel. */
    def spelled(grants: Set[String]): String =
      val methods = Methods.filter(grants)
      (Option.when(grants(Read))(Read).toVector
        ++ Option.when(grants(GitFetch))(GitFetch)
        ++ Option.when(methods.nonEmpty)("method=" + methods.mkString(","))
        ++ Option.when(grants(WebSocket))(WebSocket)
        ++ Option.when(grants(Tunnel))(Tunnel)).mkString(" ")

    /** Every grant word, in the grammar's order, a method standing for its own word. */
    val InOrder: Vector[String] = Vector(Read, GitFetch) ++ Methods ++ Vector(WebSocket, Tunnel)

  /** What a `deny` names: an exact host, or the apex and everything under it. */
  enum HostPattern:
    case Exact(host: String)
    case Subtree(base: String)

    def matches(host: String): Boolean = this match
      case Exact(h) => host == h
      // The pattern's own dot is the label boundary: `**.foo.com` covers foo.com and api.foo.com, never barfoo.com.
      case Subtree(b) => host == b || host.endsWith("." + b)

    def spelled: String = this match
      case Exact(h)   => h
      case Subtree(b) => s"**.$b"

  enum Rule:
    case DenyDefaults
    case Allow(host: String, path: String, grants: Set[String])
    case AllowProvider(name: String)
    case Deny(pattern: HostPattern, grants: Set[String])
    case DenyProvider(name: String)

  /** One parsed line, with the file that holds it and its text as written, tokens joined by one space. The file is
    * `rule` for the workspace's file, and `defaults/…` for the launcher-owned files. */
  case class Line(file: String, text: String, rule: Rule):
    def spelled: String = s"$file: $text"

  val RuleFile = "rule"

  /** The workspace's rule directory and file, relative to the workspace root, as messages name them. */
  val WorkspaceRuleDirectory = ".ko-agent-sandbox/egress"
  val WorkspaceRuleFile = s"$WorkspaceRuleDirectory/$RuleFile"

  /** How every allow line of a URL begins, as the parser reads it and the ruleset lines print it. */
  val AllowLineHead = "allow https://"

  def allowLine(host: String, path: String, grants: String): String = s"$AllowLineHead$host$path $grants"

  /** The line that grants a whole host for reading: the form every refusal and launch message suggests. */
  def hostReadLine(host: String): String = allowLine(host, RulePath.Root, Grant.Read)

  val RuleVariable = "EGRESS_RULE"

  val ProfileVariable = "EGRESS_PROFILE"
  val ModelProviderVariable = "EGRESS_MODEL_PROVIDER"

  /** The egress profiles, narrowest to widest. An unset EGRESS_PROFILE means deny-unless-allowed: the
    * launcher-owned defaults, where every line is inspected or names a model provider's own endpoints. So the
    * default is useful without opening the open internet. */
  val DenyAll = "deny-all"
  val DenyUnlessModel = "deny-unless-model"
  val DenyUnlessAllowed = "deny-unless-allowed"
  val Profiles = Vector(DenyAll, DenyUnlessModel, DenyUnlessAllowed)
  val DefaultProfile = DenyUnlessAllowed

  val ModelProviders: Vector[String] = Vector("anthropic", "openai", "google", "aws", "github")

  /** The providers that an EGRESS_MODEL_PROVIDER value selects, in the value's order, each once. The value is the
    * launcher's `--model-provider` value as written, provider names separated by commas. An unset or empty value
    * selects none.
    *
    * - This file alone defines the names, so the launcher keeps no list of providers.
    * - A name that the proxy does not define, an empty name beside a comma, or a name given twice is refused: a
    *   selection that half-parses would be a half-opened ruleset. */
  def selectedProviders(value: Option[String]): Vector[String] =
    value.filter(_.nonEmpty) match
      case None => Vector.empty
      case Some(spelled) =>
        val names = spelled.split(",", -1).toVector
        names.find(_.isEmpty).foreach: _ =>
          throw IllegalArgumentException(
            s"$ModelProviderVariable is '$spelled'; the value is provider names separated by commas",
          )
        names.diff(names.distinct).headOption.foreach: twice =>
          throw IllegalArgumentException(s"$ModelProviderVariable is '$spelled'; it names $twice twice")
        names.map(requireProvider(ModelProviderVariable, _))

  // ---------------------------------------------------------------------------
  // The grammar
  // ---------------------------------------------------------------------------

  private val GrammarForms =
    "deny defaults; allow https://HOST/PATH GRANT...; allow https://HOST/ tunnel; " +
      "allow model-provider NAME; deny https://HOST/ [GRANT...]; deny https://**.DOMAIN/ [GRANT...]; " +
      "deny model-provider NAME"

  /**
   * A file's lines as rules, in order.
   *
   * - Blank lines vanish. Tokens split on whitespace, never on a comma: a comma stays inside its token and fails
   *   validation instead of silently making two tokens.
   * - `#` starts a comment only at the start of a line or after whitespace. Inside a token, `#` is refused: cut
   *   there, `https://host/a#b` would read as `https://host/a`, a line that allows more than it says.
   * - `deny defaults` is the first line or absent. The file reads in the order that the words imply, and a `deny`
   *   above `deny defaults` would clear what the next line clears whole.
   * - A repeated line is no refusal. After an intervening line of the other action, the repeated line is the last
   *   word on its grants, and a repeat that changes nothing is warned about like any other line (contribute,
   *   take).
   */
  def parseRules(file: String, text: String): Vector[Line] =
    val lines = tokenized(file, text).map(tokens => Line(file, tokens.mkString(" "), parseRule(file, tokens)))
    lines.zipWithIndex.foreach: (line, index) =>
      if line.rule == Rule.DenyDefaults && index > 0 then
        throw IllegalArgumentException(
          s"${line.spelled} follows another line; deny defaults is the first line or absent",
        )
    lines

  /** A rule line's words: split on whitespace, up to the first word that starts with `#`.
    * The launcher reads its rule files with the same split (EgressRules.normalizeRuleText,
    * RunOnHostPrereqs.programRuleHosts). */
  def ruleTokens(line: String): Vector[String] =
    line.split("\\s+").toVector.filter(_.nonEmpty).takeWhile(!_.startsWith("#"))

  private def tokenized(file: String, text: String): Vector[Vector[String]] =
    text.linesIterator
      .map(ruleTokens)
      .filter(_.nonEmpty)
      .map: tokens =>
        tokens.find(_.contains('#')).foreach: token =>
          throw IllegalArgumentException(
            s"$file contains '$token', a token with '#' inside it; a comment starts at the " +
              "start of a line or after whitespace, and nothing else contains '#'",
          )
        tokens
      .toVector

  private def parseRule(file: String, tokens: Vector[String]): Rule =
    val text = tokens.mkString(" ")
    def refuse(problem: String): Nothing = throw IllegalArgumentException(s"$file: '$text' $problem")

    tokens match
      case Vector("deny", "defaults")              => Rule.DenyDefaults
      case "deny" +: "defaults" +: _               => refuse("takes no word after defaults")
      case Vector("allow", "model-provider", name) => Rule.AllowProvider(requireProvider(file, name))
      case Vector("deny", "model-provider", name)  => Rule.DenyProvider(requireProvider(file, name))
      case "allow" +: url +: words if url.startsWith("https://") =>
        val (authority, path) = splitUrl(refuse, url)
        if authority.startsWith("**.") then refuse("names a pattern; an allow names an exact host")
        val host = ruleHost(file, authority)
        val grants = parseGrants(refuse, words)
        if grants.isEmpty then refuse(s"names no grant; an allow line says what it grants: ${Grant.Forms}")
        if grants(Grant.Tunnel) && grants.size > 1 then
          refuse("puts tunnel beside another word; a tunnel has no path and no method to grant, so the word is " +
            "alone on its line")
        if grants(Grant.Tunnel) && path != RulePath.Root then refuse("gives a tunnel a path; a tunnel's URL ends at /")
        Rule.Allow(host, path, grants)
      case "deny" +: url +: words if url.startsWith("https://") =>
        val (authority, path) = splitUrl(refuse, url)
        if path != RulePath.Root then
          refuse("denies a path; a deny names a host or a subtree whole, and its URL ends at / (SECURITY.md, " +
            "\"Adding hosts, not patterns\")")
        val pattern =
          if authority.startsWith("**.") then HostPattern.Subtree(ruleHost(file, authority.drop(3)))
          else HostPattern.Exact(ruleHost(file, authority))
        Rule.Deny(pattern, parseGrants(refuse, words))
      case _ => refuse(s"is no line of the rule grammar: $GrammarForms")

  /** The URL's host part and path, with the scheme literal `https://` already seen. The refusals name what a rule
    * cannot name (a port, userinfo, a query) and a path outside canonical form (RulePath.literalPathProblem). */
  private def splitUrl(refuse: String => Nothing, url: String): (String, String) =
    val rest = url.drop("https://".length)
    val slash = rest.indexOf('/')
    if slash < 0 then refuse("has no / after its host; a path begins at /, the root being https://HOST/")
    val authority = rest.take(slash)
    val path = rest.drop(slash)
    if authority.isEmpty then refuse("names no host")
    Vector('@' -> "userinfo", ':' -> "a port", '[' -> "a bracket", ']' -> "a bracket").foreach: (ch, what) =>
      if authority.contains(ch) then refuse(s"carries $what in its host; a rule names an exact hostname on port 443")
    if path.contains('?') then refuse("has a query; a rule names a path, never a query")
    RulePath.literalPathProblem(path).foreach: problem =>
      refuse(s"has $problem in its path; a path is written in canonical form, as doc/egress-proxy.md gives it")
    (authority, path)

  private def parseGrants(refuse: String => Nothing, words: Vector[String]): Set[String] =
    if words.count(_.startsWith("method=")) > 1 then refuse("names method= twice; one word lists the methods")
    words.foldLeft(Set.empty[String]): (grants, word) =>
      val named: Vector[String] = word match
        case Grant.Read | Grant.GitFetch | Grant.WebSocket | Grant.Tunnel => Vector(word)
        case _ if word.startsWith("upgrade=") =>
          refuse(s"names the upgrade '${word.drop("upgrade=".length)}'; ${Grant.WebSocket} is the only upgrade")
        case _ if word.startsWith("method=") =>
          val methods = word.drop("method=".length).split(",", -1).toVector
          methods.foreach: method =>
            if !Grant.Methods.contains(method) then
              refuse(s"names the method '$method'; the methods are ${Grant.Methods.mkString(", ")}")
          methods.diff(methods.distinct).headOption.foreach(twice => refuse(s"names $twice twice"))
          methods
        case _ => refuse(s"has the word '$word', which is no grant; the grants are ${Grant.Forms}")
      named.find(grants).foreach(twice => refuse(s"names $twice twice"))
      grants ++ named

  private def requireProvider(file: String, name: String): String =
    if !ModelProviders.contains(name) then
      throw IllegalArgumentException(
        s"$file names the model provider '$name', which this proxy does not define; " +
          s"the providers are ${ModelProviders.sorted.mkString(", ")}",
      )
    name

  private def ruleHost(file: String, spelled: String): String =
    val host =
      try normalizeHost(spelled)
      catch
        case ex: BadRequest =>
          throw IllegalArgumentException(s"$file contains an invalid hostname '$spelled': ${ex.getMessage}")
    if isIpLiteral(host) then
      throw IllegalArgumentException(s"$file contains an IP literal '$spelled'; only hostnames are allowed")
    host

  // ---------------------------------------------------------------------------
  // The defaults
  // ---------------------------------------------------------------------------

  /**
   * The defaults are rules, so they are written as rules: resource files in the grammar, read through the parser
   * that a workspace's file goes through, with the reasoning for each host as a comment beside it.
   *
   * - `defaults/host` lists inspected hosts.
   * - `defaults/model-provider/<name>` supplies the rules for `allow model-provider <name>`. Provider rules cover
   *   model, authentication and control-plane endpoints, including GitHub's inspected login and token paths and
   *   Google's inspected account reads. SECURITY.md, "What is inside TLS", explains why the model endpoints are
   *   not inspected.
   *
   * A defaults file holds `allow https://` lines and nothing else, and the catalog holds no tunnel. Either
   * violation refuses the start rather than silently narrowing the ruleset. So the image's own --print-ruleset (the
   * launcher's dry run) reports a malformed defaults file.
   */
  private def readDefault(name: String): Vector[Line] =
    val file = s"defaults/$name"
    val stream = getClass.getResourceAsStream(s"/defaults/$name")
    if stream == null then throw IllegalStateException(s"the defaults file $file is missing from the proxy jar")
    val text =
      try String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
      finally stream.close()
    val lines = parseRules(file, text)
    lines.foreach: line =>
      line.rule match
        case Rule.Allow(_, _, _) => ()
        case _ =>
          throw IllegalStateException(
            s"$file contains '${line.text}'; a defaults file holds allow https:// lines only",
          )
    lines

  val CatalogLines: Vector[Line] =
    val lines = readDefault("host")
    lines.foreach: line =>
      line.rule match
        case Rule.Allow(host, _, grants) if grants(Grant.Tunnel) =>
          throw IllegalStateException(
            s"defaults/host makes $host a tunnel; this file accepts inspected rules only. " +
              "Put model-endpoint tunnel rules in defaults/model-provider/<name>.",
          )
        case _ => ()
    lines

  val ModelProviderLines: Map[String, Vector[Line]] =
    ModelProviders.map(name => name -> readDefault(s"model-provider/$name")).toMap

  private def contributionOf(line: Line, source: Source): Contribution =
    line.rule match
      case Rule.Allow(host, path, grants) => Contribution(host, path, grants, source)
      case other => throw IllegalStateException(s"${line.spelled} is no allow line: $other")

  private def providerContributions(name: String, via: Option[Line]): Vector[Contribution] =
    ModelProviderLines(name).map(line => contributionOf(line, Source(line, via)))

  private val DefaultContributions: Vector[Contribution] =
    CatalogLines.map(line => contributionOf(line, Source(line, None)))
      ++ ModelProviders.flatMap(name => providerContributions(name, None))

  /** The launcher-owned defaults resolved whole, every provider included. deny-unless-allowed enforces these with
    * every provider selected and no workspace rule file, and every file is validated over them. */
  val DefaultHosts: Map[String, Treatment] = hostsOf(start(DefaultContributions))

  /** What a launch starts from under deny-unless-allowed: the catalog and the selected providers'
    * rules. */
  private def launchDefaults(selected: Vector[String]): Vector[Contribution] =
    CatalogLines.map(line => contributionOf(line, Source(line, None)))
      ++ selected.flatMap(name => providerContributions(name, None))

  // ---------------------------------------------------------------------------
  // Resolution
  // ---------------------------------------------------------------------------

  enum Treatment:
    /** TLS-inspected. `scopes` is the host's table of resolved states by path, and the table is cumulative: a
      * scope's grants are the union of every line whose path contains the scope.
      *
      * - A request looks up its longest literal match (authorizeInspectedRequest).
      * - A host without a root scope refuses every request outside its scopes. */
    case Inspected(scopes: Map[String, Set[String]])
    case Tunnel

  /** Keeps both the default rule and the workspace rule that included it, for diagnostics. */
  private case class Source(line: Line, via: Option[Line]):
    def spelled: String = via.fold(line.spelled)(expanded => s"${expanded.spelled} (${line.spelled})")

    def fromRule: Boolean = via.exists(_.file == RuleFile) || line.file == RuleFile

  /** One allow line's active grants at its path. A contribution that denies emptied stays in the state as the
    * boundary that its path opened: a line is a boundary as well as a grant. */
  private case class Contribution(
    host: String,
    path: String,
    grants: Set[String],
    source: Source,
  ):
    def active: Boolean = grants.nonEmpty

  private case class State(
    contributions: Vector[Contribution] = Vector.empty,
    patterns: Vector[(HostPattern, Line)] = Vector.empty,
    removals: Map[String, Vector[Line]] = Map.empty,
    warnings: Vector[String] = Vector.empty,
  ):
    def active: Vector[Contribution] = contributions.filter(_.active)

    def touched: Set[String] = contributions.map(_.host).toSet

    /** The resolved grants at `path` on `host` in the current state: what a line there adds to. */
    def enclosing(host: String, path: String): Set[String] =
      active.filter(c => c.host == host && RulePath.contains(c.path, path)).flatMap(_.grants).toSet

  private def start(contributions: Vector[Contribution]): State =
    contributions.foldLeft(State())((state, contribution) => contribute(state, contribution, check = false))

  /**
   * An allow line's step. A host has one treatment, checked at each line.
   *
   * - The step refuses an inspected grant added to a host that holds `tunnel`, and `tunnel` added to a host that
   *   holds an inspected grant. The refusal names the deny that would clear the way.
   * - With `check`, the step warns about a workspace line that grants nothing its enclosing scope lacks: a
   *   redundant grant whose path still defines a boundary.
   *   - No warning comes when a defaults line at the same path already grants the same words. That restatement is
   *     how a file stays valid as the image adopts its hosts.
   */
  private def contribute(state: State, contribution: Contribution, check: Boolean): State =
    val Contribution(host, path, grants, source) = contribution
    val activeOnHost = state.active.filter(_.host == host)
    val tunnels = activeOnHost.filter(_.grants(Grant.Tunnel))
    val inspected = activeOnHost.filter(c => Grant.isInspected(c.grants))
    if grants(Grant.Tunnel) && inspected.nonEmpty then
      throw IllegalArgumentException(
        s"${source.spelled} makes $host a tunnel while it holds ${inspected.map(_.source.spelled).mkString("; ")}; " +
          s"a host has one treatment: deny https://$host/ first, or drop the line",
      )
    if Grant.isInspected(grants) && tunnels.nonEmpty then
      throw IllegalArgumentException(
        s"${source.spelled} inspects $host while it is a tunnel (${tunnels.map(_.source.spelled).mkString("; ")}); " +
          s"a host has one treatment: deny https://$host/ tunnel first, or drop the line",
      )
    val warning =
      if !check || !grants.subsetOf(state.enclosing(host, path)) then None
      else
        val restated = activeOnHost.exists(c => c.path == path && !c.source.fromRule && grants.subsetOf(c.grants))
        Option.when(!restated)(
          s"${source.spelled} grants nothing its enclosing scope lacks at its position; to narrow, take the " +
            s"grants first: deny https://$host/ ${Grant.spelled(grants)}, then this line",
        )
    state.copy(contributions = state.contributions :+ contribution, warnings = state.warnings ++ warning)

  /** A URL deny's step: the grants it names, or every grant, are taken from each contribution on the hosts it
    * matches, whichever line gave them. A whole-host or `read` deny is also kept as a pattern, so that the refusal
    * of a host beneath the pattern can name the deny (Provenance.denialOf). */
  private def take(state: State, pattern: HostPattern, grants: Set[String], line: Line): State =
    val (contributions, hit) =
      state.contributions.foldLeft((Vector.empty[Contribution], Set.empty[String])):
        case ((kept, hit), c) =>
          val left = if grants.isEmpty then Set.empty[String] else c.grants -- grants
          if c.active && pattern.matches(c.host) && left != c.grants then (kept :+ c.copy(grants = left), hit + c.host)
          else (kept :+ c, hit)
    val warning = Option.when(hit.isEmpty)(s"${line.spelled} matches nothing at its position")
    val patterns =
      if grants.isEmpty || grants(Grant.Read) then state.patterns :+ (pattern -> line) else state.patterns
    State(contributions, patterns, recordRemovals(state.removals, hit, line), state.warnings ++ warning)

  /** A provider denial removes earlier grants on its hosts regardless of which line supplied them. The expanded
    * denials and any no-op warning are attributed to the single provider line. */
  private def takeProvider(state: State, name: String, line: Line): State =
    val hosts = ModelProviderLines(name).collect { case Line(_, _, Rule.Allow(host, _, _)) => host }.distinct
    val denied = hosts.foldLeft(state): (current, host) =>
      take(current, HostPattern.Exact(host), Set.empty, line)
    val warning = Option.when(!state.active.exists(contribution => hosts.contains(contribution.host)))(
      s"${line.spelled} matches nothing at its position",
    )
    denied.copy(warnings = state.warnings ++ warning)

  private def recordRemovals(
    removals: Map[String, Vector[Line]],
    hosts: Set[String],
    line: Line,
  ): Map[String, Vector[Line]] =
    hosts.foldLeft(removals)((current, host) => current.updated(host, current.getOrElse(host, Vector.empty) :+ line))

  private def step(state: State, line: Line, consult: Rule => Boolean, check: Boolean): State =
    if !consult(line.rule) then state
    else
      line.rule match
        case Rule.DenyDefaults => state
        case Rule.Allow(host, path, grants) =>
          contribute(state, Contribution(host, path, grants, Source(line, None)), check)
        case Rule.AllowProvider(name) =>
          providerContributions(name, Some(line))
            .filter(c => consult(Rule.Allow(c.host, c.path, c.grants)))
            .foldLeft(state)((current, c) => contribute(current, c, check))
        case Rule.Deny(pattern, grants) => take(state, pattern, grants, line)
        case Rule.DenyProvider(name)    => takeProvider(state, name, line)

  /** The host map that a state resolves to.
    *
    * - A host that holds `tunnel` is opaque.
    * - Otherwise, the host has one scope per path that any of its lines opened, boundaries of emptied lines
    *   included. Each scope holds the union of the active lines that contain it.
    * - A scope that holds nothing is dropped. Its enclosing scope is empty too, so every request under it is refused
    *   with or without the boundary.
    * - A host with no active line is not in the map: the host is denied whole.
    *
    * This table compiles the ordered lines, like PF's skip steps. The longest match that a request looks up selects
    * a state that the order already settled, never a precedence among lines. A change here must keep
    * HostileInputTest's plain ordered evaluator agreeing with this table (doc/design.md, "No richer rule format"). */
  private def hostsOf(state: State): Map[String, Treatment] =
    val active = state.active
    active.groupBy(_.host).map: (host, held) =>
      if held.exists(_.grants(Grant.Tunnel)) then host -> Treatment.Tunnel
      else
        val paths = state.contributions.filter(_.host == host).map(_.path).distinct
        val scopes = paths
          .map(path => path -> held.filter(c => RulePath.contains(c.path, path)).flatMap(_.grants).toSet)
          .filter((_, grants) => grants.nonEmpty)
        host -> Treatment.Inspected(scopes.toMap)

  /**
   * The ruleset in force: the whole of what enforcement reads, and the whole of what the digest names.
   *
   * - Equality of this structure is what "one ruleset" means. Two files that resolve to it print one digest and the
   *   same lines.
   * - The same file under two profiles never resolves to one ruleset, because the profile is part of the
   *   structure. So are the selected providers, under the two profiles where they change authority:
   *   deny-unless-model and deny-unless-allowed.
   * - The host map embodies every denial, and the structure keeps no denial of its own.
   */
  case class Ruleset(
    profile: String,
    provider: Option[String],
    hosts: Map[String, Treatment],
  ):
    val inspectedScopes: Map[String, Map[String, Set[String]]] =
      hosts.collect { case (host, Treatment.Inspected(scopes)) => host -> scopes }
    val tunnelHosts: Set[String] =
      hosts.collect { case (host, Treatment.Tunnel) => host }.toSet
    val inspected: Set[String] = inspectedScopes.keySet

    /** Whether a CONNECT to `host` is allowed: the host is on the map, whatever pattern covers it. An inspected
      * host that survives beneath a denied subtree is exactly what the map records. */
    def allows(host: String): Boolean = hosts.contains(host)

    /** An allowed inspected host's scopes. */
    def scopesOf(host: String): Map[String, Set[String]] = inspectedScopes.getOrElse(host, Map.empty)

  /** The sources behind a resolved scope: one set for its boundary, which is the lines at its exact path, and one
    * set per grant it holds, which is the contributions currently supplying that grant. A folded scope has no single
    * "source", so none is invented. */
  case class ScopeProvenance(boundary: Vector[String], grants: Map[String, Vector[String]])

  /**
   * Kept beside the ruleset, never in it: what the structure's equality must not see.
   *
   * - `scopes` has one entry per inspected scope.
   * - `patterns` has one entry per whole-host or `read` deny and per host that a deny emptied, under every profile.
   *   So a refusal can say `host denied (<line>)` where a file line matched the host.
   * - `widening` holds the workspace lines that grant beyond the defaults, for the summary line's count and
   *   `--egress-effective`'s listing. Such a line names a host the defaults lack, a grant the defaults lack at the
   *   line's path, or `deny defaults`.
   */
  case class Provenance(
    scopes: Map[(String, String), ScopeProvenance],
    patterns: Vector[(HostPattern, Vector[String])],
    widening: Vector[Line],
  ):
    /** The lines behind a host's denial, or none where the structure keeps no denial of it. */
    def denialOf(host: String): Option[Vector[String]] =
      val matched = patterns.collect { case (pattern, sources) if pattern.matches(host) => sources }.flatten.distinct
      Option.when(matched.nonEmpty)(matched)

  case class ResolvedEgress(
    ruleset: Ruleset,
    provenance: Provenance,
    warnings: Vector[String],
  ):
    export ruleset.{allows, hosts, inspected, inspectedScopes, profile, provider, scopesOf, tunnelHosts}

  /**
   * The variables resolved to the ruleset in force.
   *
   * Every profile runs the same fold, from its own start and consulting its own lines:
   *
   *   deny-all            = nothing
   *   deny-unless-model   = the selected providers' lines (selectedProviders) — then the file's
   *                         deny lines
   *   deny-unless-allowed = the catalog and the selected providers' lines — none after
   *                         `deny defaults` — then every line
   *
   * Refusals and warnings come from one further fold: every line over the whole defaults, every provider included.
   * So a file that is valid under one profile and selection is valid under every one.
   *
   * The internal-network denials of the security model are not rules here. The denials are IPAddrHelper's
   * address vetting, applied to every resolved destination at connection time, so no rule file can spell them away.
   *
   * The resolution fails closed on every ambiguity:
   *
   * - an unknown profile, provider, word or line form;
   * - a line outside canonical form;
   * - a resolved host that holds `tunnel` beside an inspected grant;
   * - a `tunnel` line for a host that the defaults inspect, without `deny defaults`.
   *
   * The resolution warns at every launch, under every profile, about:
   *
   * - a `deny` that matches nothing at its position, since a misspelled deny must not fail silently;
   * - a redundant grant;
   * - a line every grant of which a later line takes back;
   * - a selected provider's host that the resolved ruleset does not allow.
   *
   * An empty ruleset is valid and reported as such. deny-all resolves empty by design, as does deny-unless-model
   * with no provider selected. deny-unless-allowed with no provider selected is the catalog alone.
   */
  def resolveRuleset(
    profileValue: Option[String],
    providerValue: Option[String],
    ruleText: Option[String],
  ): ResolvedEgress =
    val profile = profileValue.getOrElse(DefaultProfile)
    if !Profiles.contains(profile) then
      throw IllegalArgumentException(s"$ProfileVariable is '$profile'; the profiles are ${Profiles.mkString(", ")}")
    val selected = selectedProviders(providerValue)
    val provider = Option.when(selected.nonEmpty)(selected.mkString(","))

    val lines = parseRules(RuleFile, ruleText.getOrElse(""))
    val clearsDefaults = lines.headOption.exists(_.rule == Rule.DenyDefaults)

    // The check for widening to a tunnel is global: it reads the defaults, not the file's state. An opaque tunnel
    // ends inspection and the audit record for a host that every workspace has.
    lines.foreach: line =>
      line.rule match
        case Rule.Allow(host, _, grants)
            if grants(Grant.Tunnel) && !clearsDefaults && DefaultHosts.get(host).exists(_ != Treatment.Tunnel) =>
          throw IllegalArgumentException(
            s"${line.spelled} makes $host an opaque tunnel, which the defaults inspect; a tunnel there takes " +
              "deny defaults as the first line and the whole ruleset after it",
          )
        case _ => ()

    val validated = lines.foldLeft(start(if clearsDefaults then Vector.empty else DefaultContributions)):
      (state, line) => step(state, line, _ => true, check = true)
    // Per file line, by reference: a repeated line is its own line, and a provider line's expanded
    // contributions all name it.
    val takenBack = lines.flatMap: line =>
      val own = validated.contributions.filter(c => c.source.via.getOrElse(c.source.line) eq line)
      Option.when(own.nonEmpty && own.forall(!_.active))(
        s"${line.spelled} grants nothing: every grant it names is taken back by a later line",
      )

    def isDeny(rule: Rule): Boolean = rule match
      case Rule.Deny(_, _) | Rule.DenyProvider(_) => true
      case _                                      => false

    val starting = if clearsDefaults then Vector.empty else launchDefaults(selected)
    val (initial, consult) = profile match
      case DenyAll           => (Vector.empty[Contribution], (_: Rule) => false)
      case DenyUnlessModel   => (selected.flatMap(providerContributions(_, None)), isDeny)
      case DenyUnlessAllowed => (starting, (_: Rule) => true)
    val enforced =
      if profile == DenyAll then State()
      else lines.foldLeft(start(initial))((state, line) => step(state, line, consult, check = false))

    val hosts = hostsOf(enforced)

    val emptied = (enforced.touched -- hosts.keySet).toVector.sorted
    val patterns: Vector[(HostPattern, Vector[String])] =
      (enforced.patterns.map((pattern, line) => pattern -> Vector(line.spelled))
        ++ emptied.map: host =>
          HostPattern.Exact(host) -> enforced.removals.getOrElse(host, Vector.empty).map(_.spelled))
        .groupMapReduce(_(0))(_(1))(_ ++ _)
        .toVector
        .map((pattern, sources) => pattern -> sources.distinct)
        .sortBy(_(0).spelled)

    val ruleset = Ruleset(profile, Option.when(profile != DenyAll)(provider).flatten, hosts)

    val scopes = hosts.toVector.flatMap: (host, treatment) =>
      val own = enforced.contributions.filter(_.host == host)
      val held = own.filter(_.active)
      val paths = treatment match
        case Treatment.Tunnel            => Vector(RulePath.Root)
        case Treatment.Inspected(scopes) => scopes.keys.toVector
      paths.map: path =>
        val boundary = treatment match
          case Treatment.Tunnel       => held.map(_.source.spelled)
          case Treatment.Inspected(_) => own.filter(_.path == path).map(_.source.spelled)
        val supplying = held.filter(c => RulePath.contains(c.path, path))
        val grants = supplying.flatMap(_.grants).distinct.map: grant =>
          grant -> supplying.filter(_.grants(grant)).map(_.source.spelled)
        (host, path) -> ScopeProvenance(boundary.distinct, grants.toMap)

    // Widening is measured against what this launch starts from, not the whole defaults. A provider that the launch
    // did not select is a new recipient for this session, however familiar its host.
    val launchHosts = hostsOf(start(launchDefaults(selected)))
    val widening =
      if profile != DenyUnlessAllowed then Vector.empty
      else
        lines.filter: line =>
          line.rule match
            case Rule.DenyDefaults => true
            case Rule.AllowProvider(name) => !selected.contains(name)
            case Rule.Allow(host, path, grants) =>
              launchHosts.get(host) match
                case None                   => true
                case Some(Treatment.Tunnel) => false
                case Some(Treatment.Inspected(scopes)) =>
                  // Scopes are cumulative, so a grant held at the line's path is held under all of it.
                  val held = RulePath.longestMatch(scopes.keys, path).fold(Set.empty[String])(scopes)
                  !grants.subsetOf(held)
            case _ => false

    val reachability =
      selected.flatMap: name =>
        val unreachable = ModelProviderLines(name).map(_.rule)
          .collect { case Rule.Allow(host, _, _) => host }
          .distinct.sorted
          .filterNot(hosts.contains)
        Option.when(unreachable.nonEmpty)(
          s"the selected model provider '$name' is not fully reachable under $profile: " +
            unreachable.mkString(" "),
        )

    ResolvedEgress(
      ruleset,
      Provenance(scopes.toMap, patterns, widening),
      validated.warnings ++ takenBack ++ reachability,
    )

  // ---------------------------------------------------------------------------
  // Output
  // ---------------------------------------------------------------------------

  /** One host's treatment as rule lines, one per scope: the form --check-host and the ruleset lines share. */
  def ruleLines(host: String, treatment: Treatment): Vector[String] = treatment match
    case Treatment.Tunnel => Vector(allowLine(host, RulePath.Root, Grant.Tunnel))
    case Treatment.Inspected(scopes) =>
      scopes.toVector.sortBy(_(0)).map((path, grants) => allowLine(host, path, Grant.spelled(grants)))

  /**
   * The ruleset, one line each, in the rule grammar, so a reader learns one grammar.
   *
   * - The lines are the deterministic serialization of Ruleset. The digest names the lines, --print-ruleset
   *   prints them, and serve() logs them identically. The launcher reads the leaf's names off the lines and exports
   *   the lines in KO_AGENT_SANDBOX_EGRESS_RULESET.
   * - The lines are a serialization, not a rule file: no `deny defaults` header, no promise to re-parse to the same
   *   lines, and nothing reads them as input.
   * - The profile line comes first, since the grammar alone cannot say "only this provider's default rules". One
   *   allow line per resolved scope follows, with its whole grant set, hosts and paths sorted.
   */
  def rulesetLines(resolved: ResolvedEgress): Vector[String] =
    val profileLine = resolved.profile match
      case DenyAll => s"$ProfileLineHead$DenyAll"
      case other   => s"$ProfileLineHead$other; $ModelProviderLabel${resolved.provider.getOrElse("none")}"
    profileLine +: resolved.hosts.toVector.sortBy(_(0)).flatMap(ruleLines)

  /** The fixed text the launcher matches in what rulesetLines and metadataLines print
    * (EgressRules): each line's start, and the provider's label inside the profile line. */
  val ProfileLineHead = "egress profile: "
  val ModelProviderLabel = "model provider: "
  val SummaryLineHead = "ruleset summary:"
  val InspectedHostsField = "inspected hosts"
  val TunnelHostsField = "tunnel hosts"
  val WideningLineHead = "widening lines ("

  /** The lines after the ruleset lines, outside the digest. They describe the ruleset's size and how the file
    * arrived at it, not the ruleset itself. The launcher splits the dry run's text at the first of these lines
    * (EgressRules.MetadataPrefixes). */
  def metadataLines(resolved: ResolvedEgress): Vector[String] =
    val summary =
      s"$SummaryLineHead ${resolved.inspected.size} $InspectedHostsField; " +
        s"${resolved.tunnelHosts.size} $TunnelHostsField; " +
        s"${resolved.provenance.widening.size} widening lines"
    summary +: wideningLine(resolved).toVector

  /** The workspace lines that reach past the defaults (Provenance.widening). The entries are lines, so `; `
    * separates them. */
  def wideningLine(resolved: ResolvedEgress): Option[String] =
    val widening = resolved.provenance.widening
    Option.when(widening.nonEmpty)(s"$WideningLineHead${widening.size}): " + widening.map(_.text).mkString("; "))

  /**
   * Each ruleset line followed by its sources: an allow line's boundary and each of its grants. Then come the hosts
   * that the file's lines denied, for which the structure keeps no line. `--print-ruleset --provenance` prints these
   * lines, and `--egress-effective` runs that command.
   */
  def provenanceLines(resolved: ResolvedEgress): Vector[String] =
    val provenance = resolved.provenance
    val allowLines = resolved.hosts.toVector.sortBy(_(0)).flatMap: (host, treatment) =>
      val paths = treatment match
        case Treatment.Tunnel       => Vector(RulePath.Root)
        case Treatment.Inspected(scopes) => scopes.keys.toVector.sorted
      paths.flatMap: path =>
        val scope = provenance.scopes((host, path))
        val grants = treatment match
          case Treatment.Tunnel       => Set(Grant.Tunnel)
          case Treatment.Inspected(scopes) => scopes(path)
        val grantLines = Grant.InOrder
          .filter(grants)
          .map(grant => s"  $grant: ${scope.grants.getOrElse(grant, Vector.empty).mkString("; ")}")
        Vector(allowLine(host, path, Grant.spelled(grants)), s"  boundary: ${scope.boundary.mkString("; ")}")
          ++ grantLines
    val deniedHosts =
      provenance.patterns.collect { case (HostPattern.Exact(host), sources) if !resolved.hosts.contains(host) =>
        s"  $host: denied by ${sources.mkString("; ")}"
      }
    Vector("provenance:") ++ allowLines
      ++ (if deniedHosts.nonEmpty then "denied hosts:" +: deniedHosts else Vector.empty)

  // ---------------------------------------------------------------------------
  // Enforcement
  // ---------------------------------------------------------------------------

  /**
   * The one check that every inspected request must pass.
   *
   * The check classifies the request once, into what it is: a read, fetch discovery, upload-pack, push discovery,
   * or a request that uses another method. The check vets the path for the boundary it falls in, and decides the
   * classification once against the resolved scope of the path's longest literal match:
   *
   * - GET and HEAD fall under `read`, bodyless.
   * - A WebSocket handshake falls under `upgrade=websocket` alone: a `GET` with one `Upgrade: websocket` and one
   *   `Sec-WebSocket-Key`, its path in canonical form under every line. Any other `Upgrade` is refused.
   * - Fetch discovery and upload-pack fall under `git-fetch` (GitHelper.isUploadPack), so a clone that could not
   *   transfer fails at its first request.
   * - Push discovery falls under a `POST` grant, where the push is the workspace's own grant.
   * - Other requests fall under their method grants. Those requests' paths are refused for spellings that a
   *   forge decodes first (RulePath.requireUnambiguousPath).
   *
   * The path's spelling:
   *
   * - Where the longest match is a line other than the root, the request is first refused, on every method, for
   *   any spelling that RulePath.literalPathProblem names. Under such a line, the path decides grants that the root
   *   does not give.
   * - Under the root, a read may carry `%`, since the read gains nothing by any decoding. The exception keeps
   *   npm's `/@scope%2fname` reading.
   * - A path in no scope is refused.
   *
   * Receive-pack transfer, the LFS batch endpoint and GraphQL stay refused where no line grants their method
   * (SECURITY.md, "Reading without being able to write").
   */
  def authorizeInspectedRequest(
    host: String,
    head: HttpRequestHead,
    scopes: Map[String, Set[String]],
    // Which hosts this session allows. The check consults the set only where a refusal's advice would name
    // another host (RefusalAdvice.forRefusedPost); the default allows none.
    allowed: String => Boolean = _ => false,
  ): Unit =
    if !head.target.startsWith("/") then
      throw Refusal("only origin-form request targets are allowed", RefusalAdvice.originForm)

    // A second header of either name is ambiguous, as a second framing header is: refused, not resolved.
    val webSocket = head.values("Upgrade") match
      case Vector()                                                                      => false
      case Vector(value) if value.equalsIgnoreCase("websocket") && head.method == "GET" => true
      case Vector(_) => throw Refusal("HTTP Upgrade is not allowed", RefusalAdvice.upgrade)
      case _         => throw BadRequest("duplicate Upgrade header")
    if webSocket && head.values("Sec-WebSocket-Key").size != 1 then
      throw BadRequest("a WebSocket handshake carries one Sec-WebSocket-Key")

    head.values("Host") match
      case Vector(value) =>
        val declared = normalizeHostHeader(value)

        if declared != host then
          throw Refusal(s"Host header $declared", RefusalAdvice.hostHeader)

      case Vector() => throw BadRequest("missing Host header")
      case _        => throw BadRequest("duplicate Host header")

    head.bodyFraming // throws when ambiguous

    val path = head.path
    val matched = RulePath.longestMatch(scopes.keys, path)
    val grants = matched match
      case Some(scope) => scopes(scope)
      case None        => throw Refusal("path under no line", RefusalAdvice.pathOutside(scopes.keySet))
    if matched.get != RulePath.Root then RulePath.requireLiteralPath(path)

    head.method match
      case "GET" | "HEAD" =>
        // A body on a read method would be an unbounded, unlogged client-to-server channel.
        if head.bodyFraming != BodyFraming.Empty then
          throw Refusal("request body framing header", RefusalAdvice.bodyFramingHeader)

        if webSocket then
          RulePath.requireLiteralPath(path)
          if !grants(Grant.WebSocket) then
            throw Refusal(s"${Grant.WebSocket} not granted", RefusalAdvice.webSocketNotGranted(host, path))
        else if isReceivePackDiscovery(head) then
          if !grants("POST") then throw Refusal("git push ref discovery", RefusalAdvice.gitPush)
        else if isUploadPackDiscovery(head) then
          if !grants(Grant.GitFetch) then throw Refusal("git fetch ref discovery", RefusalAdvice.gitFetch)
        else if !grants(Grant.Read) then
          throw Refusal("read not granted", RefusalAdvice.noRead)

      case method if Grant.Methods.contains(method) =>
        RulePath.requireUnambiguousPath(path)

        val opened = grants(method) || (method == "POST" && grants(Grant.GitFetch) && isUploadPack(path))
        if !opened then
          throw Refusal(
            s"$method not granted",
            if method == "POST" then RefusalAdvice.forRefusedPost(host, path, allowed)
            else RefusalAdvice.methodNotGranted,
          )

      case method =>
        throw Refusal(s"$method not granted", RefusalAdvice.methodNotGranted)

  /*
   * The IP-literal refusal is defence in depth: the map cannot contain an IP literal, and resolvePublic refuses
   * private answers. `Ruleset.allows` makes the decision.
   * The refusal's reason is presentation: `host denied (<line>)` from provenance where a file line matched the host,
   * and `host not allowed` otherwise.
   */
  def authorizeRequest(
    request: ConnectRequest,
    resolved: ResolvedEgress,
  ): String =
    if request.port != 443 then
      throw Refusal(s"port ${request.port}", RefusalAdvice.port)

    val host = normalizeHost(request.host)

    if isIpLiteral(host) then
      throw Refusal("IP-literal target", RefusalAdvice.ipLiteral)

    if !resolved.allows(host) then
      resolved.provenance.denialOf(host) match
        case Some(sources) =>
          throw Refusal(s"host denied (${sources.mkString("; ")})", RefusalAdvice.hostDenied)
        case None =>
          throw Refusal("host not allowed", RefusalAdvice.hostNotAllowed(host, resolved.profile))

    host
