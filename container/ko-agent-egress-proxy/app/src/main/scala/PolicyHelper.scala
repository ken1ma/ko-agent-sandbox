// The egress policy: the rule grammar, the launcher-owned defaults, the ordered resolution that
// turns them into the policy a profile enforces, the lines that print it, and the decisions made
// against it — at the CONNECT and inside an inspected tunnel. Pure: nothing here reads a socket or
// the environment, which is what lets the launcher run the same code for its dry run
// (--print-policy) and the tests resolve policies by the thousand.

package agentsandbox.egress

import GitHelper.*
import HTTPHelper.*
import IPAddrHelper.*

object PolicyHelper:
  /*
   * A rule is a line of the project's `rule` file; a policy is what a launch enforces — the
   * defaults, the profile and the file resolved together (resolvePolicy). Two words, kept apart.
   *
   * A line grants exactly its words, under the path it names, and nothing else on the
   * host. The lines apply in the order written over the defaults, PF's and relayd's model: an
   * `allow` adds its grants at its path, a `deny` takes the grants it names from every scope on
   * the hosts it matches, and for each grant the last applicable line decides. A `deny` names a
   * host or a subtree, never a path: a grant by path needs one spelling that works while a denial
   * by path needs every spelling that reaches the tenant, and a proxy comparing literally cannot
   * know them (SECURITY.md, "Adding hosts, not patterns"). The restrictive shape is therefore a
   * host-wide deny with the narrower allow beneath it, which fails closed.
   *
   * Every allowed host is a GET-based exfiltration channel: a permitted GET carries its URL, and a
   * URL is a message. A host's treatment is one of two — `tunnel`, an opaque tunnel with nothing
   * seen or logged past the CONNECT, or inspected: TLS terminated, each request decided against
   * the resolved scope of its longest literal match (authorizeInspectedRequest).
   *
   * Which lines count is the selected profile's answer (resolvePolicy): the defaults — every
   * model-provider group plus the curated catalog — modified by the project's file. Whichever
   * policy is in force is printed at startup and every denial is logged, which is how you find out
   * what an agent actually wanted.
   *
   * Inspection is off unless the launcher supplies a certificate and key; the leaf must name
   * exactly the resolved inspected hosts (SECURITY.md, "Who holds the CA key").
   */

  /** The grant words: what a line says after its URL. A method is its own word in the set,
    * `method=POST,PUT` expanding to two. */
  object Grant:
    val Read = "read"
    val GitFetch = "git-fetch"
    val Tunnel = "tunnel"
    val Methods: Vector[String] = Vector("POST", "PUT", "PATCH", "DELETE")
    val Forms = "read, git-fetch, method=M,..., tunnel"

    def isInspected(grants: Set[String]): Boolean = grants.exists(_ != Tunnel)

    /** The words after the URL, in the grammar's order: read, git-fetch, method=…, tunnel. */
    def spelled(grants: Set[String]): String =
      val methods = Methods.filter(grants)
      (Option.when(grants(Read))(Read).toVector
        ++ Option.when(grants(GitFetch))(GitFetch)
        ++ Option.when(methods.nonEmpty)("method=" + methods.mkString(","))
        ++ Option.when(grants(Tunnel))(Tunnel)).mkString(" ")

  /** A rule's path: `/` the root, a trailing `/` a tree, none one exact path. */
  object RulePath:
    val Root = "/"

    /** Whether `path` names `request`: a tree by prefix, an exact path by equality. */
    def contains(path: String, request: String): Boolean =
      if path.endsWith("/") then request.startsWith(path) else request == path

  /** What a `deny` names: an exact host, or the apex and everything under it. */
  enum HostPattern:
    case Exact(host: String)
    case Subtree(base: String)

    def matches(host: String): Boolean = this match
      case Exact(h) => host == h
      // The pattern's own dot is the label boundary: `**.foo.com` covers foo.com and api.foo.com, never barfoo.com.
      case Subtree(b) => host == b || host.endsWith("." + b)

    /** Whether every host this pattern matches, `other` matches too. */
    def within(other: HostPattern): Boolean = (this, other) match
      case (Exact(h), _)               => other.matches(h)
      case (Subtree(b), Subtree(wide)) => b == wide || b.endsWith("." + wide)
      case (Subtree(_), Exact(_))      => false

    def spelled: String = this match
      case Exact(h)   => h
      case Subtree(b) => s"**.$b"

  enum Rule:
    case DenyDefaults
    case Allow(host: String, path: String, grants: Set[String])
    case AllowGroup(name: String)
    case Deny(pattern: HostPattern, grants: Set[String])
    case DenyGroup(name: String)

  /** One parsed line, with where it was written — `rule` for the project's file, `defaults/…` for
    * the launcher-owned files — and its text as written, tokens joined by one space. */
  case class Line(origin: String, text: String, rule: Rule):
    def spelled: String = s"$origin: $text"

  val RuleOrigin = "rule"
  val RuleVariable = "EGRESS_RULE"

  /** The variables of the grammar this one replaced: set, a refused start naming RuleVariable, so a
    * wrapper composing the old grammar fails rather than starting on the defaults alone. */
  val RetiredVariables: Vector[String] = Vector("EGRESS_ALLOWED", "EGRESS_DENIED")

  val ProfileVariable = "EGRESS_PROFILE"
  val ModelProviderVariable = "EGRESS_MODEL_PROVIDER"

  /** The authority profiles, weakest-to-widest; deny-unless-allowed is what an unset
    * EGRESS_PROFILE means — the launcher-owned defaults, every line inspected or a model
    * provider's own endpoints, so the default is useful without opening the open internet. */
  val Profiles = Vector("deny-all", "deny-unless-model", "deny-unless-allowed", "allow-unless-denied")
  val DefaultProfile = "deny-unless-allowed"

  val ModelProviders: Vector[String] = Vector("anthropic", "openai", "google", "github")

  // ---------------------------------------------------------------------------
  // The grammar
  // ---------------------------------------------------------------------------

  private val GrammarForms =
    "deny defaults; allow https://HOST/PATH GRANT...; allow https://HOST/ tunnel; " +
      "allow model-provider NAME; deny https://HOST/ [GRANT...]; deny https://**.DOMAIN/ [GRANT...]; " +
      "deny model-provider NAME"

  /**
   * A file's lines as rules, in order. Blank lines vanish, tokens split on whitespace — never comma,
   * which stays inside its token and fails validation instead of silently becoming two — and `#`
   * starts a comment at the start of a line or after whitespace only. Inside a token it is refused:
   * cut there, `https://host/a#b` would read as `https://host/a`, a line admitting more than it
   * says. `deny defaults` is the first line or absent: the file reads in the order the words imply,
   * and a `deny` above it would clear what the next line clears whole. A repeated line is no
   * refusal: after an intervening line of the other verb it is the last word on its grants, and
   * one changing nothing is warned like any other (contribute, take).
   */
  def parseRules(origin: String, text: String): Vector[Line] =
    val lines = tokenized(origin, text).map(tokens => Line(origin, tokens.mkString(" "), parseRule(origin, tokens)))
    lines.zipWithIndex.foreach: (line, index) =>
      if line.rule == Rule.DenyDefaults && index > 0 then
        throw IllegalArgumentException(
          s"${line.spelled} follows another line; deny defaults is the first line or absent",
        )
    lines

  private def tokenized(origin: String, text: String): Vector[Vector[String]] =
    text.linesIterator
      .map(_.split("\\s+").toVector.filter(_.nonEmpty).takeWhile(!_.startsWith("#")))
      .filter(_.nonEmpty)
      .map: tokens =>
        tokens.find(_.contains('#')).foreach: token =>
          throw IllegalArgumentException(
            s"$origin contains '$token', a token with '#' inside it; a comment starts at the " +
              "start of a line or after whitespace, and nothing else contains '#'",
          )
        tokens
      .toVector

  private def parseRule(origin: String, tokens: Vector[String]): Rule =
    val text = tokens.mkString(" ")
    def refuse(problem: String): Nothing = throw IllegalArgumentException(s"$origin: '$text' $problem")

    tokens match
      case Vector("deny", "defaults")              => Rule.DenyDefaults
      case "deny" +: "defaults" +: _               => refuse("takes no word after defaults")
      case Vector("allow", "model-provider", name) => Rule.AllowGroup(requireProvider(origin, name))
      case Vector("deny", "model-provider", name)  => Rule.DenyGroup(requireProvider(origin, name))
      case "allow" +: url +: words if url.startsWith("https://") =>
        val (authority, path) = splitUrl(refuse, url)
        if authority.startsWith("**.") then refuse("names a pattern; an allow names an exact host")
        val host = normalizeEntry(origin, authority)
        val grants = parseGrants(refuse, words)
        if grants.isEmpty then refuse(s"names no grant; an allow line says what it grants: ${Grant.Forms}")
        if grants(Grant.Tunnel) && grants.size > 1 then
          refuse("puts tunnel beside another word; a tunnel has no path and no method to grant, so the word stands " +
            "alone")
        if grants(Grant.Tunnel) && path != RulePath.Root then refuse("gives a tunnel a path; a tunnel's URL ends at /")
        Rule.Allow(host, path, grants)
      case "deny" +: url +: words if url.startsWith("https://") =>
        val (authority, path) = splitUrl(refuse, url)
        if path != RulePath.Root then
          refuse("denies a path; a deny names a host or a subtree whole, and its URL ends at / (SECURITY.md, " +
            "\"Adding hosts, not patterns\")")
        val pattern =
          if authority.startsWith("**.") then HostPattern.Subtree(normalizeEntry(origin, authority.drop(3)))
          else HostPattern.Exact(normalizeEntry(origin, authority))
        Rule.Deny(pattern, parseGrants(refuse, words))
      case _ => refuse(s"is no line of the rule grammar: $GrammarForms")

  /** The URL's host part and path, the scheme literal `https://` already seen; refusals name what
    * a rule cannot name — a port, userinfo, a query — and a path outside canonical form: printable
    * ASCII, no `%`, `\`, empty, `.` or `..` segment (GitHelper.literalPathProblem). */
  private def splitUrl(refuse: String => Nothing, url: String): (String, String) =
    val rest = url.drop("https://".length)
    val slash = rest.indexOf('/')
    if slash < 0 then refuse("has no / after its host; a path begins at /, the root being https://HOST/")
    val authority = rest.take(slash)
    val path = rest.drop(slash)
    if authority.isEmpty then refuse("names no host")
    Vector('@' -> "userinfo", ':' -> "a port", '[' -> "a bracket", ']' -> "a bracket").foreach: (ch, what) =>
      if authority.contains(ch) then refuse(s"carries $what in its host; a rule names an exact hostname on port 443")
    if path.exists(ch => ch < 0x21 || ch > 0x7e) then refuse("has a character outside printable ASCII in its path")
    if path.contains('?') then refuse("has a query; a rule names a path, never a query")
    literalPathProblem(path).foreach: problem =>
      refuse(s"has $problem in its path; a path is written unencoded, in canonical form")
    (authority, path)

  private def parseGrants(refuse: String => Nothing, words: Vector[String]): Set[String] =
    if words.count(_.startsWith("method=")) > 1 then refuse("names method= twice; one word lists the methods")
    words.foldLeft(Set.empty[String]): (grants, word) =>
      val named: Vector[String] = word match
        case Grant.Read | Grant.GitFetch | Grant.Tunnel => Vector(word)
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

  private def requireProvider(origin: String, name: String): String =
    if !ModelProviders.contains(name) then
      throw IllegalArgumentException(
        s"$origin names the model provider '$name', which this proxy does not define; " +
          s"the providers are ${ModelProviders.sorted.mkString(", ")}",
      )
    name

  private def normalizeEntry(origin: String, entry: String): String =
    val host =
      try normalizeHost(entry)
      catch
        case ex: BadRequest =>
          throw IllegalArgumentException(s"$origin contains an invalid hostname '$entry': ${ex.getMessage}")
    if isIpLiteral(host) then
      throw IllegalArgumentException(s"$origin contains an IP literal '$entry'; only hostnames are allowed")
    host

  // ---------------------------------------------------------------------------
  // The defaults
  // ---------------------------------------------------------------------------

  /**
   * The defaults are policy, so they are written as policy: resource files in the rule grammar,
   * read through the parser a project's file goes through, with the reasoning for each host as a
   * comment beside it. `defaults/host` is the curated catalog — what deny-unless-allowed admits on
   * its own; `defaults/model-provider/<name>` is what `allow model-provider <name>` expands to: the
   * party trusted to receive project data, and only its model, authentication and control-plane
   * endpoints, never every domain it owns (the github group's forge lines have the case). Each
   * `tunnel` line there is unbounded, unlogged write access; SECURITY.md, "What is inside TLS",
   * has why the model endpoints are not TLS-inspected.
   *
   * A defaults file holds `allow https://` lines and nothing else, and the catalog holds no
   * tunnel; either is a refused start, not a silent narrowing, so the image's own --print-policy
   * (the launcher's dry run) is where a malformed defaults file surfaces.
   */
  private def readDefault(name: String): Vector[Line] =
    val origin = s"defaults/$name"
    val stream = getClass.getResourceAsStream(s"/defaults/$name")
    if stream == null then throw IllegalStateException(s"the defaults file $origin is missing from the proxy jar")
    val text =
      try String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
      finally stream.close()
    val lines = parseRules(origin, text)
    lines.foreach: line =>
      line.rule match
        case Rule.Allow(_, _, _) => ()
        case _ =>
          throw IllegalStateException(
            s"$origin contains '${line.text}'; a defaults file holds allow https:// lines only",
          )
    lines

  val CatalogLines: Vector[Line] =
    val lines = readDefault("host")
    lines.foreach: line =>
      line.rule match
        case Rule.Allow(host, _, grants) if grants(Grant.Tunnel) =>
          throw IllegalStateException(
            s"defaults/host makes $host a tunnel; the catalog is inspected, and an opaque tunnel belongs to a " +
              "model-provider group",
          )
        case _ => ()
    lines

  val ModelProviderLines: Map[String, Vector[Line]] =
    ModelProviders.map(name => name -> readDefault(s"model-provider/$name")).toMap

  /** A defaults file's line as the fold reads it. */
  private def contributionOf(line: Line, source: Source, group: Option[String]): Contribution =
    line.rule match
      case Rule.Allow(host, path, grants) => Contribution(host, path, grants, source, group)
      case other => throw IllegalStateException(s"${line.spelled} is no allow line: $other")

  private def groupContributions(name: String, via: Option[Line]): Vector[Contribution] =
    ModelProviderLines(name).map(line => contributionOf(line, Source(line, via), Some(name)))

  private val DefaultContributions: Vector[Contribution] =
    CatalogLines.map(line => contributionOf(line, Source(line, None), None))
      ++ ModelProviders.flatMap(name => groupContributions(name, None))

  /** The defaults resolved on their own: what deny-unless-allowed enforces with no project file. */
  val DefaultHosts: Map[String, Treatment] = hostsOf(start(DefaultContributions))

  // ---------------------------------------------------------------------------
  // Resolution
  // ---------------------------------------------------------------------------

  enum Treatment:
    /** TLS-inspected; `scopes` is the host's table of resolved states by path, cumulative: a
      * scope's grants are the union of every line whose path contains it. A request looks up its
      * longest literal match (authorizeInspectedRequest). A host without a root scope refuses
      * every request outside its scopes. */
    case Inspected(scopes: Map[String, Set[String]])
    case Tunnel

  /** Where a contribution came from: its line, and the file line that expanded it when a group
    * was allowed by the project. */
  private case class Source(line: Line, via: Option[Line]):
    def spelled: String = via.fold(line.spelled)(expanded => s"${expanded.spelled} (${line.spelled})")

    /** Whether the project's file wrote it, directly or by expanding a group. */
    def fromRule: Boolean = via.exists(_.origin == RuleOrigin) || line.origin == RuleOrigin

  /** One allow line's standing grants at its path; a group's line has its group's name, which
    * is what `deny model-provider` removes. Emptied by denies, it stays in the state as the
    * boundary its path opened (invariant 5 of the plan: a line is a boundary as well as a grant). */
  private case class Contribution(
    host: String,
    path: String,
    grants: Set[String],
    source: Source,
    group: Option[String],
  ):
    def active: Boolean = grants.nonEmpty

  /** The fold's state: the contributions in order, the whole-host and `tunnel` denials as patterns
    * with their lines, the lines that took a grant from each host, and the warnings. */
  private case class State(
    contributions: Vector[Contribution] = Vector.empty,
    patterns: Vector[(HostPattern, Line)] = Vector.empty,
    removals: Map[String, Vector[Line]] = Map.empty,
    warnings: Vector[String] = Vector.empty,
  ):
    def active: Vector[Contribution] = contributions.filter(_.active)

    def touched: Set[String] = contributions.map(_.host).toSet

    /** The resolved grants at `path` on `host` as the state stands: what a line there adds to. */
    def enclosing(host: String, path: String): Set[String] =
      active.filter(c => c.host == host && RulePath.contains(c.path, path)).flatMap(_.grants).toSet

  private def start(contributions: Vector[Contribution]): State =
    contributions.foldLeft(State())((state, contribution) => contribute(state, contribution, check = false))

  /**
   * An allow line's step. A host has one treatment, checked at each line: an inspected grant added
   * to a host holding `tunnel`, or `tunnel` to a host holding an inspected grant, is the refusal,
   * naming the deny that would clear the way — except under `allow-unless-denied` with `deny
   * defaults` written, where the defaults' tunnel the profile kept standing gives way to the
   * file's inspected line (resolvePolicy has why). With `check`, the project's line is warned when
   * it grants nothing its enclosing scope lacks — a redundant grant, its boundary standing — unless
   * a defaults line at the same path already grants it, the restatement that is how a file stays
   * valid as the image adopts its hosts.
   */
  private def contribute(
    state: State,
    contribution: Contribution,
    check: Boolean,
    defaultsGiveWay: Boolean = false,
  ): State =
    val Contribution(host, path, grants, source, _) = contribution
    val standing = state.active.filter(_.host == host)
    val tunnels = standing.filter(_.grants(Grant.Tunnel))
    val inspected = standing.filter(c => Grant.isInspected(c.grants))
    if grants(Grant.Tunnel) && inspected.nonEmpty then
      throw IllegalArgumentException(
        s"${source.spelled} makes $host a tunnel while it holds ${inspected.map(_.source.spelled).mkString("; ")}; " +
          s"a host has one treatment — deny https://$host/ first, or drop the line",
      )
    val giveWay = defaultsGiveWay && Grant.isInspected(grants) && tunnels.nonEmpty && tunnels.forall(!_.source.fromRule)
    if Grant.isInspected(grants) && tunnels.nonEmpty && !giveWay then
      throw IllegalArgumentException(
        s"${source.spelled} inspects $host while it is a tunnel (${tunnels.map(_.source.spelled).mkString("; ")}); " +
          s"a host has one treatment — deny https://$host/ tunnel first, or drop the line",
      )
    val contributions =
      if giveWay then state.contributions.map(c => if c.active && c.host == host then c.copy(grants = Set.empty) else c)
      else state.contributions
    val warning =
      if !check || !grants.subsetOf(state.enclosing(host, path)) then None
      else
        val restated = standing.exists(c => c.path == path && !c.source.fromRule && grants.subsetOf(c.grants))
        Option.when(!restated)(
          s"${source.spelled} grants nothing its enclosing scope lacks at its position; to narrow, take the " +
            s"grants first: deny https://$host/ ${Grant.spelled(grants)}, then this line",
        )
    state.copy(contributions = contributions :+ contribution, warnings = state.warnings ++ warning)

  /** A URL deny's step: the grants it names, or every grant, taken from each contribution on the
    * hosts it matches, whichever line gave them. A whole-host or `tunnel` deny is also a pattern
    * under which no unlisted host is admitted, which only `allow-unless-denied` consults. */
  private def take(state: State, pattern: HostPattern, grants: Set[String], line: Line): State =
    val (contributions, hit) =
      state.contributions.foldLeft((Vector.empty[Contribution], Set.empty[String])):
        case ((kept, hit), c) =>
          val left = if grants.isEmpty then Set.empty[String] else c.grants -- grants
          if c.active && pattern.matches(c.host) && left != c.grants then (kept :+ c.copy(grants = left), hit + c.host)
          else (kept :+ c, hit)
    val warning = Option.when(hit.isEmpty)(s"${line.spelled} matches nothing at its position")
    val patterns =
      if grants.isEmpty || grants(Grant.Tunnel) then state.patterns :+ (pattern -> line) else state.patterns
    State(contributions, patterns, recordRemovals(state.removals, hit, line), state.warnings ++ warning)

  /** A provider deny's step: the group's contributions active at this position, and no other
    * line's, removed — PF's anchor, a sub-ruleset handled by name, not a host-wide deny of the
    * group's grants; the resolver keeps the two operations apart. */
  private def takeGroup(state: State, name: String, line: Line): State =
    val hit = state.active.filter(_.group.contains(name)).map(_.host).toSet
    val contributions =
      state.contributions.map(c => if c.active && c.group.contains(name) then c.copy(grants = Set.empty) else c)
    val warning = Option.when(hit.isEmpty)(
      s"${line.spelled} removes nothing at its position: the group's lines are not in force there",
    )
    State(contributions, state.patterns, recordRemovals(state.removals, hit, line), state.warnings ++ warning)

  private def recordRemovals(
    removals: Map[String, Vector[Line]],
    hosts: Set[String],
    line: Line,
  ): Map[String, Vector[Line]] =
    hosts.foldLeft(removals)((current, host) => current.updated(host, current.getOrElse(host, Vector.empty) :+ line))

  private def step(
    state: State,
    line: Line,
    consult: Rule => Boolean,
    check: Boolean,
    defaultsGiveWay: Boolean,
  ): State =
    if !consult(line.rule) then state
    else
      line.rule match
        case Rule.DenyDefaults => state
        case Rule.Allow(host, path, grants) =>
          contribute(state, Contribution(host, path, grants, Source(line, None), None), check, defaultsGiveWay)
        case Rule.AllowGroup(name) =>
          groupContributions(name, Some(line))
            .filter(c => consult(Rule.Allow(c.host, c.path, c.grants)))
            .foldLeft(state)((current, c) => contribute(current, c, check, defaultsGiveWay))
        case Rule.Deny(pattern, grants) => take(state, pattern, grants, line)
        case Rule.DenyGroup(name)       => takeGroup(state, name, line)

  /** The host map a state resolves to: a host holding `tunnel` is opaque; otherwise its scopes are
    * one per path any of its lines opened, boundaries of emptied lines included, each holding the
    * union of the active lines containing it, and a scope holding nothing is dropped — its
    * enclosing scope is empty too, so every request under it is refused with or without the
    * boundary. A host with no active line is not in the map: denied whole.
    *
    * This table is a compilation of the ordered lines, PF's skip steps: the longest match a
    * request looks up selects a state the order already settled, never a precedence among lines.
    * A change here must keep HostileInputTest's plain ordered evaluator agreeing with it
    * (design.md, "No richer egress-policy format"). */
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
   * The policy in force: the whole of what enforcement reads, and the whole of what the digest
   * names. Equality of this structure is what "one policy" means: two files resolving to it print
   * one digest and the same lines, and the same file under two profiles never does — the profile
   * is in it, and the selected provider under deny-unless-model alone, where it changes authority.
   * `denialPatterns` exists under allow-unless-denied alone: the patterns, exact hosts and
   * subtrees, under which no unlisted host — one no line names — is admitted — whole-host and `tunnel` denies alike,
   * since an unlisted host holds nothing but its tunnel, and every host a deny emptied — in normal
   * form: a pattern a subtree covers dropped, an exact pattern of a host the map holds dropped as
   * inert, sorted. Under the finite profiles the host map embodies every denial and none is kept.
   */
  case class ResolvedPolicy(
    profile: String,
    publicDefault: Boolean,
    provider: Option[String],
    hosts: Map[String, Treatment],
    denialPatterns: Vector[HostPattern],
  ):
    val inspectedScopes: Map[String, Map[String, Set[String]]] =
      hosts.collect { case (host, Treatment.Inspected(scopes)) => host -> scopes }
    val tunnelHosts: Set[String] =
      hosts.collect { case (host, Treatment.Tunnel) => host }.toSet
    val inspected: Set[String] = inspectedScopes.keySet

  /** The sources behind a resolved scope: one set for its boundary — the lines at its exact path —
    * and one per grant it holds, the contributions currently supplying it; a folded scope has no
    * one "source", so none is invented. */
  case class ScopeProvenance(boundary: Vector[String], grants: Map[String, Vector[String]])

  /**
   * Kept beside the policy, never in it: what the structure's equality must not see. `scopes` per
   * inspected scope; `patterns` per whole-host or `tunnel` deny and per host a deny emptied, under
   * every profile, so a refusal can say `host denied (<line>)` where a file line matched the host;
   * `widening`, the project lines granting beyond the defaults for their host — a host the
   * defaults lack, `tunnel`, `method=` and `git-fetch` where they lack them, `deny defaults` —
   * for the summary line's count and `--egress-effective`'s listing.
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
    policy: ResolvedPolicy,
    provenance: Provenance,
    warnings: Vector[String],
    clearsDefaults: Boolean,
  ):
    def profile: String = policy.profile
    def publicDefault: Boolean = policy.publicDefault
    def provider: Option[String] = policy.provider
    def hosts: Map[String, Treatment] = policy.hosts
    def denialPatterns: Vector[HostPattern] = policy.denialPatterns
    def inspectedScopes: Map[String, Map[String, Set[String]]] = policy.inspectedScopes
    def tunnelHosts: Set[String] = policy.tunnelHosts
    def inspected: Set[String] = policy.inspected

  /**
   * The variables resolved to the policy in force.
   *
   * Every profile runs the same fold, from its own start and consulting its own lines:
   *
   *   deny-all            = nothing
   *   deny-unless-model   = the selected group's lines, then the file's deny lines
   *   deny-unless-allowed = the defaults — none after `deny defaults` — then every line
   *   allow-unless-denied = the defaults, then every line but `deny defaults` and a `tunnel`
   *                         allow; the inspected hosts are the narrowing set, every other
   *                         public hostname on port 443 an opaque tunnel unless a denial
   *                         pattern covers it
   *
   * Refusals and warnings come from one further fold, every line over the defaults, so that a file
   * valid under one profile is valid under every one. The one place `allow-unless-denied` departs
   * from that fold: it keeps the defaults' tunnels standing where `deny defaults` would have
   * cleared them, and a project line inspecting such a host would then meet its own defaults'
   * tunnel — so there, and only there, the defaults' tunnel gives way, the deny the file's first
   * line implies for that host.
   *
   * The internal-network denials of the security model are not rules here: they are IPAddrHelper's
   * address vetting, applied to every resolved destination at connection time, unlisted hosts
   * included, so no rule file can spell them away.
   *
   * Fails closed on every ambiguity: an unknown profile, provider, word or line form; a line
   * outside canonical form; a resolved host holding `tunnel` beside an inspected grant; a `tunnel`
   * line for a host the defaults inspect without `deny defaults`. Warns at every launch, under
   * every profile: a `deny` matching nothing at its position — the misspelled deny must not fail
   * silently — a redundant grant, and a line every grant of which a later line takes back. An
   * empty resolved policy is valid and reported as such — deny-all resolves empty by design, as
   * does deny-unless-model with no provider selected.
   */
  def resolvePolicy(
    profileValue: Option[String],
    providerValue: Option[String],
    ruleText: Option[String],
  ): ResolvedEgress =
    val profile = profileValue.getOrElse(DefaultProfile)
    if !Profiles.contains(profile) then
      throw IllegalArgumentException(s"$ProfileVariable is '$profile'; the profiles are ${Profiles.mkString(", ")}")
    val provider = providerValue.filterNot(_ == "none").map(requireProvider(ModelProviderVariable, _))

    val lines = parseRules(RuleOrigin, ruleText.getOrElse(""))
    val clearsDefaults = lines.headOption.exists(_.rule == Rule.DenyDefaults)

    // Widening to a tunnel is global: it reads the defaults, not the file's state, because an opaque
    // tunnel ends inspection and the audit record for a host every project has.
    lines.foreach: line =>
      line.rule match
        case Rule.Allow(host, _, grants)
            if grants(Grant.Tunnel) && !clearsDefaults && DefaultHosts.get(host).exists(_ != Treatment.Tunnel) =>
          throw IllegalArgumentException(
            s"${line.spelled} makes $host an opaque tunnel, which the defaults inspect; a tunnel there takes " +
              "deny defaults as the first line and the whole policy after it",
          )
        case _ => ()

    val defaults = if clearsDefaults then Vector.empty else DefaultContributions
    val validated = lines.foldLeft(start(defaults)): (state, line) =>
      step(state, line, _ => true, check = true, defaultsGiveWay = false)
    // Per file line, by reference: a repeated line is its own line, and a provider line's expanded
    // contributions all name it.
    val takenBack = lines.flatMap: line =>
      val own = validated.contributions.filter(c => c.source.via.getOrElse(c.source.line) eq line)
      Option.when(own.nonEmpty && own.forall(!_.active))(
        s"${line.spelled} grants nothing: every grant it names is taken back by a later line",
      )

    def isDeny(rule: Rule): Boolean = rule match
      case Rule.Deny(_, _) | Rule.DenyGroup(_) => true
      case _                                   => false
    def narrows(rule: Rule): Boolean = rule match
      case Rule.DenyDefaults          => false
      case Rule.Allow(_, _, grants)   => Grant.isInspected(grants)
      case _                          => true

    val (initial, consult, publicDefault) = profile match
      case "deny-all"            => (Vector.empty[Contribution], (_: Rule) => false, false)
      case "deny-unless-model" =>
        (provider.fold(Vector.empty[Contribution])(groupContributions(_, None)), isDeny, false)
      case "deny-unless-allowed" => (defaults, (_: Rule) => true, false)
      case "allow-unless-denied" => (DefaultContributions, narrows, true)
    val enforced =
      if profile == "deny-all" then State()
      else
        lines.foldLeft(start(initial)): (state, line) =>
          step(state, line, consult, check = false, defaultsGiveWay = publicDefault && clearsDefaults)

    val resolvedHosts = hostsOf(enforced)
    val hosts =
      if publicDefault then resolvedHosts.filter((_, treatment) => treatment != Treatment.Tunnel) else resolvedHosts

    val emptied = (enforced.touched -- resolvedHosts.keySet).toVector.sorted
    val patterns: Vector[(HostPattern, Vector[String])] =
      (enforced.patterns.map((pattern, line) => pattern -> Vector(line.spelled))
        ++ emptied.map: host =>
          HostPattern.Exact(host) -> enforced.removals.getOrElse(host, Vector.empty).map(_.spelled))
        .groupMapReduce(_(0))(_(1))(_ ++ _)
        .toVector
        .map((pattern, sources) => pattern -> sources.distinct)
        .sortBy(_(0).spelled)
    val patternSet = patterns.map(_(0)).toSet
    val denialPatterns =
      if !publicDefault then Vector.empty
      else
        patterns.map(_(0)).filter: pattern =>
          val inert = pattern match
            case HostPattern.Exact(host) => hosts.contains(host)
            case HostPattern.Subtree(_)  => false
          !inert && !patternSet.exists(other => other != pattern && pattern.within(other))

    val policy = ResolvedPolicy(
      profile, publicDefault, Option.when(profile == "deny-unless-model")(provider).flatten, hosts, denialPatterns,
    )

    val scopes = hosts.toVector.flatMap: (host, treatment) =>
      val own = enforced.contributions.filter(_.host == host)
      val held = own.filter(_.active)
      val paths = treatment match
        case Treatment.Tunnel       => Vector(RulePath.Root)
        case Treatment.Inspected(scopes) => scopes.keys.toVector
      paths.map: path =>
        val boundary = treatment match
          case Treatment.Tunnel => held.map(_.source.spelled)
          case Treatment.Inspected(_) => own.filter(_.path == path).map(_.source.spelled)
        val supplying = held.filter(c => RulePath.contains(c.path, path))
        val grants = supplying.flatMap(_.grants).distinct.map: grant =>
          grant -> supplying.filter(_.grants(grant)).map(_.source.spelled)
        (host, path) -> ScopeProvenance(boundary.distinct, grants.toMap)

    val widening =
      if profile != "deny-unless-allowed" then Vector.empty
      else
        lines.filter: line =>
          line.rule match
            case Rule.DenyDefaults => true
            case Rule.Allow(host, _, grants) =>
              DefaultHosts.get(host) match
                case None                             => true
                case Some(Treatment.Tunnel)     => false
                case Some(Treatment.Inspected(scopes)) =>
                  val held = scopes.values.flatten.toSet
                  grants.exists(grant => grant != Grant.Read && !held(grant))
            case _ => false

    val reachability =
      provider.toVector.flatMap: selected =>
        val unreachable = ModelProviderLines(selected).map(_.rule)
          .collect { case Rule.Allow(host, _, _) => host }
          .distinct.sorted
          .filterNot(host => hosts.contains(host) || (publicDefault && !denialPatterns.exists(_.matches(host))))
        Option.when(unreachable.nonEmpty)(
          s"the selected model provider '$selected' is not fully reachable under $profile: " +
            unreachable.mkString(" "),
        )

    ResolvedEgress(
      policy,
      Provenance(scopes.toMap, patterns, widening),
      validated.warnings ++ takenBack ++ reachability,
      clearsDefaults,
    )

  // ---------------------------------------------------------------------------
  // Output
  // ---------------------------------------------------------------------------

  /** One host's treatment as rule lines, one per scope: the form --check-host and the policy lines share. */
  def ruleLines(host: String, treatment: Treatment): Vector[String] = treatment match
    case Treatment.Tunnel => Vector(s"allow https://$host/ ${Grant.Tunnel}")
    case Treatment.Inspected(scopes) =>
      scopes.toVector.sortBy(_(0)).map((path, grants) => s"allow https://$host$path ${Grant.spelled(grants)}")

  /**
   * The resolved policy, one line each, in the rule grammar so a reader learns one grammar — the
   * deterministic serialization of ResolvedPolicy, which the digest names, --print-policy prints
   * and serve() logs identically, the launcher reads the leaf's names off and the agent's authority
   * section holds. It is a serialization, not a rule file: no `deny defaults` header, no promise
   * to re-parse to itself, and nothing reads it as input. First the profile line — the grammar
   * alone cannot say "any public host" or "this provider's group only" — then, under
   * allow-unless-denied, the denial patterns as whole-host deny lines, before the allow lines so
   * that a host surviving beneath one reads as the exception the grammar's order makes it, then
   * one allow line per resolved scope with its whole grant set, hosts and paths sorted.
   */
  def policyLines(resolved: ResolvedEgress): Vector[String] =
    val profileLine = resolved.profile match
      case "deny-unless-model" =>
        s"egress profile: deny-unless-model; model provider: ${resolved.provider.getOrElse("none")}"
      case "allow-unless-denied" =>
        "egress profile: allow-unless-denied; default: public HTTPS tunnel"
      case other => s"egress profile: $other"
    val denyLines = resolved.denialPatterns.map(pattern => s"deny https://${pattern.spelled}/")
    val allowLines = resolved.hosts.toVector.sortBy(_(0)).flatMap(ruleLines)
    profileLine +: (denyLines ++ allowLines)

  /** The lines after the policy lines, outside the digest: they describe the policy's size and
    * how the file arrived at it, not the policy. The launcher splits the dry run's text at the
    * first of them (EgressProxyPolicy.MetadataPrefixes). */
  def metadataLines(resolved: ResolvedEgress): Vector[String] =
    val summary =
      s"policy summary: ${resolved.inspected.size} inspected hosts; ${resolved.tunnelHosts.size} opaque hosts; " +
        s"${resolved.denialPatterns.size} denial patterns; ${resolved.provenance.widening.size} widening lines"
    summary +: wideningLine(resolved).toVector

  /** The project lines reaching past the defaults (Provenance.widening); lines, so `; ` separates
    * them. */
  def wideningLine(resolved: ResolvedEgress): Option[String] =
    val widening = resolved.provenance.widening
    Option.when(widening.nonEmpty)(s"widening lines (${widening.size}): " + widening.map(_.text).mkString("; "))

  /**
   * Each policy line followed by its sources — an allow line's boundary and each of its grants, a
   * deny line's pattern, with the lines of every denied pattern the normal form folded into it —
   * then, under the finite profiles, the hosts the file's lines denied, which the structure keeps
   * no line for. Printed by `--print-policy --provenance`, which is what `--egress-effective` runs.
   */
  def provenanceLines(resolved: ResolvedEgress): Vector[String] =
    val provenance = resolved.provenance
    val denyLines = resolved.denialPatterns.flatMap: pattern =>
      val inert = (p: HostPattern) => p match
        case HostPattern.Exact(host) => resolved.hosts.contains(host)
        case HostPattern.Subtree(_)  => false
      val (own, folded) = provenance.patterns
        .filter((p, _) => p == pattern || (p.within(pattern) && !inert(p)))
        .partition(_(0) == pattern)
      val sources = (own ++ folded).flatMap(_(1)).distinct
      Vector(s"deny https://${pattern.spelled}/", s"  pattern: ${sources.mkString("; ")}")
    val allowLines = resolved.hosts.toVector.sortBy(_(0)).flatMap: (host, treatment) =>
      val paths = treatment match
        case Treatment.Tunnel       => Vector(RulePath.Root)
        case Treatment.Inspected(scopes) => scopes.keys.toVector.sorted
      paths.flatMap: path =>
        val scope = provenance.scopes((host, path))
        val grants = treatment match
          case Treatment.Tunnel       => Set(Grant.Tunnel)
          case Treatment.Inspected(scopes) => scopes(path)
        val grantLines = (Vector(Grant.Read, Grant.GitFetch) ++ Grant.Methods ++ Vector(Grant.Tunnel))
          .filter(grants)
          .map(grant => s"  $grant: ${scope.grants.getOrElse(grant, Vector.empty).mkString("; ")}")
        Vector(s"allow https://$host$path ${Grant.spelled(grants)}", s"  boundary: ${scope.boundary.mkString("; ")}")
          ++ grantLines
    val deniedHosts =
      if resolved.publicDefault then Vector.empty
      else
        provenance.patterns.collect { case (HostPattern.Exact(host), sources) if !resolved.hosts.contains(host) =>
          s"  $host: denied by ${sources.mkString("; ")}"
        }
    Vector("provenance:") ++ denyLines ++ allowLines
      ++ (if deniedHosts.nonEmpty then "denied hosts:" +: deniedHosts else Vector.empty)

  // ---------------------------------------------------------------------------
  // Enforcement
  // ---------------------------------------------------------------------------

  /**
   * The one gate an inspected request passes. The request is classified once, into what it is — a
   * read, fetch discovery, upload-pack, push discovery, another write — with its path vetted for
   * the boundary it lands in, and that classification is decided once against the resolved scope
   * of its longest literal match: GET and HEAD under `read`, bodyless; fetch discovery and
   * upload-pack under `git-fetch` (GitHelper.isUploadPack), so a clone that could not transfer
   * fails at its first request; push discovery under a `POST` grant, where the push is the
   * project's own grant; another write under its method, its path refused for the spellings a
   * forge decodes first (requireUnambiguousPath). Where the longest match is a line other than
   * the root, the request is first refused for `%`, a dot segment, a backslash and an empty
   * segment, on every method: under such a line the path decides grants the root does not give.
   * Under the root a read may carry `%` — what keeps npm's `/@scope%2fname` reading — since it
   * gains nothing by any decoding. A path in no scope is refused.
   *
   * Receive-pack transfer, the LFS batch endpoint and GraphQL stay refused where no line grants
   * their method: SECURITY.md, "Reading without being able to write".
   */
  def authorizeInspectedRequest(
    host: String,
    head: HttpRequestHead,
    scopes: Map[String, Set[String]],
    // Which hosts this session admits, consulted only where a refusal's advice would name another
    // host (RefusalAdvice.forRefusedPost); the default names none.
    admitted: String => Boolean = _ => false,
  ): Unit =
    if !head.target.startsWith("/") then
      throw PolicyViolation("only origin-form request targets are allowed", RefusalAdvice.originForm)

    if head.values("Upgrade").nonEmpty then
      throw PolicyViolation("HTTP Upgrade is not allowed", RefusalAdvice.upgrade)

    head.values("Host") match
      case Vector(value) =>
        val declared = normalizeHostHeader(value)

        if declared != host then
          throw PolicyViolation(s"Host header $declared", RefusalAdvice.hostHeader)

      case Vector() => throw BadRequest("missing Host header")
      case _        => throw BadRequest("duplicate Host header")

    head.bodyFraming // throws when ambiguous

    val path = head.path
    val matched = scopes.keys.filter(scope => RulePath.contains(scope, path)).maxByOption(_.length)
    val grants = matched match
      case Some(scope) => scopes(scope)
      case None        => throw PolicyViolation("path outside allowance", RefusalAdvice.pathOutside(scopes.keySet))
    if matched.get != RulePath.Root then requireLiteralPath(path)

    head.method match
      case "GET" | "HEAD" =>
        // a body on a read method would be an unbounded, unlogged client-to-server channel
        if head.bodyFraming != BodyFraming.Empty then
          throw PolicyViolation("request body", RefusalAdvice.requestBody)

        if isReceivePackDiscovery(head) then
          if !grants("POST") then throw PolicyViolation("git push ref discovery", RefusalAdvice.gitPush)
        else if isUploadPackDiscovery(head) then
          if !grants(Grant.GitFetch) then throw PolicyViolation("git fetch ref discovery", RefusalAdvice.gitFetch)
        else if !grants(Grant.Read) then
          throw PolicyViolation("read not granted", RefusalAdvice.noRead)

      case method if Grant.Methods.contains(method) =>
        requireUnambiguousPath(path)

        val opened = grants(method) || (method == "POST" && grants(Grant.GitFetch) && isUploadPack(path))
        if !opened then
          throw PolicyViolation(
            s"$method not granted",
            if method == "POST" then RefusalAdvice.forRefusedPost(host, path, admitted) else RefusalAdvice.readOnly,
          )

      case method =>
        throw PolicyViolation(s"$method not granted", RefusalAdvice.readOnly)

  /*
   * The IP-literal rejection is defence in depth for the finite profiles — their maps cannot
   * contain one and resolvePublic rejects private answers — and under `allow-unless-denied` it is
   * the named refusal a literal target gets. The host map is read first: a host in it gets its
   * treatment whatever pattern covers it, since an inspected host surviving beneath a denied
   * subtree is exactly what the map records; a host not in it is an unlisted host's tunnel under
   * allow-unless-denied when no denial pattern matches it, and refused otherwise. The refusal's
   * reason is presentation: `host denied (<line>)` where a file line matched the host, from
   * provenance, `host not allowed` otherwise.
   */
  def authorizeRequest(
    request: ConnectRequest,
    resolved: ResolvedEgress,
  ): String =
    if request.port != 443 then
      throw PolicyViolation(s"port ${request.port}", RefusalAdvice.port)

    val host = normalizeHost(request.host)

    if isIpLiteral(host) then
      throw PolicyViolation("IP-literal target", RefusalAdvice.ipLiteral)

    val admitted =
      resolved.hosts.contains(host) || (resolved.publicDefault && !resolved.denialPatterns.exists(_.matches(host)))
    if !admitted then
      resolved.provenance.denialOf(host) match
        case Some(sources) =>
          throw PolicyViolation(s"host denied (${sources.mkString("; ")})", RefusalAdvice.hostDenied)
        case None =>
          throw PolicyViolation("host not allowed", RefusalAdvice.hostNotAllowed(host, resolved.profile))

    host
