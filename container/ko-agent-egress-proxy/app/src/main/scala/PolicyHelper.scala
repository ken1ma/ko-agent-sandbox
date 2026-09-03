// The egress policy: the `allowed`/`denied` grammar, the launcher-owned baseline, the profile
// equations that resolve them into the hosts in force, the lines that print the result, and the
// decisions made against it — at the CONNECT and inside an inspected tunnel. Pure: nothing here
// reads a socket or the environment, which is what lets the launcher run the same code for its
// dry run (--print-policy) and the tests resolve policies by the thousand.

package agentsandbox.egress

import GitHelper.*
import HTTPHelper.*
import IPAddrHelper.*

object PolicyHelper:
  /*
   * Exact hostnames only. Deliberately no regex or wildcard matching on the granting side.
   *
   * Every allowed host is a GET-based exfiltration channel: a permitted GET carries its URL, and a URL is a message.
   *
   * A host's treatment is one of two:
   *
   *   - unrestricted: an opaque tunnel — nothing seen or logged past the CONNECT.
   *   - restricted: TLS-inspected; only GET and HEAD, plus the POST paths its `allow=` tags open
   *     (authorizeInspectedRequest) — on the whole host, or under the path prefix an entry's
   *     `path=` names, which only ever narrows (Scope).
   *
   * A tag names one of the fixed treatments this proxy defines (KnownTags); it never describes a
   * rule, and an unknown tag is a refused start — the guardrail design.md ("No general HTTP
   * method/path policy language") sets on this syntax. A prefix is the one path form admitted,
   * because its worst case is over-blocking (SECURITY.md, "Adding hosts, not patterns").
   *
   * Which hosts are in force is the selected profile's answer (resolvePolicy below): the
   * launcher-owned baseline — every model-provider group plus the curated restricted catalog —
   * modified by the project's `allowed` delta and `denied` rules. Whichever policy is in force is
   * printed at startup and every denial is logged, which is how you find out what an agent
   * actually wanted.
   *
   * Inspection is off unless the launcher supplies a certificate and key; the leaf must name
   * exactly the resolved restricted hosts, tags stripped (SECURITY.md, "Who holds the CA key").
   */

  enum Treatment:
    case Restricted(scopes: Set[Scope])
    case Unrestricted

  object Treatment:
    /** A host restricted whole: one scope with no prefix. */
    def restricted(tags: Set[String] = Set.empty): Treatment = Restricted(Set(Scope(None, tags)))

  /**
   * One restricted entry's reach on its host: every path when `prefix` is None, otherwise the
   * paths under `prefix`, compared literally after the request path is refused for any spelling
   * an origin might fold onto another path (authorizeInspectedRequest) — and the allowances that
   * hold there and nowhere else on the host. A host's scopes are disjoint (mergeAdditions
   * refuses nesting), so a request has at most one.
   */
  case class Scope(prefix: Option[String], tags: Set[String]):
    def admits(path: String): Boolean = prefix.forall(path.startsWith)

    /** Whether every path this scope admits, `other` admits too: the nesting one host may not carry. */
    def within(other: Scope): Boolean = other.prefix.forall(wider => prefix.exists(_.startsWith(wider)))

    /** The policy lines' token: `host`, or `host/prefix/` for a scope narrowed to a path. The
      * launcher reads the host off it for the leaf certificate (EgressProxyPolicy.inspectedHostsOf). */
    def token(host: String): String = host + prefix.getOrElse("")

    /** The entry's attribute words, `path=/prefix/` and `allow=a,b`, as the grammar spells them. */
    def attributes: Vector[String] =
      prefix.map("path=" + _).toVector :++ Option.when(tags.nonEmpty)(s"allow=${tags.toVector.sorted.mkString(",")}")

    /** The entry's words after its host, as `--print-policy --provenance` and `--check-host` show them. */
    def spelled: String = ("restricted" +: attributes).mkString(" ")

  object Scope:
    /** Two entries' scopes as one host's: a prefix both carry holds the union of their tags —
      * how the catalog's github.com and the github group's meet (BaselineHosts). */
    def merged(a: Set[Scope], b: Set[Scope]): Set[Scope] =
      (a ++ b).groupMapReduce(_.prefix)(_.tags)(_ ++ _).map(Scope(_, _)).toSet

  /** The audit endpoint the image's npm POSTs at install time — measured on the bundled Node
    * 24.19.0 / npm 11.17.0, not guessed. An older npm's /-/npm/v1/security/audits/quick is
    * refused and logged: the contract is the shipped client, and npm treats the refusal as
    * non-fatal. */
  val NpmAuditPath = "/-/npm/v1/security/advisories/bulk"

  /** GitHub's OAuth device flow, as Copilot CLI 1.0.80 drives it: the first mints the user code the
    * agent prints, the second polls for the token once the browser has approved. Both bodies are
    * fixed forms naming a client id, so the allowance carries no project data. */
  val GithubLoginDevicePaths: Set[String] = Set("/login/device/code", "/login/oauth/access_token")

  /** The tags a restricted entry may carry — a closed set: a tag names one of the fixed
    * rule-sets in authorizeInspectedRequest, never describes one. Each is named tool-operation,
    * for the single operation it opens, and maps to the fixed paths that operation POSTs to —
    * none for `git-fetch`, whose upload-pack path is the fetched repository's
    * (GitHelper.isUploadPack). A `path=` entry must contain them (requireAllowancesUnder). */
  val AllowancePaths: Map[String, Set[String]] = Map(
    "git-fetch" -> Set.empty,
    "npm-audit" -> Set(NpmAuditPath),
    "github-login-device" -> GithubLoginDevicePaths,
  )
  val KnownTags: Set[String] = AllowancePaths.keySet

  /**
   * The baseline is policy, so it is written as policy: resource files in the `allowed` grammar's
   * addition form, read through the parser a project's file goes through, with the reasoning for
   * each host as a comment beside it. `baseline/host` is the curated restricted catalog — what
   * deny-unless-allowed admits on its own; `baseline/model-provider/<name>` is what
   * `+model-provider <name>` expands to: the party trusted to receive project data, and only its
   * model, authentication and control-plane endpoints, never every domain it owns (the github
   * group's forge entries have the case).
   *
   * A baseline file holds `+host` entries and nothing else, and the catalog holds no unrestricted
   * one; either is a refused start, not a silent narrowing, so the image's own `--print-policy`
   * (the launcher's dry run) is where a malformed baseline surfaces.
   */
  val ModelProviders: Vector[String] = Vector("anthropic", "openai", "google", "github")

  private def readBaseline(name: String): Map[String, Treatment] =
    val variable = s"the baseline file $name"
    val stream = getClass.getResourceAsStream(s"/baseline/$name")
    if stream == null then throw IllegalStateException(s"$variable is missing from the proxy jar")
    val text =
      try String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
      finally stream.close()
    val entries = policyEntries(variable, text).map:
      case "+host" +: entry +: words => parseHostAddition(variable, entry, words)
      case tokens =>
        throw IllegalStateException(
          s"$variable contains '${tokens.mkString(" ")}'; a baseline file holds +host entries only",
        )
    val twice = entries.groupBy(_(0)).collect { case (host, seen) if seen.sizeIs > 1 => host }.toVector.sorted
    if twice.nonEmpty then throw IllegalStateException(s"$variable names ${twice.mkString(", ")} twice")
    // Whole hosts only: the catalog and a group merge on a host by tags (BaselineHosts, addGroup),
    // which is well-defined for one whole-host scope each and would nest prefixes otherwise.
    entries.foreach:
      case (host, Treatment.Restricted(scopes)) if scopes.exists(_.prefix.nonEmpty) =>
        throw IllegalStateException(s"$variable narrows $host with path=; a baseline entry names its host whole")
      case _ => ()
    entries.toMap

  val CuratedRestrictedHosts: Map[String, Set[String]] =
    readBaseline("host").map:
      case (host, Treatment.Restricted(scopes)) => host -> scopes.flatMap(_.tags)
      case (host, Treatment.Unrestricted) =>
        throw IllegalStateException(
          s"the baseline file host makes $host unrestricted; the catalog is restricted, and an " +
            "opaque tunnel belongs to a model-provider group",
        )

  val ModelProviderHosts: Map[String, Map[String, Treatment]] =
    ModelProviders.map(name => name -> readBaseline(s"model-provider/$name")).toMap

  /**
   * Baseline `B`: every model-provider group plus the curated restricted catalog. A host in both
   * is restricted in both — a group never widens the catalog — and carries the union of its tags
   * (github.com: `allow=git-fetch` from the catalog, `allow=github-login-device` from its group). What each
   * profile admits of it is resolvePolicy's equation.
   */
  val BaselineHosts: Map[String, Treatment] =
    (ModelProviderHosts.values.flatten
      ++ CuratedRestrictedHosts.map((host, tags) => host -> Treatment.restricted(tags)))
      .groupMapReduce(_(0))(_(1)):
        case (Treatment.Restricted(a), Treatment.Restricted(b)) => Treatment.Restricted(Scope.merged(a, b))
        case (a, b) =>
          throw IllegalStateException(s"a provider group and the catalog disagree on a host's treatment: $a, $b")

  val ProfileVariable = "EGRESS_PROFILE"
  val ModelProviderVariable = "EGRESS_MODEL_PROVIDER"
  val AllowedVariable = "EGRESS_ALLOWED"
  val DeniedVariable = "EGRESS_DENIED"

  /** The authority profiles, weakest-to-widest; deny-unless-allowed is what an unset
    * EGRESS_PROFILE means — the launcher-owned baseline, every entry restricted or a model
    * provider's own endpoints, so the default is useful without opening the open internet. */
  val Profiles = Vector("deny-all", "deny-unless-model", "deny-unless-allowed", "allow-unless-denied")
  val DefaultProfile = "deny-unless-allowed"

  /**
   * One `denied` rule, or an entry of the launcher-owned internal denials. Every form is
   * removal-only, so none can widen authority; the provider form keeps a denied provider denied
   * when its concrete endpoints change, because it matches whatever the group expands to now.
   */
  enum DenyRule:
    case Exact(host: String)
    case Subtree(base: String)
    case Provider(name: String)

    def matches(host: String): Boolean = this match
      case Exact(h) => host == h
      // The pattern's own dot is the label boundary: `**.foo.com` covers foo.com and api.foo.com, never barfoo.com.
      case Subtree(b)  => host == b || host.endsWith("." + b)
      case Provider(p) => ModelProviderHosts(p).contains(host)

    def spelled: String = this match
      case Exact(h)    => h
      case Subtree(b)  => s"**.$b"
      case Provider(p) => s"model-provider:$p"

  /**
   * The policy in force: the selected profile's finite host map — under allow-unless-denied,
   * the restricted exceptions, with `ambient` admitting every other public hostname on port 443
   * as unrestricted — and the denied rules, which win over both treatments. What each treatment
   * means is the policy comment's enumeration; how the restricted rules are enforced once TLS
   * is terminated is authorizeInspectedRequest. The provenance fields exist for presentation
   * only — `sources` labels each pre-denial host with the rule that last changed it,
   * `deniedAdmitted` the hosts a denial cost, `removedSpellings` the allowed-delta rules that
   * actually removed something, `widening` the delta entries reaching past the baseline this
   * image ships; enforcement reads `hosts`, `ambient` and `denied`.
   */
  case class ResolvedEgress(
    profile: String,
    provider: Option[String],
    ambient: Boolean,
    hosts: Map[String, Treatment],
    denied: Vector[DenyRule],
    idleDenied: Vector[DenyRule],
    warnings: Vector[String],
    sources: Map[String, String],
    deniedAdmitted: Map[String, DenyRule],
    removedSpellings: Vector[String],
    widening: Vector[String],
  ):
    val restricted: Map[String, Set[Scope]] =
      hosts.collect { case (host, Treatment.Restricted(scopes)) => host -> scopes }
    val unrestrictedHosts: Set[String] =
      hosts.collect { case (host, Treatment.Unrestricted) => host }.toSet
    val inspected: Set[String] = restricted.keySet

    /** The hosts on which `tag` holds, in any scope. */
    def tagged(tag: String): Set[String] =
      restricted.collect { case (host, scopes) if scopes.exists(_.tags(tag)) => host }.toSet

    /** Every restricted scope as the policy lines spell it (Scope.token), sorted; with `tag`, those carrying it. */
    def scopeTokens(tag: Option[String] = None): Vector[String] =
      restricted.toVector
        .flatMap((host, scopes) => scopes.filter(scope => tag.forall(scope.tags)).map(_.token(host)))
        .sorted

  /**
   * The variables resolved to the policy in force.
   *
   * Let `M` be the selected provider's group, `B` the baseline (BaselineHosts), `A` the result
   * of applying the `allowed` delta to `B`, `N` the restricted narrowing set — `B`'s restricted
   * entries plus restricted exact-host additions; removals, `-**` and unrestricted
   * additions cannot subtract from it — `D` the `denied` rules expanded, and `U` the implicit
   * map from every public hostname on port 443 to unrestricted:
   *
   *   deny-all            = empty
   *   deny-unless-model   = M - D
   *   deny-unless-allowed = A - D
   *   allow-unless-denied = narrow(U, N) - D
   *
   * A provider group is a contribution, not a replacement: `+model-provider` merges a group's
   * restricted tags into a host the catalog restricts too, and `-model-provider` takes back only
   * those — `+` then `-` is the identity, and over the baseline `+` alone is a no-op. `D`'s
   * `model-provider` form is the one that removes such a host outright.
   *
   * The internal-network denials of the security model are not host rules here: they are
   * IPAddrHelper's address vetting, applied to every resolved destination at connection time,
   * ambient hosts included, so no policy file can spell them away.
   *
   * Fails closed on every ambiguity: an unknown profile, provider, tag or entry form; duplicate
   * exact-host additions with different treatments; a host both added and removed — a `+host`
   * under a `-host **.domain` included; an addition that would widen a restricted baseline host
   * to unrestricted, which the delta grammar cannot write short of `-**` plus a complete
   * replacement; a removal matching neither the baseline nor an addition. A `denied` entry
   * matching nothing the selected profile admits is a startup warning, not an error: it can
   * still apply under another profile or a future provider expansion, and a typo cannot be
   * distinguished from a proactive denial against the ambient host universe. An empty effective
   * map is valid and reported as such — deny-all resolves empty by design, as does
   * deny-unless-model with no provider selected. The only wildcard is the taking-away side's
   * `**.domain`; SECURITY.md ("Adding hosts, not patterns") records the asymmetry.
   */
  def resolvePolicy(
    profileValue: Option[String],
    providerValue: Option[String],
    allowedText: Option[String],
    deniedText: Option[String],
  ): ResolvedEgress =
    val profile = profileValue.getOrElse(DefaultProfile)
    if !Profiles.contains(profile) then
      throw IllegalArgumentException(
        s"$ProfileVariable is '$profile'; the profiles are ${Profiles.mkString(", ")}",
      )
    val provider =
      providerValue.filterNot(_ == "none").map(requireProvider(ModelProviderVariable, _))

    val delta = parseAllowed(allowedText.getOrElse(""))
    val denied = parseDenied(deniedText.getOrElse(""))

    delta.addedHosts.foreach: (host, treatment) =>
      val widens = !delta.clearsBaseline && treatment == Treatment.Unrestricted &&
        BaselineHosts.get(host).exists {
          case Treatment.Restricted(_) => true
          case Treatment.Unrestricted  => false
        }
      if widens then
        throw IllegalArgumentException(
          s"$AllowedVariable re-adds the restricted baseline host $host as unrestricted; " +
            "treatment widening cannot be written as a delta — use -** and state the complete " +
            "replacement policy",
        )

    val contradicted =
      delta.addedHosts.keySet.filter(host => delta.removals.exists(_.matches(host)))
    if contradicted.nonEmpty then
      throw IllegalArgumentException(
        s"$AllowedVariable both adds and removes ${contradicted.toVector.sorted.mkString(", ")}",
      )

    delta.removals.foreach: removal =>
      if !(BaselineHosts.keySet ++ delta.addedHosts.keySet).exists(removal.matches) then
        throw IllegalArgumentException(
          s"$AllowedVariable removes ${removal.spelled}, which matches neither the baseline " +
            "nor an addition; a '-' that removes nothing is refused",
        )

    // Provenance rides along with the transformation itself: each host carries the label of the
    // last rule that actually changed it, and a delta rule is reported as a removal only when it
    // removed a host that was present when it applied. A rule the profile never consults, or one
    // that restates what already held — re-adding a baseline host with its baseline treatment,
    // removing under -** what -** already cleared — changes nothing and is reported
    // nowhere.
    // A host in the catalog and in a group at once names both sources: its tags came from both.
    def baselineSource(host: String): String =
      (Option.when(CuratedRestrictedHosts.contains(host))("curated baseline")
        ++ ModelProviderHosts.collect { case (name, hosts) if hosts.contains(host) => s"model-provider $name" })
        .mkString(", ")

    def overlay(
      current: Map[String, (Treatment, String)],
      host: String,
      treatment: Treatment,
      source: String,
    ): Map[String, (Treatment, String)] =
      current.get(host) match
        case Some((standing, _)) if standing == treatment => current
        case _ => current.updated(host, (treatment, source))

    // A group's restricted entry contributes its tags to a host the catalog already restricts, as
    // BaselineHosts merged them: `+model-provider github` over the baseline is a no-op, not a
    // second grant of github.com's allowances. Removing the group takes back only what it contributed.
    def addGroup(current: Map[String, (Treatment, String)], name: String, source: String) =
      ModelProviderHosts(name).foldLeft(current):
        case (current, (host, Treatment.Restricted(scopes))) =>
          current.get(host) match
            case Some((Treatment.Restricted(standing), _)) if Scope.merged(standing, scopes) == standing => current
            case Some((Treatment.Restricted(standing), _)) =>
              current.updated(host, (Treatment.Restricted(Scope.merged(standing, scopes)), source))
            case _ => current.updated(host, (Treatment.Restricted(scopes), source))
        case (current, (host, treatment)) => overlay(current, host, treatment, source)
    def removeGroup(current: Map[String, (Treatment, String)], name: String) =
      ModelProviderHosts(name).keys.foldLeft(current): (current, host) =>
        CuratedRestrictedHosts.get(host) match
          case Some(tags) if current.contains(host) =>
            current.updated(host, (Treatment.restricted(tags), "curated baseline"))
          case _ => current - host

    // A: the allowed delta applied to B, in the delta's fixed order. Additions land last, so an
    // exact entry overrides the baseline's treatment of the same host (the widening direction was
    // refused above).
    val cleared: Map[String, (Treatment, String)] =
      if delta.clearsBaseline then Map.empty
      else BaselineHosts.map((host, treatment) => host -> (treatment, baselineSource(host)))
    val afterProviderRemovals = delta.removedProviders.toVector.sorted.foldLeft(cleared)(removeGroup)
    val withAddedProviders =
      delta.addedProviders.toVector.sorted.foldLeft(afterProviderRemovals): (current, name) =>
        addGroup(current, name, s"allowed +model-provider $name")
    // Sequentially, each rule judged against the map as the rules before it left it: of two
    // overlapping removals, only the first removes anything, and only it is reported.
    val (afterRemovals, effectiveHostRemovals) =
      delta.removals.foldLeft((withAddedProviders, Vector.empty[String])):
        case ((current, effective), rule) =>
          val remaining = current.filterNot((host, _) => rule.matches(host))
          (remaining, if remaining.size < current.size then effective :+ rule.spelled else effective)
    val admitted = delta.addedHosts.toVector.sortBy(_(0)).foldLeft(afterRemovals):
      case (current, (host, treatment)) => overlay(current, host, treatment, "allowed +host")

    val effectiveRemovals =
      Option.when(delta.clearsBaseline)("-** (baseline cleared)").toVector
        ++ delta.removedProviders.toVector.sorted
          .filter(name => cleared.keys.exists(ModelProviderHosts(name).contains))
          .map(name => s"model-provider:$name")
        ++ effectiveHostRemovals

    // N: what stays restricted under allow-unless-denied — every restricted baseline entry, a
    // group's included, so github.com keeps allow=github-login-device. Only additions extend it; nothing in
    // the delta subtracts from it, so a removal or `-**` cannot widen an ambient host.
    val narrowed: Map[String, (Treatment, String)] =
      delta.addedHosts.toVector.sortBy(_(0))
        .filter((_, treatment) => treatment != Treatment.Unrestricted)
        .foldLeft(
          BaselineHosts.collect { case (host, treatment @ Treatment.Restricted(_)) =>
            host -> ((treatment: Treatment) -> baselineSource(host))
          },
        ):
          case (current, (host, treatment)) => overlay(current, host, treatment, "allowed +host")

    val (preDenyWithSources, ambient) = profile match
      case "deny-all" => (Map.empty[String, (Treatment, String)], false)
      case "deny-unless-model" =>
        (
          provider.fold(Map.empty[String, (Treatment, String)])(name =>
            ModelProviderHosts(name).map((host, treatment) => host -> (treatment, s"model-provider $name")),
          ),
          false,
        )
      case "deny-unless-allowed" => (admitted, false)
      case "allow-unless-denied" => (narrowed, true)

    val preDeny = preDenyWithSources.view.mapValues(_(0)).toMap
    val sources = preDenyWithSources.view.mapValues(_(1)).toMap

    val deniedAdmitted: Map[String, DenyRule] =
      preDeny.keys.toVector.flatMap(host => denied.find(_.matches(host)).map(host -> _)).toMap

    // deny-all warns about nothing: its denials are idle by definition. Under
    // allow-unless-denied every syntactically valid rule matches the ambient universe.
    val idleDenied =
      if profile == "deny-all" || ambient then Vector.empty
      else denied.filterNot(rule => preDeny.keys.exists(rule.matches))

    val hosts = preDeny.filterNot((host, _) => deniedAdmitted.contains(host))

    val warnings =
      provider.toVector.flatMap: selected =>
        val unreachable = ModelProviderHosts(selected).keys.toVector.sorted.filterNot: host =>
          !denied.exists(_.matches(host)) && (hosts.contains(host) || ambient)
        Option.when(unreachable.nonEmpty)(
          s"the selected model provider '$selected' is not fully reachable under $profile: " +
            unreachable.mkString(" "),
        )
      ++ Option.when(idleDenied.nonEmpty)(
        "denied rules matching nothing this profile admits (kept: they can apply under " +
          s"another profile or a future provider expansion): ${idleDenied.map(_.spelled).mkString(" ")}",
      )

    // Only deny-unless-allowed consults the removal side of the delta; under every other profile
    // even an effective-looking removal shaped nothing.
    val activeRemovals =
      if profile == "deny-unless-allowed" then effectiveRemovals else Vector.empty[String]

    // The delta entries reaching past the baseline this image ships — `-**`; a host the
    // baseline lacks, whatever its treatment; a restricted baseline host re-added unrestricted,
    // which only `-**` lets through; an allowance the baseline entry lacks — spelled as entries,
    // for the launcher to print on a line of their own from this resolution rather than from a
    // baseline of its own that a custom image would not share. A baseline tunnel restated or
    // narrowed to inspected reads widens nothing. Under every other profile the delta shapes
    // nothing, or under the ambient one only narrows, so nothing widens there.
    def entriesOf(host: String, treatment: Treatment): Vector[(Scope, String)] = treatment match
      case Treatment.Unrestricted       => Vector(Scope(None, Set.empty) -> s"+host $host unrestricted")
      case Treatment.Restricted(scopes) =>
        scopes.toVector.sortBy(_.prefix).map(scope => scope -> (s"+host $host" +: scope.attributes).mkString(" "))
    val widening =
      if profile != "deny-unless-allowed" then Vector.empty[String]
      else
        Option.when(delta.clearsBaseline)("-**").toVector
          ++ delta.addedHosts.toVector.sortBy(_(0)).flatMap: (host, treatment) =>
            val entries = entriesOf(host, treatment)
            (BaselineHosts.get(host), treatment) match
              case (None, _)                                                  => entries.map(_(1))
              case (Some(Treatment.Unrestricted), _)                          => Vector.empty
              case (Some(Treatment.Restricted(_)), Treatment.Unrestricted)    => entries.map(_(1))
              case (Some(Treatment.Restricted(standing)), Treatment.Restricted(_)) =>
                val baselineTags = standing.flatMap(_.tags)
                entries.collect { case (scope, entry) if !scope.tags.subsetOf(baselineTags) => entry }

    ResolvedEgress(
      profile, provider, ambient, hosts, denied, idleDenied, warnings,
      sources, deniedAdmitted, activeRemovals, widening,
    )

  private def requireProvider(variable: String, name: String): String =
    if !ModelProviderHosts.contains(name) then
      throw IllegalArgumentException(
        s"$variable names the model provider '$name', which this proxy does not define; " +
          s"the providers are ${ModelProviderHosts.keys.toVector.sorted.mkString(", ")}",
      )
    name

  /**
   * The allowances of one `allow=<tag>,...` word: KnownTags members only, so a tag names a fixed
   * treatment, and never empty — `allow=` saying nothing is refused, not read as none.
   */
  private def parseAllowances(variable: String, host: String, value: String): Set[String] =
    val tags = value.split(",", -1).toVector
    tags.foreach: tag =>
      if !KnownTags.contains(tag) then
        throw IllegalArgumentException(
          s"$variable allows '$host' the operation '$tag', which this proxy does not define; " +
            s"the allowances are: ${KnownTags.toVector.sorted.mkString(", ")}",
        )
    tags.toSet

  /**
   * The form a `path=` prefix must be in, so that what is compared is what was reviewed: begins
   * and ends with `/`, printable ASCII — the request path is bytes, and a wider character has no
   * one spelling on the wire — and none of the spellings the request gate refuses
   * (GitHelper.literalPathProblem), nor a query — a fragment cannot be written, `#` opening a
   * comment (policyEntries). `path=/` narrows nothing and is refused as a second spelling of no
   * prefix. Case is kept as written: the origin's, which the proxy does not know (SECURITY.md,
   * "Adding hosts, not patterns").
   */
  private def parsePathPrefix(variable: String, host: String, prefix: String): String =
    def refuse(problem: String): Nothing =
      throw IllegalArgumentException(
        s"$variable narrows $host to 'path=$prefix', which $problem; a prefix begins and ends " +
          "with /, and has no percent-encoding, backslash, empty, . or .. segment, or query",
      )
    if prefix == "/" then refuse("narrows nothing: omit path= for the whole host")
    if !prefix.startsWith("/") then refuse("does not begin with /")
    if !prefix.endsWith("/") then refuse("does not end with /")
    if prefix.exists(ch => ch < 0x21 || ch > 0x7e) then refuse("has a character outside printable ASCII")
    if prefix.contains('?') then refuse("has a query")
    literalPathProblem(prefix).foreach(problem => refuse(s"has $problem"))
    prefix

  /** An allowance whose fixed paths (AllowancePaths) lie outside the entry's prefix would be
    * granted and never open: refused at launch, naming both. */
  private def requireAllowancesUnder(variable: String, host: String, prefix: String, tags: Set[String]): Unit =
    tags.toVector.sorted.foreach: tag =>
      val outside = AllowancePaths(tag).filterNot(_.startsWith(prefix)).toVector.sorted
      if outside.nonEmpty then
        throw IllegalArgumentException(
          s"$variable gives $host allow=$tag under path=$prefix, which does not contain " +
            s"${outside.mkString(" ")}; the allowance would open nothing there — put it on an " +
            "entry whose prefix contains its paths",
        )

  private def parseHostAddition(variable: String, entry: String, words: Vector[String]): (String, Treatment) =
    val host = normalizeEntry(variable, entry)
    val attributes = Set("allow", "path")
    def attribute(name: String): Option[String] =
      words.filter(_.startsWith(name + "=")) match
        case Vector()     => None
        case Vector(word) => Some(word.drop(name.length + 1))
        case _ =>
          throw IllegalArgumentException(s"$variable gives $host two $name= words; one word states the whole value")
    words match
      case Vector()               => host -> Treatment.restricted()
      case Vector("unrestricted") => host -> Treatment.Unrestricted
      case _ if words.contains("unrestricted") =>
        val narrowing = if words.exists(_.startsWith("path=")) then "a path" else "an allowance"
        throw IllegalArgumentException(
          s"$variable gives the unrestricted host $host $narrowing; an opaque tunnel has no path and " +
            "no operation to open, so path= and allow= belong on a restricted entry only",
        )
      case _ if words.contains("restricted") =>
        throw IllegalArgumentException(
          s"$variable spells $host's treatment 'restricted', which is the default and " +
            "has no word: +host <host>, or +host <host> [path=/<prefix>/] [allow=<tag>,...]",
        )
      case _ if words.forall(word => attributes.exists(name => word.startsWith(name + "="))) =>
        val tags = attribute("allow").fold(Set.empty[String])(parseAllowances(variable, host, _))
        val prefix = attribute("path").map(parsePathPrefix(variable, host, _))
        prefix.foreach(requireAllowancesUnder(variable, host, _, tags))
        host -> Treatment.Restricted(Set(Scope(prefix, tags)))
      case other =>
        throw IllegalArgumentException(
          s"$variable follows $host with '${other.mkString(" ")}'; the forms are " +
            "+host <host>, +host <host> [path=/<prefix>/] [allow=<tag>,...], +host <host> unrestricted",
        )

  /**
   * One host's `+host` entries as its treatment. Restricted entries with different prefixes are
   * that many scopes — their reach unions, each allowance stays with the prefix it was written on —
   * and must be disjoint: nested, a whole-host entry beside a prefixed one included, a request
   * under both would take its scope from selection order or from pooling, either being reach no
   * single line says. Two entries for one scope with different words, or an unrestricted entry
   * beside any other, are one host with two treatments, refused.
   */
  private def mergeAdditions(host: String, treatments: Vector[Treatment]): Treatment =
    val scopes = treatments.collect { case Treatment.Restricted(scopes) => scopes }.flatten.distinct
    if treatments.sizeIs == 1 then treatments.head
    else if scopes.size < treatments.size || scopes.map(_.prefix).distinct.size < scopes.size then
      throw IllegalArgumentException(
        s"$AllowedVariable adds $host with two different treatments; " +
          "an entry states its host's complete treatment, once",
      )
    else
      scopes.combinations(2).foreach: pair =>
        val (inner, outer) = if pair(0).within(pair(1)) then (pair(0), pair(1)) else (pair(1), pair(0))
        if inner.within(outer) then
          throw IllegalArgumentException(
            outer.prefix match
              case None =>
                s"$AllowedVariable adds $host whole and under path=${inner.prefix.get}; the " +
                  "whole-host entry already contains the prefix, and a request under both would " +
                  "have two scopes — keep one entry"
              case Some(wider) =>
                s"$AllowedVariable narrows $host to path=${inner.prefix.get} inside path=$wider; " +
                  "a request under both would have two scopes — make the prefixes disjoint, or " +
                  "keep the wider one",
          )
      Treatment.Restricted(scopes.toSet)

  private enum AllowedEntry:
    case ClearBaseline
    case AddProvider(name: String)
    case RemoveProvider(name: String)
    case AddHost(host: String, treatment: Treatment)
    case RemoveHost(removal: DenyRule)

  private case class AllowedDelta(
    clearsBaseline: Boolean,
    addedProviders: Set[String],
    removedProviders: Set[String],
    addedHosts: Map[String, Treatment],
    removals: Vector[DenyRule],
  )

  /**
   * The `allowed` delta's grammar, one entry per line, `#` comments:
   *
   *   +model-provider <name>            -model-provider <name>
   *   +host <host>                      restricted, the default: TLS-inspected, GET and HEAD
   *   +host <host> allow=<tag>,...      restricted, plus the named allowances (KnownTags)
   *   +host <host> path=/<prefix>/      restricted under the prefix only (Scope); with allow=
   *                                     in either order, the allowances hold there only
   *   +host <host> unrestricted         an opaque tunnel — the one word that widens
   *   -host <host | **.domain>
   *   -**                               removes the whole baseline, wherever it appears
   *
   * The safe treatment has no word, so the dangerous one is the only entry with an extra word;
   * `restricted` spelled out is refused rather than accepted as a second spelling. `-**` is a
   * flag, not a rule in sequence — the file is not applied top to bottom (resolvePolicy) — so
   * the file's own additions stand above or below it.
   *
   * An entry outside the grammar is refused, never skipped: a stray line configures nothing,
   * which is the silent-weakening failure mode this file must not have. An addition states its
   * host's complete allowances and overrides the baseline entry for the same host — never a
   * merge, which would widen a host to a treatment no single line says. Several `path=` entries
   * for one host are the one exception, each its own scope (mergeAdditions); two entries for one
   * host or scope with different treatments or allowances are refused; restating a baseline
   * entry identically stays the legal defensive no-op, so a policy that names a host keeps
   * working when the image adopts it.
   */
  private def parseAllowed(text: String): AllowedDelta =
    import AllowedEntry.*
    val entries = policyEntries(AllowedVariable, text).map:
      case Vector("-**")                   => ClearBaseline
      case Vector("+model-provider", name) => AddProvider(requireProvider(AllowedVariable, name))
      case Vector("-model-provider", name) => RemoveProvider(requireProvider(AllowedVariable, name))
      case "+host" +: entry +: words =>
        val (host, treatment) = parseHostAddition(AllowedVariable, entry, words)
        AddHost(host, treatment)
      case Vector("-host", entry) => RemoveHost(parseHostRule(AllowedVariable, entry))
      case tokens =>
        throw IllegalArgumentException(
          s"$AllowedVariable contains '${tokens.mkString(" ")}', which is no entry of the " +
            "allowed grammar: +model-provider <name>, -model-provider <name>, " +
            "+host <host> [path=/<prefix>/] [allow=<tag>,... | unrestricted], -host <host | **.domain>, -**",
        )

    val added = entries.collect { case AddHost(host, treatment) => (host, treatment) }.distinct
    val addedHosts = added.groupMap(_(0))(_(1)).toVector.sortBy(_(0)).map: (host, treatments) =>
      host -> mergeAdditions(host, treatments)

    val addedProviders = entries.collect { case AddProvider(name) => name }.toSet
    val removedProviders = entries.collect { case RemoveProvider(name) => name }.toSet
    val bothWays = (addedProviders intersect removedProviders).toVector.sorted
    if bothWays.nonEmpty then
      throw IllegalArgumentException(
        s"$AllowedVariable both adds and removes model-provider ${bothWays.mkString(", ")}",
      )

    AllowedDelta(
      entries.contains(ClearBaseline),
      addedProviders,
      removedProviders,
      addedHosts.toMap,
      entries.collect { case RemoveHost(removal) => removal },
    )

  /**
   * The `denied` file's grammar, one entry per line, `#` comments — no `+`/`-` prefixes and no
   * `allow=`, because denied only ever takes away, the host whole, under every profile:
   *
   *   model-provider <name>
   *   host <host | **.domain>
   */
  private def parseDenied(text: String): Vector[DenyRule] =
    policyEntries(DeniedVariable, text)
      .map:
        case Vector("model-provider", name) =>
          DenyRule.Provider(requireProvider(DeniedVariable, name))
        case Vector("host", entry) => parseHostRule(DeniedVariable, entry)
        case tokens =>
          throw IllegalArgumentException(
            s"$DeniedVariable contains '${tokens.mkString(" ")}', which is no entry of the " +
              "denied grammar: model-provider <name>, host <host | **.domain>",
          )
      .distinct

  private def parseHostRule(variable: String, entry: String): DenyRule =
    if entry.startsWith("**.") then DenyRule.Subtree(normalizeEntry(variable, entry.drop(3)))
    else DenyRule.Exact(normalizeEntry(variable, entry))

  /** A policy file's lines as token vectors: blank lines vanish, tokens split on whitespace —
    * never comma, which stays inside its token and fails hostname validation instead of
    * silently becoming two entries — and `#` starts a comment at the start of a line or after
    * whitespace only. Inside a token it is refused: cut there, `path=/my-bucket/#private/`
    * would read as `path=/my-bucket/`, an entry admitting more than it says. */
  private def policyEntries(variable: String, text: String): Vector[Vector[String]] =
    text.linesIterator
      .map(_.split("\\s+").toVector.filter(_.nonEmpty).takeWhile(!_.startsWith("#")))
      .filter(_.nonEmpty)
      .map: tokens =>
        tokens.find(_.contains('#')).foreach: token =>
          throw IllegalArgumentException(
            s"$variable contains '$token', a token with '#' inside it; a comment starts at the " +
              "start of a line or after whitespace, and nothing else contains '#'",
          )
        tokens
      .toVector

  private def normalizeEntry(variable: String, entry: String): String =
    val host =
      try normalizeHost(entry)
      catch
        case ex: BadRequest =>
          throw IllegalArgumentException(
            s"$variable contains an invalid hostname '$entry': ${ex.getMessage}",
          )

    if isIpLiteral(host) then
      throw IllegalArgumentException(
        s"$variable contains an IP literal '$entry'; only hostnames are allowed",
      )

    host

  /** A treatment as entries, one per scope. */
  def spelled(treatment: Treatment): Vector[String] = treatment match
    case Treatment.Restricted(scopes) => scopes.toVector.map(_.spelled).sorted
    case Treatment.Unrestricted       => Vector("unrestricted")

  /**
   * The resolved policy, one line each — printed by --print-policy and
   * logged by serve() identically, so the dry-run banner, the runtime
   * log and the launcher's leaf minting all read one format. The restricted
   * line is the whole inspected set, one token per scope — `host`, or
   * `host/prefix/` for an entry narrowed by `path=` (Scope.token), the host part
   * being what the leaf certificate names — and each allowance in force gets a
   * line of its own (`restricted allow=git-fetch (7): ...`) in the same tokens,
   * so which scopes carry which exception is read off directly. Under
   * allow-unless-denied there is no finite unrestricted line to print — the
   * profile line carries the public-HTTPS default instead, and no host count
   * is invented.
   */
  def policyLines(resolved: ResolvedEgress): Vector[String] =
    val profileLine = resolved.profile match
      case "deny-unless-model" =>
        s"egress profile: deny-unless-model; model provider: ${resolved.provider.getOrElse("none")}"
      case "allow-unless-denied" =>
        "egress profile: allow-unless-denied; default: public HTTPS unrestricted"
      case other => s"egress profile: $other"

    val restrictedTokens = resolved.scopeTokens()
    val allowanceLines = resolved.restricted.values.flatten.flatMap(_.tags).toVector.distinct.sorted.map: tag =>
      val tokens = resolved.scopeTokens(Some(tag))
      s"restricted allow=$tag (${tokens.size}):" + tokens.map(" " + _).mkString
    val unrestrictedLine = Option.when(!resolved.ambient)(
      s"unrestricted hosts (${resolved.unrestrictedHosts.size}):"
        + resolved.unrestrictedHosts.toVector.sorted.map(" " + _).mkString,
    )

    Vector(
      profileLine,
      s"restricted hosts (${restrictedTokens.size}):" + restrictedTokens.map(" " + _).mkString,
    ) ++ allowanceLines ++ unrestrictedLine ++ Vector(
      s"denied rules (${resolved.denied.size}):"
        + resolved.denied.map(" " + _.spelled).mkString,
    ) ++ Option.when(resolved.idleDenied.nonEmpty)(
      s"idle denied rules (${resolved.idleDenied.size}):"
        + resolved.idleDenied.map(" " + _.spelled).mkString,
    )

  /** The delta entries reaching past the baseline (ResolvedEgress.widening), printed after the
    * policy lines and outside their digest: it describes how the file arrived at the policy, not
    * the policy, and two files resolving to one policy keep one digest. Entries, so `; ` separates
    * them where the policy lines separate hosts by a space. */
  def wideningLine(resolved: ResolvedEgress): Option[String] =
    Option.when(resolved.widening.nonEmpty)(
      s"widening entries (${resolved.widening.size}): " + resolved.widening.mkString("; "),
    )

  /**
   * Where each effective entry came from — built-in provider group or curated catalog, `allowed`
   * addition, `denied` — and what overrode what: a removal or denial that costs a host is a line
   * here, never a silent subtraction. Printed by `--print-policy --provenance`, which is what
   * `--egress-effective` runs.
   */
  def provenanceLines(resolved: ResolvedEgress): Vector[String] =
    def sourceOf(host: String): String = resolved.sources(host)

    val hostLines = resolved.hosts.toVector.sorted(using Ordering.by(_(0))).flatMap: (host, treatment) =>
      spelled(treatment).map(entry => s"  $host: $entry; ${sourceOf(host)}")
    val deniedOverrides = resolved.deniedAdmitted.toVector.sortBy(_(0)).map: (host, rule) =>
      s"  $host: denied by ${rule.spelled}; ${sourceOf(host)}"
    val removalLines = resolved.removedSpellings.map(spelling => s"  $spelling: removed by allowed")
    val idleLines = resolved.idleDenied.map(rule => s"  ${rule.spelled}: denies nothing this profile admits (idle)")

    Vector("provenance:") ++ hostLines ++ deniedOverrides ++ removalLines ++ idleLines

  /**
   * What "read access" means once TLS is terminated. Everywhere: GET and
   * HEAD to any path, bodyless. Each of the host's tags additionally admits
   * its POSTs: `allow=git-fetch` the git-upload-pack path, without which "read
   * access" would silently exclude `git clone`; `allow=npm-audit` the audit
   * endpoint npm hits during install (NpmAuditPath); `allow=github-login-device` the
   * device-flow pair (GithubLoginDevicePaths). On a host without it, no
   * POST at all: a path there is an object name anyone can choose, so a
   * path rule authorizes nothing.
   *
   * Receive-pack discovery, the LFS batch endpoint and GraphQL stay refused:
   * SECURITY.md, "Reading without being able to write".
   *
   * On a host narrowed by `path=`, all of that holds within the scope whose prefix the
   * path begins with, and the path is compared literally — after refusing every
   * spelling an origin might read as another path (requireLiteralPath), on every
   * method, since the proxy cannot know how the origin decodes. A path in no scope
   * is refused: the scopes are disjoint (mergeAdditions), so the one found is the
   * one, and its allowances alone reach the method rule.
   */
  def authorizeInspectedRequest(
    host: String,
    head: HttpRequestHead,
    hostScopes: Set[Scope],
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

    val prefixes = hostScopes.flatMap(_.prefix)
    if prefixes.nonEmpty then requireLiteralPath(head.path)
    val hostTags = hostScopes.find(_.admits(head.path)) match
      case Some(scope)              => scope.tags
      case None if prefixes.isEmpty => Set.empty[String]
      case None => throw PolicyViolation("path outside allowance", RefusalAdvice.pathOutside(prefixes))

    head.method match
      case "GET" | "HEAD" =>
        // a body on a read method would be an unbounded, unlogged client-to-server channel
        if head.bodyFraming != BodyFraming.Empty then
          throw PolicyViolation("request body", RefusalAdvice.requestBody)

        if isReceivePackDiscovery(head) then
          throw PolicyViolation("git push ref discovery", RefusalAdvice.gitPush)

      case "POST" =>
        requireUnambiguousPath(head.path)

        val opened =
          (hostTags.contains("git-fetch") && isUploadPack(head.path))
            || (hostTags.contains("npm-audit") && head.path == NpmAuditPath)
            || (hostTags.contains("github-login-device") && GithubLoginDevicePaths.contains(head.path))
        if !opened then
          throw PolicyViolation(
            if hostTags.isEmpty then "restricted host" else "restricted path",
            RefusalAdvice.forRefusedPost(host, head.path, admitted),
          )

      case _ =>
        throw PolicyViolation("restricted host", RefusalAdvice.readOnly)

  /*
   * The IP-literal rejection is defence in depth for the finite profiles — their maps cannot
   * contain one and resolvePublic rejects private answers — and under the ambient profile it is
   * the named refusal a literal target gets. Denial wins over both treatments and over the
   * ambient default.
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

    resolved.denied.find(_.matches(host)).foreach: rule =>
      throw PolicyViolation(s"host denied (${rule.spelled})", RefusalAdvice.hostDenied)

    if !resolved.hosts.contains(host) && !resolved.ambient then
      throw PolicyViolation("host not allowed", RefusalAdvice.hostNotAllowed(host, resolved.profile))

    host
