// The second layer over AgentEgressProxyTest: the parsers under hostile and randomized input,
// aimed at parser disagreement, canonicalization and fail-open policy parsing rather than at more
// examples of rules that file already pins — and the reference evaluator the resolved policy is
// property-tested against. Where a rule is pinned there, this file asserts only
// what it adds — the two Smokescreen bypasses and the alternate IPv4 spellings live there, and this
// is the wider corpus around them.
//
// The randomized tests count both outcomes and assert each happened. A generator that drifts into
// refusing everything leaves the branch that matters unexecuted, and the suite would keep passing.
//
// The randomized tests seed a plain `scala.util.Random` rather than pulling in a property library:
// the proxy's dependency list is part of its attack surface, and a fixed seed buys reproducibility
// for the one line it costs.

package agentsandbox.egress

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import scala.util.Random

import PolicyHelper.*
import HTTPHelper.*
import IPAddrHelper.*
import TLSHelper.*

class HostileInputTest extends munit.FunSuite:

  private def ascii(value: String): Array[Byte] = value.getBytes(StandardCharsets.US_ASCII)

  private def connect(authority: Array[Byte]): Array[Byte] =
    ascii("CONNECT ") ++ authority ++ ascii(" HTTP/1.1\r\n\r\n")

  private lazy val defaultsPolicy: ResolvedEgress =
    resolvePolicy(Some("deny-unless-allowed"), None, None)

  private def authorize(authority: Array[Byte]): String =
    authorizeRequest(ConnectRequest.parse(connect(authority)), defaultsPolicy)

  /** "refused" for either typed refusal, the reached host otherwise. An untyped exception escapes
    * and fails the test: a parser that throws something else has read hostile bytes badly, which is
    * the failure mode this file exists to catch. */
  private def outcomeOf(authority: Array[Byte]): String =
    try s"reached ${authorize(authority)}"
    catch
      case _: BadRequest      => "refused"
      case _: PolicyViolation => "refused"

  private def printable(value: String): String =
    value.map(ch => if ch < 0x20 || ch > 0x7e then f"\\u${ch.toInt}%04x" else ch).mkString

  private val RefusedAuthorities = Vector(
    // Malformed bracket/port combinations. A bracketed *hostname* is accepted and canonicalized
    // (AgentEgressProxyTest pins that, the Smokescreen bypass class); these are the cases where
    // the brackets do not close a name at all.
    "[]:443",
    "[github.com]",
    "[github.com]443",
    "[github.com:443",
    "github.com]:443",
    "[[github.com]]:443",

    // IPv6, IPv4-mapped IPv6 and zone identifiers. Every one contains a colon, which the hostname
    // rules refuse outright, so none of them reaches the IP-literal check behind it.
    "[2001:db8::1]:443",
    "[::ffff:127.0.0.1]:443",
    "[::ffff:7f00:1]:443",
    "::ffff:127.0.0.1:443",
    "[fe80::1%eth0]:443",
    "[fe80::1%25eth0]:443",

    // Control and whitespace characters, inside the authority and around its port.
    "git hub.com:443",
    "github.com: 443",
    "github.com\t:443",
    "github.com\u0000:443",
    "github.com\u0007:443",
    "github.com\u001b:443",
    "github.com\u007f:443",
    "\u0000github.com:443",

    // Unusual authority forms: userinfo, a second port, a missing one, an out-of-range one.
    "user@github.com:443",
    "github.com:443:443",
    ":443",
    "github.com:",
    "github.com:65536",
    "github.com:0",
    "github.com:-1",
    "github.com:44 3",

    // Canonicalization: normalizeHost strips one trailing dot, so a doubled one leaves a name the
    // policy does not hold. Refused rather than reduced again — the fail-closed direction.
    "github.com..:443",

    // Percent-encoding means nothing in an authority, and a punycode label nobody allowed is
    // nobody's host.
    "github%2ecom:443",
    "xn--a.example:443",

    // An IP literal in a spelling the last-label rule catches without enumerating the resolver's
    // numeric forms.
    "0x7f.0.0.1:443",
  )

  /** Forms one parser accepts and another would not, which reach an allowed host all the same:
    * Java takes a leading `+` and leading zeros in a port, so both spell 443. Pinned because they
    * are surprising, not because they are dangerous — the proxy dials the port it parsed. */
  private val ReachingAuthorities = Vector(
    "github.com:443" -> "github.com",
    "github.com:0443" -> "github.com",
    "github.com:+443" -> "github.com",
  )

  test("no authority in the hostile corpus reaches a host"):
    RefusedAuthorities.foreach: authority =>
      assertEquals(outcomeOf(ascii(authority)), "refused", printable(authority))

  test("the surprising-but-accepted authority forms reach exactly one canonical host"):
    ReachingAuthorities.foreach: (authority, host) =>
      assertEquals(outcomeOf(ascii(authority)), s"reached $host", printable(authority))

  test("the CONNECT path is ASCII-only, so IDN mapping never runs on anything from the wire"):
    // normalizeHost maps confusables to ASCII — nameprep folds a fullwidth `g` to `g` and an
    // ideographic full stop to a dot, and drops zero-width characters — so on paper these spell
    // `github.com`. Over the wire they never get that far: the bytes arrive as UTF-8, decode as
    // ISO-8859-1 into characters above 0x7f, and the authority is refused before any mapping.
    // The mapping is reachable only from a policy file, where an operator wrote the name.
    Vector("\uff47ithub.com:443", "GITHUB\u3002com:443", "github\u200b.com:443", "\u00adgithub.com:443")
      .foreach: authority =>
        assertEquals(
          outcomeOf(authority.getBytes(StandardCharsets.UTF_8)),
          "refused",
          printable(authority),
        )
    assertEquals(normalizeHost("\uff47ithub.com"), "github.com")
    assertEquals(normalizeHost("GITHUB\u3002com"), "github.com")
    assertEquals(normalizeHost("github\u200b.com"), "github.com")

  test("an authorized host is a fixed point of normalization, and never an IP literal"):
    // Not "normalization is idempotent" — it is not. One trailing dot is stripped per pass, so
    // `github.com..` becomes `github.com.`, which another pass would reduce again. That
    // non-idempotence fails closed, because the once-normalized form is what the policy is
    // compared against and it is not in it. What has to hold is the property enforcement rests
    // on: whatever authorizeRequest returns is unchanged by normalizing it again, since that is
    // the name later resolved and bound to SNI.
    assertEquals(normalizeHost("github.com.."), "github.com.")
    assertNotEquals(normalizeHost(normalizeHost("github.com..")), normalizeHost("github.com.."))
    DefaultHosts.keySet.foreach: host =>
      assertEquals(normalizeHost(host), host, host)
      assert(!isIpLiteral(host), host)

  test("the hostname policy authorized is the one SNI is bound to"):
    // A mismatched SNI and an encrypted one are AgentEgressProxyTest's; what is added here is the
    // join between the two halves — that the name authorizeRequest *returned* is the one the
    // binding is made against, whichever spelling asked for it.
    val spellings = Vector("github.com", "GitHub.COM", "github.com.")
    spellings.foreach: spelling =>
      val authorized = authorize(ascii(s"$spelling:443"))
      assertEquals(authorized, "github.com", spelling)
      spellings.foreach: sni =>
        validateTlsIdentity(authorized, TlsClientHello(Array.emptyByteArray, Some(sni), false))

  // ---------------------------------------------------------------------------
  // Randomized boundaries
  // ---------------------------------------------------------------------------

  private val random = Random(20260816)

  private val Noise = Vector(
    '[', ']', '@', '%', ':', '.', ' ', '\t', '\r', '\n', '+', '-', '0', '\u0000', '\u007f',
  )

  /** Mutations of a real authority, never uniform noise: a uniform draw is refused at its first
    * character, which leaves the branch that matters — a draw that *does* reach a host — never
    * executed, and a fuzz test whose interesting branch never runs passes for the wrong reason. */
  private def mutate(value: String): String =
    if value.isEmpty then Noise(random.nextInt(Noise.size)).toString
    else
      val at = random.nextInt(value.length)
      val noise = Noise(random.nextInt(Noise.size))
      random.nextInt(5) match
        case 0 => value.take(at) + noise + value.drop(at)
        case 1 => value.take(at) + value.drop(at + 1)
        case 2 => value.take(at) + noise + value.drop(at + 1)
        case 3 => "[" + value + "]"
        case _ => value.map(ch => if random.nextBoolean() then ch.toUpper else ch)

  test("no mutation of a real authority authorizes anything outside the defaults"):
    val seeds = Vector("github.com:443", "pypi.org:443", "api.anthropic.com:443")
    var reached = 0
    var refused = 0
    (1 to 3000).foreach: _ =>
      val authority = (0 to random.nextInt(3))
        .foldLeft(seeds(random.nextInt(seeds.size)))((value, _) => mutate(value))
      try
        val host = authorize(ascii(authority))
        assert(DefaultHosts.contains(host), s"reached '$host' from '${printable(authority)}'")
        assert(!isIpLiteral(host), s"authorized the IP literal '$host'")
        assertEquals(normalizeHost(host), host, s"'$host' is not a fixed point")
        reached += 1
      catch
        case _: BadRequest | _: PolicyViolation => refused += 1
    assert(reached > 0, "no mutation reached a host; the generator stopped producing near-misses")
    assert(refused > 0, "no mutation was refused; the generator stopped mutating")

  test("a path that would select a refusal's advice is refused at the parser when it contains a control"):
    // RefusalAdvice.forRefusedPost reads HttpRequestHead.path, so no advice is ever chosen for a
    // target the audit log would refuse to print; and the absolute form is refused before the
    // path is looked at, with the origin-form step, not GraphQL's.
    Vector("/graphql\u0007", "/graphql\u001b[0m", "/o/r.git/info/lfs/objects/batch\t").foreach: path =>
      intercept[BadRequest]:
        HttpRequestHead.parse(ascii(s"POST $path HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"))
    val absolute = intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "github.com",
        HttpRequestHead.parse(
          ascii("POST https://github.com/graphql HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"),
        ),
        Map("/" -> Set("read", "git-fetch")),
      )
    assertEquals(absolute.advice, RefusalAdvice.originForm)

  test("the TLS parser survives arbitrary bytes"):
    // Nothing else feeds the ClientHello parser bytes it did not build itself. A typed refusal or
    // an EOF is the whole contract; anything else escapes and fails.
    (1 to 500).foreach: _ =>
      val bytes = Array.fill(random.nextInt(96))(random.nextInt(256).toByte)
      try
        TlsClientHello.read(ByteArrayInputStream(bytes), 512)
        ()
      catch
        case _: BadTls | _: java.io.EOFException => ()

  test("an inspected request has exactly one message boundary, and never a close-delimited one"):
    val framings = Vector(
      Vector.empty,
      Vector("Content-Length: 0"),
      Vector("Content-Length: 5"),
      Vector("Content-Length: 5", "Content-Length: 5"),
      Vector("Content-Length: 5", "Content-Length: 6"),
      Vector("Content-Length: -1"),
      Vector("Content-Length: 5x"),
      Vector("Content-Length:"),
      Vector("Transfer-Encoding: chunked"),
      Vector("Transfer-Encoding: gzip"),
      Vector("Transfer-Encoding: chunked", "Transfer-Encoding: chunked"),
      Vector("Content-Length: 5", "Transfer-Encoding: chunked"),
    )
    // Which of these are refused is AgentEgressProxyTest's; the refusals are swallowed here. What
    // is added is what holds of the ones that are *not* refused: the answer is stable, and it is
    // never the response-only framing whose request forwarder throws on sight.
    var framed = 0
    framings.foreach: headers =>
      val request =
        ("POST /x HTTP/1.1" +: "Host: github.com" +: headers).mkString("", "\r\n", "\r\n\r\n")
      val head = HttpRequestHead.parse(ascii(request))
      try
        assertNotEquals(head.bodyFraming, BodyFraming.UntilClose, request)
        framed += 1
      catch case _: BadRequest => ()
    assert(framed > 0, "every header set was refused; the table asserts nothing about framing")

  test("no control character survives into a forwarded request or an audit line"):
    // The request head's two halves. The parser is the single gate for both sinks: what is
    // forwarded to an origin, and what is written to a log the operator later reads on a terminal —
    // where a tab breaks the audit grammar's own fields and an escape sequence rewrites the line
    // around it. CR and LF are pinned elsewhere, as smuggling; these are the ones a whitespace test
    // lets through. The authority half is in the corpus above.
    val controls = Vector('\u0000', '\u0001', '\u0007', '\u001b', '\t', '\u001f', '\u007f')

    controls.foreach: ch =>
      intercept[BadRequest](
        HttpRequestHead.parse(ascii(s"GET /a${ch}b HTTP/1.1\r\nHost: github.com\r\n\r\n")),
      )

    // HTAB is legal in a field value and nowhere else, so it is the one that must survive here and
    // be refused above.
    controls.filter(_ != '\t').foreach: ch =>
      intercept[BadRequest](
        HttpRequestHead.parse(
          ascii(s"GET /a HTTP/1.1\r\nHost: github.com\r\nX-Probe: a${ch}b\r\n\r\n"),
        ),
      )
    val tabbed = HttpRequestHead.parse(
      ascii("GET /a HTTP/1.1\r\nHost: github.com\r\nX-Probe: a\tb\r\n\r\n"),
    )
    assertEquals(tabbed.values("X-Probe"), Vector("a\tb"))

  test("no rule file, however malformed, admits a host or a grant nobody named"):
    // The fail-open direction for policy parsing: a file that resolves at all must resolve to
    // defaults hosts plus the ones its own text spells, never to something the arithmetic invented,
    // and every grant on a resolved scope is a word some line wrote.
    val lines = Vector(
      "allow https://github.com/ read git-fetch", "deny https://github.com/", "deny https://**.github.com/",
      "allow https://pypi.org/ read", "deny https://pypi.org/ read", "allow https://mirror.example/ tunnel",
      "allow https://mirror.example/ git-fetch", "allow https://mirror.example/ allow=lfs",
      "allow https://mirror.example/ writable", "deny defaults", "allow model-provider anthropic",
      "deny model-provider google", "allow", "deny", "allow https://a..b/ read",
      "allow https://10.0.0.1/ tunnel", "allow https://[github.com]/ read", "allow https://github.com./ read",
      "+host github.com", "pypi.org", "host pypi.org", "allow=git-fetch",
      "allow https://github.com/octocat/ read", "allow https://github.com/octocat/ git-fetch",
      "allow https://github.com/login/ method=POST", "allow https://github.com/octocat/Hello-World/ read",
      "allow https://pypi.org/simple/ read", "allow https://pypi.org/simple/../ read",
      "allow https://pypi.org/simple read",
      "allow https://pypi.org/ tunnel", "allow https://mirror.example/a/ tunnel",
      "allow https://registry.npmjs.org/lodash/ method=POST,PUT", "deny https://github.com/ git-fetch",
      "deny https://**.googleapis.com/ tunnel", "allow https://x.example/ method=GET", "deny https://x.example/a/",
    )
    val words = Set("read", "git-fetch", "tunnel", "POST", "PUT", "PATCH", "DELETE")
    var resolved = 0
    var refused = 0
    (1 to 1000).foreach: _ =>
      val value = (0 to random.nextInt(4)).map(_ => lines(random.nextInt(lines.size))).mkString("\n")
      try
        val policy = resolvePolicy(Some("deny-unless-allowed"), None, Some(value))
        val named = value.toLowerCase
        policy.hosts.keySet.foreach: host =>
          assert(DefaultHosts.contains(host) || named.contains(host), s"'$value' admitted the unnamed host '$host'")
        policy.inspectedScopes.foreach: (host, scopes) =>
          scopes.foreach: (path, grants) =>
            assert(grants.nonEmpty && grants.subsetOf(words), s"'$value' granted '$host' $grants")
            assert(!grants("tunnel"), s"'$value' tunnelled inside the inspected $host")
            // A scope's path is some line's own words, the defaults' included, in canonical form.
            val defaultsPath = DefaultHosts.get(host).exists {
              case Treatment.Inspected(scopes) => scopes.contains(path)
              case Treatment.Tunnel       => false
            }
            assert(
              path == "/" || defaultsPath || named.contains(s"$host$path".toLowerCase),
              s"'$value' opened the unnamed $path on $host",
            )
            assert(
              path.startsWith("/") && GitHelper.literalPathProblem(path).isEmpty,
              s"'$value' opened the non-canonical $path",
            )
        resolved += 1
      catch case _: IllegalArgumentException => refused += 1
    // The same guard as the authority draws: a line set that only ever refused would assert nothing
    // about what a resolved policy may contain.
    assert(resolved > 0, "no file ever resolved; the line set stopped producing valid policies")
    assert(refused > 0, "no file was ever refused; the line set stopped producing invalid ones")

  test("no URL of the hostile corpus reaches a rule: ports, userinfo, query, fragment, literals, patterns, spellings"):
    Vector(
      "allow https://github.com:443/ read", "allow https://github.com:8443/ read",
      "allow https://user:pw@github.com/ read",
      "allow https://github.com/?x=1 read", "allow https://github.com/#frag read", "allow https://127.0.0.1/ read",
      "allow https://[::1]/ read", "allow https://**.github.com/ read", "allow https://*.github.com/ read",
      "allow https://github.com/a\\b read", "allow https://git%68ub.com/ read", "allow https://github.com/%2e%2e/ read",
      "allow HTTPS://github.com/ read", "allow https:/github.com/ read", "allow https//github.com/ read",
      "allow https://github.com/a//b/ read", "allow https://github.com/./ read", "allow https://github.com/a/.. read",
      "allow https://github.com/é/ read", "allow https://github.com/a\tb read", "allow https://gith ub.com/ read",
      "deny https://github.com/a/", "deny https://**.github.com/a/", "deny https://github.com:443/",
    ).foreach: line =>
      intercept[IllegalArgumentException](resolvePolicy(Some("deny-unless-allowed"), None, Some(line)))

  // ---------------------------------------------------------------------------
  // The reference evaluator: the simple order is the specification, and the fold must be invisible
  // to it — PF's own discipline for its skip steps. A deliberately plain evaluator, applying each
  // line's contributions and removals to one request in textual order and building no resolved
  // scope, property-tested against the resolved policy's authorization over a drawn domain that
  // names every equation: each profile, the provider selected and not, files with `deny defaults`
  // and without, groups allowed and denied, `tunnel` taken and re-granted, hosts the defaults lack
  // and hosts they tunnel, and requests to unlisted hosts, to inspected ones under a denied subtree,
  // and at both sides of a boundary.
  // ---------------------------------------------------------------------------

  /** A line in structured form: rendered to text for the proxy, applied as is by the evaluator. */
  private enum Drawn:
    case DenyDefaults
    case Allow(host: String, path: String, grants: Set[String])
    case AllowGroup(name: String)
    case Deny(host: String, subtree: Boolean, grants: Set[String])
    case DenyGroup(name: String)

    def text: String = this match
      case DenyDefaults                 => "deny defaults"
      case Allow(host, path, grants)    => s"allow https://$host$path ${spell(grants)}"
      case AllowGroup(name)             => s"allow model-provider $name"
      case Deny(host, subtree, grants)  => s"deny https://${if subtree then "**." else ""}$host/ ${spell(grants)}".trim
      case DenyGroup(name)              => s"deny model-provider $name"

  private def spell(grants: Set[String]): String =
    val methods = Vector("POST", "PUT", "PATCH", "DELETE").filter(grants)
    (Vector("read", "git-fetch").filter(grants)
      ++ Option.when(methods.nonEmpty)("method=" + methods.mkString(","))
      ++ Option.when(grants("tunnel"))("tunnel")).mkString(" ")

  /** One line's standing grants: what the evaluator holds, one per line, never folded. */
  private case class Given(
    host: String,
    path: String,
    grants: Set[String],
    group: Option[String],
  )

  private def givenOf(line: Line, group: Option[String]): Given = line.rule match
    case Rule.Allow(host, path, grants) => Given(host, path, grants, group)
    case other                          => throw IllegalStateException(other.toString)

  private lazy val defaultsGiven: Vector[Given] =
    CatalogLines.map(
      givenOf(_, None),
    ) ++ ModelProviders.flatMap(name => ModelProviderLines(name).map(givenOf(_, Some(name))))

  private def groupGiven(name: String): Vector[Given] = ModelProviderLines(name).map(givenOf(_, Some(name)))

  /** What a request is, hand-labelled: the evaluator classifies nothing. */
  private enum Kind:
    case Read, FetchDiscovery, UploadPack, PushDiscovery, Write

  private case class Request(method: String, target: String, kind: Kind, ambiguous: Boolean)

  private val Requests = Vector(
    Request("GET", "/org/x", Kind.Read, ambiguous = false),
    Request("GET", "/other", Kind.Read, ambiguous = false),
    Request("GET", "/org/repo/info/refs?service=git-upload-pack", Kind.FetchDiscovery, ambiguous = false),
    Request("POST", "/org/repo/git-upload-pack", Kind.UploadPack, ambiguous = false),
    Request("GET", "/org/repo/info/refs?service=git-receive-pack", Kind.PushDiscovery, ambiguous = false),
    Request("POST", "/login/device/code", Kind.Write, ambiguous = false),
    Request("POST", "/org/x", Kind.Write, ambiguous = false),
    Request("PUT", "/org/x", Kind.Write, ambiguous = false),
    Request("GET", "/%2e%2e/x", Kind.Read, ambiguous = true),
    Request("GET", "/org/%2e/x", Kind.Read, ambiguous = true),
    Request("GET", "/org/repo/x", Kind.Read, ambiguous = false),
    Request("POST", "/org/%2e%2e/x", Kind.Write, ambiguous = true),
  )

  private val Hosts = Vector(
    "github.com", "api.github.com", "api.githubcopilot.com", "docs.python.org", "api.anthropic.com",
    "new.example", "sub.new.example",
  )

  private def hostMatches(pattern: String, subtree: Boolean, host: String): Boolean =
    host == pattern || (subtree && host.endsWith("." + pattern))

  private def pathContains(path: String, request: String): Boolean =
    if path.endsWith("/") then request.startsWith(path) else request == path

  /** The evaluator: "tunnel", "admitted" or "refused" for one request under one file. */
  private def evaluate(
    profile: String,
    provider: Option[String],
    lines: Vector[Drawn],
    host: String,
    request: Request,
  ): String =
    import Drawn.*
    val clears = lines.headOption.contains(DenyDefaults)
    val publicDefault = profile == "allow-unless-denied"
    if profile == "deny-all" then return "refused"
    var standing: Vector[Given] = profile match
      case "deny-unless-model" => provider.fold(Vector.empty)(groupGiven)
      case _                   => if clears then Vector.empty else defaultsGiven
    var patterns = Vector.empty[(String, Boolean)]
    var touched = standing.map(_.host).toSet
    def consult(line: Drawn): Boolean = (profile, line) match
      case ("deny-unless-model", Deny(_, _, _) | DenyGroup(_)) => true
      case ("deny-unless-model", _)                            => false
      case _                                                   => true
    def add(entry: Given): Unit =
      standing :+= entry
      touched += entry.host
    lines.filter(consult).foreach:
      case DenyDefaults => ()
      case Allow(h, p, g) => add(Given(h, p, g, None))
      case AllowGroup(name) =>
        groupGiven(
          name,
        ).filter(g => consult(Allow(g.host, g.path, g.grants))).foreach(add)
      case Deny(h, subtree, g) =>
        standing = standing.map: entry =>
          if !hostMatches(h, subtree, entry.host) then entry
          else entry.copy(grants = if g.isEmpty then Set.empty else entry.grants -- g)
        // An unlisted host holds `read` and nothing else, so those are the denies that reach it.
        if g.isEmpty || g("read") then patterns :+= (h, subtree)
      case DenyGroup(name) =>
        standing = standing.map(entry => if entry.group.contains(name) then entry.copy(grants = Set.empty) else entry)
    val listed = standing.filter(entry => entry.host == host && entry.grants.nonEmpty)
    if listed.exists(_.grants("tunnel")) then return "tunnel"
    // An unlisted host under the public default holds `read` at the root and nothing else.
    val open = publicDefault && !touched(host) && !patterns.exists((p, s) => hostMatches(p, s, host))
    val active =
      if listed.nonEmpty then listed else if open then Vector(Given(host, "/", Set("read"), None)) else Vector()
    if active.isEmpty then return "refused"
    val path = request.target.takeWhile(_ != '?')
    val covering = active.filter(entry => pathContains(entry.path, path))
    if covering.isEmpty then return "refused"
    val grants = covering.flatMap(_.grants).toSet
    val longest = (standing ++ active).filter(
      entry => entry.host == host && pathContains(entry.path, path),
    ).map(_.path).maxBy(_.length)
    if longest != "/" && request.ambiguous then return "refused"
    val opened = request.kind match
      case Kind.Read           => grants("read")
      case Kind.FetchDiscovery => grants("git-fetch")
      case Kind.PushDiscovery  => grants("POST")
      case Kind.UploadPack     => !request.ambiguous && (grants("git-fetch") || grants("POST"))
      case Kind.Write          => !request.ambiguous && grants(request.method)
    if opened then "admitted" else "refused"

  private def production(resolved: ResolvedEgress, host: String, request: Request): String =
    try
      authorizeRequest(ConnectRequest(host, 443), resolved)
      if resolved.tunnelHosts(host) then "tunnel"
      else
        val framing = if request.method == "GET" then "" else "Content-Length: 0\r\n"
        val head = HttpRequestHead.parse(
          ascii(s"${request.method} ${request.target} HTTP/1.1\r\nHost: $host\r\n$framing\r\n"),
        )
        authorizeInspectedRequest(host, head, resolved.scopesOf(host))
        "admitted"
    catch case _: PolicyViolation => "refused"

  test("the resolved policy authorizes exactly what the plain ordered evaluator does, over the drawn domain"):
    import Drawn.*
    val grantSets = Vector(
      Set("read"),
      Set("git-fetch"),
      Set("read", "git-fetch"),
      Set("POST"),
      Set("read", "POST"),
      Set("PUT"),
    )
    val paths = Vector("/", "/org/", "/org/repo/", "/login/device/code")
    val pool: Vector[Drawn] =
      (for host <- Hosts; path <- paths; grants <- grantSets yield Allow(host, path, grants))
        ++ Hosts.map(host => Allow(host, "/", Set("tunnel")))
        ++ (for
          host <- Hosts
          grants <- Vector(Set.empty[String], Set("read"), Set("git-fetch"), Set("POST"), Set("tunnel"))
        yield Deny(host, subtree = false, grants))
        ++ Vector(Deny("github.com", subtree = true, Set.empty), Deny("new.example", subtree = true, Set.empty),
          Deny("new.example", subtree = true, Set("tunnel")), Deny("github.com", subtree = true, Set("read")))
        ++ Vector(
          AllowGroup("github"),
          AllowGroup("anthropic"),
          DenyGroup("github"),
          DenyGroup("google"),
          DenyGroup("anthropic"),
        )
    val providers = Vector(None, Some("github"), Some("anthropic"), Some("google"))
    val outcomes = scala.collection.mutable.Map.empty[String, Int].withDefaultValue(0)
    var files = 0
    var refusedFiles = 0
    (1 to 2500).foreach: _ =>
      val profile = Profiles(random.nextInt(Profiles.size))
      val provider = providers(random.nextInt(providers.size))
      val body = (0 until random.nextInt(6)).map(_ => pool(random.nextInt(pool.size))).toVector
      val lines = if random.nextInt(4) == 0 then DenyDefaults +: body else body
      val text = lines.map(_.text).mkString("\n")
      val resolved =
        try Some(resolvePolicy(Some(profile), provider, Some(text)))
        catch case _: IllegalArgumentException => None
      resolved match
        case None => refusedFiles += 1
        case Some(policy) =>
          files += 1
          Hosts.foreach: host =>
            Requests.foreach: request =>
              val expected = evaluate(profile, provider, lines, host, request)
              val actual = production(policy, host, request)
              assertEquals(
                actual,
                expected,
                s"$profile provider=$provider\n$text\n$host ${request.method} ${request.target}",
              )
              outcomes(expected) += 1
    assert(files > 0 && refusedFiles > 0, s"$files files resolved, $refusedFiles refused")
    Vector(
      "tunnel",
      "admitted",
      "refused",
    ).foreach(outcome => assert(outcomes(outcome) > 0, s"no $outcome outcome was ever drawn"))
