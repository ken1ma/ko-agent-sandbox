// The second layer over AgentEgressProxyTest: the parsers under hostile and randomized input,
// aimed at parser disagreement, canonicalization and fail-open policy parsing rather than at more
// examples of rules that file already pins. Where a rule is pinned there, this file asserts only
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

import AgentEgressProxy.*
import HTTPHelper.*
import IPAddrHelper.*
import TLSHelper.*

class HostileInputTest extends munit.FunSuite:

  private def ascii(value: String): Array[Byte] = value.getBytes(StandardCharsets.US_ASCII)

  private def connect(authority: Array[Byte]): Array[Byte] =
    ascii("CONNECT ") ++ authority ++ ascii(" HTTP/1.1\r\n\r\n")

  private lazy val baselinePolicy: ResolvedEgress =
    resolvePolicy(Some("deny-unless-allowed"), None, None, None)

  private def authorize(authority: Array[Byte]): String =
    authorizeRequest(ConnectRequest.parse(connect(authority)), baselinePolicy)

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

    // IPv6, IPv4-mapped IPv6 and zone identifiers. Every one carries a colon, which the hostname
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
    // allowlist does not hold. Refused rather than reduced again — the fail-closed direction.
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
    // non-idempotence fails closed, because the once-normalized form is what the allowlist is
    // compared against and it is not in it. What has to hold is the property enforcement rests
    // on: whatever authorizeRequest returns is unchanged by normalizing it again, since that is
    // the name later resolved and bound to SNI.
    assertEquals(normalizeHost("github.com.."), "github.com.")
    assertNotEquals(normalizeHost(normalizeHost("github.com..")), normalizeHost("github.com.."))
    BaselineHosts.keySet.foreach: host =>
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

  test("no mutation of a real authority authorizes anything outside the allowlist"):
    val seeds = Vector("github.com:443", "pypi.org:443", "api.anthropic.com:443")
    var reached = 0
    var refused = 0
    (1 to 3000).foreach: _ =>
      val authority = (0 to random.nextInt(3))
        .foldLeft(seeds(random.nextInt(seeds.size)))((value, _) => mutate(value))
      try
        val host = authorize(ascii(authority))
        assert(BaselineHosts.contains(host), s"reached '$host' from '${printable(authority)}'")
        assert(!isIpLiteral(host), s"authorized the IP literal '$host'")
        assertEquals(normalizeHost(host), host, s"'$host' is not a fixed point")
        reached += 1
      catch
        case _: BadRequest | _: PolicyViolation => refused += 1
    assert(reached > 0, "no mutation reached a host; the generator stopped producing near-misses")
    assert(refused > 0, "no mutation was refused; the generator stopped mutating")

  test("a path that would select a refusal's advice is refused at the parser when it carries a control"):
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
        Set("git-fetch"),
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

  test("no allowed delta, however malformed, admits a host nobody named"):
    // The fail-open direction for policy parsing: a delta that resolves at all must resolve to
    // baseline hosts plus the ones its own text spells, never to something the arithmetic
    // invented — and never to a treatment wider than a single line says.
    val lines = Vector(
      "+host github.com allow=git-fetch", "-host github.com", "-host **.github.com",
      "+host pypi.org", "-host pypi.org", "+host mirror.example unrestricted",
      "+host mirror.example allow=git-fetch", "+host mirror.example allow=lfs",
      "+host mirror.example writable", "-**", "+model-provider anthropic",
      "-model-provider google", "+host", "-host", "+host a..b",
      "+host 10.0.0.1 unrestricted", "+host [github.com] restricted", "+host github.com.",
      "+github.com", "pypi.org", "host pypi.org", "allow=git-fetch",
    )
    var resolved = 0
    var refused = 0
    (1 to 1000).foreach: _ =>
      val value = (0 to random.nextInt(4)).map(_ => lines(random.nextInt(lines.size))).mkString("\n")
      try
        val policy = resolvePolicy(Some("deny-unless-allowed"), None, Some(value), None)
        val named = value.toLowerCase
        policy.hosts.keySet.foreach: host =>
          assert(
            BaselineHosts.contains(host) || named.contains(host),
            s"'$value' admitted the unnamed host '$host'",
          )
        policy.restricted.foreach: (host, tags) =>
          assert(tags.subsetOf(KnownTags), s"'$value' tagged '$host' with $tags")
        resolved += 1
      catch case _: IllegalArgumentException => refused += 1
    // The same guard as the authority draws: a delta set that only ever refused would assert
    // nothing about what a resolved policy may contain.
    assert(resolved > 0, "no delta ever resolved; the line set stopped producing valid policies")
    assert(refused > 0, "no delta was ever refused; the line set stopped producing invalid ones")
