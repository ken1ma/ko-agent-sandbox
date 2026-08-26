package agentsandbox.egress

import java.io.{ByteArrayInputStream, IOException}
import java.net.InetAddress
import java.nio.charset.StandardCharsets

import AgentEgressProxy.*
import HTTPHelper.*
import IPAddrHelper.*
import TLSHelper.*

class AgentEgressProxyTest extends munit.FunSuite:

  test("normalizeHost lowercases and removes one trailing dot"):
    assertEquals(
      normalizeHost("API.Anthropic.COM."),
      "api.anthropic.com"
    )

  test("normalizeHost converts IDN to ASCII"):
    assertEquals(
      normalizeHost("bücher.example"),
      "xn--bcher-kva.example"
    )

  test("CONNECT parser accepts a normal HTTP/1.1 CONNECT"):
    val request = parseConnect(
      "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
        "Host: api.anthropic.com:443\r\n" +
        "Proxy-Connection: keep-alive\r\n" +
        "\r\n"
    )

    assertEquals(
      request,
      ConnectRequest("api.anthropic.com", 443)
    )

  test("CONNECT parser rejects a request body framing header"):
    intercept[BadRequest]:
      parseConnect(
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
          "Content-Length: 0\r\n" +
          "\r\n"
      )

  test("CONNECT parser rejects a non-CONNECT method"):
    intercept[BadRequest]:
      parseConnect("GET https://api.anthropic.com/ HTTP/1.1\r\n\r\n")

  test("the pull hosts are reachable and restricted"):
    // The registry APIs and blob CDNs have no unauthenticated write of their own; membership in
    // the restricted catalog is defense in depth plus a method-and-path log line per pull. The
    // one member that needs the treatment is storage.googleapis.com — its own test below.
    Vector(
      "registry-1.docker.io", "auth.docker.io",
      "production.cloudflare.docker.com", "production.cloudfront.docker.com",
      "gcr.io", "storage.googleapis.com", "public.ecr.aws",
      "d2glxqk2uabbnd.cloudfront.net", "d5l0dvt14r5h8.cloudfront.net"
    ).foreach: host =>
      assertEquals(authorize(host, 443), host)
      assert(CuratedRestrictedHosts.contains(host), host)

  test("authorizeRequest rejects ports other than 443"):
    intercept[PolicyViolation]:
      authorize("api.anthropic.com", 8443)

  test("authorizeRequest rejects a hostname outside the allowlist"):
    intercept[PolicyViolation]:
      authorize("example.com", 443)

  test("authorizeRequest rejects every spelling of an IP-literal target"):
    // The first four all resolve to 127.0.0.1 through InetAddress on JDK 25; 8.8.8.8 shows a public literal is
    // refused just the same — the rule is "hostnames only", not "no private targets".
    val literals =
      Vector("127.0.0.1", "2130706433", "127.1", "0177.0.0.1", "8.8.8.8")

    literals.foreach: literal =>
      assert(isIpLiteral(literal), literal)

      intercept[PolicyViolation]:
        authorize(literal, 443)

  test("Smokescreen-class canonicalization tricks reach no non-allowed host"):
    // Permanent regression inputs from Smokescreen's deny-list bypasses: bracketed hostname (GHSA-qwrf-gfpj-qvj6),
    // trailing dot / letter case (GHSA-gcj7-j438-hjj2). An allowlist with one normalizeHost chokepoint keeps every
    // dressing of a non-listed host refused.
    Vector(
      "[example.com]:443",
      "example.com.:443",
      "EXAMPLE.COM:443",
      "ExAmPlE.CoM.:443"
    ).foreach: authority =>
      intercept[PolicyViolation]:
        authorizeRequest(
          ConnectRequest.parse(ascii(s"CONNECT $authority HTTP/1.1\r\n\r\n")),
          baselinePolicy
        )

  test("an allowed host authorizes to one canonical form however it is spelled"):
    // The other half: every spelling of an allowed host collapses to one canonical name — the one later bound to SNI
    // (validateTlsIdentity).
    Vector(
      "github.com:443",
      "GitHub.COM:443",
      "github.com.:443",
      "[github.com]:443"
    ).foreach: authority =>
      assertEquals(
        authorizeRequest(
          ConnectRequest.parse(ascii(s"CONNECT $authority HTTP/1.1\r\n\r\n")),
          baselinePolicy
        ),
        "github.com"
      )

  test("isIpLiteral leaves ordinary hostnames alone"):
    Vector(
      "api.anthropic.com",
      "files.pythonhosted.org",
      "xn--bcher-kva.example",
      "host123.example.com"
    ).foreach(host => assert(!isIpLiteral(host), host))

  // ---------------------------------------------------------------------------
  // Policy resolution: profile equations over the baseline, the allowed delta,
  // and the always-applied denied rules
  // ---------------------------------------------------------------------------

  private def policyOf(
    profile: String = "deny-unless-allowed",
    provider: String = "",
    allowed: String = "",
    denied: String = ""
  ): ResolvedEgress =
    def opt(value: String) = Option(value).filter(_.nonEmpty)
    resolvePolicy(Some(profile), opt(provider), opt(allowed), opt(denied))

  test("deny-unless-allowed with no policy files resolves to the whole baseline"):
    val resolved = policyOf()
    assertEquals(resolved.restricted, CuratedRestrictedHosts)
    assertEquals(resolved.unrestrictedHosts, ModelProviderHosts.values.flatten.toSet)
    assert(!resolved.ambient)

  test("deny-all resolves empty, and empty is a valid policy, not a broken one"):
    val resolved = policyOf(profile = "deny-all", denied = "host example.com")
    assertEquals(resolved.hosts, Map.empty[String, Treatment])
    intercept[PolicyViolation](authorize("api.anthropic.com", 443, resolved))
    // Its denials are idle by definition and deliberately unwarned.
    assertEquals(resolved.idleDenied, Vector.empty)
    assertEquals(resolved.warnings, Vector.empty)

  test("deny-unless-model admits the selected provider's endpoints and no project extras"):
    val resolved = policyOf(profile = "deny-unless-model", provider = "anthropic")
    assertEquals(resolved.hosts.keySet, ModelProviderHosts("anthropic"))
    assertEquals(authorize("api.anthropic.com", 443, resolved), "api.anthropic.com")
    intercept[PolicyViolation](authorize("github.com", 443, resolved))
    val withExtras = policyOf(
      profile = "deny-unless-model", provider = "anthropic",
      allowed = "+host docs.example restricted"
    )
    assertEquals(withExtras.hosts.keySet, ModelProviderHosts("anthropic"))

  test("deny-unless-model with no provider selected is a valid empty policy"):
    val resolved = policyOf(profile = "deny-unless-model")
    assertEquals(resolved.hosts, Map.empty[String, Treatment])
    assertEquals(
      policyLines(resolved)(0),
      "egress profile: deny-unless-model; model provider: none"
    )

  test("an unknown profile or provider is refused, never defaulted"):
    intercept[IllegalArgumentException](policyOf(profile = "allow-all"))
    intercept[IllegalArgumentException](policyOf(profile = "deny-unless-model", provider = "meta"))

  test("allow-unless-denied admits any public host, keeps the catalog restricted, denial wins"):
    val resolved = policyOf(profile = "allow-unless-denied", denied = "host telemetry.example.com")
    assert(resolved.ambient)
    assertEquals(authorize("anything.example.org", 443, resolved), "anything.example.org")
    // The narrowing set: a catalog host stays restricted rather than widening to the default.
    assertEquals(resolved.restricted.get("github.com"), Some(Set("git-fetch")))
    intercept[PolicyViolation](authorize("telemetry.example.com", 443, resolved))
    // The port and IP-literal rules hold for ambient hosts too.
    intercept[PolicyViolation](authorize("anything.example.org", 8443, resolved))
    intercept[PolicyViolation](authorize("8.8.8.8", 443, resolved))

  test("an allowed removal narrows the curated profile but can never widen an ambient host"):
    // Under deny-unless-allowed the removal takes github.com away entirely...
    intercept[PolicyViolation](
      authorize("github.com", 443, policyOf(allowed = "-host github.com"))
    )
    // ...while under allow-unless-denied the same delta subtracts nothing from the narrowing
    // set: only denied removes ambient access, so github.com stays restricted rather than
    // becoming an opaque tunnel.
    val ambient = policyOf(profile = "allow-unless-denied", allowed = "-host github.com")
    assertEquals(ambient.restricted.get("github.com"), Some(Set("git-fetch")))
    // .defaults cannot subtract from it either.
    val reset = policyOf(profile = "allow-unless-denied", allowed = ".defaults")
    assertEquals(reset.restricted, CuratedRestrictedHosts)

  test("a restricted addition extends the narrowing set; an unrestricted one adds nothing to it"):
    val resolved = policyOf(
      profile = "allow-unless-denied",
      allowed = "+host mirror.example=git-fetch restricted\n+host opaque.example unrestricted"
    )
    assertEquals(resolved.restricted.get("mirror.example"), Some(Set("git-fetch")))
    assert(!resolved.hosts.contains("opaque.example"))
    assertEquals(authorize("opaque.example", 443, resolved), "opaque.example")

  test("the allowed delta adds to and removes from the baseline"):
    val resolved = policyOf(allowed = "+host html.spec.whatwg.org restricted\n-host pypi.org")
    assertEquals(
      resolved.restricted,
      CuratedRestrictedHosts - "pypi.org" + ("html.spec.whatwg.org" -> Set.empty[String])
    )
    assertEquals(resolved.unrestrictedHosts, ModelProviderHosts.values.flatten.toSet)

  test("entries are enforced in the normalized form they resolve to"):
    // The launcher passes the files' lines, resolvePolicy normalizes the entries, and
    // authorizeRequest normalizes the CONNECT target: whatever spelling either side used,
    // enforcement compares one canonical form.
    val resolved = policyOf(allowed = "+host Example.ORG. restricted\n-host GitLab.COM.")
    assertEquals(authorize("EXAMPLE.ORG.", 443, resolved), "example.org")
    assert(!resolved.hosts.contains("gitlab.com"))
    intercept[PolicyViolation](authorize("example.com", 443, resolved))

  test("an entry outside the grammar is refused with the grammar in hand, never skipped"):
    // The pre-release egress-hosts spelling is the likely stray: a bare +host token.
    val ex = intercept[IllegalArgumentException](policyOf(allowed = "+pypi.org"))
    assert(ex.getMessage.contains("allowed grammar"), ex.getMessage)
    intercept[IllegalArgumentException](policyOf(allowed = "host example.com"))
    intercept[IllegalArgumentException](policyOf(denied = "+host example.com"))
    intercept[IllegalArgumentException](policyOf(denied = "example.com"))
    intercept[IllegalArgumentException](policyOf(denied = ".defaults"))

  test("restating a baseline entry identically is a harmless no-op"):
    // Deliberately not an error: a defensively added host must not start failing when a later
    // image adopts it into the baseline.
    assertEquals(policyOf(allowed = "+host pypi.org restricted").restricted, CuratedRestrictedHosts)
    assertEquals(
      policyOf(allowed = "+host github.com=git-fetch restricted").restricted,
      CuratedRestrictedHosts
    )
    assertEquals(policyOf(allowed = "+model-provider anthropic").hosts, policyOf().hosts)

  test("a retagging addition states its host's complete tagging, and =git-fetch opens git fetch"):
    // An addition states its host's complete tagging and overrides the baseline entry for that
    // host — explicit, printed as written at launch, never a merge.
    val mirror = policyOf(allowed = "+host mirror.example=git-fetch restricted")
    assert(mirror.tagged("git-fetch").contains("mirror.example"))
    authorizeInspectedRequest(
      "mirror.example",
      head(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\n" +
          "Host: mirror.example\r\nContent-Length: 0\r\n\r\n"
      ),
      Set("git-fetch")
    )
    // Revoking: a bare restatement strips the built-in =git-fetch; the host stays restricted.
    val demoted = policyOf(allowed = "+host gitlab.com restricted")
    assert(!demoted.tagged("git-fetch").contains("gitlab.com"))
    assert(demoted.restricted.contains("gitlab.com"))
    // Granting is just as explicit — legal, and the entry says exactly what it opens.
    assert(
      policyOf(allowed = "+host pypi.org=git-fetch restricted")
        .tagged("git-fetch").contains("pypi.org")
    )

  test("one host, one treatment: entries that disagree are refused"):
    val ex = intercept[IllegalArgumentException](
      policyOf(allowed = "+host docs.example restricted\n+host docs.example=git-fetch restricted")
    )
    assert(ex.getMessage.contains("two different treatments"), ex.getMessage)
    intercept[IllegalArgumentException](
      policyOf(allowed = "+host docs.example restricted\n+host docs.example unrestricted")
    )

  test("an unknown tag or treatment is refused with the closed set in hand"):
    // A tag names a fixed treatment, never describes one — and the port habit (host=8443) fails
    // closed here too.
    val ex = intercept[IllegalArgumentException](
      policyOf(allowed = "+host mirror.example=lfs restricted")
    )
    assert(ex.getMessage.contains("the tags are: git-fetch, npm-audit"), ex.getMessage)
    intercept[IllegalArgumentException](policyOf(allowed = "+host mirror.example=8443 restricted"))
    val treatment = intercept[IllegalArgumentException](
      policyOf(allowed = "+host mirror.example writable")
    )
    assert(treatment.getMessage.contains("restricted and unrestricted"), treatment.getMessage)

  test("a tag belongs on a restricted addition and nowhere else"):
    intercept[IllegalArgumentException](policyOf(allowed = "+host api.example=git-fetch unrestricted"))
    intercept[IllegalArgumentException](policyOf(allowed = "-host github.com=git-fetch"))
    intercept[IllegalArgumentException](policyOf(denied = "host github.com=git-fetch"))

  test("adding and removing the same host is refused"):
    intercept[IllegalArgumentException](policyOf(allowed = "+host pypi.org restricted\n-host pypi.org"))

  test("a removal matching neither the baseline nor an addition is refused, not a silent no-op"):
    // The sharp fail-open edge: a typo'd '-host githib.example' that removed nothing would read
    // as a narrowing that never happened.
    intercept[IllegalArgumentException](policyOf(allowed = "-host githib.example"))
    // A provider endpoint is baseline like any other host; removing one exactly works.
    assert(!policyOf(allowed = "-host api.anthropic.com").hosts.contains("api.anthropic.com"))

  test("delta entries reject IP literals and malformed hostnames like any other"):
    intercept[IllegalArgumentException](policyOf(allowed = "+host 10.0.0.1 unrestricted"))
    intercept[IllegalArgumentException](policyOf(allowed = "+host api..example restricted"))
    intercept[IllegalArgumentException](policyOf(denied = "host 10.0.0.1"))

  test("a comma joins nothing: tokens split on whitespace alone, like the policy files"):
    // A comma-joined pair must not silently become two entries — it stays one token and fails
    // hostname validation, so the mistake is a refused launch, not a policy nobody wrote.
    intercept[IllegalArgumentException](policyOf(allowed = "+host a.example,b.example restricted"))
    intercept[IllegalArgumentException](policyOf(denied = "host gitlab.com,chatgpt.com"))

  test("a -host **.domain removal drops the domain and everything under it"):
    val resolved = policyOf(allowed = "-host **.github.com")
    assert(!resolved.hosts.contains("github.com"))
    assert(!resolved.hosts.contains("api.github.com"))
    assert(!resolved.hosts.contains("codeload.github.com"))
    // A label boundary, not a suffix match: the .githubusercontent.com hosts stay.
    assert(resolved.hosts.contains("raw.githubusercontent.com"))

  test("a +host under a -host **.domain is a contradiction, not a precedence"):
    intercept[IllegalArgumentException](
      policyOf(allowed = "-host **.github.com\n+host api.github.com=git-fetch restricted")
    )

  test("a bare -host * and the undotted **domain spelling are refused, never suffix-matched"):
    // Only **.domain is a wildcard; * is neither a valid pattern nor a host, and the pattern's
    // dot is load-bearing — without it the spelling reads as a suffix match (barfoo.com).
    intercept[IllegalArgumentException](policyOf(allowed = "-host *"))
    intercept[IllegalArgumentException](policyOf(allowed = "-host **pypi.org"))
    intercept[IllegalArgumentException](policyOf(denied = "host **pypi.org"))

  test("denied removes a host from any treatment and beats an addition"):
    val resolved = policyOf(denied = "host gitlab.com\nhost developer.mozilla.org\nhost chatgpt.com")
    Vector("gitlab.com", "developer.mozilla.org", "chatgpt.com").foreach: host =>
      assert(!resolved.hosts.contains(host), host)
      intercept[PolicyViolation](authorize(host, 443, resolved))
    assert(
      !policyOf(allowed = "+host docs.example restricted", denied = "host docs.example")
        .hosts.contains("docs.example")
    )

  test("denied applies under every profile, a selected provider's endpoints included"):
    val resolved = policyOf(
      profile = "deny-unless-model", provider = "openai", denied = "host chatgpt.com"
    )
    assert(!resolved.hosts.contains("chatgpt.com"))
    assert(resolved.hosts.contains("api.openai.com"))
    // Absent-or-denied endpoints warn but never fail the start: the profile stays the user's
    // authority decision.
    assert(resolved.warnings.exists(_.contains("chatgpt.com")), resolved.warnings.toString)

  test("a denied **.domain subtree crosses treatment boundaries"):
    val resolved = policyOf(denied = "host **.googleapis.com")
    assert(!resolved.hosts.contains("storage.googleapis.com"))   // curated catalog
    assert(!resolved.hosts.contains("oauth2.googleapis.com"))    // provider endpoint
    assert(!resolved.hosts.contains("cloudcode-pa.googleapis.com"))

  test("a denied model-provider group denies whatever the group expands to"):
    val resolved = policyOf(denied = "model-provider google")
    ModelProviderHosts("google").foreach: host =>
      assert(!resolved.hosts.contains(host), host)
      intercept[PolicyViolation](authorize(host, 443, resolved))
    intercept[IllegalArgumentException](policyOf(denied = "model-provider meta"))

  test("an idle denial is a startup warning and a marked line, not an error"):
    // A typo cannot be distinguished from a proactive denial against the ambient host universe,
    // so exact no-match refusal would make legitimate cross-profile denials unwritable.
    val resolved = policyOf(
      profile = "deny-unless-model", provider = "anthropic", denied = "host telemetry.example.com"
    )
    assertEquals(resolved.idleDenied.map(_.spelled), Vector("telemetry.example.com"))
    assert(resolved.warnings.exists(_.contains("telemetry.example.com")), resolved.warnings.toString)
    assert(
      policyLines(resolved).contains("idle denied rules (1): telemetry.example.com"),
      policyLines(resolved).toString
    )
    // Under allow-unless-denied every syntactically valid rule matches the ambient universe.
    assertEquals(
      policyOf(profile = "allow-unless-denied", denied = "host telemetry.example.com").idleDenied,
      Vector.empty
    )

  test(".defaults removes the whole baseline before additions apply"):
    val resolved = policyOf(
      allowed = ".defaults\n+model-provider anthropic\n+host docs.python.org restricted"
    )
    assertEquals(resolved.unrestrictedHosts, ModelProviderHosts("anthropic"))
    assertEquals(resolved.restricted, Map("docs.python.org" -> Set.empty[String]))

  test("treatment widening has no delta spelling; .defaults states a replacement instead"):
    val ex = intercept[IllegalArgumentException](policyOf(allowed = "+host github.com unrestricted"))
    assert(ex.getMessage.contains(".defaults"), ex.getMessage)
    // Under a .defaults replacement the same entry is the stated policy, not a widening.
    assertEquals(
      policyOf(allowed = ".defaults\n+host github.com unrestricted").unrestrictedHosts,
      Set("github.com")
    )

  test("a model-provider removal takes exactly that provider's endpoints"):
    val resolved = policyOf(allowed = "-model-provider google")
    ModelProviderHosts("google").foreach(host => assert(!resolved.hosts.contains(host), host))
    assert(resolved.hosts.contains("api.anthropic.com"))
    intercept[IllegalArgumentException](policyOf(allowed = "-model-provider meta"))
    intercept[IllegalArgumentException](
      policyOf(allowed = "+model-provider google\n-model-provider google")
    )

  test("a provider the profile does not fully admit warns but never fails the start"):
    val resolved = policyOf(provider = "google", allowed = "-model-provider google")
    assert(resolved.warnings.exists(_.contains("google")), resolved.warnings.toString)

  test("--print-policy is the shape the launcher mints the leaf from"):
    val lines = policyLines(policyOf())
    assertEquals(lines(0), "egress profile: deny-unless-allowed")
    assert(lines(1).startsWith(s"restricted hosts (${CuratedRestrictedHosts.size}): "), lines(1))
    // Tags travel in the line; the launcher strips them when minting the leaf's names.
    assert(lines(1).contains(" github.com=git-fetch "), lines(1))
    assert(lines(1).contains(" registry.npmjs.org=npm-audit "), lines(1))
    assert(lines(1).contains(" pypi.org "), lines(1))
    assert(lines(2).startsWith("unrestricted hosts (9): "), lines(2))
    assertEquals(lines(3), "denied rules (0):")

  test("an empty policy prints zero counts, parseable like any other"):
    val lines = policyLines(policyOf(profile = "deny-unless-model"))
    assertEquals(lines(1), "restricted hosts (0):")
    assertEquals(lines(2), "unrestricted hosts (0):")

  test("allow-unless-denied prints its default and invents no host count"):
    val lines = policyLines(policyOf(profile = "allow-unless-denied", denied = "host x.example"))
    assertEquals(lines(0), "egress profile: allow-unless-denied; default: public HTTPS unrestricted")
    assert(!lines.exists(_.startsWith("unrestricted hosts")), lines.toString)
    assertEquals(lines(2), "denied rules (1): x.example")

  test("provenance names each entry's source, and an overriding removal or denial is shown"):
    val lines = provenanceLines(
      policyOf(allowed = "+host docs.example restricted\n-host pypi.org", denied = "host gitlab.com")
    )
    assert(lines.contains("  docs.example: restricted; allowed +host"), lines.toString)
    assert(lines.contains("  api.anthropic.com: unrestricted; model-provider anthropic"), lines.toString)
    assert(lines.contains("  crates.io: restricted; curated baseline"), lines.toString)
    assert(lines.contains("  gitlab.com: denied by gitlab.com; curated baseline"), lines.toString)
    assert(lines.contains("  pypi.org: removed by allowed"), lines.toString)

  test("provenance is profile-scoped: a rule the profile never consults is not reported"):
    // Under deny-unless-model the allowed delta shapes nothing, so an effective provider
    // endpoint is the group's, never "allowed", and a removal of it is not reported as done.
    val model = provenanceLines(
      policyOf(
        profile = "deny-unless-model", provider = "openai",
        allowed = "-host api.openai.com\n+host docs.example restricted"
      )
    )
    assert(model.contains("  api.openai.com: unrestricted; model-provider openai"), model.toString)
    assert(!model.exists(_.contains("allowed")), model.toString)
    // Under allow-unless-denied only restricted additions reach the narrowing set: an
    // unrestricted addition and a removal change nothing and are not reported as sources.
    val ambient = provenanceLines(
      policyOf(
        profile = "allow-unless-denied",
        allowed =
          "-host github.com\n+host opaque.example unrestricted\n+host mirror.example restricted"
      )
    )
    assert(ambient.contains("  mirror.example: restricted; allowed +host"), ambient.toString)
    assert(ambient.contains("  github.com: restricted =git-fetch; curated baseline"), ambient.toString)
    assert(!ambient.exists(_.contains("removed by allowed")), ambient.toString)
    assert(!ambient.exists(_.contains("opaque.example")), ambient.toString)

  test("provenance reports a rule only when it actually changed the resolved policy"):
    // A removal under .defaults removes what .defaults already cleared: not reported.
    val defaults = policyOf(allowed = ".defaults\n-host pypi.org\n+host docs.example restricted")
    assertEquals(defaults.removedSpellings, Vector(".defaults (baseline cleared)"))
    // Of two overlapping removals, the second finds nothing left to remove: not reported.
    val overlapping = policyOf(allowed = "-host pypi.org\n-host **.pypi.org")
    assertEquals(overlapping.removedSpellings, Vector("pypi.org"))
    // Re-adding a baseline host with its baseline treatment changes nothing, so the standing
    // source holds — the provider group's and the curated catalog's alike.
    val restated = provenanceLines(
      policyOf(allowed = "+host api.openai.com unrestricted\n+host crates.io restricted")
    )
    assert(
      restated.contains("  api.openai.com: unrestricted; model-provider openai"),
      restated.toString
    )
    assert(restated.contains("  crates.io: restricted; curated baseline"), restated.toString)
    // A provider group the allowed delta restored after .defaults is the delta's doing; naming
    // the built-in group would hide that the project's own file re-opened it.
    val restored = provenanceLines(policyOf(allowed = ".defaults\n+model-provider openai"))
    assert(
      restored.contains("  api.openai.com: unrestricted; allowed +model-provider openai"),
      restored.toString
    )

  test("IPv4 public-destination policy"):
    assert(isPublicDestination(InetAddress.getByName("8.8.8.8")))
    assert(!isPublicDestination(InetAddress.getByName("10.0.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("100.64.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("169.254.169.254")))
    assert(!isPublicDestination(InetAddress.getByName("192.0.2.1")))
    assert(!isPublicDestination(InetAddress.getByName("198.18.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("224.0.0.1")))
    assert(!isPublicDestination(InetAddress.getByName("255.255.255.255")))

  test("IPv6 public-destination policy"):
    assert(
      isPublicDestination(
        InetAddress.getByName("2606:4700:4700::1111")
      )
    )
    assert(!isPublicDestination(InetAddress.getByName("::1")))
    assert(!isPublicDestination(InetAddress.getByName("fc00::1")))
    assert(!isPublicDestination(InetAddress.getByName("fe80::1")))
    assert(!isPublicDestination(InetAddress.getByName("2001:db8::1")))

  test("CIDR handles non-byte-aligned prefixes"):
    val cgnat = Cidr("100.64.0.0", 10)

    assert(cgnat.contains(InetAddress.getByName("100.64.0.1")))
    assert(cgnat.contains(InetAddress.getByName("100.127.255.254")))
    assert(!cgnat.contains(InetAddress.getByName("100.128.0.1")))

  test("readHttpHeader stops exactly at CRLF CRLF"):
    val remaining = Array[Byte](1, 2, 3, 4)
    val input =
      ByteArrayInputStream(
        ascii("CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n") ++ remaining
      )

    val header = readHttpHeader(input, 4096)

    assertEquals(
      String(header, StandardCharsets.ISO_8859_1),
      "CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n"
    )
    assertEquals(input.readAllBytes().toVector, remaining.toVector)

  test("readHttpHeader enforces its size bound"):
    intercept[BadRequest]:
      readHttpHeader(
        ByteArrayInputStream(ascii("0123456789\r\n\r\n")),
        8
      )

  test("readHttpHeader tells an unused connection from a half-sent header"):
    // Zero bytes then EOF is routine pooled-client behavior and must not read as a refused
    // request; EOF inside a header stays the BadRequest it always was.
    intercept[ClosedWithoutRequest](readHttpHeader(ByteArrayInputStream(Array.emptyByteArray), 4096))
    intercept[BadRequest](readHttpHeader(ByteArrayInputStream(ascii("GET / HT")), 4096))

  test("a response head parses for status and framing, and malformations blame the origin"):
    val head = HttpResponseHead.parse(
      ascii("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
    )
    assertEquals(head.status, 200)
    assertEquals(head.bodyFraming("GET"), BodyFraming.Length(5))
    // Origin-side malformations are IOExceptions — the 502 blames the world, never the client.
    intercept[IOException](HttpResponseHead.parse(ascii("ICY 200 OK\r\n\r\n")))
    intercept[IOException](HttpResponseHead.parse(ascii("HTTP/1.1 abc OK\r\n\r\n")))

  test("response framing: HEAD and status codes without bodies, chunked, and the refusals"):
    def head(lines: String): HttpResponseHead = HttpResponseHead.parse(ascii(lines))

    assertEquals(head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").bodyFraming("HEAD"), BodyFraming.Empty)
    assertEquals(head("HTTP/1.1 304 Not Modified\r\n\r\n").bodyFraming("GET"), BodyFraming.Empty)
    assertEquals(head("HTTP/1.1 204 No Content\r\n\r\n").bodyFraming("GET"), BodyFraming.Empty)
    assertEquals(
      head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").bodyFraming("GET"),
      BodyFraming.Chunked
    )
    // No framing header: the body runs to the connection's end — this proxy sends
    // Connection: close upstream, so EOF is the terminator there, not a truncation.
    assertEquals(head("HTTP/1.1 200 OK\r\n\r\n").bodyFraming("GET"), BodyFraming.UntilClose)
    assertEquals(head("HTTP/1.1 100 Continue\r\n\r\n").bodyFraming("GET"), BodyFraming.Empty)
    // The request side's ambiguity refusals, as origin faults.
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n").bodyFraming("GET")
    )
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n").bodyFraming("GET")
    )
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n").bodyFraming("GET")
    )

  test("the relayed response head speaks this hop's own Connection: close"):
    // The origin's connection options describe the origin↔proxy leg; the client must hear close
    // from this proxy, whatever the origin sent — a client that misses it reuses or pipelines,
    // and its next request turns the proxy's close into an RST that eats the response's tail.
    val head = HttpResponseHead.parse(
      ascii(
        "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n" +
          "Content-Length: 5\r\nETag: \"abc\"\r\n\r\n"
      )
    )
    val relayed = String(head.toClientBytes, StandardCharsets.ISO_8859_1)
    assert(relayed.startsWith("HTTP/1.1 200 OK\r\n"), relayed)
    assert(relayed.endsWith("Connection: close\r\n\r\n"), relayed)
    assert(!relayed.toLowerCase.contains("keep-alive"), relayed)
    assert(relayed.contains("Content-Length: 5\r\n"), relayed)
    assert(relayed.contains("ETag: \"abc\"\r\n"), relayed)

  test("headers the message's own Connection header names are this hop's to remove, both ways"):
    // RFC 9110 §7.6.1's second half: hop-by-hop is not only the fixed set — a peer can declare
    // any header hop-by-hop by naming it in Connection, and forwarding it would leak this hop's
    // negotiation to the other side.
    val request = HttpRequestHead.parse(
      ascii(
        "GET /x HTTP/1.1\r\nHost: docs.python.org\r\nConnection: x-tracing, close\r\n" +
          "X-Tracing: abc\r\nAccept: */*\r\n\r\n"
      )
    )
    val upstream = String(request.toUpstreamBytes, StandardCharsets.ISO_8859_1)
    assert(!upstream.contains("X-Tracing"), upstream)
    assert(upstream.contains("Accept: */*\r\n"), upstream)

    val response = HttpResponseHead.parse(
      ascii("HTTP/1.1 200 OK\r\nConnection: x-server-hint\r\nX-Server-Hint: h2\r\nVary: A\r\n\r\n")
    )
    val relayed = String(response.toClientBytes, StandardCharsets.ISO_8859_1)
    assert(!relayed.contains("X-Server-Hint"), relayed)
    assert(relayed.contains("Vary: A\r\n"), relayed)

  test("HTTP/1.0 is refused by name, at CONNECT and inside the tunnel"):
    // No such client exists here, and half-supporting one — it could not parse a relayed
    // chunked response — would be a silent gap instead of this log line.
    val connect = intercept[BadRequest](
      ConnectRequest.parse(ascii("CONNECT github.com:443 HTTP/1.0\r\n\r\n"))
    )
    assertEquals(connect.getMessage, "HTTP/1.0 is not supported")
    val inTunnel = intercept[BadRequest](
      HttpRequestHead.parse(ascii("GET / HTTP/1.0\r\nHost: github.com\r\n\r\n"))
    )
    assertEquals(inTunnel.getMessage, "HTTP/1.0 is not supported")

  test("Expect: 100-continue is answered by this proxy and never forwarded"):
    // The proxy forwards every body unconditionally, so an origin must not be left waiting for
    // one — and the client must not stall until its own 100 timeout (git's large fetch
    // negotiation sends the Expect).
    val head = HttpRequestHead.parse(
      ascii(
        "POST /r.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\n" +
          "Content-Length: 4\r\n\r\n"
      )
    )
    assert(head.expectsContinue)
    val upstream = String(head.toUpstreamBytes, StandardCharsets.ISO_8859_1)
    assert(!upstream.toLowerCase.contains("expect"), upstream)
    assert(!HttpRequestHead.parse(ascii("GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n")).expectsContinue)

  test("forwardResponseBody relays complete bodies and turns early EOF into TruncatedResponse"):
    // The invisible-kill fix: an upstream close inside a declared length must become a loggable
    // failure, never a quiet end the client can mistake for a completed response.
    def relay(bytes: Array[Byte], framing: BodyFraming): Array[Byte] =
      val out = java.io.ByteArrayOutputStream()
      forwardResponseBody(ByteArrayInputStream(bytes), out, framing)
      out.toByteArray

    assertEquals(relay(ascii("hello"), BodyFraming.Length(5)).toVector, ascii("hello").toVector)
    assertEquals(relay(ascii("anything"), BodyFraming.Empty).toVector, Vector.empty)
    assertEquals(relay(ascii("to the end"), BodyFraming.UntilClose).toVector, ascii("to the end").toVector)
    assertEquals(
      relay(ascii("5\r\nhello\r\n0\r\n\r\n"), BodyFraming.Chunked).toVector,
      ascii("5\r\nhello\r\n0\r\n\r\n").toVector
    )

    val short = intercept[TruncatedResponse](relay(ascii("hel"), BodyFraming.Length(5)))
    assert(short.getMessage.contains("truncated"), short.getMessage)
    intercept[TruncatedResponse](relay(ascii("5\r\nhel"), BodyFraming.Chunked))
    // An origin whose chunking cannot be parsed is the same abort, not a 400 at the client.
    intercept[TruncatedResponse](relay(ascii("zz\r\n"), BodyFraming.Chunked))

  // ---------------------------------------------------------------------------
  // The relay on real sockets: loopback pairs, a thread playing the origin, the in-tunnel client
  // observed on the wire. These are the tests that catch what head-level assertions cannot — the
  // bytes a client actually receives, and what a straggling client does to the close.

  private def socketPair(): (java.net.Socket, java.net.Socket) =
    val server = java.net.ServerSocket(0, 1, InetAddress.getLoopbackAddress)
    val connecting = java.net.Socket(InetAddress.getLoopbackAddress, server.getLocalPort)
    val accepted = server.accept()
    server.close()
    (connecting, accepted)

  private def playOrigin(socket: java.net.Socket, response: Array[Byte]): Thread =
    Thread.startVirtualThread: () =>
      try
        readHttpHeader(socket.getInputStream, 64 * 1024)
        socket.getOutputStream.write(response)
        socket.getOutputStream.close()
      catch case _: Exception => ()

  test("relayInspected puts this hop's close on the wire and survives a pipelined straggler"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    val origin = playOrigin(
      upstreamPeer,
      ascii("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello")
    )
    // The client pipelines a second request past the close notice, then half-closes: the drain
    // must consume it so the proxy's close stays a clean FIN, never an RST eating the tail.
    clientPeer.getOutputStream.write(ascii("GET /again HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(ascii("GET /f HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    relayInspected(client, upstream, "docs.python.org", head)
    client.close()
    origin.join()

    val received = String(clientPeer.getInputStream.readAllBytes(), StandardCharsets.ISO_8859_1)
    assert(received.contains("Connection: close\r\n"), received)
    assert(!received.toLowerCase.contains("keep-alive"), received)
    assert(received.endsWith("\r\n\r\nhello"), received)

  test("relayInspected turns an origin that quits mid-body into TruncatedResponse"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    val origin = playOrigin(
      upstreamPeer,
      ascii("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf")
    )
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(ascii("GET /f HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    intercept[TruncatedResponse]:
      relayInspected(client, upstream, "docs.python.org", head)
    origin.join()

  test("relayInspected answers Expect: 100-continue before the origin says anything"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    // The origin answers only after the whole request (head and body) arrives, so a 100 in front
    // of its response can only have come from the proxy.
    val origin = Thread.startVirtualThread: () =>
      try
        readHttpHeader(upstreamPeer.getInputStream, 64 * 1024)
        val body = new Array[Byte](4)
        upstreamPeer.getInputStream.readNBytes(body, 0, 4)
        upstreamPeer.getOutputStream.write(ascii("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
        upstreamPeer.getOutputStream.close()
      catch case _: Exception => ()
    clientPeer.getOutputStream.write(ascii("ping"))
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(
      ascii(
        "POST /r.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\n" +
          "Content-Length: 4\r\n\r\n"
      )
    )
    relayInspected(client, upstream, "github.com", head)
    client.close()
    origin.join()

    val received = String(clientPeer.getInputStream.readAllBytes(), StandardCharsets.ISO_8859_1)
    assert(received.startsWith("HTTP/1.1 100 Continue\r\n\r\n"), received)
    assert(received.endsWith("\r\n\r\nok"), received)

  test("relayInspected forwards an origin's own 1xx and frames the body by the final head"):
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    val origin = playOrigin(
      upstreamPeer,
      ascii(
        "HTTP/1.1 100 Continue\r\n\r\n" +
          "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata"
      )
    )
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(ascii("GET /f HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    relayInspected(client, upstream, "docs.python.org", head)
    client.close()
    origin.join()

    val received = String(clientPeer.getInputStream.readAllBytes(), StandardCharsets.ISO_8859_1)
    assert(received.startsWith("HTTP/1.1 100 Continue\r\n\r\n"), received)
    assert(received.contains("HTTP/1.1 200 OK\r\n"), received)
    assert(received.endsWith("\r\n\r\ndata"), received)

  test("TLS ClientHello extracts SNI"):
    val bytes = clientHello("api.anthropic.com")
    val hello = TlsClientHello.read(
      ByteArrayInputStream(bytes),
      64 * 1024
    )

    assertEquals(hello.serverName, Some("api.anthropic.com"))
    assertEquals(hello.echPresent, false)
    assertEquals(hello.wireBytes.toVector, bytes.toVector)

  test("TLS ClientHello can be fragmented across TLS records"):
    val bytes = clientHello("api.anthropic.com", splitAt = Some(17))
    val hello = TlsClientHello.read(
      ByteArrayInputStream(bytes),
      64 * 1024
    )

    assertEquals(hello.serverName, Some("api.anthropic.com"))
    assertEquals(hello.wireBytes.toVector, bytes.toVector)

  test("TLS parser refuses bytes trailing the ClientHello in its record"):
    intercept[BadTls]:
      TlsClientHello.read(
        ByteArrayInputStream(
          clientHello("api.anthropic.com", trailingInRecord = Array[Byte](0, 0))
        ),
        64 * 1024
      )

  test("TLS ClientHello detects ECH"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(
        clientHello("api.anthropic.com", ech = true)
      ),
      64 * 1024
    )

    assert(hello.echPresent)

  test("TLS identity validation accepts CONNECT host == SNI"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(clientHello("api.anthropic.com")),
      64 * 1024
    )

    validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects SNI mismatch"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(clientHello("example.com")),
      64 * 1024
    )

    intercept[PolicyViolation]:
      validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects ECH"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(
        clientHello("api.anthropic.com", ech = true)
      ),
      64 * 1024
    )

    intercept[PolicyViolation]:
      validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects a ClientHello carrying no SNI"):
    // The third refusal beside the mismatch and the ECH above. Built directly rather than read off
    // the wire: what is under test is the identity check, and a hello with no server_name extension
    // is exactly the absence the case class already models.
    intercept[PolicyViolation]:
      validateTlsIdentity(
        "api.anthropic.com",
        TlsClientHello(Array.emptyByteArray, None, echPresent = false)
      )

  test("TLS parser rejects a truncated ClientHello"):
    val bytes = clientHello("api.anthropic.com")

    intercept[java.io.EOFException]:
      TlsClientHello.read(
        ByteArrayInputStream(bytes.dropRight(3)),
        64 * 1024
      )

  test("providers and catalog are disjoint, the groups are the agent endpoints, tags pinned"):
    // Disjointness is load-bearing (BaselineHosts is a map, and an overlap would silently give
    // one host whichever treatment won); the provider pin is the privacy boundary: unrestricted
    // is the hosts whose TLS must not be read — the agent endpoints — and not one host more.
    // The tag pins bound each POST allowance to the hosts that genuinely serve the operation.
    assertEquals(
      ModelProviderHosts.values.flatten.toSet.intersect(CuratedRestrictedHosts.keySet),
      Set.empty[String]
    )
    assertEquals(
      ModelProviderHosts,
      Map(
        "anthropic" -> Set("api.anthropic.com", "claude.ai", "platform.claude.com"),
        "openai" -> Set("api.openai.com", "auth.openai.com", "chatgpt.com"),
        "google" -> Set("accounts.google.com", "oauth2.googleapis.com", "cloudcode-pa.googleapis.com")
      )
    )
    assertEquals(
      builtinGitHosts,
      Set(
        "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
        "codeload.github.com", "api.github.com", "codeberg.org", "gitlab.com"
      )
    )
    assertEquals(baselinePolicy.tagged("npm-audit"), Set("registry.npmjs.org"))

  test("the leaf must name exactly the inspected hosts, in either direction"):
    val required = Set("github.com", "gitlab.com")

    assertEquals(TlsInspection.inspectedNamesError(required, required), None)

    // Under-coverage would fail later anyway, as a certificate error inside the sandbox; refusing names it here.
    val missing = TlsInspection.inspectedNamesError(Set("github.com"), required)
    assert(missing.exists(_.contains("does not cover gitlab.com")), missing.toString)

    // Over-coverage is the fail-open direction: a launcher minting a name this proxy does not inspect believes that
    // host is restricted while it tunnels opaquely, writable.
    val extra = TlsInspection.inspectedNamesError(required + "gist.github.com", required)
    assert(extra.exists(_.contains("gist.github.com")), extra.toString)

    // Both at once report both.
    val both = TlsInspection.inspectedNamesError(Set("github.com", "gist.github.com"), required)
    assert(both.exists(r => r.contains("gitlab.com") && r.contains("gist.github.com")), both.toString)

  test("a restricted host allows reading and nothing else"):
    // The tier exists for storage.googleapis.com: all of GCS, where an attacker-signed URL
    // accepts writes — so unlike a =git-fetch host there is no POST exception at all. The sharp case is a
    // POST whose path mimics git-upload-pack: an object name is anyone's to choose, and it must
    // NOT ride the =git-fetch rule through.
    def storage(request: String): Unit =
      authorizeInspectedRequest("storage.googleapis.com", head(request), Set.empty)

    storage("GET /bucket/blobs/sha256:abc?X-Goog-Signature=x HTTP/1.1\r\nHost: storage.googleapis.com\r\n\r\n")
    storage("HEAD /bucket/object HTTP/1.1\r\nHost: storage.googleapis.com\r\n\r\n")

    Vector("PUT", "POST", "PATCH", "DELETE").foreach: method =>
      intercept[PolicyViolation]:
        storage(
          s"$method /bucket/object HTTP/1.1\r\nHost: storage.googleapis.com\r\nContent-Length: 0\r\n\r\n"
        )
    intercept[PolicyViolation]:
      storage(
        "POST /bucket/x/git-upload-pack HTTP/1.1\r\n" +
          "Host: storage.googleapis.com\r\nContent-Length: 0\r\n\r\n"
      )
    // The user-facing concern is not the method name but the channel: a GET carrying a body is
    // an upload wearing a read method, and is refused on every inspected host — the fact named,
    // never a git host blamed for one that is not.
    val bodied = intercept[PolicyViolation]:
      storage(
        "GET /bucket/object HTTP/1.1\r\n" +
          "Host: storage.googleapis.com\r\nContent-Length: 9\r\n\r\n"
      )
    assert(bodied.getMessage.contains("request body"), bodied.getMessage)

    // The other refusal branches carry the tier in their wording too.
    val optioned = intercept[PolicyViolation]:
      storage(
        "OPTIONS /bucket HTTP/1.1\r\nHost: storage.googleapis.com\r\nContent-Length: 0\r\n\r\n"
      )
    assert(optioned.getMessage.contains("restricted host"), optioned.getMessage)

    // Uniform deny-side rules still apply: push ref discovery is refused here as anywhere.
    intercept[PolicyViolation]:
      storage(
        "GET /x/info/refs?service=git-receive-pack HTTP/1.1\r\n" +
          "Host: storage.googleapis.com\r\n\r\n"
      )

    // A documentation site wears the same tier: reads pass, anything else does not.
    authorizeInspectedRequest(
      "developer.mozilla.org",
      head("GET /en-US/docs/Web HTTP/1.1\r\nHost: developer.mozilla.org\r\n\r\n"),
      Set.empty
    )
    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "developer.mozilla.org",
        head("POST /api/x HTTP/1.1\r\nHost: developer.mozilla.org\r\nContent-Length: 0\r\n\r\n"),
        Set.empty
      )

    // A package registry wears the tier too — security is not traded for performance — so a
    // fetch reads, npm's measured install-time audit POST is its =npm-audit allowance, and an
    // older npm's endpoint (or any other POST) earns an honest refusal.
    authorizeInspectedRequest(
      "registry.npmjs.org",
      head("GET /lodash HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n"),
      Set("npm-audit")
    )
    authorizeInspectedRequest(
      "registry.npmjs.org",
      head(
        s"POST $NpmAuditPath HTTP/1.1\r\n" +
          "Host: registry.npmjs.org\r\nContent-Length: 0\r\n\r\n"
      ),
      Set("npm-audit")
    )
    val oldNpm = intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "registry.npmjs.org",
        head(
          "POST /-/npm/v1/security/audits/quick HTTP/1.1\r\n" +
            "Host: registry.npmjs.org\r\nContent-Length: 0\r\n\r\n"
        ),
        Set("npm-audit")
      )
    assert(oldNpm.getMessage.contains("restricted path"), oldNpm.getMessage)
    // The =npm-audit allowance opens nothing on a =git-fetch host, and vice versa.
    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "github.com",
        head(
          s"POST $NpmAuditPath HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        ),
        Set("git-fetch")
      )

  test("HTTP request head parses a request line and its headers"):
    val request = head(
      "GET /owner/repo HTTP/1.1\r\n" +
        "Host: github.com\r\n" +
        "User-Agent: git/2.51.0\r\n" +
        "\r\n"
    )

    assertEquals(request.method, "GET")
    assertEquals(request.target, "/owner/repo")
    assertEquals(request.values("host"), Vector("github.com"))
    assertEquals(request.values("User-Agent"), Vector("git/2.51.0"))

  test("HTTP request head splits a target into path and query"):
    val request = head(
      "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n"
    )

    assertEquals(request.path, "/owner/repo.git/info/refs")
    assertEquals(request.query, "service=git-upload-pack")

  test("HTTP request head rejects an obsolete folded header"):
    intercept[BadRequest]:
      head("GET / HTTP/1.1\r\nHost: github.com\r\n continued\r\n\r\n")

  test("reading a =git-fetch host is allowed"):
    inspected("GET /owner/repo HTTP/1.1\r\nHost: github.com\r\n\r\n")
    inspected("HEAD /owner/repo HTTP/1.1\r\nHost: github.com\r\n\r\n")
    inspected(
      "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n"
    )

  test("a read method may not carry a request body"):
    Vector("GET", "HEAD").foreach: method =>
      intercept[PolicyViolation]:
        inspected(
          s"$method /owner/repo HTTP/1.1\r\nHost: github.com\r\nContent-Length: 5\r\n\r\n"
        )

  test("git fetch is allowed and git push is not"):
    inspected(
      "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\nContent-Length: 0\r\n\r\n"
    )

    intercept[PolicyViolation]:
      inspected(
        "POST /owner/repo.git/git-receive-pack HTTP/1.1\r\n" +
          "Host: github.com\r\nContent-Length: 0\r\n\r\n"
      )

  test("git fetch from a nested GitLab subgroup is allowed, push is not"):
    // gitlab.com nests a repository under arbitrarily deep subgroups; the whole-path rule admits the depth, never a
    // different final segment.
    authorizeInspectedRequest(
      "gitlab.com",
      head(
        "POST /group/subgroup/project.git/git-upload-pack HTTP/1.1\r\n" +
          "Host: gitlab.com\r\nContent-Length: 0\r\n\r\n"
      ),
      Set("git-fetch")
    )

    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "gitlab.com",
        head(
          "POST /group/subgroup/project.git/git-receive-pack HTTP/1.1\r\n" +
            "Host: gitlab.com\r\nContent-Length: 0\r\n\r\n"
        ),
        Set("git-fetch")
      )

  test("git push ref discovery is refused even though it is a GET"):
    intercept[PolicyViolation]:
      inspected(
        "GET /owner/repo.git/info/refs?service=git-receive-pack HTTP/1.1\r\n" +
          "Host: github.com\r\n\r\n"
      )

  test("git push ref discovery is refused in percent-encoded spellings too"):
    // The origin server decodes before routing, so an encoded spelling asks for the same service; the classification
    // decodes the same way.
    Vector(
      "/owner/repo.git/info/refs?service=git%2Dreceive-pack",
      "/owner/repo.git/info/refs?%73ervice=git-receive-pack",
      "/owner/repo.git/inf%6F/refs?service=git-receive-pack"
    ).foreach: target =>
      intercept[PolicyViolation]:
        inspected(s"GET $target HTTP/1.1\r\nHost: github.com\r\n\r\n")

  test("a malformed percent escape is no receive-pack discovery"):
    // Kept as it is by the decode, it matches nothing an origin would route to receive-pack either; the GET stays an
    // ordinary read.
    inspected(
      "GET /owner/repo.git/info/refs?service=git-receive%2xpack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n"
    )

  test("no other method reaches an inspected host"):
    Vector("PUT", "PATCH", "DELETE", "OPTIONS", "TRACE").foreach: method =>
      intercept[PolicyViolation]:
        inspected(
          s"$method /owner/repo HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        )

  test("no other path accepts a POST"):
    Vector(
      "/graphql",
      "/owner/repo/issues",
      "/owner/repo.git/git-upload-pack/x",
      // At least owner/repo before the service segment: a single segment is no repository on any forge, and the bare
      // name is not a path.
      "/x/git-upload-pack",
      "/git-upload-pack"
    ).foreach: path =>
      intercept[PolicyViolation]:
        inspected(
          s"POST $path HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        )

  test("a write path may not be spelled ambiguously"):
    Vector(
      "/owner/repo.git/%2e%2e/git-upload-pack",
      "/owner/repo.git/../git-upload-pack",
      "/owner/repo.git/./git-upload-pack"
    ).foreach: path =>
      intercept[PolicyViolation]:
        inspected(
          s"POST $path HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
        )

  test("the Host header must name the host the connection was authorized for"):
    intercept[PolicyViolation]:
      inspected("GET /x HTTP/1.1\r\nHost: evil.example\r\n\r\n")

    inspected("GET /x HTTP/1.1\r\nHost: GitHub.com:443\r\n\r\n")

  test("a Host header naming another port is refused"):
    intercept[BadRequest]:
      inspected("GET /x HTTP/1.1\r\nHost: github.com:8443\r\n\r\n")

  test("only origin-form request targets are accepted"):
    intercept[PolicyViolation]:
      inspected("GET https://github.com/x HTTP/1.1\r\nHost: github.com\r\n\r\n")

  test("HTTP Upgrade is refused"):
    intercept[PolicyViolation]:
      inspected("GET /x HTTP/1.1\r\nHost: github.com\r\nUpgrade: websocket\r\n\r\n")

  test("ambiguous message framing is refused rather than resolved"):
    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
      )

    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Content-Length: 5\r\nContent-Length: 6\r\n\r\n"
      )

    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Transfer-Encoding: gzip\r\n\r\n"
      )

  test("message framing is read from the headers"):
    assertEquals(
      head("GET /x HTTP/1.1\r\nHost: github.com\r\n\r\n").bodyFraming,
      BodyFraming.Empty
    )
    assertEquals(
      head("POST /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 12\r\n\r\n").bodyFraming,
      BodyFraming.Length(12)
    )
    assertEquals(
      head(
        "POST /x HTTP/1.1\r\nHost: github.com\r\nTransfer-Encoding: chunked\r\n\r\n"
      ).bodyFraming,
      BodyFraming.Chunked
    )

  test("the forwarded request is HTTP/1.1, closes, and drops hop-by-hop headers"):
    val forwarded =
      String(
        head(
          "GET /owner/repo HTTP/1.1\r\n" +
            "Host: github.com\r\n" +
            "Proxy-Connection: keep-alive\r\n" +
            "Proxy-Authorization: Basic x\r\n" +
            "Keep-Alive: timeout=5\r\n" +
            "Accept: */*\r\n" +
            "\r\n"
        ).toUpstreamBytes,
        StandardCharsets.ISO_8859_1
      )

    assertEquals(
      forwarded,
      "GET /owner/repo HTTP/1.1\r\n" +
        "Host: github.com\r\n" +
        "Accept: */*\r\n" +
        "Connection: close\r\n\r\n"
    )

  test("chunked lines are read up to CRLF and bounded"):
    val input = ByteArrayInputStream(ascii("1a;ext\r\nrest"))

    assertEquals(readCrLfLine(input, 64), "1a;ext")

    intercept[BadRequest]:
      readCrLfLine(ByteArrayInputStream(ascii("0123456789\r\n")), 4)

  test("audit lines are verb host method [target] tail, with - for fields never learned"):
    // The stable head SECURITY.md ("The audit line grammar") documents: fields 1-3 always
    // present, the target exactly when a parsed inspected request exists, the rest human text.
    assertEquals(
      auditLine("allow", "github.com", "GET", "/r?tab=readme", "-> 140.82.112.3"),
      "allow github.com GET /r?tab=readme -> 140.82.112.3"
    )
    assertEquals(
      auditLine("allow", "api.anthropic.com", "CONNECT", "", "-> 160.79.104.10"),
      "allow api.anthropic.com CONNECT -> 160.79.104.10"
    )
    assertEquals(
      auditLine("deny", "tracker.example", "CONNECT", "", "host not allowed"),
      "deny tracker.example CONNECT host not allowed"
    )
    assertEquals(
      auditLine("deny", "-", "-", "", "invalid CONNECT port"),
      "deny - - invalid CONNECT port"
    )
    assertEquals(
      auditLine("deny", "github.com", "POST", "/r.git/git-receive-pack", "restricted path"),
      "deny github.com POST /r.git/git-receive-pack restricted path"
    )

  test("every reported line is stamped once with the UTC instant, however it is written"):
    val sink = java.io.ByteArrayOutputStream()
    val ticks = Iterator.from(0)
    val stamped = java.io.PrintStream(
      stampLines(sink, () => java.time.Instant.parse("2026-08-26T11:59:38.250Z").plusSeconds(ticks.next())),
      true
    )

    stamped.println("allow github.com CONNECT -> 140.82.112.3")
    stamped.print("deny ")
    stamped.print("x.example")
    stamped.println(" CONNECT host not allowed")
    stamped.write("a\nb\n".getBytes)
    stamped.print("tail without newline")
    stamped.flush()

    assertEquals(
      String(sink.toByteArray, StandardCharsets.US_ASCII),
      """2026-08-26T11:59:38Z allow github.com CONNECT -> 140.82.112.3
        |2026-08-26T11:59:39Z deny x.example CONNECT host not allowed
        |2026-08-26T11:59:40Z a
        |2026-08-26T11:59:41Z b
        |2026-08-26T11:59:42Z tail without newline""".stripMargin
    )

  test("the audit tee writes and flushes every byte to both sinks"):
    val a = java.io.ByteArrayOutputStream()
    val b = java.io.ByteArrayOutputStream()
    val tee = java.io.PrintStream(teeOutput(a, b), true)

    tee.println("allow github.com")
    tee.write('x')
    tee.flush()

    assertEquals(a.toByteArray.toVector, b.toByteArray.toVector)
    assert(String(a.toByteArray, StandardCharsets.US_ASCII).startsWith("allow github.com"))

  private def head(value: String): HttpRequestHead =
    HttpRequestHead.parse(ascii(value))

  /** The built-in =git-fetch hosts, as the resolved default policy carries them. */
  /** The baseline as a policy: deny-unless-allowed with no project files. */
  private lazy val baselinePolicy: ResolvedEgress =
    resolvePolicy(Some("deny-unless-allowed"), None, None, None)

  private lazy val builtinGitHosts: Set[String] = baselinePolicy.tagged("git-fetch")

  private def inspected(value: String): Unit =
    authorizeInspectedRequest("github.com", head(value), Set("git-fetch"))

  private def parseConnect(value: String): ConnectRequest =
    ConnectRequest.parse(ascii(value))

  private def authorize(host: String, port: Int, resolved: ResolvedEgress = baselinePolicy): String =
    authorizeRequest(ConnectRequest(host, port), resolved)

  private def clientHello(
    serverName: String,
    ech: Boolean = false,
    splitAt: Option[Int] = None,
    trailingInRecord: Array[Byte] = Array.emptyByteArray
  ): Array[Byte] =
    val sniBytes = ascii(serverName)

    val serverNameEntry =
      Array[Byte](0) ++ u16(sniBytes.length) ++ sniBytes

    val serverNameExtensionData =
      u16(serverNameEntry.length) ++ serverNameEntry

    val serverNameExtension =
      u16(0x0000) ++
        u16(serverNameExtensionData.length) ++
        serverNameExtensionData

    val echExtension =
      if ech then u16(0xfe0d) ++ u16(1) ++ Array[Byte](0)
      else Array.emptyByteArray

    val extensions = serverNameExtension ++ echExtension

    val payload =
      u16(0x0303) ++                    // legacy_version
        Array.fill[Byte](32)(0x42) ++   // random
        Array[Byte](0) ++               // legacy_session_id
        u16(2) ++ u16(0x1301) ++        // one cipher suite
        Array[Byte](1, 0) ++             // compression_methods = { null }
        u16(extensions.length) ++
        extensions

    val handshake =
      Array[Byte](1) ++ u24(payload.length) ++ payload

    splitAt match
      case None => tlsRecord(handshake ++ trailingInRecord)
      case Some(index) =>
        require(index > 0 && index < handshake.length)
        tlsRecord(handshake.take(index)) ++
          tlsRecord(handshake.drop(index))

  private def tlsRecord(payload: Array[Byte]): Array[Byte] =
    Array[Byte](22, 3, 3) ++ u16(payload.length) ++ payload

  private def ascii(value: String): Array[Byte] =
    value.getBytes(StandardCharsets.US_ASCII)

  private def u16(value: Int): Array[Byte] =
    Array(
      ((value >>> 8) & 0xff).toByte,
      (value & 0xff).toByte
    )

  private def u24(value: Int): Array[Byte] =
    Array(
      ((value >>> 16) & 0xff).toByte,
      ((value >>> 8) & 0xff).toByte,
      (value & 0xff).toByte
    )
