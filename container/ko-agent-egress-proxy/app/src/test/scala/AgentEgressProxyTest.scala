package agentsandbox.egress

import scala.jdk.CollectionConverters.*
import java.io.{ByteArrayInputStream, IOException}
import java.net.InetAddress
import java.nio.charset.StandardCharsets

import AgentEgressProxy.*
import LogHelper.*
import PolicyHelper.*
import HTTPHelper.*
import IPAddrHelper.*
import TLSHelper.*

class AgentEgressProxyTest extends munit.FunSuite:

  test("normalizeHost lowercases and removes one trailing dot"):
    assertEquals(
      normalizeHost("API.Anthropic.COM."),
      "api.anthropic.com",
    )

  test("normalizeHost converts IDN to ASCII"):
    assertEquals(
      normalizeHost("bücher.example"),
      "xn--bcher-kva.example",
    )

  test("CONNECT parser accepts a normal HTTP/1.1 CONNECT"):
    val request = parseConnect(
      "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
        "Host: api.anthropic.com:443\r\n" +
        "Proxy-Connection: keep-alive\r\n" +
        "\r\n",
    )

    assertEquals(
      request,
      ConnectRequest("api.anthropic.com", 443),
    )

  test("CONNECT parser rejects a request body framing header"):
    intercept[BadRequest]:
      parseConnect(
        "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
          "Content-Length: 0\r\n" +
          "\r\n",
      )

  test("CONNECT parser rejects a non-CONNECT method"):
    intercept[BadRequest]:
      parseConnect("GET https://api.anthropic.com/ HTTP/1.1\r\n\r\n")

  test("the pull hosts are reachable and inspected"):
    // Why the treatment: SECURITY.md, "Reading without being able to write".
    Vector(
      "registry-1.docker.io", "auth.docker.io",
      "production.cloudflare.docker.com", "production.cloudfront.docker.com",
      "gcr.io", "public.ecr.aws",
      "d2glxqk2uabbnd.cloudfront.net", "d5l0dvt14r5h8.cloudfront.net",
    ).foreach: host =>
      assertEquals(authorize(host, 443), host)
      assertEquals(DefaultHosts.get(host), Some(Treatment.Inspected(Map("/" -> Set("read")))), host)


  test("authorizeRequest rejects ports other than 443"):
    intercept[PolicyViolation]:
      authorize("api.anthropic.com", 8443)

  test("authorizeRequest rejects a hostname outside the policy"):
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
    // trailing dot / letter case (GHSA-gcj7-j438-hjj2). A policy with one normalizeHost chokepoint keeps every
    // dressing of a non-listed host refused.
    Vector(
      "[example.com]:443",
      "example.com.:443",
      "EXAMPLE.COM:443",
      "ExAmPlE.CoM.:443",
    ).foreach: authority =>
      intercept[PolicyViolation]:
        authorizeRequest(
          ConnectRequest.parse(ascii(s"CONNECT $authority HTTP/1.1\r\n\r\n")),
          defaultsPolicy,
        )

  test("an allowed host authorizes to one canonical form however it is spelled"):
    // The other half: every spelling of an allowed host collapses to one canonical name — the one later bound to SNI
    // (validateTlsIdentity).
    Vector(
      "github.com:443",
      "GitHub.COM:443",
      "github.com.:443",
      "[github.com]:443",
    ).foreach: authority =>
      assertEquals(
        authorizeRequest(
          ConnectRequest.parse(ascii(s"CONNECT $authority HTTP/1.1\r\n\r\n")),
          defaultsPolicy,
        ),
        "github.com",
      )

  test("isIpLiteral leaves ordinary hostnames alone"):
    Vector(
      "api.anthropic.com",
      "files.pythonhosted.org",
      "xn--bcher-kva.example",
      "host123.example.com",
    ).foreach(host => assert(!isIpLiteral(host), host))

  // ---------------------------------------------------------------------------
  // The grammar: every launch refusal names its line and the problem
  // ---------------------------------------------------------------------------

  private def policyOf(
    profile: String = "deny-unless-allowed",
    provider: String = "",
    rule: String = "",
  ): ResolvedEgress =
    def opt(value: String) = Option(value).filter(_.nonEmpty)
    resolvePolicy(Some(profile), opt(provider), opt(rule))

  private def refusalOf(rule: String): String =
    intercept[IllegalArgumentException](policyOf(rule = rule)).getMessage

  test("a line outside the grammar is refused naming the line and the problem, never skipped"):
    Vector(
      "allow https://x.example" -> "has no / after its host",
      "allow https://x.example/" -> "names no grant",
      "allow https://x.example/ read read" -> "names read twice",
      "allow https://x.example/ method=POST,POST" -> "names POST twice",
      "allow https://x.example/ method=POST method=PUT" -> "names method= twice",
      "allow https://x.example/ method=" -> "names the method ''",
      "allow https://x.example/ method=GET" -> "names the method 'GET'",
      "allow https://x.example/ method=post" -> "names the method 'post'",
      "allow https://x.example/ tunnel read" -> "puts tunnel beside another word",
      "allow https://x.example/api/ tunnel" -> "gives a tunnel a path",
      "allow https://x.example/ write" -> "has the word 'write', which is no grant",
      "allow https://x.example/ allow=git-fetch" -> "has the word 'allow=git-fetch', which is no grant",
      "deny https://x.example/api/" -> "denies a path",
      "deny https://x.example/api/ read" -> "denies a path",
      "deny https://x.example/api" -> "denies a path",
      "deny https://x.example" -> "has no / after its host",
      "allow https://**.example/ read" -> "names a pattern",
      "allow https://x.example:8443/ read" -> "carries a port",
      "allow https://user@x.example/ read" -> "carries userinfo",
      "allow https://[x.example]/ read" -> "carries a bracket",
      "allow https:///a/ read" -> "names no host",
      "allow https://x.example/a?b=1 read" -> "has a query",
      "allow https://x.example/a%20b/ read" -> "has percent-encoding in its path",
      "allow https://x.example/a/../b/ read" -> "has a dot segment in its path",
      "allow https://x.example/./ read" -> "has a dot segment in its path",
      "allow https://x.example/a//b/ read" -> "has an empty segment in its path",
      "allow https://x.example/a\\b/ read" -> "has a backslash in its path",
      "allow https://x.example/ä/ read" -> "outside printable ASCII",
      "allow HTTPS://x.example/ read" -> "is no line of the rule grammar",
      "allow http://x.example/ read" -> "is no line of the rule grammar",
      "allow x.example read" -> "is no line of the rule grammar",
      "+host x.example" -> "is no line of the rule grammar",
      "host x.example" -> "is no line of the rule grammar",
      "-**" -> "is no line of the rule grammar",
      "allow" -> "is no line of the rule grammar",
      "deny" -> "is no line of the rule grammar",
      "allow model-provider" -> "is no line of the rule grammar",
      "allow model-provider anthropic read" -> "is no line of the rule grammar",
      "allow model-provider meta" -> "names the model provider 'meta'",
      "deny model-provider meta" -> "names the model provider 'meta'",
      "deny defaults read" -> "takes no word after defaults",
      "allow https://x.example/ read\ndeny defaults" -> "follows another line",
      "deny https://x.example/\ndeny defaults" -> "follows another line",
      "allow https://x.example/a#b read" -> "a token with '#' inside it",
      "allow https://x.example/ read#" -> "a token with '#' inside it",
      "deny https://x.example/#y" -> "a token with '#' inside it",
      "allow https://10.0.0.1/ read" -> "IP literal",
      "allow https://a..b/ read" -> "invalid hostname",
      "deny https://a.example,b.example/" -> "invalid hostname",
      "deny https://**pypi.org/" -> "invalid hostname",
      "deny https://*/" -> "invalid hostname",
      "allow https://x.example/ tunnel\nallow https://x.example/api/ read" -> "inspects x.example while it is a tunnel",
      "allow https://x.example/api/ read\nallow https://x.example/ tunnel" -> "makes x.example a tunnel while it holds",
      "allow https://api.anthropic.com/safe/ read" -> "inspects api.anthropic.com while it is a tunnel",
      "allow https://github.com/ tunnel" -> "makes github.com an opaque tunnel, which the defaults inspect",
      "deny https://github.com/\nallow https://github.com/ tunnel" -> "makes github.com an opaque tunnel",
    ).foreach: (rule, problem) =>
      val message = refusalOf(rule)
      assert(message.contains(problem), s"$rule: $message")
      assert(message.startsWith("rule"), s"$rule: $message")

  test("an unknown profile or provider is refused, never defaulted"):
    intercept[IllegalArgumentException](policyOf(profile = "allow-all"))
    intercept[IllegalArgumentException](policyOf(profile = "deny-unless-model", provider = "meta"))

  test("a retired variable refuses the start naming the one variable the proxy reads"):
    assertEquals(RetiredVariables, Vector("EGRESS_ALLOWED", "EGRESS_DENIED"))
    RetiredVariables.foreach: retired =>
      val ex = intercept[IllegalArgumentException](
        configuredPolicy(name => Option.when(name == retired)("+host x.example")),
      )
      assert(ex.getMessage.contains(RuleVariable), ex.getMessage)
    assertEquals(configuredPolicy(_ => None).hosts, DefaultHosts)
    assert(
      !configuredPolicy(name => Option.when(name == RuleVariable)("deny https://pypi.org/")).hosts.contains("pypi.org"),
    )

  // ---------------------------------------------------------------------------
  // The warnings: printed at every launch, the same under every profile
  // ---------------------------------------------------------------------------

  test("a deny matching nothing at its position is warned under every profile, so a misspelling cannot fail silently"):
    Profiles.foreach: profile =>
      val provider = if profile == "deny-unless-model" then "anthropic" else ""
      val resolved = policyOf(profile = profile, provider = provider, rule = "deny https://telemetry.example/")
      assertEquals(
        resolved.warnings,
        Vector("rule: deny https://telemetry.example/ matches nothing at its position"),
        profile,
      )
    // A deny that takes something is no warning, under a profile that never consults it included.
    assertEquals(policyOf(profile = "deny-all", rule = "deny https://github.com/").warnings, Vector.empty)
    // A grant no line gave, a subtree over nothing, a group after `deny defaults`, and `tunnel` on an
    // inspected host: each names its line.
    Vector(
      "deny https://api.anthropic.com/ read" -> "matches nothing",
      "deny https://**.example.com/" -> "matches nothing",
      "deny https://github.com/ tunnel" -> "matches nothing",
      "deny defaults\ndeny model-provider google" -> "removes nothing",
      "deny model-provider google\ndeny model-provider google" -> "removes nothing",
    ).foreach: (rule, problem) =>
      val warnings = policyOf(rule = rule).warnings
      assert(
        warnings.exists(warning => warning.contains(problem) && warning.contains(rule.linesIterator.toVector.last)),
        s"$rule: $warnings",
      )
    assertEquals(policyOf(rule = "deny https://**.googleapis.com/").warnings, Vector.empty)
    assertEquals(policyOf(rule = "deny model-provider google").warnings, Vector.empty)

  test("a redundant grant is warned naming the deny-then-re-grant pair; a restatement of the defaults is silent"):
    val redundant = policyOf(rule = "allow https://github.com/my-org/ git-fetch")
    assertEquals(
      redundant.warnings,
      Vector(
        "rule: allow https://github.com/my-org/ git-fetch grants nothing its enclosing scope lacks at its position; " +
          "to narrow, take the grants first: deny https://github.com/ git-fetch, then this line",
      ),
    )
    // The boundary stands all the same: the scope is in the policy (invariant 5 of the plan).
    assertEquals(redundant.inspectedScopes("github.com")("/my-org/"), Set("read", "git-fetch"))
    Vector(
      "allow https://github.com/ read",
      "allow https://github.com/ read git-fetch",
      "allow https://github.com/login/device/code method=POST",
      "allow https://api.github.com/copilot_internal/v2/token read",
      "allow https://api.anthropic.com/ tunnel",
      "allow model-provider anthropic",
      "allow model-provider github",
    ).foreach(rule => assertEquals(policyOf(rule = rule).warnings, Vector.empty, rule))
    // The pair itself is what the line was written for.
    assertEquals(
      policyOf(rule = "deny https://github.com/ git-fetch\nallow https://github.com/my-org/ git-fetch").warnings,
      Vector.empty,
    )
    // A file line restating an earlier file line at its path, or repeating it, is the file's own redundancy.
    Vector(
      "allow https://x.example/ read git-fetch\nallow https://x.example/ read",
      "allow https://x.example/ read\nallow https://x.example/ read",
      "deny defaults\nallow model-provider anthropic\nallow model-provider anthropic",
    ).foreach: rule =>
      assert(policyOf(rule = rule).warnings.exists(_.contains("grants nothing its enclosing")), rule)
    // The check reads the defaults and the file, never the profile.
    Profiles.foreach: profile =>
      assertEquals(
        policyOf(profile = profile, rule = "allow https://github.com/my-org/ git-fetch").warnings,
        redundant.warnings,
        profile,
      )

  test("a line every grant of which a later line takes back is warned, whatever boundary it leaves"):
    val taken = policyOf(rule = "allow https://x.example/ read\ndeny https://x.example/")
    assertEquals(
      taken.warnings,
      Vector("rule: allow https://x.example/ read grants nothing: every grant it names is taken back by a later line"),
    )
    // Taken back in part is no warning; the pair the other way round is none either.
    assertEquals(
      policyOf(rule = "allow https://x.example/ read git-fetch\ndeny https://x.example/ read").warnings,
      Vector.empty,
    )
    assertEquals(policyOf(rule = "deny https://pypi.org/\nallow https://pypi.org/simple/ read").warnings, Vector.empty)
    // The three-line cases: a repeated deny takes the exception back and the exception is warned; a
    // repeated allow restores what the deny between them took, and the first allow is warned.
    val third = policyOf(
      rule = "deny https://codeberg.org/ git-fetch\nallow https://codeberg.org/my-org/ git-fetch\n" +
        "deny https://codeberg.org/ git-fetch",
    )
    assertEquals(third.inspectedScopes("codeberg.org"), Map("/" -> Set("read"), "/my-org/" -> Set("read")))
    assert(third.warnings.exists(_.contains("taken back")), third.warnings.toString)
    val restored = policyOf(
      rule = "allow https://x.example/ read\ndeny https://x.example/ read\nallow https://x.example/ read",
    )
    assertEquals(restored.inspectedScopes("x.example"), Map("/" -> Set("read")))
    assertEquals(restored.warnings.size, 1)
    assert(restored.warnings.head.contains("taken back"), restored.warnings.toString)
    // A provider line is warned once, naming itself, when every line it expands to is taken back —
    // by the group's deny or host by host; one host left standing is no warning.
    val groupTaken = "deny defaults\nallow model-provider anthropic\ndeny model-provider anthropic"
    assertEquals(
      policyOf(rule = groupTaken).warnings,
      Vector("rule: allow model-provider anthropic grants nothing: every grant it names is taken back by a later line"),
    )
    val hostByHost = "deny defaults\nallow model-provider anthropic\ndeny https://api.anthropic.com/\n" +
      "deny https://claude.ai/\ndeny https://platform.claude.com/"
    assertEquals(policyOf(rule = hostByHost).warnings.count(_.contains("taken back")), 1)
    assertEquals(
      policyOf(rule = "deny defaults\nallow model-provider anthropic\ndeny https://api.anthropic.com/").warnings,
      Vector.empty,
    )

  // ---------------------------------------------------------------------------
  // Resolution: the profiles, the defaults, and the lines in order
  // ---------------------------------------------------------------------------

  test("deny-unless-allowed with no rule file resolves to the defaults, the groups' lines in their hosts' scopes"):
    val resolved = policyOf()
    assertEquals(resolved.hosts, DefaultHosts)
    assert(!resolved.ambient)
    assertEquals(
      resolved.inspectedScopes("github.com"),
      Map(
        "/" -> Set("read", "git-fetch"),
        "/login/device/code" -> Set("read", "git-fetch", "POST"),
        "/login/oauth/access_token" -> Set("read", "git-fetch", "POST"),
      ),
    )
    assertEquals(
      resolved.inspectedScopes("api.github.com"),
      Map("/" -> Set("read"), "/copilot_internal/v2/token" -> Set("read")),
    )
    assertEquals(resolved.hosts("api.githubcopilot.com"), Treatment.Tunnel)
    assertEquals(resolved.ambientDenials, Vector.empty)
    assertEquals(resolved.warnings, Vector.empty)
    assert(!resolved.clearsDefaults)

  test("the defaults are the catalog, every line a root read, and the groups, pinned"):
    // The provider pin is the privacy boundary: a tunnel is a host whose TLS must not be read — the
    // agent endpoints — and not one host more; a group's forge lines are precise, or deny-unless-model
    // would admit a push or a browse of the forge.
    CatalogLines.foreach: line =>
      line.rule match
        case Rule.Allow(_, path, grants) =>
          assertEquals(path, "/", line.text)
          assert(grants("read") && !grants("tunnel"), line.text)
        case other => fail(s"${line.text}: $other")
    assertEquals(ModelProviderLines.keySet, ModelProviders.toSet)
    def lines(name: String): Vector[String] = ModelProviderLines(name).map(_.text)
    assertEquals(
      lines("anthropic"),
      Vector(
        "allow https://api.anthropic.com/ tunnel",
        "allow https://claude.ai/ tunnel",
        "allow https://platform.claude.com/ tunnel",
      ),
    )
    assertEquals(
      lines("openai"),
      Vector(
        "allow https://chatgpt.com/ tunnel",
        "allow https://api.openai.com/ tunnel",
        "allow https://auth.openai.com/ tunnel",
      ),
    )
    assertEquals(
      lines("google"),
      Vector(
        "allow https://cloudcode-pa.googleapis.com/ tunnel",
        "allow https://accounts.google.com/ tunnel",
        "allow https://oauth2.googleapis.com/ tunnel",
      ),
    )
    assertEquals(
      lines("github"),
      Vector(
        "allow https://api.githubcopilot.com/ tunnel",
        "allow https://api.individual.githubcopilot.com/ tunnel",
        "allow https://api.business.githubcopilot.com/ tunnel",
        "allow https://api.enterprise.githubcopilot.com/ tunnel",
        "allow https://github.com/login/device/code method=POST",
        "allow https://github.com/login/oauth/access_token method=POST",
        "allow https://api.github.com/copilot_internal/v2/token read",
      ),
    )
    assertEquals(builtinGitHosts, Set("github.com", "codeberg.org", "gitlab.com"))
    // The provider list names exactly the defaults' model-provider files: a jar cannot list a
    // resource directory, so the names are a constant, held to the files both ways.
    val dir = java.nio.file.Paths.get("src/main/resources/default/model-provider")
    val files = java.nio.file.Files.list(dir).iterator.asScala.map(_.getFileName.toString).toSet
    assertEquals(files, ModelProviders.toSet)

  test("deny-all resolves empty, and empty is a valid policy, not a broken one"):
    val resolved = policyOf(profile = "deny-all", rule = "deny https://example.com/")
    assertEquals(resolved.hosts, Map.empty[String, Treatment])
    intercept[PolicyViolation](authorize("api.anthropic.com", 443, resolved))
    assertEquals(resolved.ambientDenials, Vector.empty)

  test("deny-unless-model admits the selected group and consults the file's deny lines alone"):
    val resolved = policyOf(profile = "deny-unless-model", provider = "anthropic")
    assertEquals(
      resolved.hosts,
      Map(
        "api.anthropic.com" -> Treatment.Tunnel,
        "claude.ai" -> Treatment.Tunnel,
        "platform.claude.com" -> Treatment.Tunnel,
      ),
    )
    assertEquals(authorize("api.anthropic.com", 443, resolved), "api.anthropic.com")
    intercept[PolicyViolation](authorize("github.com", 443, resolved))
    // Allow lines, another group and deny defaults change nothing.
    assertEquals(
      policyOf(
        profile = "deny-unless-model", provider = "anthropic",
        rule = "deny defaults\nallow https://docs.example/ read\nallow model-provider openai",
      ).policy,
      resolved.policy,
    )
    // A deny applies, and an endpoint it takes is warned, never a failed start: the profile stays
    // the user's authority decision.
    val denied = policyOf(profile = "deny-unless-model", provider = "openai", rule = "deny https://chatgpt.com/")
    assert(!denied.hosts.contains("chatgpt.com"))
    assert(denied.hosts.contains("api.openai.com"))
    assert(denied.warnings.exists(_.contains("chatgpt.com")), denied.warnings.toString)
    assertEquals(
      policyOf(profile = "deny-unless-model", provider = "github", rule = "deny model-provider github").hosts,
      Map.empty,
    )
    // No provider selected: valid and empty.
    val none = policyOf(profile = "deny-unless-model")
    assertEquals(none.hosts, Map.empty[String, Treatment])
    assertEquals(policyLines(none), Vector("egress profile: deny-unless-model; model provider: none"))

  test("deny-unless-model for copilot admits the precise group: two login POSTs, one token read, four tunnels"):
    val resolved = policyOf(profile = "deny-unless-model", provider = "github")
    assertEquals(
      resolved.inspectedScopes,
      Map(
        "github.com" -> Map("/login/device/code" -> Set("POST"), "/login/oauth/access_token" -> Set("POST")),
        "api.github.com" -> Map("/copilot_internal/v2/token" -> Set("read")),
      ),
    )
    assertEquals(
      resolved.tunnelHosts,
      Set(
        "api.githubcopilot.com", "api.individual.githubcopilot.com",
        "api.business.githubcopilot.com", "api.enterprise.githubcopilot.com",
      ),
    )
    // The forge is readable nowhere and clonable nowhere: the group grants no read of it.
    val scopes = resolved.inspectedScopes("github.com")
    def request(request: String): Unit = authorizeInspectedRequest("github.com", head(request), scopes)
    request("POST /login/device/code HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n")
    request("POST /login/oauth/access_token HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n")
    assertEquals(
      intercept[PolicyViolation](request("GET /octocat/Hello-World HTTP/1.1\r\nHost: github.com\r\n\r\n")).getMessage,
      "path outside allowance",
    )
    assertEquals(
      intercept[PolicyViolation](request("GET /login/device/code HTTP/1.1\r\nHost: github.com\r\n\r\n")).getMessage,
      "read not granted",
    )
    intercept[PolicyViolation](
      request(
        "POST /octocat/Hello-World.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n",
      ),
    )
    authorizeInspectedRequest(
      "api.github.com",
      head("GET /copilot_internal/v2/token HTTP/1.1\r\nHost: api.github.com\r\n\r\n"),
      resolved.inspectedScopes("api.github.com"),
    )
    intercept[PolicyViolation](
      authorizeInspectedRequest(
        "api.github.com", head(
          "GET /user HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        ), resolved.inspectedScopes("api.github.com"),
      ),
    )

  test("allow-unless-denied admits any public host, keeps the defaults' inspected hosts narrowed; a denial wins"):
    val resolved = policyOf(profile = "allow-unless-denied", rule = "deny https://telemetry.example.com/")
    assert(resolved.ambient)
    assertEquals(authorize("anything.example.org", 443, resolved), "anything.example.org")
    // The narrowing set is every inspected default, the groups' scopes included: a catalog host stays
    // inspected rather than widening to the default, and copilot still signs in.
    assertEquals(resolved.inspectedScopes, policyOf().inspectedScopes)
    // No finite tunnel set: the tunnels are the ambient default.
    assertEquals(resolved.tunnelHosts, Set.empty[String])
    assertEquals(authorize("api.anthropic.com", 443, resolved), "api.anthropic.com")
    assertEquals(resolved.ambientDenials, Vector(HostPattern.Exact("telemetry.example.com")))
    assertEquals(
      intercept[PolicyViolation](authorize("telemetry.example.com", 443, resolved)).getMessage,
      "host denied (rule: deny https://telemetry.example.com/)",
    )
    // The port and IP-literal rules hold for ambient hosts too.
    intercept[PolicyViolation](authorize("anything.example.org", 8443, resolved))
    intercept[PolicyViolation](authorize("8.8.8.8", 443, resolved))
    // A tunnel line and deny defaults are not consulted: nothing widens or narrows by them.
    assertEquals(
      policyOf(
        profile = "allow-unless-denied",
        rule = "deny defaults\nallow https://api.example/ tunnel\nallow model-provider anthropic",
      ).policy,
      policyOf(profile = "allow-unless-denied").policy,
    )
    // An inspected line extends the narrowing set.
    assertEquals(
      policyOf(
        profile = "allow-unless-denied",
        rule = "allow https://mirror.example/ read git-fetch",
      ).inspectedScopes("mirror.example"),
      Map("/" -> Set("read", "git-fetch")),
    )

  test("the lines apply in the order written: for each grant the last applicable line decides"):
    val narrowed = policyOf(rule = "deny https://codeberg.org/ git-fetch\nallow https://codeberg.org/my-org/ git-fetch")
    assertEquals(
      narrowed.inspectedScopes("codeberg.org"),
      Map("/" -> Set("read"), "/my-org/" -> Set("read", "git-fetch")),
    )
    assertEquals(narrowed.warnings, Vector.empty)
    val reversed = policyOf(rule = "allow https://codeberg.org/my-org/ git-fetch\ndeny https://codeberg.org/ git-fetch")
    assertEquals(reversed.inspectedScopes("codeberg.org"), Map("/" -> Set("read"), "/my-org/" -> Set("read")))
    // A deny is host-wide, so the exception beneath it is the narrower scope, and a spelling the
    // proxy cannot place in it lands where the deny holds.
    val owner = policyOf(rule = "deny https://github.com/\nallow https://github.com/my-org/ read")
    assertEquals(owner.inspectedScopes("github.com"), Map("/my-org/" -> Set("read")))
    def get(path: String): Unit =
      authorizeInspectedRequest(
        "github.com",
        head(s"GET $path HTTP/1.1\r\nHost: github.com\r\n\r\n"),
        owner.inspectedScopes("github.com"),
      )
    get("/my-org/repo")
    Vector(
      "/other/repo" -> "path outside allowance",
      "/My-Org/repo" -> "path outside allowance",
      "/my-org/%2e%2e/x" -> "percent-encoding in the path",
      "/my-org/repo.git/info/refs?service=git-upload-pack" -> "git fetch ref discovery",
    ).foreach: (path, why) =>
      assertEquals(intercept[PolicyViolation](get(path)).getMessage, why, path)
    // The same two lines the other way round deny the owner too, the deny being the last word.
    val denied = policyOf(rule = "allow https://github.com/my-org/ read\ndeny https://github.com/")
    assert(!denied.hosts.contains("github.com"))
    // Under the ambient profile the pair holds as it does elsewhere.
    Vector("deny-unless-allowed", "allow-unless-denied").foreach: profile =>
      val resolved = policyOf(
        profile = profile,
        rule = "deny https://github.com/\nallow https://github.com/my-org/ read",
      )
      assertEquals(resolved.inspectedScopes("github.com"), Map("/my-org/" -> Set("read")), profile)
      assertEquals(resolved.ambientDenials, Vector.empty, profile)
      assertEquals(authorize("github.com", 443, resolved), "github.com")

  test("deny takes by host, by subtree, by grant and by group, each what it names and no more"):
    val host = policyOf(rule = "deny https://gitlab.com/")
    assert(!host.hosts.contains("gitlab.com"))
    assertEquals(
      intercept[PolicyViolation](authorize("gitlab.com", 443, host)).getMessage,
      "host denied (rule: deny https://gitlab.com/)",
    )
    // A subtree: a label boundary, not a suffix match, crossing treatments.
    val subtree = policyOf(rule = "deny https://**.github.com/")
    Vector("github.com", "api.github.com", "codeload.github.com").foreach(h => assert(!subtree.hosts.contains(h), h))
    assert(subtree.hosts.contains("raw.githubusercontent.com"))
    val claude = policyOf(rule = "deny https://**.claude.com/")
    assert(!claude.hosts.contains("code.claude.com"))
    assert(!claude.hosts.contains("platform.claude.com"))
    // A grant: read taken leaves a forge clonable and not browsable; git-fetch taken leaves it readable.
    val unreadable = policyOf(rule = "deny https://github.com/ read")
    assertEquals(unreadable.inspectedScopes("github.com")("/"), Set("git-fetch"))
    assertEquals(unreadable.inspectedScopes("github.com")("/login/device/code"), Set("git-fetch", "POST"))
    val unclonable = policyOf(rule = "deny https://github.com/ git-fetch")
    assertEquals(unclonable.inspectedScopes("github.com")("/"), Set("read"))
    assertEquals(
      policyOf(rule = "deny https://**.github.com/ git-fetch").inspectedScopes("github.com")("/"),
      Set("read"),
    )
    assertEquals(
      policyOf(rule = "deny https://github.com/ method=POST").inspectedScopes("github.com")("/login/device/code"),
      Set("read", "git-fetch"),
    )
    // The tunnel word takes the treatment.
    assert(!policyOf(rule = "deny https://api.anthropic.com/ tunnel").hosts.contains("api.anthropic.com"))
    // A group: its contributions and no other line's — the catalog's read on api.github.com outlives
    // the group's token line, and the forge stays readable and clonable.
    val noGithub = policyOf(rule = "deny model-provider github")
    // The group's paths stay as boundaries, holding the catalog's grants and nothing of the group's.
    assertEquals(
      noGithub.inspectedScopes("github.com"),
      Map(
        "/" -> Set("read", "git-fetch"),
        "/login/device/code" -> Set("read", "git-fetch"),
        "/login/oauth/access_token" -> Set("read", "git-fetch"),
      ),
    )
    assertEquals(
      noGithub.inspectedScopes("api.github.com"),
      Map("/" -> Set("read"), "/copilot_internal/v2/token" -> Set("read")),
    )
    assert(!noGithub.hosts.contains("api.githubcopilot.com"))
    assertEquals(authorize("github.com", 443, noGithub), "github.com")
    authorizeInspectedRequest(
      "github.com", head(
        "GET /octocat/Hello-World HTTP/1.1\r\nHost: github.com\r\n\r\n",
      ), noGithub.inspectedScopes("github.com"),
    )
    intercept[PolicyViolation](
      authorizeInspectedRequest(
        "github.com",
        head("POST /login/device/code HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"),
        noGithub.inspectedScopes("github.com"),
      ),
    )
    val noGoogle = policyOf(rule = "deny model-provider google")
    ModelProviderLines("google").map(_.rule).foreach:
      case Rule.Allow(h, _, _) => assert(!noGoogle.hosts.contains(h), h)
      case other               => fail(other.toString)
    assert(noGoogle.hosts.contains("api.anthropic.com"))

  test("a group is lines: allowed after a deny it contributes again, denied after an allow it is removed"):
    assertEquals(policyOf(rule = "deny model-provider github\nallow model-provider github").policy, policyOf().policy)
    assertEquals(
      policyOf(rule = "allow model-provider github\ndeny model-provider github").policy,
      policyOf(rule = "deny model-provider github").policy,
    )
    // A URL deny between them: the re-added group is the last word for its own lines.
    val between = policyOf(rule = "deny model-provider github\ndeny https://github.com/\nallow model-provider github")
    assertEquals(
      between.inspectedScopes("github.com"),
      Map("/login/device/code" -> Set("POST"), "/login/oauth/access_token" -> Set("POST")),
    )
    // After deny defaults the group is the whole policy: the lockdown.
    val lockdown = policyOf(rule = "deny defaults\nallow model-provider anthropic")
    assertEquals(lockdown.hosts, policyOf(profile = "deny-unless-model", provider = "anthropic").hosts)
    assertEquals(lockdown.inspectedScopes, Map.empty)
    assertEquals(lockdown.warnings, Vector.empty)
    intercept[PolicyViolation](authorize("github.com", 443, lockdown))
    // Under the ambient profile the lockdown narrows nothing: neither line is consulted.
    assertEquals(
      policyOf(profile = "allow-unless-denied", rule = "deny defaults\nallow model-provider anthropic").policy,
      policyOf(profile = "allow-unless-denied").policy,
    )
    // Under every profile a group's lines meet the one-treatment check like any line.
    val ex = intercept[IllegalArgumentException](
      policyOf(rule = "deny defaults\nallow model-provider anthropic\nallow https://api.anthropic.com/ read"),
    )
    assert(ex.getMessage.contains("inspects api.anthropic.com while it is a tunnel"), ex.getMessage)

  test("a host has one treatment: narrowing a tunnel to inspected is local, widening needs deny defaults"):
    val narrowed = policyOf(rule = "deny https://api.anthropic.com/ tunnel\nallow https://api.anthropic.com/ read")
    assertEquals(narrowed.inspectedScopes("api.anthropic.com"), Map("/" -> Set("read")))
    assertEquals(narrowed.warnings, Vector.empty)
    val beneath = policyOf(
      rule = "deny https://api.anthropic.com/ tunnel\nallow https://api.anthropic.com/v1/models read",
    )
    assertEquals(beneath.inspectedScopes("api.anthropic.com"), Map("/v1/models" -> Set("read")))
    // Widened, with the whole policy stated after deny defaults; and a new host as a tunnel.
    assertEquals(
      policyOf(rule = "deny defaults\nallow https://github.com/ tunnel").hosts,
      Map("github.com" -> Treatment.Tunnel),
    )
    assertEquals(policyOf(rule = "allow https://api.example/ tunnel").hosts("api.example"), Treatment.Tunnel)
    // Under the ambient profile the narrowing holds with the same two lines; the tunnel taken alone
    // denies the host rather than leaving it ambient.
    val ambient = policyOf(
      profile = "allow-unless-denied",
      rule = "deny https://api.anthropic.com/ tunnel\nallow https://api.anthropic.com/ read",
    )
    assertEquals(ambient.inspectedScopes("api.anthropic.com"), Map("/" -> Set("read")))
    assertEquals(ambient.ambientDenials, Vector.empty)
    val taken = policyOf(profile = "allow-unless-denied", rule = "deny https://api.anthropic.com/ tunnel")
    assertEquals(taken.ambientDenials, Vector(HostPattern.Exact("api.anthropic.com")))
    intercept[PolicyViolation](authorize("api.anthropic.com", 443, taken))
    // deny defaults with an inspected line on a defaults tunnel is valid under every profile: the
    // ambient profile keeps the defaults' tunnels standing, and there the tunnel gives way.
    Vector("deny-unless-allowed", "allow-unless-denied").foreach: profile =>
      val resolved = policyOf(profile = profile, rule = "deny defaults\nallow https://api.anthropic.com/ read")
      assertEquals(resolved.inspectedScopes("api.anthropic.com"), Map("/" -> Set("read")), profile)
      assertEquals(resolved.warnings, Vector.empty, profile)

  test("a host left with no grant is denied whole: off the map, off the leaf, denied rather than ambient"):
    val emptied = policyOf(rule = "deny https://docs.python.org/ read")
    val whole = policyOf(rule = "deny https://docs.python.org/")
    assert(!emptied.hosts.contains("docs.python.org"))
    assert(!emptied.inspected.contains("docs.python.org"))
    assertEquals(emptied.policy, whole.policy)
    assertEquals(policyLines(emptied), policyLines(whole))
    assertEquals(
      intercept[PolicyViolation](authorize("docs.python.org", 443, emptied)).getMessage,
      "host denied (rule: deny https://docs.python.org/ read)",
    )
    val ambientEmptied = policyOf(profile = "allow-unless-denied", rule = "deny https://docs.python.org/ read")
    val ambientWhole = policyOf(profile = "allow-unless-denied", rule = "deny https://docs.python.org/")
    assertEquals(ambientEmptied.ambientDenials, Vector(HostPattern.Exact("docs.python.org")))
    assertEquals(ambientEmptied.policy, ambientWhole.policy)
    assertEquals(policyLines(ambientEmptied), policyLines(ambientWhole))
    intercept[PolicyViolation](authorize("docs.python.org", 443, ambientEmptied))
    // The two forms name their own lines.
    assert(provenanceLines(ambientEmptied).contains("  pattern: rule: deny https://docs.python.org/ read"))
    assert(provenanceLines(ambientWhole).contains("  pattern: rule: deny https://docs.python.org/"))
    // Re-granted beneath a narrower path: back on the map, narrowed, under both profiles.
    Vector("deny-unless-allowed", "allow-unless-denied").foreach: profile =>
      val regranted = policyOf(
        profile = profile,
        rule = "deny https://docs.python.org/ read\nallow https://docs.python.org/3/ read",
      )
      assertEquals(regranted.inspectedScopes("docs.python.org"), Map("/3/" -> Set("read")), profile)
      assertEquals(regranted.ambientDenials, Vector.empty, profile)

  test("a scope left with no grant while its host keeps some is dropped; one adding nothing stays as a boundary"):
    // The login scopes emptied with the root are gone; the file's scope alone remains.
    val dropped = policyOf(rule = "deny https://github.com/\nallow https://github.com/a/ read")
    assertEquals(dropped.inspectedScopes("github.com"), Map("/a/" -> Set("read")))
    // A scope a deny has left with only its enclosing scope's grants stays, and is where invariant 5's
    // refusal begins: `/api/%2e%2e/x` under it is refused where `/%2e%2e/x` under the root reads.
    val boundary = policyOf(
      rule = "allow https://x.example/ read\nallow https://x.example/api/ method=POST\n" +
        "deny https://x.example/ method=POST",
    )
    assertEquals(boundary.inspectedScopes("x.example"), Map("/" -> Set("read"), "/api/" -> Set("read")))
    def get(path: String): Unit =
      authorizeInspectedRequest(
        "x.example",
        head(s"GET $path HTTP/1.1\r\nHost: x.example\r\n\r\n"),
        boundary.inspectedScopes("x.example"),
      )
    get("/%2e%2e/x")
    assertEquals(intercept[PolicyViolation](get("/api/%2e%2e/x")).getMessage, "percent-encoding in the path")

  test("deny defaults is the whole policy under deny-unless-allowed and is not consulted elsewhere"):
    val own = policyOf(rule = "deny defaults\nallow https://docs.python.org/ read")
    assertEquals(own.hosts, Map("docs.python.org" -> Treatment.Inspected(Map("/" -> Set("read")))))
    assert(own.clearsDefaults)
    assertEquals(own.warnings, Vector.empty)
    assertEquals(
      policyOf(profile = "allow-unless-denied", rule = "deny defaults").policy,
      policyOf(profile = "allow-unless-denied").policy,
    )
    assertEquals(
      policyOf(profile = "deny-unless-model", provider = "anthropic", rule = "deny defaults").policy,
      policyOf(profile = "deny-unless-model", provider = "anthropic").policy,
    )

  test("two files resolving to one policy yield one ResolvedPolicy and the same lines; two profiles never do"):
    def same(profile: String, a: String, b: String, provider: String = ""): Unit =
      val (x, y) = (policyOf(profile, provider, a), policyOf(profile, provider, b))
      assertEquals(x.policy, y.policy, s"$profile: '$a' against '$b'")
      assertEquals(policyLines(x), policyLines(y))
    def differ(profile: String, a: String, b: String): Unit =
      assertNotEquals(policyOf(profile, "", a).policy, policyOf(profile, "", b).policy, s"$profile: '$a' against '$b'")
    // A group denial against its exact lines under deny-unless-model.
    same(
      "deny-unless-model", "deny model-provider github",
      "deny https://api.githubcopilot.com/\ndeny https://api.individual.githubcopilot.com/\n" +
        "deny https://api.business.githubcopilot.com/\ndeny https://api.enterprise.githubcopilot.com/\n" +
        "deny https://github.com/\ndeny https://api.github.com/",
      provider = "github",
    )
    Vector("deny-unless-allowed", "allow-unless-denied").foreach: profile =>
      // A grant subtree against its exact lines.
      same(
        profile, "deny https://**.github.com/ read",
        "deny https://github.com/ read\ndeny https://api.github.com/ read\ndeny https://codeload.github.com/ read\n" +
          "deny https://docs.github.com/ read",
      )
      // A grant list emptying a host against a whole-host line.
      same(profile, "deny https://docs.python.org/ read", "deny https://docs.python.org/")
    // A whole-host subtree against its tunnel form over ambient hosts, and apart from it over an inspected one.
    same("allow-unless-denied", "deny https://**.example.com/", "deny https://**.example.com/ tunnel")
    differ("allow-unless-denied", "deny https://**.python.org/", "deny https://**.python.org/ tunnel")
    // A deny list against its reordering where no grant depends on the order.
    same(
      "allow-unless-denied",
      "deny https://a.example/\ndeny https://**.b.example/\ndeny https://docs.python.org/ read",
      "deny https://docs.python.org/ read\ndeny https://**.b.example/\ndeny https://a.example/",
    )
    // A pattern a subtree covers is dropped from the normal form.
    same(
      "allow-unless-denied",
      "deny https://**.example.com/\ndeny https://api.example.com/",
      "deny https://**.example.com/",
    )
    // The provider selected and unselected: one policy under every profile but deny-unless-model.
    Vector("deny-all", "deny-unless-allowed", "allow-unless-denied").foreach: profile =>
      assertEquals(policyOf(profile, "google").policy, policyOf(profile).policy, profile)
    assertNotEquals(policyOf("deny-unless-model", "google").policy, policyOf("deny-unless-model", "anthropic").policy)
    // One file under three profiles: three line sets, so three digests and three authority texts.
    val texts = Vector("deny-unless-allowed", "allow-unless-denied", "deny-unless-model")
      .map(profile => policyLines(policyOf(profile, "anthropic", "deny https://github.com/ git-fetch")).mkString("\n"))
    assertEquals(texts.distinct.size, 3)
    assertEquals(texts.map(sha256Hex).distinct.size, 3)

  test("the widening line names the project lines granting beyond the defaults for their host, and only those"):
    val resolved = policyOf(
      rule =
        "allow https://html.spec.whatwg.org/ read      # a host the defaults lack: a new recipient\n" +
          "allow https://storage.googleapis.com/b/ read   # narrowed, and still a new recipient\n" +
          "allow https://pypi.org/ git-fetch              # a grant the defaults lack\n" +
          "allow https://github.com/ read git-fetch       # the defaults' own line, restated\n" +
          "allow https://registry.npmjs.org/-/npm/v1/security/advisories/bulk method=POST\n" +
          "allow https://api.anthropic.com/ tunnel        # the defaults' own tunnel, restated\n" +
          "deny https://gitlab.com/\ndeny model-provider google\nallow model-provider anthropic\n" +
          "deny https://claude.ai/ tunnel\nallow https://claude.ai/ read  # a tunnel narrowed to inspected reads\n" +
          "deny https://github.com/ git-fetch\nallow https://github.com/my-org/ git-fetch\n",
    )
    val widening = Vector(
      "allow https://html.spec.whatwg.org/ read",
      "allow https://storage.googleapis.com/b/ read",
      "allow https://pypi.org/ git-fetch",
      "allow https://registry.npmjs.org/-/npm/v1/security/advisories/bulk method=POST",
    )
    assertEquals(resolved.provenance.widening.map(_.text), widening)
    assertEquals(wideningLine(resolved), Some(s"widening lines (4): ${widening.mkString("; ")}"))
    // Printed after the policy lines and outside their digest: metadata about the file, not the policy.
    assert(!policyLines(resolved).exists(_.startsWith("widening")), policyLines(resolved).toString)
    assertEquals(metadataLines(resolved)(1), wideningLine(resolved).get)
    // `deny defaults` widens, and under it a defaults host may go tunnel: both listed.
    assertEquals(
      policyOf(
        rule = "deny defaults\nallow https://github.com/ tunnel\nallow https://pypi.org/ read",
      ).provenance.widening.map(_.text),
      Vector("deny defaults", "allow https://github.com/ tunnel"),
    )
    // Nothing widens under a profile the file cannot widen; a file that only takes prints no line.
    Vector("allow-unless-denied", "deny-all", "deny-unless-model").foreach: profile =>
      assertEquals(
        policyOf(profile = profile, rule = "allow https://new.example/ read").provenance.widening,
        Vector.empty,
        profile,
      )
    val narrowing = policyOf(rule = "deny https://github.com/")
    assertEquals(wideningLine(narrowing), None)
    assertEquals(metadataLines(narrowing).size, 1)

  test("--print-policy is the rule grammar, one line per resolved scope, sorted: what the leaf is minted from"):
    val resolved = policyOf()
    val lines = policyLines(resolved)
    assertEquals(lines(0), "egress profile: deny-unless-allowed")
    val scopes = DefaultHosts.values.map {
      case Treatment.Inspected(scopes) => scopes.size
      case Treatment.Tunnel       => 1
    }.sum
    assertEquals(lines.size, 1 + scopes)
    assert(lines.contains("allow https://github.com/ read git-fetch"), lines.toString)
    assert(lines.contains("allow https://github.com/login/device/code read git-fetch method=POST"), lines.toString)
    assert(lines.contains("allow https://api.github.com/copilot_internal/v2/token read"), lines.toString)
    assert(lines.contains("allow https://api.anthropic.com/ tunnel"), lines.toString)
    assert(lines.contains("allow https://pypi.org/ read"), lines.toString)
    val hosts = lines.drop(1).map(_.stripPrefix("allow https://").takeWhile(_ != '/'))
    assertEquals(hosts, hosts.sorted)
    assert(!lines.exists(_.startsWith("deny")), lines.toString)
    assertEquals(
      metadataLines(resolved),
      Vector(
        s"policy summary: ${resolved.inspected.size} inspected hosts; " +
          s"${resolved.tunnelHosts.size} opaque hosts; 0 ambient denials; 0 widening lines",
      ),
    )
    assertEquals(
      metadataLines(policyOf(profile = "deny-all")),
      Vector("policy summary: 0 inspected hosts; 0 opaque hosts; 0 ambient denials; 0 widening lines"),
    )
    // Under allow-unless-denied the deny lines come before the allow lines, so a host surviving
    // beneath one reads as the exception the grammar's order makes it; no tunnel line is printed,
    // the profile line carrying the public-HTTPS default instead.
    val ambient = policyOf(
      profile = "allow-unless-denied",
      rule = "deny https://**.example.com/\nallow https://docs.example.com/ read\ndeny https://x.example/",
    )
    val ambientLines = policyLines(ambient)
    assertEquals(ambientLines(0), "egress profile: allow-unless-denied; default: public HTTPS tunnel")
    assertEquals(ambientLines(1), "deny https://**.example.com/")
    assertEquals(ambientLines(2), "deny https://x.example/")
    assert(ambientLines.contains("allow https://docs.example.com/ read"), ambientLines.toString)
    assert(!ambientLines.exists(line => line.startsWith("allow") && line.endsWith(" tunnel")), ambientLines.toString)
    assertEquals(
      metadataLines(ambient)(0),
      s"policy summary: ${ambient.inspected.size} inspected hosts; 0 opaque hosts; 2 ambient denials; 0 widening lines",
    )
    assertEquals(authorize("docs.example.com", 443, ambient), "docs.example.com")
    intercept[PolicyViolation](authorize("api.example.com", 443, ambient))

  test("provenance names each scope's boundary and each grant's contributions, a pattern's lines, and a denied host's"):
    val lines = provenanceLines(
      policyOf(
        rule = "deny https://codeberg.org/ git-fetch\nallow https://codeberg.org/my-org/ git-fetch\n" +
          "deny https://gitlab.com/",
      ),
    )
    assertEquals(lines(0), "provenance:")
    val narrowed = lines.indexOf("allow https://codeberg.org/my-org/ read git-fetch")
    assertEquals(
      lines.slice(narrowed, narrowed + 4),
      Vector(
        "allow https://codeberg.org/my-org/ read git-fetch",
        "  boundary: rule: allow https://codeberg.org/my-org/ git-fetch",
        "  read: default/host: allow https://codeberg.org/ read git-fetch",
        "  git-fetch: rule: allow https://codeberg.org/my-org/ git-fetch",
      ),
    )
    val root = lines.indexOf("allow https://codeberg.org/ read")
    assertEquals(
      lines.slice(root, root + 3),
      Vector(
        "allow https://codeberg.org/ read",
        "  boundary: default/host: allow https://codeberg.org/ read git-fetch",
        "  read: default/host: allow https://codeberg.org/ read git-fetch",
      ),
    )
    // A grant two lines supply names both: the group's token read beside the catalog's root read.
    val token = lines.indexOf("allow https://api.github.com/copilot_internal/v2/token read")
    assertEquals(
      lines(token + 2),
      "  read: default/host: allow https://api.github.com/ read; " +
        "default/model-provider/github: allow https://api.github.com/copilot_internal/v2/token read",
    )
    assert(
      lines.contains("  tunnel: default/model-provider/anthropic: allow https://api.anthropic.com/ tunnel"),
      lines.toString,
    )
    assert(lines.contains("denied hosts:"), lines.toString)
    assert(lines.contains("  gitlab.com: denied by rule: deny https://gitlab.com/"), lines.toString)
    // A group the file expanded names both lines.
    assert(
      provenanceLines(policyOf(rule = "deny defaults\nallow model-provider anthropic")).contains(
        "  tunnel: rule: allow model-provider anthropic " +
          "(default/model-provider/anthropic: allow https://api.anthropic.com/ tunnel)",
      ),
    )
    // Under the ambient profile a pattern's lines: the group behind an expanded pattern, the absorbed
    // exact line behind its subtree, the two forms behind one host — and the refusal names the same.
    val ambient = policyOf(
      profile = "allow-unless-denied",
      rule = "deny model-provider google\ndeny https://**.example.com/\ndeny https://api.example.com/\n" +
        "deny https://x.example/\ndeny https://x.example/ tunnel",
    )
    val ambientLines = provenanceLines(ambient)
    assert(ambientLines.contains("deny https://accounts.google.com/"), ambientLines.toString)
    assert(ambientLines.contains("  pattern: rule: deny model-provider google"), ambientLines.toString)
    // The exact line the normal form folded into its subtree is named under the subtree, as the
    // refusal names it.
    assert(
      ambientLines.contains("  pattern: rule: deny https://**.example.com/; rule: deny https://api.example.com/"),
      ambientLines.toString,
    )
    assert(!ambientLines.contains("deny https://api.example.com/"), ambientLines.toString)
    assert(
      ambientLines.contains("  pattern: rule: deny https://x.example/; rule: deny https://x.example/ tunnel"),
      ambientLines.toString,
    )
    assertEquals(
      intercept[PolicyViolation](authorize("api.example.com", 443, ambient)).getMessage,
      "host denied (rule: deny https://**.example.com/; rule: deny https://api.example.com/)",
    )
    assertEquals(
      intercept[PolicyViolation](authorize("accounts.google.com", 443, ambient)).getMessage,
      "host denied (rule: deny model-provider google)",
    )

  test("--check-host spells a host's treatment as its resolved lines, one per scope"):
    assertEquals(
      ruleLines("github.com", policyOf().hosts("github.com")),
      Vector(
        "allow https://github.com/ read git-fetch",
        "allow https://github.com/login/device/code read git-fetch method=POST",
        "allow https://github.com/login/oauth/access_token read git-fetch method=POST",
      ),
    )
    assertEquals(
      ruleLines("api.anthropic.com", Treatment.Tunnel),
      Vector("allow https://api.anthropic.com/ tunnel"),
    )
    assertEquals(Grant.spelled(Set("DELETE", "PUT", "read", "POST")), "read method=POST,PUT,DELETE")

  test("a comment starts at line start or after whitespace; lines are enforced in the normalized form they resolve to"):
    val commented = policyOf(
      rule = "# a comment\nallow https://Docs.Example./ read   # trailing\n  # indented\n" +
        "allow https://b.example/ read #x",
    )
    assert(commented.inspectedScopes.contains("docs.example") && commented.inspectedScopes.contains("b.example"))
    assertEquals(authorize("DOCS.EXAMPLE.", 443, commented), "docs.example")
    assert(!policyOf(rule = "deny https://GitLab.COM./").hosts.contains("gitlab.com"))


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
        InetAddress.getByName("2606:4700:4700::1111"),
      ),
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
        ascii("CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n") ++ remaining,
      )

    val header = readHttpHeader(input, 4096)

    assertEquals(
      String(header, StandardCharsets.ISO_8859_1),
      "CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n",
    )
    assertEquals(input.readAllBytes().toVector, remaining.toVector)

  test("readHttpHeader enforces its size bound"):
    intercept[BadRequest]:
      readHttpHeader(
        ByteArrayInputStream(ascii("0123456789\r\n\r\n")),
        8,
      )

  test("readHttpHeader tells an unused connection from a half-sent header"):
    intercept[ClosedWithoutRequest](readHttpHeader(ByteArrayInputStream(Array.emptyByteArray), 4096))
    intercept[BadRequest](readHttpHeader(ByteArrayInputStream(ascii("GET / HT")), 4096))

  test("a response head parses for status and framing, and malformations blame the origin"):
    val head = HttpResponseHead.parse(
      ascii("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
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
      BodyFraming.Chunked,
    )
    // No framing header: the body runs to the connection's end — this proxy sends
    // Connection: close upstream, so EOF is the terminator there, not a truncation.
    assertEquals(head("HTTP/1.1 200 OK\r\n\r\n").bodyFraming("GET"), BodyFraming.UntilClose)
    assertEquals(head("HTTP/1.1 100 Continue\r\n\r\n").bodyFraming("GET"), BodyFraming.Empty)
    // The request side's ambiguity refusals, as origin faults.
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n").bodyFraming("GET"),
    )
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n").bodyFraming("GET"),
    )
    intercept[IOException](
      head("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n").bodyFraming("GET"),
    )

  test("the relayed response head speaks this hop's own Connection: close"):
    val head = HttpResponseHead.parse(
      ascii(
        "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n" +
          "Content-Length: 5\r\nETag: \"abc\"\r\n\r\n",
      ),
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
          "X-Tracing: abc\r\nAccept: */*\r\n\r\n",
      ),
    )
    val upstream = String(request.toUpstreamBytes, StandardCharsets.ISO_8859_1)
    assert(!upstream.contains("X-Tracing"), upstream)
    assert(upstream.contains("Accept: */*\r\n"), upstream)

    val response = HttpResponseHead.parse(
      ascii("HTTP/1.1 200 OK\r\nConnection: x-server-hint\r\nX-Server-Hint: h2\r\nVary: A\r\n\r\n"),
    )
    val relayed = String(response.toClientBytes, StandardCharsets.ISO_8859_1)
    assert(!relayed.contains("X-Server-Hint"), relayed)
    assert(relayed.contains("Vary: A\r\n"), relayed)

  test("a Connection header may not nominate a header this hop reads, on either side"):
    // The nomination would strip the framing the proxy already trusted — the body forwarded by
    // the original framing, its header gone, readable upstream as a second request — or the Host
    // the policy checked. Every name in the protected set, both directions, so the set and the
    // rule cannot drift apart; the spelling is the peer's, so one is mixed-case.
    ConnectionProtectedHeaders.foreach: name =>
      val spelled = if name == "host" then "Host" else name
      val request = head(
        s"POST /r.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nContent-Length: 4\r\n" +
          s"Connection: keep-alive, $spelled\r\n\r\n",
      )
      val refused = intercept[BadRequest](request.bodyFraming)
      assert(refused.getMessage.contains(name), refused.getMessage)
      // The relay's own gate, before any byte goes upstream.
      intercept[BadRequest](authorizeInspectedRequest("github.com", request, whole("git-fetch")))

      val response = HttpResponseHead.parse(
        ascii(s"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: $spelled\r\n\r\n"),
      )
      val origin = intercept[IOException](response.bodyFraming("GET"))
      assert(origin.getMessage.contains(name), origin.getMessage)

    // A nomination of anything else still frames as before.
    assertEquals(
      head(
        "POST /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 4\r\nConnection: x-tracing\r\n\r\n",
      ).bodyFraming,
      BodyFraming.Length(4),
    )

  test("relayInspected refuses an origin whose Connection strips its own framing, before the head"):
    // On the wire: the refusal has to land before toClientBytes, while a 502 is still possible —
    // afterwards the client would read chunk markers as payload.
    val (client, clientPeer) = socketPair()
    val (upstream, upstreamPeer) = socketPair()
    val origin = playOrigin(
      upstreamPeer,
      ascii(
        "HTTP/1.1 200 OK\r\nConnection: Transfer-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n" +
          "5\r\nhello\r\n0\r\n\r\n",
      ),
    )
    clientPeer.shutdownOutput()

    val head = HttpRequestHead.parse(ascii("GET /f HTTP/1.1\r\nHost: docs.python.org\r\n\r\n"))
    intercept[IOException]:
      relayInspected(client, upstream, "docs.python.org", head)
    client.close()
    origin.join()
    assertEquals(clientPeer.getInputStream.readAllBytes().length, 0, "bytes reached the client")

  test("HTTP/1.0 is refused by name, at CONNECT and inside the tunnel"):
    val connect = intercept[BadRequest](
      ConnectRequest.parse(ascii("CONNECT github.com:443 HTTP/1.0\r\n\r\n")),
    )
    assertEquals(connect.getMessage, "HTTP/1.0 is not supported")
    val inTunnel = intercept[BadRequest](
      HttpRequestHead.parse(ascii("GET / HTTP/1.0\r\nHost: github.com\r\n\r\n")),
    )
    assertEquals(inTunnel.getMessage, "HTTP/1.0 is not supported")

  test("Expect: 100-continue is answered by this proxy and never forwarded"):
    val head = HttpRequestHead.parse(
      ascii(
        "POST /r.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\n" +
          "Content-Length: 4\r\n\r\n",
      ),
    )
    assert(head.expectsContinue)
    val upstream = String(head.toUpstreamBytes, StandardCharsets.ISO_8859_1)
    assert(!upstream.toLowerCase.contains("expect"), upstream)
    assert(!HttpRequestHead.parse(ascii("GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n")).expectsContinue)

  test("forwardResponseBody relays complete bodies and turns early EOF into TruncatedResponse"):
    // An upstream close inside a declared length must become a loggable
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
      ascii("5\r\nhello\r\n0\r\n\r\n").toVector,
    )

    val short = intercept[TruncatedResponse](relay(ascii("hel"), BodyFraming.Length(5)))
    assert(short.getMessage.contains("truncated"), short.getMessage)
    intercept[TruncatedResponse](relay(ascii("5\r\nhel"), BodyFraming.Chunked))
    // An origin whose chunking cannot be parsed is the same abort, not a 400 at the client.
    intercept[TruncatedResponse](relay(ascii("zz\r\n"), BodyFraming.Chunked))

  test("each bulk body relay reuses one 16 KiB buffer"):
    final class TrackingInput(bytes: Array[Byte]) extends java.io.InputStream:
      private val delegate = ByteArrayInputStream(bytes)
      val bulkReadBuffers = scala.collection.mutable.ArrayBuffer.empty[Array[Byte]]

      override def read(): Int = delegate.read()

      override def read(buffer: Array[Byte], offset: Int, length: Int): Int =
        bulkReadBuffers += buffer
        delegate.read(buffer, offset, length)

    def assertOneBuffer(bytes: Array[Byte])(relay: (TrackingInput, java.io.OutputStream) => Unit): Unit =
      val in = TrackingInput(bytes)
      val out = java.io.ByteArrayOutputStream()
      relay(in, out)

      assert(in.bulkReadBuffers.nonEmpty)
      assert(in.bulkReadBuffers.forall(_ eq in.bulkReadBuffers.head))
      assertEquals(in.bulkReadBuffers.head.length, RelayBufferBytes)

    val largeBody = Array.fill[Byte](RelayBufferBytes * 2 + 1)(0x5a)
    assertOneBuffer(largeBody)((in, out) => copyExactly(in, out, largeBody.length))
    assertOneBuffer(largeBody)(copyUntilEof)
    assertOneBuffer(ascii("3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n"))(copyChunked)

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
      ascii("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello"),
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
      ascii("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf"),
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
          "Content-Length: 4\r\n\r\n",
      ),
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
          "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata",
      ),
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

  /** An origin that records the request head it received and answers an empty 200: what reaches
    * the origin is the test's subject, so the head is captured before the reply. */
  private def recordingOrigin(socket: java.net.Socket): (Thread, java.util.concurrent.atomic.AtomicReference[String]) =
    val received = java.util.concurrent.atomic.AtomicReference("")
    val thread = Thread.startVirtualThread: () =>
      try
        val head = readHttpHeader(socket.getInputStream, 64 * 1024)
        received.set(String(head, StandardCharsets.ISO_8859_1))
        socket.getOutputStream.write(ascii("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        socket.getOutputStream.close()
      catch case _: Exception => ()
    (thread, received)

  test("what is authorized is what is forwarded: the method and request-target byte for byte, the Host by its meaning"):
    // The pipeline, not the authorizer, is what this proves: after the decision nothing rewrites,
    // normalizes or re-encodes the request line, and the Host reaches the origin as the client
    // spelled it, its optional whitespace stripped — every spelling naming the one host the
    // tunnel was opened to (normalizeHostHeader).
    val scopes = Map("/" -> Set("read", "POST"))
    Vector(
      "GET /a%2Fb/%2e%2e/c HTTP/1.1\r\nHost: docs.python.org\r\n\r\n" -> "GET /a%2Fb/%2e%2e/c HTTP/1.1",
      "GET //a//b HTTP/1.1\r\nHost: docs.python.org\r\n\r\n" -> "GET //a//b HTTP/1.1",
      "GET /a\\b/../c?x=%20y HTTP/1.1\r\nHost: docs.python.org\r\n\r\n" -> "GET /a\\b/../c?x=%20y HTTP/1.1",
      "POST /a/b HTTP/1.1\r\nHost: docs.python.org\r\nContent-Length: 0\r\n\r\n" -> "POST /a/b HTTP/1.1",
    ).foreach: (request, requestLine) =>
      val head = HttpRequestHead.parse(ascii(request))
      authorizeInspectedRequest("docs.python.org", head, scopes)
      val (client, clientPeer) = socketPair()
      val (upstream, upstreamPeer) = socketPair()
      val (origin, received) = recordingOrigin(upstreamPeer)
      clientPeer.shutdownOutput()
      relayInspected(client, upstream, "docs.python.org", head)
      client.close()
      origin.join()
      assertEquals(received.get.linesIterator.next(), requestLine, request)
    Vector(
      "Host:  docs.python.org \t" -> "Host: docs.python.org",
      "Host: docs.python.org:443" -> "Host: docs.python.org:443",
      "Host: Docs.Python.ORG" -> "Host: Docs.Python.ORG",
      "Host: docs.python.org." -> "Host: docs.python.org.",
    ).foreach: (sent, forwarded) =>
      val head = HttpRequestHead.parse(ascii(s"GET /x HTTP/1.1\r\n$sent\r\n\r\n"))
      authorizeInspectedRequest("docs.python.org", head, scopes)
      val (client, clientPeer) = socketPair()
      val (upstream, upstreamPeer) = socketPair()
      val (origin, received) = recordingOrigin(upstreamPeer)
      clientPeer.shutdownOutput()
      relayInspected(client, upstream, "docs.python.org", head)
      client.close()
      origin.join()
      assert(received.get.linesIterator.contains(forwarded), s"$sent: ${received.get}")

  test("a header value edged with a control is refused on a request and a response head; SP and HTAB are stripped"):
    // Checked raw: Java's `trim` removes every character up to SP, so a check after it would let an
    // edge NUL, VT or FF through as the value's whitespace.
    Vector('\u0000', '\u000b', '\u000c').foreach: ch =>
      intercept[BadRequest](
        HttpRequestHead.parse(ascii(s"GET /a HTTP/1.1\r\nHost: github.com\r\nX-Probe: ${ch}v\r\n\r\n")),
      )
      intercept[BadRequest](
        HttpRequestHead.parse(ascii(s"GET /a HTTP/1.1\r\nHost: github.com\r\nX-Probe: v$ch\r\n\r\n")),
      )
      intercept[IOException](HttpResponseHead.parse(ascii(s"HTTP/1.1 200 OK\r\nX-Probe: ${ch}v\r\n\r\n")))
      intercept[IOException](HttpResponseHead.parse(ascii(s"HTTP/1.1 200 OK\r\nX-Probe: v$ch\r\n\r\n")))
    // A bare CR or LF is refused before any header is read.
    intercept[BadRequest](HttpRequestHead.parse(ascii("GET /a HTTP/1.1\r\nHost: github.com\r\nX-Probe: v\r\r\n\r\n")))
    intercept[IOException](HttpResponseHead.parse(ascii("HTTP/1.1 200 OK\r\nX-Probe: v\n\r\n\r\n")))
    val request = HttpRequestHead.parse(ascii("GET /a HTTP/1.1\r\nHost: github.com\r\nX-Probe: \t v \t\r\n\r\n"))
    assertEquals(request.values("X-Probe"), Vector("v"))
    val response = HttpResponseHead.parse(ascii("HTTP/1.1 200 OK\r\nX-Probe: \t v \t\r\n\r\n"))
    assertEquals(response.values("X-Probe"), Vector("v"))
    assertEquals(stripOptionalWhitespace(" \t a\tb \t "), "a\tb")

  test("TLS ClientHello extracts SNI"):
    val bytes = clientHello("api.anthropic.com")
    val hello = TlsClientHello.read(
      ByteArrayInputStream(bytes),
      64 * 1024,
    )

    assertEquals(hello.serverName, Some("api.anthropic.com"))
    assertEquals(hello.echPresent, false)
    assertEquals(hello.wireBytes.toVector, bytes.toVector)

  test("TLS ClientHello can be fragmented across TLS records"):
    val bytes = clientHello("api.anthropic.com", splitAt = Some(17))
    val hello = TlsClientHello.read(
      ByteArrayInputStream(bytes),
      64 * 1024,
    )

    assertEquals(hello.serverName, Some("api.anthropic.com"))
    assertEquals(hello.wireBytes.toVector, bytes.toVector)

  test("TLS parser refuses bytes trailing the ClientHello in its record"):
    intercept[BadTls]:
      TlsClientHello.read(
        ByteArrayInputStream(
          clientHello("api.anthropic.com", trailingInRecord = Array[Byte](0, 0)),
        ),
        64 * 1024,
      )

  test("TLS ClientHello detects ECH"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(
        clientHello("api.anthropic.com", ech = true),
      ),
      64 * 1024,
    )

    assert(hello.echPresent)

  test("TLS identity validation accepts CONNECT host == SNI"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(clientHello("api.anthropic.com")),
      64 * 1024,
    )

    validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects SNI mismatch"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(clientHello("example.com")),
      64 * 1024,
    )

    intercept[PolicyViolation]:
      validateTlsIdentity("api.anthropic.com", hello)

  test("TLS identity validation rejects ECH"):
    val hello = TlsClientHello.read(
      ByteArrayInputStream(
        clientHello("api.anthropic.com", ech = true),
      ),
      64 * 1024,
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
        TlsClientHello(Array.emptyByteArray, None, echPresent = false),
      )

  test("TLS parser rejects a truncated ClientHello"):
    val bytes = clientHello("api.anthropic.com")

    intercept[java.io.EOFException]:
      TlsClientHello.read(
        ByteArrayInputStream(bytes.dropRight(3)),
        64 * 1024,
      )

  test("the leaf must name exactly the inspected hosts, in either direction"):
    val required = Set("github.com", "gitlab.com")

    assertEquals(TlsInspection.inspectedNamesError(required, required), None)

    // Under-coverage would fail later anyway, as a certificate error inside the sandbox; refusing names it here.
    val missing = TlsInspection.inspectedNamesError(Set("github.com"), required)
    assert(missing.exists(_.contains("does not cover gitlab.com")), missing.toString)

    // Over-coverage is the fail-open direction: a launcher minting a name this proxy does not inspect believes that
    // host is inspected while it tunnels opaquely, writable.
    val extra = TlsInspection.inspectedNamesError(required + "gist.github.com", required)
    assert(extra.exists(_.contains("gist.github.com")), extra.toString)

    val both = TlsInspection.inspectedNamesError(Set("github.com", "gist.github.com"), required)
    assert(both.exists(r => r.contains("gitlab.com") && r.contains("gist.github.com")), both.toString)


  test("a request is decided against the resolved scope of its longest literal match, and no match is refused"):
    def get(path: String, scopes: Map[String, Set[String]]): Unit =
      authorizeInspectedRequest("docs.example", head(s"GET $path HTTP/1.1\r\nHost: docs.example\r\n\r\n"), scopes)
    // The tree under /x/, and no root line.
    get("/x/y", under("/x/", "read"))
    get("/x/y/z?download=1", under("/x/", "read"))
    get("/x/", under("/x/", "read"))
    Vector(
      "/z/y" -> "path outside allowance",
      "/x" -> "path outside allowance", // the tree's own name is not in it
      "/xy/z" -> "path outside allowance",
      "/X/y" -> "path outside allowance", // wrong case fails closed, whatever the origin folds
      "/x/../z/y" -> "a dot segment in the path",
      "/x/%2e%2e/z/y" -> "percent-encoding in the path",
      "/x/./y" -> "a dot segment in the path",
      "/x\\..\\z" -> "path outside allowance", // matches no scope before any spelling is judged
      "/x/a\\b" -> "a backslash in the path",
      "//x/y" -> "path outside allowance",
      "/x//y" -> "an empty segment in the path",
      "/x/%2Fy" -> "percent-encoding in the path",
    ).foreach: (path, why) =>
      assertEquals(intercept[PolicyViolation](get(path, under("/x/", "read"))).getMessage, why, path)
    // Under the root a read may carry any spelling: it has the host's least grants.
    get("/blobs/a%2Fb", whole("read"))
    get("/x/%2e%2e/y", whole("read"))
    // An exact path names that one path.
    get("/v2/token", under("/v2/token", "read"))
    assertEquals(
      intercept[PolicyViolation](get("/v2/token/x", under("/v2/token", "read"))).getMessage,
      "path outside allowance",
    )
    assertEquals(
      intercept[PolicyViolation](get("/v2/tokens", under("/v2/token", "read"))).getMessage,
      "path outside allowance",
    )
    // The longest match selects the state and the boundary: a request under both takes the narrower.
    val two = Map("/" -> Set("read"), "/api/" -> Set("read", "POST"))
    def post(path: String): Unit =
      authorizeInspectedRequest(
        "docs.example",
        head(s"POST $path HTTP/1.1\r\nHost: docs.example\r\nContent-Length: 0\r\n\r\n"),
        two,
      )
    post("/api/x")
    assertEquals(intercept[PolicyViolation](post("/x")).getMessage, "POST not granted")
    assertEquals(intercept[PolicyViolation](post("/api/%2e%2e/x")).getMessage, "percent-encoding in the path")
    assertEquals(intercept[PolicyViolation](post("/%2e%2e/x")).getMessage, "percent-encoding in the path")
    get("/%2e%2e/x", two)
    assertEquals(intercept[PolicyViolation](get("/api/%2e%2e/x", two)).getMessage, "percent-encoding in the path")
    // The paths named in the refusal are the policy's own words for the host.
    assertEquals(
      intercept[PolicyViolation](get("/q/r", under("/o/", "read") ++ under("/p/", "read"))).advice,
      RefusalAdvice.pathOutside(Set("/o/", "/p/")),
    )

  test("read is GET and HEAD, bodyless; git-fetch is the clone's two requests; method= its list; nothing else"):
    def request(request: String, scopes: Map[String, Set[String]], host: String = "github.com"): Unit =
      authorizeInspectedRequest(host, head(request), scopes)
    def refused(request: String, scopes: Map[String, Set[String]], host: String = "github.com"): String =
      intercept[PolicyViolation](authorizeInspectedRequest(host, head(request), scopes)).getMessage
    val discovery = "GET /o/r.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\n\r\n"
    val transfer = "POST /o/r.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"
    val browse = "GET /o/r HTTP/1.1\r\nHost: github.com\r\n\r\n"
    // git-fetch alone: clonable and not browsable.
    request(discovery, whole("git-fetch"))
    request(transfer, whole("git-fetch"))
    assertEquals(refused(browse, whole("git-fetch")), "read not granted")
    assertEquals(refused("HEAD /o/r HTTP/1.1\r\nHost: github.com\r\n\r\n", whole("git-fetch")), "read not granted")
    assertEquals(
      refused(
        "POST /o/r.git/git-receive-pack HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n",
        whole("git-fetch"),
      ),
      "POST not granted",
    )
    // read alone: browsable, and a clone fails at its first request rather than its second.
    request(browse, whole("read"))
    assertEquals(refused(discovery, whole("read")), "git fetch ref discovery")
    assertEquals(refused(transfer, whole("read")), "POST not granted")
    // A POST whose path mimics upload-pack rides nothing through on a host without git-fetch.
    assertEquals(
      refused(
        "POST /v2/x/x/git-upload-pack HTTP/1.1\r\nHost: public.ecr.aws\r\nContent-Length: 0\r\n\r\n",
        whole("read"),
        "public.ecr.aws",
      ),
      "POST not granted",
    )
    // A body on a read method is an upload wearing a read method: the fact named, on every host.
    Vector("GET", "HEAD").foreach: method =>
      assertEquals(
        refused(s"$method /o/r HTTP/1.1\r\nHost: github.com\r\nContent-Length: 9\r\n\r\n", whole("read", "git-fetch")),
        "request body",
      )
    // method= is its list, under its path, and write-only where the scope has no read.
    val api = Map("/" -> Set("read"), "/api/" -> Set("read", "PUT", "DELETE"))
    request("PUT /api/x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", api)
    request("DELETE /api/x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", api)
    assertEquals(
      refused("PATCH /api/x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", api),
      "PATCH not granted",
    )
    assertEquals(
      refused("POST /api/x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", api),
      "POST not granted",
    )
    assertEquals(refused("PUT /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", api), "PUT not granted")
    val login = under("/login/device/code", "POST")
    request("POST /login/device/code HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", login)
    assertEquals(refused("GET /login/device/code HTTP/1.1\r\nHost: github.com\r\n\r\n", login), "read not granted")
    assertEquals(
      refused("POST /login/device/codes HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", login),
      "path outside allowance",
    )
    Vector("OPTIONS", "TRACE").foreach: method =>
      assertEquals(
        refused(s"$method /o/r HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", whole("read", "git-fetch")),
        s"$method not granted",
      )
    // Push discovery is refused under read and git-fetch, admitted under a POST grant at the repository.
    val pushDiscovery = "GET /o/r.git/info/refs?service=git-receive-pack HTTP/1.1\r\nHost: github.com\r\n\r\n"
    assertEquals(refused(pushDiscovery, whole("read", "git-fetch")), "git push ref discovery")
    request(pushDiscovery, Map("/" -> Set("read"), "/o/" -> Set("read", "POST")))
    assertEquals(
      refused(pushDiscovery, Map("/" -> Set("read"), "/p/" -> Set("read", "POST"))),
      "git push ref discovery",
    )
    Vector(
      "/o/r.git/info/refs?service=git%2Dreceive-pack",
      "/o/r.git/info/refs?%73ervice=git-receive-pack",
      "/o/r.git/inf%6F/refs?service=git-receive-pack",
    ).foreach: target =>
      assertEquals(
        refused(s"GET $target HTTP/1.1\r\nHost: github.com\r\n\r\n", whole("read", "git-fetch")),
        "git push ref discovery",
      )
    // A malformed escape is no discovery of either service: the GET stays an ordinary read.
    request("GET /o/r.git/info/refs?service=git-receive%2xpack HTTP/1.1\r\nHost: github.com\r\n\r\n", whole("read"))
    // npm: the audit line beside the root read admits the audit POST at its exact path, an older
    // npm's endpoint gets an honest refusal, and a scoped package keeps reading under the root.
    val npm = Map("/" -> Set("read"), "/-/npm/v1/security/advisories/bulk" -> Set("read", "POST"))
    request(
      "POST /-/npm/v1/security/advisories/bulk HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Length: 0\r\n\r\n",
      npm,
      "registry.npmjs.org",
    )
    assertEquals(
      refused(
        "POST /-/npm/v1/security/audits/quick HTTP/1.1\r\nHost: registry.npmjs.org\r\nContent-Length: 0\r\n\r\n",
        npm,
        "registry.npmjs.org",
      ),
      "POST not granted",
    )
    request("GET /@scope%2fname HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n", npm, "registry.npmjs.org")
    // The github group's login lines beside the catalog's root: the device-flow pair and nothing beside it.
    val github = policyOf().inspectedScopes("github.com")
    request("POST /login/device/code HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", github)
    request("POST /login/oauth/access_token HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", github)
    request("GET /login/device/code HTTP/1.1\r\nHost: github.com\r\n\r\n", github)
    assertEquals(
      refused("POST /login/oauth/authorize HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", github),
      "POST not granted",
    )
    assertEquals(
      refused("POST /o/r.git/git-receive-pack HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n", github),
      "POST not granted",
    )
    // A documentation site: reads pass, nothing else does.
    request(
      "GET /en-US/docs/Web HTTP/1.1\r\nHost: developer.mozilla.org\r\n\r\n",
      whole("read"),
      "developer.mozilla.org",
    )
    assertEquals(
      refused(
        "POST /api/x HTTP/1.1\r\nHost: developer.mozilla.org\r\nContent-Length: 0\r\n\r\n",
        whole("read"),
        "developer.mozilla.org",
      ),
      "POST not granted",
    )

  test("HTTP request head parses a request line and its headers"):
    val request = head(
      "GET /owner/repo HTTP/1.1\r\n" +
        "Host: github.com\r\n" +
        "User-Agent: git/2.51.0\r\n" +
        "\r\n",
    )

    assertEquals(request.method, "GET")
    assertEquals(request.target, "/owner/repo")
    assertEquals(request.values("host"), Vector("github.com"))
    assertEquals(request.values("User-Agent"), Vector("git/2.51.0"))

  test("HTTP request head splits a target into path and query"):
    val request = head(
      "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n",
    )

    assertEquals(request.path, "/owner/repo.git/info/refs")
    assertEquals(request.query, "service=git-upload-pack")

  test("HTTP request head rejects an obsolete folded header"):
    intercept[BadRequest]:
      head("GET / HTTP/1.1\r\nHost: github.com\r\n continued\r\n\r\n")

  test("reading a read git-fetch host is allowed"):
    inspected("GET /owner/repo HTTP/1.1\r\nHost: github.com\r\n\r\n")
    inspected("HEAD /owner/repo HTTP/1.1\r\nHost: github.com\r\n\r\n")
    inspected(
      "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n",
    )

  test("a read method may not carry a request body"):
    Vector("GET", "HEAD").foreach: method =>
      intercept[PolicyViolation]:
        inspected(
          s"$method /owner/repo HTTP/1.1\r\nHost: github.com\r\nContent-Length: 5\r\n\r\n",
        )

  test("git fetch is allowed and git push is not"):
    inspected(
      "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\n" +
        "Host: github.com\r\nContent-Length: 0\r\n\r\n",
    )

    intercept[PolicyViolation]:
      inspected(
        "POST /owner/repo.git/git-receive-pack HTTP/1.1\r\n" +
          "Host: github.com\r\nContent-Length: 0\r\n\r\n",
      )

  test("git fetch from a nested GitLab subgroup is allowed, push is not"):
    // gitlab.com nests a repository under arbitrarily deep subgroups; the whole-path rule admits the depth, never a
    // different final segment.
    authorizeInspectedRequest(
      "gitlab.com",
      head(
        "POST /group/subgroup/project.git/git-upload-pack HTTP/1.1\r\n" +
          "Host: gitlab.com\r\nContent-Length: 0\r\n\r\n",
      ),
      whole("git-fetch"),
    )

    intercept[PolicyViolation]:
      authorizeInspectedRequest(
        "gitlab.com",
        head(
          "POST /group/subgroup/project.git/git-receive-pack HTTP/1.1\r\n" +
            "Host: gitlab.com\r\nContent-Length: 0\r\n\r\n",
        ),
        whole("git-fetch"),
      )

  test("git push ref discovery is refused even though it is a GET"):
    intercept[PolicyViolation]:
      inspected(
        "GET /owner/repo.git/info/refs?service=git-receive-pack HTTP/1.1\r\n" +
          "Host: github.com\r\n\r\n",
      )

  test("git push ref discovery is refused in percent-encoded spellings too"):
    // The origin server decodes before routing, so an encoded spelling asks for the same service; the classification
    // decodes the same way.
    Vector(
      "/owner/repo.git/info/refs?service=git%2Dreceive-pack",
      "/owner/repo.git/info/refs?%73ervice=git-receive-pack",
      "/owner/repo.git/inf%6F/refs?service=git-receive-pack",
    ).foreach: target =>
      intercept[PolicyViolation]:
        inspected(s"GET $target HTTP/1.1\r\nHost: github.com\r\n\r\n")

  test("a malformed percent escape is no receive-pack discovery"):
    // Kept as it is by the decode, it matches nothing an origin would route to receive-pack either; the GET stays an
    // ordinary read.
    inspected(
      "GET /owner/repo.git/info/refs?service=git-receive%2xpack HTTP/1.1\r\n" +
        "Host: github.com\r\n\r\n",
    )

  test("no other method reaches an inspected host"):
    Vector("PUT", "PATCH", "DELETE", "OPTIONS", "TRACE").foreach: method =>
      intercept[PolicyViolation]:
        inspected(
          s"$method /owner/repo HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n",
        )

  test("no other path accepts a POST"):
    Vector(
      "/graphql",
      "/owner/repo/issues",
      "/owner/repo.git/git-upload-pack/x",
      // At least owner/repo before the service segment: a single segment is no repository on any forge, and the bare
      // name is not a path.
      "/x/git-upload-pack",
      "/git-upload-pack",
    ).foreach: path =>
      intercept[PolicyViolation]:
        inspected(
          s"POST $path HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n",
        )

  test("a write path may not be spelled ambiguously"):
    Vector(
      "/owner/repo.git/%2e%2e/git-upload-pack",
      "/owner/repo.git/../git-upload-pack",
      "/owner/repo.git/./git-upload-pack",
    ).foreach: path =>
      intercept[PolicyViolation]:
        inspected(
          s"POST $path HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n",
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
          "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
      )

    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Content-Length: 5\r\nContent-Length: 6\r\n\r\n",
      )

    intercept[BadRequest]:
      inspected(
        "POST /owner/repo.git/git-upload-pack HTTP/1.1\r\nHost: github.com\r\n" +
          "Transfer-Encoding: gzip\r\n\r\n",
      )

  test("message framing is read from the headers"):
    assertEquals(
      head("GET /x HTTP/1.1\r\nHost: github.com\r\n\r\n").bodyFraming,
      BodyFraming.Empty,
    )
    assertEquals(
      head("POST /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 12\r\n\r\n").bodyFraming,
      BodyFraming.Length(12),
    )
    assertEquals(
      head(
        "POST /x HTTP/1.1\r\nHost: github.com\r\nTransfer-Encoding: chunked\r\n\r\n",
      ).bodyFraming,
      BodyFraming.Chunked,
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
            "\r\n",
        ).toUpstreamBytes,
        StandardCharsets.ISO_8859_1,
      )

    assertEquals(
      forwarded,
      "GET /owner/repo HTTP/1.1\r\n" +
        "Host: github.com\r\n" +
        "Accept: */*\r\n" +
        "Connection: close\r\n\r\n",
    )

  test("chunked lines are read up to CRLF and bounded"):
    val input = ByteArrayInputStream(ascii("1a;ext\r\nrest"))

    assertEquals(readCrLfLine(input, 64), "1a;ext")

    intercept[BadRequest]:
      readCrLfLine(ByteArrayInputStream(ascii("0123456789\r\n")), 4)

  test("audit lines are verb host method [target] tail, with - for fields never learned"):
    // SECURITY.md, "The audit line grammar".
    assertEquals(
      auditLine("allow", "github.com", "GET", "/r?tab=readme", "-> 140.82.112.3"),
      "allow github.com GET /r?tab=readme -> 140.82.112.3",
    )
    assertEquals(
      auditLine("allow", "api.anthropic.com", "CONNECT", "", "-> 160.79.104.10"),
      "allow api.anthropic.com CONNECT -> 160.79.104.10",
    )
    assertEquals(
      auditLine("deny", "tracker.example", "CONNECT", "", "host not allowed"),
      "deny tracker.example CONNECT host not allowed",
    )
    assertEquals(
      auditLine("deny", "-", "-", "", "invalid CONNECT port"),
      "deny - - invalid CONNECT port",
    )
    assertEquals(
      auditLine("deny", "github.com", "POST", "/r.git/git-receive-pack", "POST not granted"),
      "deny github.com POST /r.git/git-receive-pack POST not granted",
    )

  test("every reported line is stamped once with the UTC instant, however it is written"):
    val sink = java.io.ByteArrayOutputStream()
    val ticks = Iterator.from(0)
    val stamped = java.io.PrintStream(
      stampLines(sink, () => java.time.Instant.parse("2026-08-26T11:59:38.250Z").plusSeconds(ticks.next())),
      true,
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

  test("EGRESS_BIND unset or empty is the wildcard on the fixed port"):
    for value <- Seq(None, Some("")) do
      val bind = parseBind(value)
      assertEquals(bind.getPort, ListenPort)
      assert(bind.getAddress.isAnyLocalAddress)

  test("EGRESS_BIND accepts an IPv4 literal with an ephemeral port"):
    val bind = parseBind(Some("127.0.0.1:0"))
    assertEquals(bind.getAddress, InetAddress.getByName("127.0.0.1"))
    assertEquals(bind.getPort, 0)

  test("EGRESS_BIND accepts a bracketed IPv6 literal"):
    val bind = parseBind(Some("[::1]:3129"))
    assertEquals(bind.getAddress, InetAddress.getByName("::1"))
    assertEquals(bind.getPort, 3129)

  test("EGRESS_BIND refuses every value that is not <ip-literal>:<port>"):
    for
      value <- Seq(
        "127.0.0.1",       // no port
        "localhost:3128",  // a hostname needs a resolver
        "::1:3128",        // IPv6 without brackets: the port is ambiguous
        "[::1]3128",       // brackets without the separating colon
        "127.0.0.1:x",     // not a port
        "127.0.0.1:65536", // past the port range
        "127.0.0.1:-1",    // negative
      )
    do
      val ex = intercept[IllegalArgumentException](parseBind(Some(value)))
      assert(ex.getMessage.contains(BindVariable), clue = ex.getMessage)

  test("the ready line spells the bound port, and the fixed-port form is the launcher's"):
    assertEquals(readyLine(51234), "agent-egress-proxy listening on :51234")
    assertEquals(ReadyLine, readyLine(ListenPort))

  // ---------------------------------------------------------------------------
  // Refusal advice: the 403 body's second line, RefusalAdvice's table
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Refusal advice: the 403 body's second line, RefusalAdvice's table
  // ---------------------------------------------------------------------------

  /** One row per outcome of a `throw PolicyViolation(` in the sources, keyed by the site. The
    * population test counts the sites against the sources, so a refusal added without a row
    * fails it. `host` is the request's own — the one host an advice may name unadmitted. */
  private case class RefusalRow(site: String, host: String, expected: String, refuse: () => Unit)

  private def post(
    host: String,
    path: String,
    scopes: Map[String, Set[String]],
    admitted: String => Boolean = _ => false,
  ): () => Unit =
    () =>
      authorizeInspectedRequest(
        host,
        head(s"POST $path HTTP/1.1\r\nHost: $host\r\nContent-Length: 0\r\n\r\n"),
        scopes,
        admitted,
      )

  private lazy val refusalRows: Vector[RefusalRow] =
    import RefusalAdvice.*
    val github = "github.com"
    val gitlab = "gitlab.com"
    val fetch = whole("read", "git-fetch")
    def hello(sni: Option[String], ech: Boolean = false): TlsClientHello =
      TlsClientHello(Array.emptyByteArray, sni, echPresent = ech)
    Vector(
      RefusalRow("authorizeRequest port", github, port, () => authorize(github, 8443)),
      RefusalRow("authorizeRequest IP literal", "8.8.8.8", ipLiteral, () => authorize("8.8.8.8", 443)),
      RefusalRow(
        "authorizeRequest denied", gitlab, hostDenied,
        () => authorize(gitlab, 443, policyOf(rule = s"deny https://$gitlab/")),
      ),
      // A host a grant list emptied is denied as the whole-host line denies it.
      RefusalRow(
        "authorizeRequest denied", gitlab, hostDenied,
        () => authorize(gitlab, 443, policyOf(rule = s"deny https://$gitlab/ read git-fetch")),
      ),
      RefusalRow(
        "authorizeRequest denied", "api.example.com", hostDenied,
        () =>
          authorize(
            "api.example.com", 443,
            policyOf(profile = "allow-unless-denied", rule = "deny https://**.example.com/"),
          ),
      ),
      RefusalRow(
        "authorizeRequest not allowed", "tracker.example", hostNotAllowed("tracker.example", DefaultProfile),
        () => authorize("tracker.example", 443),
      ),
      // A defaults host under the default profile reaches this refusal through `deny defaults` alone.
      RefusalRow(
        "authorizeRequest not allowed", github, hostNotAllowed(github, DefaultProfile),
        () => authorize(github, 443, policyOf(rule = "deny defaults\nallow https://pypi.org/ read")),
      ),
      // Under a profile the rule file cannot widen, the step is the relaunch.
      RefusalRow(
        "authorizeRequest not allowed", github, hostNotAllowed(github, "deny-all"),
        () => authorize(github, 443, policyOf(profile = "deny-all")),
      ),
      // The same step with the project's file denying the host: the relaunch is named as
      // necessary, and the denial the default profile would apply is the user's to see.
      RefusalRow(
        "authorizeRequest not allowed", github, hostNotAllowed(github, "deny-all"),
        () => authorize(github, 443, policyOf(profile = "deny-all", rule = "deny https://github.com/")),
      ),
      RefusalRow(
        "authorizeRequest not allowed", "tracker.example", hostNotAllowed("tracker.example", "deny-unless-model"),
        () =>
          authorize("tracker.example", 443, policyOf(profile = "deny-unless-model", provider = "anthropic")),
      ),
      RefusalRow("requirePublic no address", "-", nonPublicAddress, () => requirePublic(Vector.empty)),
      RefusalRow(
        "requirePublic non-public", "-", nonPublicAddress,
        () => requirePublic(Vector(InetAddress.getByAddress(Array[Byte](10, 0, 0, 5)))),
      ),
      RefusalRow(
        "authorizeInspectedRequest origin-form", github, originForm,
        () => inspected("GET https://github.com/x HTTP/1.1\r\nHost: github.com\r\n\r\n"),
      ),
      RefusalRow(
        "authorizeInspectedRequest Upgrade", github, upgrade,
        () => inspected("GET /x HTTP/1.1\r\nHost: github.com\r\nUpgrade: websocket\r\n\r\n"),
      ),
      RefusalRow(
        "authorizeInspectedRequest Host header", github, hostHeader,
        () => inspected("GET /x HTTP/1.1\r\nHost: evil.example\r\n\r\n"),
      ),
      RefusalRow(
        "authorizeInspectedRequest request body", github, requestBody,
        () => inspected("GET /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 9\r\n\r\n"),
      ),
      RefusalRow(
        "authorizeInspectedRequest push discovery", github, gitPush,
        () => inspected("GET /o/r.git/info/refs?service=git-receive-pack HTTP/1.1\r\nHost: github.com\r\n\r\n"),
      ),
      RefusalRow(
        "authorizeInspectedRequest fetch discovery", github, gitFetch,
        () =>
          authorizeInspectedRequest(
            github, head(
              "GET /o/r.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\n\r\n",
            ), whole("read"),
          ),
      ),
      RefusalRow(
        "authorizeInspectedRequest read not granted", github, noRead,
        () =>
          authorizeInspectedRequest(github, head("GET /o/r HTTP/1.1\r\nHost: github.com\r\n\r\n"), whole("git-fetch")),
      ),
      // The refused-write site chooses by path for a POST — api.github.com's GraphQL is the case that
      // matters — and names the write for any other method.
      RefusalRow("authorizeInspectedRequest write not granted", github, graphql, post(github, "/graphql", fetch)),
      RefusalRow(
        "authorizeInspectedRequest write not granted", "api.github.com", graphql,
        post("api.github.com", "/graphql", whole("read")),
      ),
      RefusalRow("authorizeInspectedRequest write not granted", gitlab, graphql, post(gitlab, "/api/graphql", fetch)),
      RefusalRow(
        "authorizeInspectedRequest write not granted", github, lfsBatchGithub,
        post(github, "/o/r.git/info/lfs/objects/batch", fetch, defaultsPolicy.hosts.contains),
      ),
      // The content host is named only while the policy admits it, and only for the forge it serves.
      RefusalRow(
        "authorizeInspectedRequest write not granted", github, lfsBatch,
        post(
          github, "/o/r.git/info/lfs/objects/batch", fetch,
          policyOf(rule = s"deny https://$LfsContentHost/").hosts.contains,
        ),
      ),
      RefusalRow(
        "authorizeInspectedRequest write not granted", gitlab, lfsBatch,
        post(gitlab, "/g/o/r.git/info/lfs/objects/batch", fetch, defaultsPolicy.hosts.contains),
      ),
      RefusalRow("authorizeInspectedRequest write not granted", github, readOnly, post(github, "/o/r/issues", fetch)),
      RefusalRow(
        "authorizeInspectedRequest write not granted", github, readOnly,
        () => inspected("PUT /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"),
      ),
      RefusalRow(
        "authorizeInspectedRequest other method", github, readOnly,
        () => inspected("OPTIONS /x HTTP/1.1\r\nHost: github.com\r\nContent-Length: 0\r\n\r\n"),
      ),
      // GitHelper's one refusal site, reached by a write path's two spellings and, under a line
      // other than the root, a read path's two further ones.
      RefusalRow(
        "requireSpelledPlainly", github, ambiguousPath,
        post(github, "/o/r.git/%2e%2e/git-upload-pack", fetch),
      ),
      RefusalRow(
        "requireSpelledPlainly", github, ambiguousPath,
        post(github, "/o/r.git/../git-upload-pack", fetch),
      ),
      RefusalRow(
        "requireSpelledPlainly", github, ambiguousPath,
        () =>
          authorizeInspectedRequest(
            github, head("GET /o/a\\r HTTP/1.1\r\nHost: github.com\r\n\r\n"), under("/o/", "read"),
          ),
      ),
      RefusalRow(
        "requireSpelledPlainly", github, ambiguousPath,
        () =>
          authorizeInspectedRequest(
            github, head("GET /o//r HTTP/1.1\r\nHost: github.com\r\n\r\n"), under("/o/", "read"),
          ),
      ),
      RefusalRow(
        "authorizeInspectedRequest path outside", github, pathOutside(Set("/o/", "/p/")),
        () =>
          authorizeInspectedRequest(
            github, head("GET /q/r HTTP/1.1\r\nHost: github.com\r\n\r\n"), under("/o/", "read") ++ under("/p/", "read"),
          ),
      ),
      RefusalRow(
        "validateTlsIdentity ECH", github, RefusalAdvice.clientHello,
        () => validateTlsIdentity(github, hello(Some(github), ech = true)),
      ),
      RefusalRow(
        "validateTlsIdentity invalid SNI", github, RefusalAdvice.clientHello,
        () => validateTlsIdentity(github, hello(Some(""))),
      ),
      RefusalRow(
        "validateTlsIdentity no SNI", github, RefusalAdvice.clientHello,
        () => validateTlsIdentity(github, hello(None)),
      ),
      RefusalRow(
        "validateTlsIdentity mismatch", github, RefusalAdvice.clientHello,
        () => validateTlsIdentity(github, hello(Some("evil.example"))),
      ),
    )

  /** A hostname as it would appear in advice: dotted lowercase labels. */
  private val HostToken = """[a-z0-9-]+(?:\.[a-z0-9-]+)+""".r

  test("every refusal names its next step: one line, control-free, naming no unadmitted host"):
    val sourceDir = java.nio.file.Paths.get("src", "main", "scala")
    val sites =
      java.nio.file.Files.list(sourceDir).iterator.asScala
        .map(path => java.nio.file.Files.readString(path))
        .map(_.split(java.util.regex.Pattern.quote("throw PolicyViolation("), -1).length - 1)
        .sum
    val covered = refusalRows.map(_.site).distinct.size
    assertEquals(covered, sites, s"$sites refusal sites in the sources, $covered with a row here: add one per new site")

    refusalRows.foreach: row =>
      val refusal = intercept[PolicyViolation](row.refuse())
      val advice = refusal.advice
      assertEquals(advice, row.expected, s"${row.site}: ${refusal.getMessage}")
      assert(advice.nonEmpty && !advice.exists(isForbiddenControl), s"${row.site}: '$advice'")
      assert(refusalBody(refusal.getMessage, Some(advice)).length <= 512, s"${row.site}: body over 512 bytes")
      HostToken.findAllIn(advice).foreach: named =>
        assert(named == row.host || defaultsPolicy.hosts.contains(named), s"${row.site} names $named")

  test("the host-not-allowed step names a configuration that can admit the host, or none"):
    // The named line, in a clean project file, admits the host; a defaults host is refused under the
    // default profile only through `deny defaults`, and the step says so rather than naming a line
    // the defaults already carry. The relaunch is named as possible only ("can admit"), since the
    // project's file may deny the host under the default profile (the deny-all row above).
    import RefusalAdvice.hostNotAllowed
    val addition = "'allow https://tracker.example/ read' in .ko-agent-sandbox/egress/rule"
    Vector(DefaultProfile, "deny-all", "deny-unless-model").foreach: profile =>
      assert(hostNotAllowed("tracker.example", profile).contains(addition), profile)
      assert(!hostNotAllowed("github.com", profile).contains("allow https://"), profile)
    assertEquals(
      authorize("tracker.example", 443, policyOf(rule = "allow https://tracker.example/ read")),
      "tracker.example",
    )
    assertEquals(authorize("github.com", 443, policyOf()), "github.com")
    Vector("deny-all", "deny-unless-model").foreach: profile =>
      Vector("github.com", "tracker.example").foreach: host =>
        val advice = hostNotAllowed(host, profile)
        assert(advice.contains(s"a relaunch under $DefaultProfile"), advice)
        assert(advice.endsWith("can admit it."), advice)
    assert(hostNotAllowed("github.com", DefaultProfile).contains("deny defaults"))

  test("a refusal inside the tunnel is the reason and the step, framed as text/plain"):
    val (client, server) = socketPair()
    respondInsideTls(server, 403, "Forbidden", "POST not granted", Some(RefusalAdvice.readOnly))
    server.close()
    val received = String(client.getInputStream.readAllBytes(), StandardCharsets.UTF_8)
    client.close()

    val body = s"ko-agent-egress-proxy: POST not granted\n${RefusalAdvice.readOnly}\n"
    assertEquals(
      received,
      "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n" +
        s"Content-Length: ${body.getBytes(StandardCharsets.UTF_8).length}\r\nConnection: close\r\n\r\n" + body,
    )
    // A 400 or 502 has no step to name, and keeps the one-line body.
    assertEquals(
      String(refusalBody("origin: certificate expired", None), StandardCharsets.UTF_8),
      "ko-agent-egress-proxy: origin: certificate expired\n",
    )

  test("a refused CONNECT answers 403 with the same body, and the audit line is the reason alone"):
    def exchange(request: String): (String, String) =
      val (client, server) = socketPair()
      val log = java.io.ByteArrayOutputStream()
      val saved = System.err
      System.setErr(java.io.PrintStream(log, true))
      try
        val handling = Thread.startVirtualThread(() => handle(server, EgressPolicy(defaultsPolicy, None)))
        client.getOutputStream.write(ascii(request))
        client.getOutputStream.flush()
        val received = String(client.getInputStream.readAllBytes(), StandardCharsets.UTF_8)
        handling.join()
        (received, String(log.toByteArray, StandardCharsets.UTF_8).trim)
      finally
        System.setErr(saved)
        client.close()

    val body =
      s"ko-agent-egress-proxy: host not allowed\n${RefusalAdvice.hostNotAllowed("tracker.example", DefaultProfile)}\n"
    assertEquals(
      exchange("CONNECT tracker.example:443 HTTP/1.1\r\nHost: tracker.example:443\r\n\r\n"),
      (
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n" +
          s"Content-Length: ${body.getBytes(StandardCharsets.UTF_8).length}\r\nConnection: close\r\n\r\n" + body,
        "deny tracker.example CONNECT host not allowed",
      ),
    )
    // A malformed request is the client's defect, answered with no body as before.
    assertEquals(
      exchange("GET / HTTP/1.1\r\nHost: tracker.example\r\n\r\n"),
      (
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "deny - - GET non-CONNECT request",
      ),
    )

  private def head(value: String): HttpRequestHead =
    HttpRequestHead.parse(ascii(value))

  private lazy val defaultsPolicy: ResolvedEgress =
    resolvePolicy(Some("deny-unless-allowed"), None, None)

  private lazy val builtinGitHosts: Set[String] =
    defaultsPolicy.inspectedScopes
      .collect { case (host, scopes) if scopes.get("/").exists(_("git-fetch")) => host }
      .toSet

  private def inspected(value: String): Unit =
    authorizeInspectedRequest("github.com", head(value), whole("read", "git-fetch"))

  /** A host with one root line carrying these grants: the scopes every `allow https://host/` line resolves to. */
  private def whole(grants: String*): Map[String, Set[String]] = Map("/" -> grants.toSet)

  /** One scope at a path, as an `allow https://host/path` line resolves to on a host with no other line. */
  private def under(path: String, grants: String*): Map[String, Set[String]] = Map(path -> grants.toSet)

  private def parseConnect(value: String): ConnectRequest =
    ConnectRequest.parse(ascii(value))

  private def authorize(host: String, port: Int, resolved: ResolvedEgress = defaultsPolicy): String =
    authorizeRequest(ConnectRequest(host, port), resolved)


  private def clientHello(
    serverName: String,
    ech: Boolean = false,
    splitAt: Option[Int] = None,
    trailingInRecord: Array[Byte] = Array.emptyByteArray,
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
      (value & 0xff).toByte,
    )

  private def u24(value: Int): Array[Byte] =
    Array(
      ((value >>> 16) & 0xff).toByte,
      ((value >>> 8) & 0xff).toByte,
      (value & 0xff).toByte,
    )