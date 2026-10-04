// The brokered credential's grammar, the lines a proxy reads its bindings from, and the head rewrite
// (doc/egress-proxy.md, "Where the value goes"). The whole inspected path is AgentEgressProxyTest's.

package agentsandbox.egress

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.util.Base64

import CredentialRewrite.*
import HTTPHelper.*
import RulesetHelper.*

class CredentialTest extends munit.FunSuite:

  private val GhPlaceholder = "ghp_placeholder0000000000000000000000000"
  private val GhValue = "ghp_realvalue111111111111111111111111111"

  private def bound(spelled: String, placeholder: String, value: String): BrokeredCredential =
    BrokeredCredential(CredentialGrammar.parseBinding(spelled).fold(fail(_), identity), placeholder, value)

  private val github = bound("GH_TOKEN@api.github.com", GhPlaceholder, GhValue)

  private def head(target: String, headers: (String, String)*): HttpRequestHead =
    HttpRequestHead("GET", target, "HTTP/1.1", ("Host" -> "api.github.com") +: headers.toVector)

  private def basic(pair: String): String =
    "Basic " + Base64.getEncoder.encodeToString(pair.getBytes(StandardCharsets.ISO_8859_1))

  // --------------------------------------------------------------------------
  // The grammar
  // --------------------------------------------------------------------------

  test("a binding spells its host, prefix and place, Authorization by default, and spells back the same"):
    val cases = Vector(
      "GH_TOKEN@api.github.com" -> ("api.github.com", "/", CredentialPlace.Header("Authorization")),
      "T@gitlab.com:PRIVATE-TOKEN" -> ("gitlab.com", "/", CredentialPlace.Header("PRIVATE-TOKEN")),
      "K@API.Example.COM:X-Goog-Api-Key" -> ("api.example.com", "/", CredentialPlace.Header("X-Goog-Api-Key")),
      "A@h.example:authorization" -> ("h.example", "/", CredentialPlace.Header("Authorization")),
      "C@h.example:Cookie" -> ("h.example", "/", CredentialPlace.Header("Cookie")),
      "S@acct.blob.core.windows.net?sig" -> ("acct.blob.core.windows.net", "/", CredentialPlace.Parameter("sig")),
      "G@maven.pkg.github.com/owner/" -> ("maven.pkg.github.com", "/owner/", CredentialPlace.Header("Authorization")),
      "G@h.example/a/b/:x-api-key" -> ("h.example", "/a/b/", CredentialPlace.Header("x-api-key")),
      "G@h.example/a/?key" -> ("h.example", "/a/", CredentialPlace.Parameter("key")),
    )
    cases.foreach: (spelled, expected) =>
      val binding = CredentialGrammar.parseBinding(spelled).fold(reason => fail(s"$spelled: $reason"), identity)
      assertEquals((binding.host, binding.prefix, binding.place), expected, spelled)
      assertEquals(CredentialGrammar.parseBinding(binding.spelled), Right(binding), spelled)

  test("each refusal of a malformed binding says what is wrong"):
    val cases = Vector(
      "GH_TOKEN" -> "a credential needs a host; to set the value itself in the sandbox, use --env=NAME",
      "GH_TOKEN=ghp_x@api.github.com" ->
        "a credential's value is not given on the command line; set the variable for the launch and pass NAME@HOST",
      "1X@api.github.com" -> "'1X' is not an environment variable name: a letter or _, then letters, digits and _",
      "X@" -> "a credential needs a host after @",
      "X@10.0.0.1" -> "'10.0.0.1' is an IP literal; a credential is bound to a hostname",
      "X@h.example:443" ->
        "'443' is a port, not a header name; a credential is bound to a hostname, reached on port 443 only",
      "X@h.example:" -> "'' is not a header name: only letters, digits and !#$%&'*+-.^_`|~",
      "X@h.example:a:b" -> "'a:b' is not a header name: only letters, digits and !#$%&'*+-.^_`|~",
      "X@h.example:a\"b" -> "'a\"b' is not a header name: only letters, digits and !#$%&'*+-.^_`|~",
      "X@h.example?" -> "'' is not a query parameter name: visible ASCII without &, =, # or +",
      "X@h.example?a&b" -> "'a&b' is not a query parameter name: visible ASCII without &, =, # or +",
      "X@h.example?a=b" -> "'a=b' is not a query parameter name: visible ASCII without &, =, # or +",
      "X@h.example?a#b" -> "'a#b' is not a query parameter name: visible ASCII without &, =, # or +",
      // A form parser reads "api key".
      "X@h.example?api+key" -> "'api+key' is not a query parameter name: visible ASCII without &, =, # or +",
      "X@h.example:Authorization?sig" -> "a binding names one place: :HEADER or ?PARAM, not both",
      "X@h.example/a/:x-api-key?sig" -> "a binding names one place: :HEADER or ?PARAM, not both",
      "X@h.example/a/../" -> "a prefix has a dot segment; it is written in canonical form, as a rule's path is",
      "X@h.example/a%2f/" ->
        ("a prefix has an escaped ASCII character other than a space; it is written in canonical form, " +
          "as a rule's path is"),
      "X@h.example/a//" -> "a prefix has an empty segment; it is written in canonical form, as a rule's path is",
      "X@h.example/public#/private/" ->
        "a prefix has a number sign; it is written in canonical form, as a rule's path is",
      "X@h.example/a" -> "'a' follows the host; a binding is NAME@HOST[/PREFIX/][:HEADER|?PARAM]",
    )
    cases.foreach: (spelled, reason) =>
      assertEquals(CredentialGrammar.parseBinding(spelled), Left(reason), spelled)

  test("a header the proxy reads or removes is refused, whatever its case: the value would never arrive as it"):
    val names = Vector("Host", "content-length", "Transfer-Encoding", "Connection", "Keep-Alive", "Proxy-Authorization",
      "Proxy-Authenticate", "Proxy-Connection", "TE", "Trailer", "UPGRADE")
    assertEquals(names.map(_.toLowerCase(java.util.Locale.ROOT)).toSet, CredentialGrammar.RefusedHeaders)
    names.foreach: name =>
      assertEquals(
        CredentialGrammar.parseBinding(s"X@h.example:$name"),
        Left(s"$name is read or removed by the proxy; bind the header the service authenticates with"),
      )

  test("a value is 1–4096 bytes of visible ASCII; a refusal names the offset, never the value"):
    val refused = Vector(
      "" -> "X is empty",
      "ab\rc" -> "X contains a byte a header cannot carry, at offset 2",
      "ab\nc" -> "X contains a byte a header cannot carry, at offset 2",
      "\u0000" -> "X contains a byte a header cannot carry, at offset 0",
      "a\tb" -> "X contains a byte a header cannot carry, at offset 1",
      "a b" -> "X contains a byte a header cannot carry, at offset 1",
      "ab\u007f" -> "X contains a byte a header cannot carry, at offset 2",
      "abcé" -> "X contains a byte a header cannot carry, at offset 3",
      "a" * 4097 -> "X is longer than 4096 bytes",
    )
    refused.foreach: (value, reason) =>
      assertEquals(CredentialGrammar.valueProblem("X", value), Some(reason), value.take(8))
    Vector("a", "a" * 4096, "&=#%@:?/~!", "sv=1&sp=rl&sig=x%2By").foreach: value =>
      assertEquals(CredentialGrammar.valueProblem("X", value), None, value.take(8))

  // --------------------------------------------------------------------------
  // The bindings' lines
  // --------------------------------------------------------------------------

  test("the bindings read back as written, and the read stops at the last one's line"):
    val credentials = Vector(github, bound("S@acct.blob.core.windows.net/c/?sig", "PLACEHOLDERsig", "sv&=%#"))
    val text = CredentialGrammar.bindingInput(credentials) + "after"
    val in = ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII))
    assertEquals(CredentialGrammar.readBindings(in), Right(credentials))
    assertEquals(String(in.readAllBytes(), StandardCharsets.US_ASCII), "after")

  test("a binding line outside the grammar refuses the whole read, naming the binding and never the value"):
    def read(text: String) =
      CredentialGrammar.readBindings(ByteArrayInputStream(text.getBytes(StandardCharsets.ISO_8859_1)))
    val cases = Vector(
      "" -> "the bindings ended before their count",
      "x\n" -> "the bindings' count line is 'x', not a count up to 256",
      "-1\n" -> "the bindings' count line is '-1', not a count up to 256",
      "+1\n" -> "the bindings' count line is '+1', not a count up to 256",
      "1\n" -> "the bindings ended before their count",
      "1\nX@h.example PH\n" -> "a binding line is not <binding> <placeholder> <value>",
      "1\nX@h.example PH sec ret\n" -> "a binding line is not <binding> <placeholder> <value>",
      "1\nX@h.example PH sec\u0001ret\n" -> "X contains a byte a header cannot carry, at offset 3",
      "1\nX@h.example PH secÿret\n" -> "X contains a byte a header cannot carry, at offset 3",
      "1\nX@h.example:Host PH secret\n" ->
        "Host is read or removed by the proxy; bind the header the service authenticates with",
      "1\nX@h.example?a&b PH secret\n" -> "'a&b' is not a query parameter name: visible ASCII without &, =, # or +",
      "1\nX@h.example  secret\n" -> "the placeholder of X is empty",
      "2\nX@h.example A secret\nX@i.example B secret\n" -> "X is bound twice; one name, one host",
      "2\nX@h.example A secret\nY@i.example A secret\n" -> "two bindings share a placeholder",
      s"1\nX@h.example PH ${"a" * 10000}\n" -> "a binding line is longer than a binding can be",
    )
    cases.foreach: (text, reason) =>
      assertEquals(read(text), Left(reason), text.take(40))
      assert(!reason.contains("secret") && !reason.contains("ret"), reason)

  test("the proxy reads its standard input only with EGRESS_CREDS=stdin, and binds only hosts it inspects"):
    val resolved = resolveRuleset(Some("deny-unless-allowed"), None, Some("allow https://h.example/ read\n"))
    val inspecting = true
    def input = ByteArrayInputStream(CredentialGrammar.bindingInput(Vector(bound("X@h.example", "PH", "v"))).getBytes)
    def unread: java.io.InputStream = throw AssertionError("read standard input without EGRESS_CREDS=stdin")
    assertEquals(AgentEgressProxy.readCredentials(resolved, inspecting, unread, _ => None), Vector.empty)
    assertEquals(AgentEgressProxy.readCredentials(resolved, inspecting, unread, _ => Some("")), Vector.empty)
    assertEquals(
      AgentEgressProxy.readCredentials(resolved, inspecting, input, _ => Some("stdin")).map(_.binding.spelled),
      Vector("X@h.example:Authorization"),
    )
    def refusal(read: => Any): String = intercept[IllegalArgumentException](read).getMessage
    assertEquals(
      refusal(AgentEgressProxy.readCredentials(resolved, inspecting, unread, _ => Some("file"))),
      "EGRESS_CREDS is 'file'; the only value it accepts is stdin",
    )
    assertEquals(
      refusal(AgentEgressProxy.readCredentials(resolved, false, input, _ => Some("stdin"))),
      "brokered credentials need TLS inspection; set EGRESS_TLS_CERTIFICATE and EGRESS_TLS_PRIVATE_KEY",
    )
    val elsewhere =
      ByteArrayInputStream(CredentialGrammar.bindingInput(Vector(bound("X@i.example", "PH", "v"))).getBytes)
    assertEquals(
      refusal(AgentEgressProxy.readCredentials(resolved, inspecting, elsewhere, _ => Some("stdin"))),
      "X@i.example:Authorization: this proxy does not inspect i.example, so nothing would be substituted there",
    )
    val tunnel = resolveRuleset(Some("deny-unless-allowed"), None, Some("allow https://h.example/ tunnel\n"))
    assertEquals(
      refusal(AgentEgressProxy.readCredentials(tunnel, inspecting, input, _ => Some("stdin"))),
      "X@h.example:Authorization: this proxy does not inspect h.example, so nothing would be substituted there",
    )

  // --------------------------------------------------------------------------
  // The rewrite
  // --------------------------------------------------------------------------

  test("Authorization: the whole token of Bearer and token, and only Basic's password half"):
    val cases = Vector(
      s"Bearer $GhPlaceholder" -> s"Bearer $GhValue",
      s"bearer $GhPlaceholder" -> s"bearer $GhValue",
      s"token  $GhPlaceholder" -> s"token  $GhValue",
      basic(s"x-access-token:$GhPlaceholder") -> basic(s"x-access-token:$GhValue"),
      basic(s":$GhPlaceholder") -> basic(s":$GhValue"),
    )
    cases.foreach: (sent, forwarded) =>
      val substituted = head("/user", "Authorization" -> sent).withCredentials("api.github.com", Vector(github))
      assertEquals(substituted.head.values("Authorization"), Vector(forwarded), sent)
      assertEquals(substituted.injected, Vector("GH_TOKEN"), sent)

  test("an application's own credential, another scheme, a partial token or the user half stays as sent"):
    val untouched = Vector(
      "Bearer ghp_theapplicationsown000000000000000000",
      basic("user:ghp_theapplicationsown000000000000000000"),
      basic(s"$GhPlaceholder:x"),
      s"Digest $GhPlaceholder",
      s"Bearer ${GhPlaceholder}x",
      s"Bearer x$GhPlaceholder",
      s"Bearer $GhPlaceholder extra",
      s"Bearer",
      GhPlaceholder,
      "Basic !!!not-base64",
    )
    untouched.foreach: sent =>
      val substituted = head("/user", "Authorization" -> sent).withCredentials("api.github.com", Vector(github))
      assertEquals(substituted.head.values("Authorization"), Vector(sent), sent)
      assertEquals(substituted.injected, Vector.empty, sent)

  test("a bound host, path and place only: another host, the path, an unbound header or parameter stay as sent"):
    val placed = s"/repos/$GhPlaceholder?q=$GhPlaceholder"
    val request = head(placed, "Authorization" -> s"Bearer $GhPlaceholder", "x-api-key" -> GhPlaceholder)
    val elsewhere = request.withCredentials("gitlab.com", Vector(github))
    assertEquals(elsewhere.head, request)
    val here = request.withCredentials("api.github.com", Vector(github))
    assertEquals(here.head.target, placed)
    assertEquals(here.head.values("x-api-key"), Vector(GhPlaceholder))
    assertEquals(here.head.values("Authorization"), Vector(s"Bearer $GhValue"))

  test("a bound header sent twice is rewritten in each occurrence holding the placeholder, and no other"):
    // Whichever occurrence the origin reads, it reads what the client meant there.
    val bearer = s"Bearer $GhPlaceholder"
    val own = "Bearer ghp_theapplicationsown000000000000000000"
    val twice = head("/user", "Authorization" -> bearer, "authorization" -> bearer)
      .withCredentials("api.github.com", Vector(github))
    assertEquals(
      twice.head.headers.tail,
      Vector("Authorization" -> s"Bearer $GhValue", "authorization" -> s"Bearer $GhValue"),
    )
    assertEquals(twice.injected, Vector("GH_TOKEN"))
    val beside = head("/user", "Authorization" -> own, "Authorization" -> bearer)
      .withCredentials("api.github.com", Vector(github))
    assertEquals(beside.head.headers.tail, Vector("Authorization" -> own, "Authorization" -> s"Bearer $GhValue"))

  test("two placeholders in one request: the one bound to this host is substituted, the other stays"):
    val gitlab = bound("GL_TOKEN@gitlab.com:PRIVATE-TOKEN", "glpat-placeholder00000000", "glpat-value")
    val request = head("/user", "Authorization" -> s"Bearer $GhPlaceholder", "PRIVATE-TOKEN" -> gitlab.placeholder)
    val substituted = request.withCredentials("api.github.com", Vector(github, gitlab))
    assertEquals(substituted.head.values("Authorization"), Vector(s"Bearer $GhValue"))
    assertEquals(substituted.head.values("PRIVATE-TOKEN"), Vector(gitlab.placeholder))
    assertEquals(substituted.injected, Vector("GH_TOKEN"))

  test("another header named by a binding: its whole value, in whatever case the client spells the name"):
    val key = bound("API_KEY@api.github.com:x-api-key", "PLACEHOLDERkey", "realkey")
    val substituted = head("/v1", "X-Api-Key" -> "PLACEHOLDERkey").withCredentials("api.github.com", Vector(key))
    assertEquals(substituted.head.headers.last, "X-Api-Key" -> "realkey")
    assertEquals(substituted.injected, Vector("API_KEY"))
    val partial = head("/v1", "x-api-key" -> "PLACEHOLDERkey2")
    assertEquals(partial.withCredentials("api.github.com", Vector(key)).head, partial)

  test("under a prefix, only requests whose literal path is under it"):
    val packages = bound("GH_TOKEN@maven.pkg.github.com/owner/", GhPlaceholder, GhValue)
    def sent(path: String) =
      HttpRequestHead("GET", path, "HTTP/1.1", Vector("Authorization" -> s"Bearer $GhPlaceholder"))
        .withCredentials("maven.pkg.github.com", Vector(packages)).injected
    assertEquals(sent("/owner/repo/a.jar"), Vector("GH_TOKEN"))
    Vector("/other/repo/a.jar", "/owner", "/owner/%2e%2e/other/a.jar", "/owner/../other/a.jar", "/owner//a",
      "/owner/..;/other/a.jar", "/owner/a;b", "/owner/a#/b", "/owner/\u00e4.jar", "/owner/%EF%BC%8F/a.jar")
      .foreach(path => assertEquals(sent(path), Vector.empty, path))
    // Non-ASCII text, escaped in UTF-8 as RFC 3986 spells it, in the prefix and under it; hex case is
    // compared byte for byte, so the other case is not under the prefix.
    assertEquals(sent("/owner/%C3%A4%20b.jar"), Vector("GH_TOKEN"))
    assertEquals(sent("/owner/%c3%a4.jar"), Vector("GH_TOKEN"))
    val named = bound("GH_TOKEN@h.example/%E3%81%82/", GhPlaceholder, GhValue)
    val underNamed =
      HttpRequestHead("GET", "/%E3%81%82/x", "HTTP/1.1", Vector("Authorization" -> s"Bearer $GhPlaceholder"))
    assertEquals(underNamed.withCredentials("h.example", Vector(named)).injected, Vector("GH_TOKEN"))
    val otherCase = underNamed.copy(target = "/%e3%81%82/x")
    assertEquals(otherCase.withCredentials("h.example", Vector(named)).injected, Vector.empty)

  test("a bound parameter: its decoded value equal to the placeholder, the value written percent-encoded"):
    val sas = bound("SAS_SIG@acct.blob.core.windows.net?sig", "PLACEHOLDERsig", "a&b=c%d#e+f/g")
    def substituted(target: String) =
      HttpRequestHead("GET", target, "HTTP/1.1", Vector.empty)
        .withCredentials("acct.blob.core.windows.net", Vector(sas))
    val one = substituted("/c/b?sv=1&sig=PLACEHOLDERsig&sp=r")
    assertEquals(one.head.target, "/c/b?sv=1&sig=a%26b%3Dc%25d%23e%2Bf%2Fg&sp=r")
    assertEquals(one.injected, Vector("SAS_SIG"))
    assertEquals(one.printedTarget, "/c/b?sv=1&sig=SAS_SIG&sp=r")
    assertEquals(substituted("/c/b?%73ig=PLACEHOLDER%73ig").head.target, "/c/b?%73ig=a%26b%3Dc%25d%23e%2Bf%2Fg")
    Vector("/c/b?sig=x", "/c/b?sig", "/c/b?other=PLACEHOLDERsig").foreach: target =>
      assertEquals(substituted(target).head.target, target)
      assertEquals(substituted(target).injected, Vector.empty, target)
    // Sent twice, each occurrence holding the placeholder is rewritten, and an occurrence that does not stays.
    val twice = substituted("/c/b?sig=PLACEHOLDERsig&sig=x&sig=PLACEHOLDERsig")
    assertEquals(twice.head.target, "/c/b?sig=a%26b%3Dc%25d%23e%2Bf%2Fg&sig=x&sig=a%26b%3Dc%25d%23e%2Bf%2Fg")
    assertEquals(twice.injected, Vector("SAS_SIG"))
    assertEquals(
      substituted("/c/b?sig=PLACEHOLDERsig&sig=PLACEHOLDERsig").printedTarget,
      "/c/b?sig=SAS_SIG&sig=SAS_SIG",
    )

  test("the printed target carries no placeholder spelled as issued, wherever the request put it"):
    val request = head(s"/a/$GhPlaceholder?x=$GhPlaceholder&y=z")
    assertEquals(request.withCredentials("gitlab.com", Vector(github)).printedTarget, "/a/GH_TOKEN?x=GH_TOKEN&y=z")

  test("authorization reads the rewritten head: a bound service parameter is classified as what it becomes"):
    val push = bound("SERVICE@github.com?service", "PLACEHOLDERservice", "git-receive-pack")
    val request = HttpRequestHead(
      "GET", "/o/r.git/info/refs?service=PLACEHOLDERservice", "HTTP/1.1", Vector("Host" -> "github.com"),
    )
    val substituted = request.withCredentials("github.com", Vector(push))
    assertEquals(substituted.printedTarget, "/o/r.git/info/refs?service=SERVICE")
    val refused = intercept[Refusal](
      authorizeInspectedRequest("github.com", substituted.head, Map("/" -> Set("read", "git-fetch"))),
    )
    assertEquals(refused.getMessage, "git push ref discovery")
