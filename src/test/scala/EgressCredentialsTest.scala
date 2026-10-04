package agentsandbox.launcher

import java.lang.foreign.{Arena, FunctionDescriptor, Linker, ValueLayout}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import java.security.SecureRandom

import agentsandbox.egress.{BrokeredCredential, CredentialBinding, CredentialGrammar}
import AgentSandboxLauncher.*

class EgressCredentialsTest extends munit.FunSuite:

  private def binding(spelled: String): CredentialBinding =
    CredentialGrammar.parseBinding(spelled).fold(fail(_), identity)

  private val ghValue = "ghp_" + "r" * 36

  test("option parsing: --egress-cred binds a name to a host, each name once, and never beside --env"):
    assertEquals(
      parseCommandLine(
        List("--egress-cred=GH_TOKEN@api.github.com", "--egress-cred=S@a.example/c/?sig", "claude"),
      ).map(_.credentialBindings.map(_.spelled)),
      Right(Vector("GH_TOKEN@api.github.com:Authorization", "S@a.example/c/?sig")),
    )
    val refusals = Vector(
      List("--egress-cred=GH_TOKEN") ->
        ("error: --egress-cred=GH_TOKEN; a credential needs a host; to set the value itself in the sandbox, " +
          "use --env=NAME"),
      List("--egress-cred=GH_TOKEN@a.example", "--egress-cred=GH_TOKEN@b.example") ->
        "error: --egress-cred=GH_TOKEN@b.example:Authorization; GH_TOKEN is bound twice; one name, one host",
      List("--egress-cred=GH_TOKEN@a.example", "--env=GH_TOKEN") ->
        "error: --env=GH_TOKEN and --egress-cred=GH_TOKEN@…; pass GH_TOKEN to one of them",
      List("--env=GH_TOKEN=x", "--egress-cred=GH_TOKEN@a.example") ->
        "error: --env=GH_TOKEN and --egress-cred=GH_TOKEN@…; pass GH_TOKEN to one of them",
      List("--egress-cred=KO_AGENT_SANDBOX_X@a.example") ->
        "error: --egress-cred=KO_AGENT_SANDBOX_X@a.example; the launcher sets KO_AGENT_SANDBOX_* itself",
      List("--egress-cred=X@a.example:Host") ->
        ("error: --egress-cred=X@a.example:Host; Host is read or removed by the proxy; bind the header the service " +
          "authenticates with"),
      List("--egress-cred=X@a.example:Authorization?sig") ->
        "error: --egress-cred=X@a.example:Authorization?sig; a binding names one place: :HEADER or ?PARAM, not both",
      List("--egress-cred=X@a.example?a&b") ->
        "error: --egress-cred=X@a.example?a&b; 'a&b' is not a query parameter name: visible ASCII without &, =, # or +",
      List("--egress-cred", "X@a.example") ->
        ("error: the launch options are spelled --write=<mode>, --egress=<profile>, --env=<name>[=<value>], " +
          "--egress-cred=<name>@<host> and --run-on-host=<programs>"),
    )
    refusals.foreach: (args, refusal) =>
      assertEquals(parseCommandLine(args), Left(refusal), args.mkString(" "))
    // After the command name, the option belongs to the command.
    assertEquals(
      parseCommandLine(List("claude", "--egress-cred=X@a.example")).map(_.credentialBindings),
      Right(Vector.empty),
    )

  test("a value on the command line is refused naming the variable alone"):
    val refused = parseCommandLine(List("--egress-cred=GH_TOKEN=ghp_secretvalue@api.github.com"))
    assertEquals(
      refused,
      Left(
        "error: --egress-cred=GH_TOKEN=…; a credential's value is not given on the command line; set the variable " +
          "for the launch and pass NAME@HOST",
      ),
    )

  test("a value is the host variable's, checked against the grammar; refusals name the variable, never the value"):
    val bindings = Vector(binding("GH_TOKEN@api.github.com"))
    def resolved(value: Option[String]) = EgressCredentials.resolve(bindings, Map("GH_TOKEN" -> value).get(_).flatten)
    assertEquals(
      resolved(None),
      Left("error: --egress-cred=GH_TOKEN@api.github.com:Authorization; GH_TOKEN is not set on the host"),
    )
    assertEquals(
      resolved(Some("")),
      Left("error: --egress-cred=GH_TOKEN@api.github.com:Authorization; GH_TOKEN is empty"),
    )
    for value <- Vector("ghp_se cret", "ghp_se\ncret", "ghp_seécret") do
      val refusal = resolved(Some(value)).swap.getOrElse(fail(value))
      assert(refusal.contains("contains a byte a header cannot carry, at offset 6"), refusal)
      assert(!refusal.contains("cret"), refusal)
    assertEquals(resolved(Some(ghValue)).map(_.map(_.value)), Right(Vector(ghValue)))

  test("a placeholder keeps a recognized prefix, the length and the separators, each other character's class"):
    val random = SecureRandom()
    def placeholder(value: String) = EgressCredentials.placeholderFor(value, Set(value), random)
    def classOf(char: Char): String =
      if char.isDigit then "digit"
      else if char.isUpper then "upper"
      else if char.isLower then "lower"
      else char.toString
    val values = Vector(
      ghValue, "gho_" + "o" * 36, "github_pat_" + "p" * 82, "glpat-" + "g" * 20,
      "ghs_12345_eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0NSJ9.c2lnbmF0dXJl-_x",
    )
    for value <- values do
      val made = placeholder(value)
      val prefix = EgressCredentials.RecognizedPrefixes.find(value.startsWith).get
      assert(made.startsWith(prefix), made)
      assertEquals(made.drop(prefix.length).map(classOf), value.drop(prefix.length).map(classOf), made)
      assertNotEquals(made, value)
      assertNotEquals(placeholder(value), made)
    // Without a recognized prefix the same holds from the first character; punctuation that would split
    // or re-parse a query becomes a letter or a digit.
    for value <- Vector("sv=2024&sig=abc%2F#x", "Ab1", "ghp_", "1234567890ab") do
      val made = placeholder(value)
      assertEquals(made.length, value.length)
      made.zip(value).foreach: (replaced, sent) =>
        if "-._~".contains(sent) then assertEquals(replaced, sent)
        else if sent.isLetterOrDigit then assertEquals(classOf(replaced), classOf(sent), made)
        else assert(replaced.isLetterOrDigit, made)
    val two = EgressCredentials.resolve(
      Vector(binding("A@a.example"), binding("B@b.example")),
      Map("A" -> ghValue, "B" -> ghValue).get,
    ).fold(fail(_), identity)
    assertNotEquals(two(0).placeholder, two(1).placeholder)

  test("a value too short for a placeholder with 64 random bits is refused, naming the variable alone"):
    def resolved(value: String) =
      EgressCredentials.resolve(Vector(binding("K@a.example:x-api-key")), Map("K" -> value).get)
    // Bits are counted for the characters replaced: 4.7 a letter, 3.3 a digit, 5.95 other punctuation;
    // a recognized prefix and the kept separators add none.
    assert(EgressCredentials.placeholderBits("a" * 13) < 64)
    assert(EgressCredentials.placeholderBits("a" * 14) >= 64)
    assert(EgressCredentials.placeholderBits("1" * 19) < 64)
    assert(EgressCredentials.placeholderBits("1" * 20) >= 64)
    assertEquals(EgressCredentials.placeholderBits("ghp_" + "-._~" * 10), 0.0)
    for value <- Vector("short-secret", "1234567890123456789", "ghp_abc", "a.b.c.d.e.f.g.h.i.j.k.l.m") do
      assertEquals(
        resolved(value),
        Left(
          "error: --egress-cred=K@a.example:x-api-key; value of K is too short to be replaced by an unguessable " +
            "placeholder, which needs 64 random bits; if the sandbox may hold it, forward it with --env=K",
        ),
        value,
      )
    assert(resolved("a" * 14).isRight)
    assert(resolved(ghValue).isRight)

  test("a binding must reach a proxy that inspects its host: the session's, or a selected program's"):
    val sessionInspected = Set("api.github.com")
    val tunnels = Set("api.anthropic.com")
    val programs = Map("sbt" -> Set("repo1.maven.org", "maven.pkg.github.com"))
    def checked(spelled: String) =
      EgressCredentials.checkHosts(Vector(binding(spelled)), sessionInspected, tunnels, programs)
    assertEquals(checked("GH_TOKEN@api.github.com"), Right(()))
    assertEquals(checked("GH_TOKEN@maven.pkg.github.com"), Right(()))
    assertEquals(
      checked("ANTHROPIC_API_KEY@api.anthropic.com:x-api-key"),
      Left(
        "error: --egress-cred=ANTHROPIC_API_KEY@api.anthropic.com:x-api-key; api.anthropic.com is an opaque tunnel, " +
          "where nothing can be substituted; bind to an inspected host or forward the value itself with " +
          "--env=ANTHROPIC_API_KEY",
      ),
    )
    assertEquals(
      checked("T@gitlab.com:PRIVATE-TOKEN"),
      Left(
        "error: --egress-cred=T@gitlab.com:PRIVATE-TOKEN; no proxy of this launch allows gitlab.com; add " +
          "`allow https://gitlab.com/ read` to .ko-agent-sandbox/egress/rule or to " +
          ".ko-agent-sandbox/run-on-host/sbt/egress/rule",
      ),
    )

  test("each proxy is given the bindings whose host it inspects, and no other"):
    val credentials = Vector(
      BrokeredCredential(binding("A@api.github.com"), "PHa", "va"),
      BrokeredCredential(binding("B@maven.pkg.github.com"), "PHb", "vb"),
    )
    assertEquals(EgressCredentials.bindingsFor(credentials, Set("api.github.com")).map(_.binding.name), Vector("A"))
    assertEquals(
      RunOnHostSandbox.credentialsFor(RunOnHostPrereqs.Program.Sbt, Vector("maven.pkg.github.com"), credentials)
        .map(_.binding.name),
      Vector("B"),
    )
    assertEquals(RunOnHostSandbox.credentialsFor(RunOnHostPrereqs.Program.Mvn, Vector.empty, credentials), Vector.empty)

  test("no value in anything the launcher writes: proxy arguments, sandbox arguments, the banner, the instructions"):
    val credentials = Vector(BrokeredCredential(binding("GH_TOKEN@api.github.com"), "ghp_" + "P" * 36, ghValue))
    val said = proxyCredentialArgs(credentials) ++ placeholderArgs(credentials)
      ++ EgressCredentials.bannerLines(credentials)
      :+ brokeredParagraph(credentials.map(_.binding))
      :+ agentDocumentStamp("image", "live", "ruleset", brokered = credentials.map(_.binding))
    for line <- said do assert(!line.contains(ghValue), line)
    assertEquals(proxyCredentialArgs(credentials), Vector("--interactive", "--env=EGRESS_CREDS=stdin"))
    assertEquals(proxyCredentialArgs(Vector.empty), Vector.empty)
    assertEquals(placeholderArgs(credentials), Vector(s"--env=GH_TOKEN=ghp_${"P" * 36}"))
    assertEquals(
      EgressCredentials.bannerLines(credentials),
      Vector(s"brokered credential: GH_TOKEN → api.github.com (Authorization), placeholder ghp_${"P" * 36}"),
    )
    // The placeholder changes each launch; the instructions, cached by their stamp, name the binding alone.
    val other = credentials.map(_.copy(placeholder = "ghp_" + "Q" * 36))
    assertEquals(
      agentDocumentStamp("image", "live", "ruleset", brokered = other.map(_.binding)),
      agentDocumentStamp("image", "live", "ruleset", brokered = credentials.map(_.binding)),
    )
    assertNotEquals(
      agentDocumentStamp("image", "live", "ruleset", brokered = credentials.map(_.binding)),
      agentDocumentStamp("image", "live", "ruleset"),
    )
    assert(brokeredParagraph(credentials.map(_.binding)).contains("`GH_TOKEN` (api.github.com, Authorization)"))
    assertEquals(brokeredParagraph(Vector.empty), "")

  test("a withheld name is gone from what a started process inherits, and from an edited environment's copy"):
    val name = "KO_AGENT_EGRESS_CREDENTIALS_TEST"
    val linker = Linker.nativeLinker()
    val setenv = linker.downcallHandle(
      linker.defaultLookup().find("setenv").orElseThrow(),
      FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
    )
    val arena = Arena.ofConfined()
    try
      val set: Int = setenv.invokeExact(arena.allocateFrom(name), arena.allocateFrom("held"), 1)
      assertEquals(set, 0)
    finally arena.close()
    def inherited(): String = String(ProcessBuilder("/usr/bin/env").start().getInputStream.readAllBytes(), UTF_8)
    assert(inherited().linesIterator.contains(s"$name=held"))
    EgressCredentials.withhold(Vector(name), HostCommands.currentOs)
    assert(!inherited().contains(name))
    val edited = ProcessBuilder("/usr/bin/env")
    edited.environment.put(name, "copied")
    EgressCredentials.scrub(edited)
    assert(!edited.environment.containsKey(name))

  test("a host proxy's audit log is named after the channel log, so --egress-log lists it and pruning keeps it"):
    val channelLog = Path.of("/s/log/p/run-on-host-20261004-120000-abcd1234.log")
    assertEquals(
      RunOnHostSandbox.projectAuditLog(channelLog, Path.of("/tmp/ko-agent-501/rXYZ/proxy-sbt-0123456789ab.log")),
      Some(Path.of("/s/log/p/proxy-20261004-120000-rXYZ-proxy-sbt-0123456789ab-abcd1234.log")),
    )
    assertEquals(
      EgressRules.logsToPrune(
        Vector("proxy-20261004-120000-rXYZ-proxy-sbt-0123456789ab-abcd1234.log"), retain = 0, Set("abcd1234"),
      ),
      Vector.empty,
    )
    assertEquals(RunOnHostSandbox.projectAuditLog(Path.of("/s/log/p/other.log"), Path.of("/t/r/proxy.log")), None)
