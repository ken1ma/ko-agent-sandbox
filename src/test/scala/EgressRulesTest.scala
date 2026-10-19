// The launcher's side of the egress proxy: rule normalization (what the proxy is handed), the
// launch banner's format, command classification, and audit-log retention.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import EgressRules.*

class EgressRulesTest extends munit.FunSuite:

  test("rule normalization strips comments and collapses whitespace but keeps lines"):
    val text =
      """# Reads public Python documentation.
        |allow https://docs.python.org/ read
        |
        |deny   https://pypi.org/
        |allow model-provider anthropic  # trailing comment
        |""".stripMargin
    assertEquals(
      normalizeRuleText(text),
      "allow https://docs.python.org/ read\ndeny https://pypi.org/\nallow model-provider anthropic",
    )

  test("a rule file of only comments and blanks normalizes to empty"):
    assertEquals(normalizeRuleText("# nothing\n\n   \n# more\n"), "")

  test("normalization is idempotent, so a normalized rule file re-reads unchanged"):
    val normalized = normalizeRuleText("allow https://a.example/ read\n\ndeny defaults # x\n")
    assertEquals(normalizeRuleText(normalized), normalized)

  test("HTTPS_PROXY reaches the proxy container by name alone, uppercase before lowercase"):
    assertEquals(upstreamProxyArgs(Map.empty[String, String].get), Vector.empty)
    assertEquals(upstreamProxyArgs(Map("HTTPS_PROXY" -> "").get), Vector.empty)
    assertEquals(
      upstreamProxyArgs(Map("https_proxy" -> "http://alice:secret@proxy.corp.example:3128").get),
      Vector("--env=https_proxy"),
    )
    assertEquals(
      upstreamProxyArgs(Map("HTTPS_PROXY" -> "http://a.example:1", "https_proxy" -> "http://b.example:1").get),
      Vector("--env=HTTPS_PROXY"),
    )

  test("the transport line is read back from the proxy's stamped log"):
    val line = "egress transport: upstream proxy http://proxy.corp.example:3128 -> 10.1.2.3 (HTTPS_PROXY)"
    val ready = "2026-08-26T11:59:38Z ko-agent-egress-proxy listening on :3128\n"
    assertEquals(transportLineOf(s"2026-08-26T11:59:38Z $line\n$ready"), Some(line))
    assertEquals(transportLineOf(ready), None)

  test("an egress action's rule file line joins the file's lines on one line"):
    assertEquals(
      lineSummary("allow https://a.example/ read\ndeny https://b.example/"),
      "allow https://a.example/ read; deny https://b.example/",
    )

  private def summary(inspected: Int, tunnel: Int, widening: Int = 0): String =
    s"ruleset summary: $inspected inspected hosts; $tunnel tunnel hosts; $widening widening lines"

  // The profile reads as the ruleset spells it; case is not emphasis (HostCommands, "Emphasis").
  test("the launch banner names the profile off the profile line and the counts off the summary line, never a host"):
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-allowed; model provider: anthropic\n" +
          "allow https://github.com/ read git-fetch\nallow https://secret.example/ read\n" +
          "allow https://a.example/ tunnel\n" + summary(2, 1, 1) +
          "\nwidening lines (1): allow https://secret.example/ read",
        color = false,
      ),
      Right("egress: deny-unless-allowed; model provider anthropic; 2 inspected, 1 tunnel"),
    )
    assertEquals(
      egressBanner("egress profile: deny-unless-allowed; model provider: aws,google\n" + summary(9, 2), color = false),
      Right("egress: deny-unless-allowed; model providers aws, google; 9 inspected, 2 tunnel"),
    )
    assertEquals(
      egressBanner("egress profile: deny-unless-allowed; model provider: none\n" + summary(9, 0), color = false),
      Right("egress: deny-unless-allowed; no provider selected; 9 inspected, 0 tunnel"),
    )
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-model; model provider: anthropic\n" +
          "allow https://a/ tunnel\nallow https://b/ tunnel\nallow https://c/ tunnel\n" + summary(0, 3),
        color = false,
      ),
      Right("egress: deny-unless-model; model provider anthropic; 0 inspected, 3 tunnel"),
    )
    assertEquals(
      egressBanner("egress profile: deny-unless-model; model provider: none\n" + summary(0, 0), color = false),
      Right("egress: deny-unless-model; no provider selected; 0 inspected, 0 tunnel"),
    )
    assertEquals(
      egressBanner("egress profile: deny-all\n" + summary(0, 0), color = false),
      Right("egress: deny-all; 0 inspected, 0 tunnel"),
    )
    // The options file's options name it after the part each states.
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-allowed; model provider: anthropic,openai\n" + summary(9, 2),
        profileSource = " (from F)", providerSource = " (from G)", color = false,
      ),
      Right("egress: deny-unless-allowed (from F); model providers anthropic, openai (from G); 9 inspected, 2 tunnel"),
    )
    // Keep the banner concise by showing counts rather than the resolved host list.
    assert(
      !egressBanner(
        "egress profile: deny-all\nallow https://secret.example/ read\n" + summary(1, 0, 0),
        color = false,
      ).exists(_.contains("secret.example")),
    )

  test("a dry run without the profile line, the provider field or both summary counts is refused, not shown"):
    for resolved <- Vector("some reason instead", summary(1, 0)) do
      assert(clue(egressBanner(resolved, color = false)).swap.exists(_.contains("no 'egress profile' line")))
    for resolved <- Vector(
        "egress profile: deny-all\nallow https://secret.example/ read",
        "egress profile: deny-all\nruleset summary: 1 inspected hosts; widening lines",
      )
    do
      val refused = egressBanner(resolved, profileSource = " (from F)", color = false)
      assert(clue(refused).swap.exists(_.contains("no 'ruleset summary:' line with both host counts")))
      assert(!refused.swap.exists(_.contains("secret.example")))
    // Every profile but deny-all states its providers, "none" included.
    for head <- Vector("egress profile: deny-unless-model", "egress profile: deny-unless-allowed; model provider: ")
    do
      val refused = egressBanner(s"$head\n" + summary(0, 0), providerSource = " (from G)", color = false)
      assert(clue(refused).swap.exists(_.contains("names no model provider under the deny-unless")))

  test("the launch banner reads the proxy's summary across profiles and provider selections"):
    import agentsandbox.egress.RulesetHelper.{Profiles, metadataLines, resolveRuleset, rulesetLines}

    val workspaceRules =
      "allow https://artifact.example/releases/ read\nallow https://model.example/ tunnel\n" +
        "deny https://**.blocked.example/"
    for
      profile <- Profiles
      provider <- Vector(None, Some("openai"), Some("anthropic,google"))
      workspaceFile <- Vector(None, Some(workspaceRules))
    do
      val resolved = resolveRuleset(Some(profile), provider, workspaceFile)
      val output = (rulesetLines(resolved) ++ metadataLines(resolved)).mkString("\n")
      val banner = egressBanner(output, color = false).fold(fail(_), identity)
      assert(banner.startsWith(s"egress: $profile; "), banner)
      assert(banner.endsWith(s"${resolved.inspected.size} inspected, ${resolved.tunnelHosts.size} tunnel"), banner)

  test("a terminal reads the profile and the provider selection as chosen, and never in the severity hue"):
    val (on, off) = ("\u001b[38;5;207m", "\u001b[0m")
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-allowed; model provider: none\nallow https://a/ read\n" + summary(1, 0),
        color = true,
      ),
      Right(s"egress: ${on}deny-unless-allowed$off; ${on}no provider$off selected; 1 inspected, 0 tunnel"),
    )
    // The counts are what the profile resolved to, not a mode of their own.
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-model; model provider: anthropic\nallow https://a/ tunnel\n" + summary(0, 1),
        color = true,
      ),
      Right(s"egress: ${on}deny-unless-model$off; model provider ${on}anthropic$off; 0 inspected, 1 tunnel"),
    )
    // Where an option came from is not what was chosen.
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-allowed; model provider: anthropic,openai\n" + summary(9, 2),
        profileSource = " (from F)", providerSource = " (from G)", color = true,
      ),
      Right(
        s"egress: ${on}deny-unless-allowed$off (from F); model providers ${on}anthropic, openai$off (from G); " +
          "9 inspected, 2 tunnel",
      ),
    )

  test("only the basename of a recognized agent command selects a provider"):
    assertEquals(commandProvider(Some("claude")), Some("anthropic"))
    assertEquals(commandProvider(Some("/usr/local/bin/codex")), Some("openai"))
    assertEquals(commandProvider(Some("C:\\programs\\agy")), Some("google"))
    assertEquals(commandProvider(Some("kiro-cli")), Some("aws"))
    assertEquals(commandProvider(Some("copilot")), Some("github"))
    assertEquals(commandProvider(Some("opencode")), None)
    assertEquals(commandProvider(Some("bash")), None)
    assertEquals(commandProvider(Some("./run-claude.sh")), None)
    assertEquals(commandProvider(None), None)

  test("the launch's selection is the option, else the command's provider; opencode needs the option"):
    val profiles = Vector("deny-unless-allowed", "deny-unless-model")
    profiles.foreach: profile =>
      assertEquals(selectedProvider(None, Some("claude"), profile), Right(Some("anthropic")))
      assertEquals(selectedProvider(Some("aws"), Some("claude"), profile), Right(Some("aws")))
      assertEquals(selectedProvider(Some("anthropic,aws"), Some("bash"), profile), Right(Some("anthropic,aws")))
      assertEquals(selectedProvider(Some("aws,github"), Some("/opt/bin/opencode"), profile), Right(Some("aws,github")))
      assertEquals(selectedProvider(None, Some("bash"), profile), Right(None))
      assertEquals(selectedProvider(None, None, profile), Right(None))
      val refused = selectedProvider(None, Some("/opt/bin/opencode"), profile)
      assert(refused.swap.exists(_.startsWith("error: opencode has no fixed model provider")), refused.toString)
      assert(refused.swap.exists(_.contains("--model-provider=<names>")), refused.toString)
    // deny-all admits nothing, so the option is refused there and opencode needs none.
    assertEquals(selectedProvider(None, Some("opencode"), "deny-all"), Right(None))
    assertEquals(selectedProvider(None, Some("claude"), "deny-all"), Right(Some("anthropic")))
    assert(selectedProvider(Some("aws"), Some("claude"), "deny-all").swap.exists(_.contains("deny-all")))
    // The warning names the command and the profile's effect, under the two profiles that admit providers.
    assertEquals(noProviderLine(Some("bash"), "deny-all"), None)
    assert(
      noProviderLine(None, "deny-unless-model").exists(_.startsWith("no command is given and no --model-provider")),
    )
    assertEquals(
      noProviderLine(Some("bash"), "deny-unless-model"),
      Some(
        "'bash' is not a recognized agent command and no --model-provider is given, " +
          "so deny-unless-model selects no model provider and allows no host",
      ),
    )
    assert(noProviderLine(Some("./run.sh"), "deny-unless-allowed").exists(_.endsWith("rule file applies after it")))

  test("the egress directory reads the rule file, normalized"):
    val dir = Files.createTempDirectory("egress")
    Files.writeString(dir.resolve("rule"), "allow https://ghcr.io/ read\ndeny https://**.example.org/ # a comment\n")
    Files.createFile(dir.resolve(".DS_Store"))
    assertEquals(
      readRuleFiles(dir),
      Right(Vector("rule" -> "allow https://ghcr.io/ read\ndeny https://**.example.org/")),
    )

  test("a missing egress directory reads as no rule file"):
    assertEquals(readRuleFiles(Paths.get("/nonexistent/egress")), Right(Vector.empty))

  test("the egress directory's refused forms each name their reason; a file with no rule line is absent"):
    val parent = Files.createTempDirectory("rule-forms")

    val asFile = parent.resolve("egress")
    Files.writeString(asFile, "allow https://ghcr.io/ read\n")
    assert(readRuleFiles(asFile).swap.exists(_.contains("is a file")))
    Files.delete(asFile)

    val dir = Files.createDirectory(parent.resolve("egress"))
    Files.writeString(dir.resolve("rules"), "allow https://ghcr.io/ read\n")
    assert(readRuleFiles(dir).swap.exists(_.contains("not a rule file")))
    Files.delete(dir.resolve("rules"))

    // The repository chose the stray's name, so what a terminal acts on is spelled out.
    Files.writeString(dir.resolve("rule\u202e"), "allow https://ghcr.io/ read\n")
    val bidi = readRuleFiles(dir)
    assert(bidi.swap.exists(reason => reason.contains("rule\\u202e") && !reason.contains("\u202e")), bidi.toString)
    Files.delete(dir.resolve("rule\u202e"))

    Files.createDirectory(dir.resolve("rule"))
    assert(readRuleFiles(dir).swap.exists(_.contains("not a regular file")))
    Files.delete(dir.resolve("rule"))

    Files.createSymbolicLink(dir.resolve("rule"), parent.resolve("elsewhere"))
    assert(readRuleFiles(dir).swap.exists(_.contains("symlink")))
    Files.delete(dir.resolve("rule"))

    // Bytes that are not UTF-8 are refused by name, not thrown.
    Files.write(dir.resolve("rule"), Array[Byte](0xff.toByte))
    assert(readRuleFiles(dir).swap.exists(reason => reason.contains("rule") && reason.contains("not UTF-8")))

    // A file with no rule line reads as absent: no EGRESS_RULE, no rule line printed.
    Files.writeString(dir.resolve("rule"), "# only a comment\n")
    assertEquals(readRuleFiles(dir), Right(Vector.empty))
    Files.writeString(dir.resolve("rule"), "")
    assertEquals(readRuleFiles(dir), Right(Vector.empty))

  test("a dry run's refusal names the option when the proxy refused its variable, else the workspace's rules"):
    val refused = rulesetRefusal("EGRESS_MODEL_PROVIDER is 'meta'; ...")
    assert(refused.startsWith("error: --model-provider is not valid\n"), refused)
    val rules = rulesetRefusal("rule: allow https://x/ frob has the word ...")
    assert(rules.startsWith("error: this workspace's egress rules"), rules)

  test("the ruleset env args pass the selected profile, provider and each file's variable"):
    assertEquals(
      rulesetEnvArgs(
        "deny-unless-allowed",
        Some("anthropic"),
        Vector("rule" -> "allow https://api.example/ tunnel\ndeny https://x.example/"),
      ),
      Vector(
        "--env=EGRESS_PROFILE=deny-unless-allowed",
        "--env=EGRESS_MODEL_PROVIDER=anthropic",
        "--env=EGRESS_RULE=allow https://api.example/ tunnel\ndeny https://x.example/",
      ),
    )
    assertEquals(
      rulesetEnvArgs("deny-unless-model", None, Vector.empty),
      Vector("--env=EGRESS_PROFILE=deny-unless-model", "--env=EGRESS_MODEL_PROVIDER="),
    )

  test("the inspected hosts are the allow lines' hosts, a tunnel line never among them"):
    assertEquals(
      inspectedHostsOf(
        "egress profile: deny-unless-allowed\n" +
          "allow https://pypi.org/ read\nallow https://github.com/ read git-fetch\n" +
          "allow https://github.com/login/device/code read git-fetch method=POST\n" +
          "allow https://api.anthropic.com/ tunnel\n" + summary(2, 1),
      ),
      Right(Vector("github.com", "pypi.org")),
    )
    assertEquals(inspectedHostsOf("egress profile: deny-all\n" + summary(0, 0)), Right(Vector.empty))
    assert(inspectedHostsOf("another form entirely").isLeft)
    assert(inspectedHostsOf("allow https://pypi.org/ read").isLeft)

  test("the widening lines are the proxy's own line, and an image printing none reports none"):
    // Which lines widen is the proxy's classification against the defaults it ships
    // (AgentEgressProxyTest has the classes); the launcher only reads the line back.
    assertEquals(
      wideningLines(
        "egress profile: deny-unless-allowed\nallow https://a/ read\n" + summary(1, 0, 2) + "\n" +
          "widening lines (2): allow https://api.example/ tunnel; allow https://pypi.org/ git-fetch",
      ),
      Vector("allow https://api.example/ tunnel", "allow https://pypi.org/ git-fetch"),
    )
    assertEquals(
      wideningLines("egress profile: deny-unless-allowed\nallow https://a/ read\n" + summary(1, 0, 0)),
      Vector.empty,
    )
    // The consumers holding the ruleset alone get the text up to the first metadata line, whatever
    // follows it, and unchanged when nothing does.
    val ruleset = "egress profile: deny-unless-allowed\nallow https://a/ read"
    assertEquals(
      rulesetLinesOf(ruleset + "\n" + summary(1, 0, 1) + "\nwidening lines (1): allow https://a/ tunnel"),
      ruleset,
    )
    assertEquals(rulesetLinesOf(ruleset), ruleset)
    MetadataPrefixes.foreach(prefix => assertEquals(rulesetLinesOf(ruleset + "\n" + prefix + "x"), ruleset))

  test("whole-host rules sharing their grant words join into one line at the first one's place"):
    assertEquals(
      groupedByHost(Vector(
        "allow https://a.example/ read",
        "deny defaults",
        "allow https://b.example/ tunnel",
        "allow https://c.example/ read",
        "allow https://d.example/x/ read",
        "allow https://e.example/ tunnel",
        "allow https://a.example/ read",
        "allow https://f.example/ read method=POST",
      )),
      Vector(
        "allow read: a.example, c.example",
        "deny defaults",
        "allow tunnel: b.example, e.example",
        "allow https://d.example/x/ read",
        "allow https://f.example/ read method=POST",
      ),
    )
    // A host alone with its words, even when its line repeats, stays a rule line.
    assertEquals(
      groupedByHost(Vector("allow https://a.example/ read", "allow https://a.example/ read")),
      Vector("allow https://a.example/ read"),
    )

  test("a launch prints each line of the rule file once, those that widen under a counted heading"):
    def launched(file: String, widening: String*): Vector[String] =
      val line = if widening.isEmpty then "" else s"\nwidening lines (${widening.size}): ${widening.mkString("; ")}"
      launchLines(
        Vector("rule" -> file),
        "egress profile: deny-unless-allowed\n" + summary(1, 0, widening.size) + line,
        color = false,
      )
    val source = ".ko-agent-sandbox/egress/rule"
    assertEquals(
      launched(
        "allow https://a.example/ read\nallow https://b.example/ read",
        "allow https://a.example/ read",
        "allow https://b.example/ read",
      ),
      Vector(s"$source: 2 widening lines", "  allow read: a.example, b.example"),
    )
    assertEquals(
      launched("deny https://gitlab.com/\nallow https://a.example/ read", "allow https://a.example/ read"),
      Vector(
        s"$source: 1 widening line",
        "  allow https://a.example/ read",
        s"$source, other lines: deny https://gitlab.com/",
      ),
    )
    assertEquals(
      launched("deny https://gitlab.com/\nallow https://github.com/ read"),
      Vector(s"$source: deny https://gitlab.com/; allow https://github.com/ read"),
    )
    assertEquals(launchLines(Vector.empty, "egress profile: deny-all\n" + summary(0, 0), color = false), Vector.empty)

  test("normalizing keeps a # inside a token, so the proxy refuses it instead of reading a wider line"):
    assertEquals(
      normalizeRuleText(
        "# whole line\nallow https://a.example/ read   # trailing\n  allow https://b.example/x/#y/ read\n" +
          "allow https://c.example/#d read",
      ),
      "allow https://a.example/ read\nallow https://b.example/x/#y/ read\nallow https://c.example/#d read",
    )

  test("a host under several scopes names itself once for the leaf; the banner counts hosts, as the summary does"):
    // The proxy prints one line per scope; the leaf names the host, and a host under two scopes
    // is one name.
    val resolution =
      "egress profile: deny-unless-allowed; model provider: anthropic\n" +
        "allow https://api.anthropic.com/ tunnel\n" +
        "allow https://github.com/login/ read method=POST\nallow https://github.com/owner/ read git-fetch\n" +
        "allow https://pypi.org/ read\nallow https://storage.googleapis.com/my-bucket/ read\n" + summary(3, 1, 0)
    assertEquals(inspectedHostsOf(resolution), Right(Vector("github.com", "pypi.org", "storage.googleapis.com")))
    assertEquals(
      egressBanner(resolution, color = false),
      Right("egress: deny-unless-allowed; model provider anthropic; 3 inspected, 1 tunnel"),
    )

  test("log pruning keeps the newest run directories and leaves room for the new one"):
    val names = Vector(
      "run-20260810T090000Z-aaaaaaaa",
      "run-20260812T110000Z-cccccccc",
      "run-20260811T100000Z-bbbbbbbb",
    )
    // retain 2: the new directory plus the newest existing one survive.
    assertEquals(
      runLogDirsToPrune(names, 2, Set.empty),
      Seq("run-20260810T090000Z-aaaaaaaa", "run-20260811T100000Z-bbbbbbbb"),
    )
    // Enough room already: nothing is pruned.
    assertEquals(runLogDirsToPrune(names, 4, Set.empty), Seq())
    assertEquals(runLogDirsToPrune(Vector(), 20, Set.empty), Seq())

    assertEquals(
      runLogDirsToPrune(names, 2, Set("aaaaaaaa")),
      Seq("run-20260811T100000Z-bbbbbbbb"),
    )
    assertEquals(runLogDirsToPrune(names, 1, Set("aaaaaaaa", "bbbbbbbb", "cccccccc")), Seq())

    // The suffix has to be the whole one: a run whose name is another's tail keeps nothing alive.
    assertEquals(
      runLogDirsToPrune(names, 2, Set("aaaaaaa")),
      Seq("run-20260810T090000Z-aaaaaaaa", "run-20260811T100000Z-bbbbbbbb"),
    )

    // A name outside the run directories' pattern is not a run's, however old it sorts.
    val strays = Vector("run-20260810-090000-aaaaaaaa", "run-20260810T090000Z-AAAAAAAA", "notes.txt", "proxy.log")
    assertEquals(runLogDirsToPrune(strays ++ names, 2, Set.empty), runLogDirsToPrune(names, 2, Set.empty))

    // The flat files of the layout before run directories go whatever the count, unless their run is live.
    val flat = Vector(
      "proxy-20260812-110000-dddddddd.log",
      "proxy-20260812-110000-r123-proxy-sbt-0a-dddddddd.log",
      "run-on-host-20260812-110000-dddddddd.log",
      "microphone-20260812-110000-eeeeeeee.log",
    )
    assertEquals(runLogDirsToPrune(flat, 20, Set.empty), flat)
    assertEquals(runLogDirsToPrune(flat, 20, Set("dddddddd")), Seq("microphone-20260812-110000-eeeeeeee.log"))

  test("--egress-log lists each run's proxy logs, oldest run first and the container proxy's first within a run"):
    val logDir = Files.createTempDirectory("egress-log")
    try
      def run(name: String, files: String*) =
        val directory = Files.createDirectory(logDir.resolve(name))
        files.foreach(file => Files.writeString(directory.resolve(file), file))
      run("run-20261005T080000Z-bbbbbbbb", "proxy.log", "proxy-r2.log", "run-on-host.log", "microphone.log")
      run("run-20261004T120000Z-aaaaaaaa", "proxy-sbt-0a-r1.log", "proxy.log", "proxy-r1-2.log", "proxy-r1.log")
      // Not a run's: an old layout's flat file and a directory outside the pattern.
      Files.writeString(logDir.resolve("proxy-20261003-120000-cccccccc.log"), "old")
      run("run-elsewhere", "proxy.log")
      assertEquals(
        retainedProxyLogs(logDir).map(file => logDir.relativize(file).toString),
        Vector(
          "run-20261004T120000Z-aaaaaaaa/proxy.log",
          "run-20261004T120000Z-aaaaaaaa/proxy-r1-2.log",
          "run-20261004T120000Z-aaaaaaaa/proxy-r1.log",
          "run-20261004T120000Z-aaaaaaaa/proxy-sbt-0a-r1.log",
          "run-20261005T080000Z-bbbbbbbb/proxy.log",
          "run-20261005T080000Z-bbbbbbbb/proxy-r2.log",
        ),
      )
    finally FileHelper.deleteRecursively(logDir)
