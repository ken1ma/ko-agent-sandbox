// The launcher's side of the egress proxy: policy normalization (what the proxy is handed), the
// launch banner's format, command classification, and audit-log retention.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import EgressProxyPolicy.*

class EgressProxyPolicyTest extends munit.FunSuite:

  test("policy normalization strips comments and collapses whitespace but keeps lines"):
    val text =
      """# Reads public Python documentation.
        |allow https://docs.python.org/ read
        |
        |deny   https://pypi.org/
        |allow model-provider anthropic  # trailing comment
        |""".stripMargin
    assertEquals(
      normalizePolicyText(text),
      "allow https://docs.python.org/ read\ndeny https://pypi.org/\nallow model-provider anthropic",
    )

  test("a policy of only comments and blanks normalizes to empty"):
    assertEquals(normalizePolicyText("# nothing\n\n   \n# more\n"), "")

  test("normalization is idempotent, so a normalized policy re-reads unchanged"):
    val normalized = normalizePolicyText("allow https://a.example/ read\n\ndeny defaults # x\n")
    assertEquals(normalizePolicyText(normalized), normalized)

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
    val ready = "2026-08-26T11:59:38Z agent-egress-proxy listening on :3128\n"
    assertEquals(transportLineOf(s"2026-08-26T11:59:38Z $line\n$ready"), Some(line))
    assertEquals(transportLineOf(ready), None)

  test("the banner summary joins a file's entries on one line"):
    assertEquals(
      entriesSummary("allow https://a.example/ read\ndeny https://b.example/"),
      "allow https://a.example/ read; deny https://b.example/",
    )

  private def summary(inspected: Int, opaque: Int, denied: Int, widening: Int = 0): String =
    s"policy summary: $inspected inspected hosts; $opaque opaque hosts; $denied denial patterns; " +
      s"$widening widening lines"

  // The profile reads as the policy spells it; case is not emphasis (HostCommands, "Emphasis").
  test("the launch banner names the profile off the profile line and the counts off the summary line, never a host"):
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-allowed\n" +
          "allow https://github.com/ read git-fetch\nallow https://secret.example/ read\n" +
          "allow https://a.example/ tunnel\n" + summary(
            2,
            1,
            0,
            1,
          ) + "\nwidening lines (1): allow https://secret.example/ read",
        color = false,
      ),
      "egress: deny-unless-allowed; 2 inspected, 1 opaque",
    )
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-model; model provider: anthropic\n" +
          "allow https://a/ tunnel\nallow https://b/ tunnel\nallow https://c/ tunnel\n" + summary(0, 3, 0),
        color = false,
      ),
      "egress: deny-unless-model; model provider anthropic; 0 inspected, 3 opaque",
    )
    assertEquals(
      egressBanner("egress profile: deny-unless-model; model provider: none\n" + summary(0, 0, 0), color = false),
      "egress: deny-unless-model; no provider selected; 0 inspected, 0 opaque",
    )
    assertEquals(
      egressBanner(
        "egress profile: allow-unless-denied; default: public HTTPS read\n" +
          "deny https://w/\ndeny https://x/\ndeny https://**.y/\ndeny https://z/\n" +
          "allow https://a/ read\nallow https://b/ read\n" + summary(2, 0, 4),
        color = false,
      ),
      "egress: allow-unless-denied; public HTTPS read; 0 opaque, 4 denied",
    )
    assertEquals(
      egressBanner("egress profile: deny-all\n" + summary(0, 0, 0), color = false),
      "egress: deny-all; 0 inspected, 0 opaque",
    )
    assertEquals(egressBanner("some reason instead", color = false), "egress: some reason instead")
    // Each source alone is insufficient: a resolution without its summary line is printed whole.
    assertEquals(
      egressBanner("egress profile: deny-all\nallow https://secret.example/ read", color = false),
      "egress: egress profile: deny-all",
    )
    assertEquals(egressBanner(summary(1, 0, 0), color = false), "egress: " + summary(1, 0, 0))
    // Whatever the proxy says, no hostname survives into the banner.
    assert(
      !egressBanner(
        "egress profile: deny-all\nallow https://secret.example/ read\n" + summary(1, 0, 0),
        color = false,
      ).contains("secret.example"),
    )

  test("a terminal reads the profile as the mode it is, and never in the severity hue"):
    assertEquals(
      egressBanner("egress profile: deny-unless-allowed\nallow https://a/ read\n" + summary(1, 0, 0), color = true),
      "egress: \u001b[38;5;207mdeny-unless-allowed\u001b[0m; 1 inspected, 0 opaque",
    )
    // The counts are what the profile resolved to, not a mode of their own.
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-model; model provider: anthropic\nallow https://a/ tunnel\n" + summary(0, 1, 0),
        color = true,
      ),
      "egress: \u001b[38;5;207mdeny-unless-model\u001b[0m; model provider anthropic; 0 inspected, 1 opaque",
    )
    // The permissive line is tinted whole by the caller, so nothing inside it ends that colour.
    assertEquals(
      egressBanner(
        "egress profile: allow-unless-denied; default: public HTTPS read\n" + summary(0, 0, 0),
        color = true,
      ),
      "egress: allow-unless-denied; public HTTPS read; 0 opaque, 0 denied",
    )

  test("the permissive profile is the one the banner tints, whatever follows it on the line"):
    assert(
      permissiveProfile(
        "egress profile: allow-unless-denied; default: public HTTPS read\n" + summary(0, 0, 0),
      ),
    )
    assert(!permissiveProfile("egress profile: deny-unless-allowed\n" + summary(0, 0, 0)))
    assert(!permissiveProfile("egress profile: deny-all"))
    assert(!permissiveProfile("some reason instead"))
    assert(!permissiveProfile(""))
    // Only the head line decides; a hostname further down cannot make a strict profile read weak.
    assert(!permissiveProfile("egress profile: deny-all\nallow https://allow-unless-denied.example/ read"))

  test("only the basename of a recognized agent command selects a provider"):
    assertEquals(commandProvider(Some("claude")), Some("anthropic"))
    assertEquals(commandProvider(Some("/usr/local/bin/codex")), Some("openai"))
    assertEquals(commandProvider(Some("C:\\tools\\agy")), Some("google"))
    assertEquals(commandProvider(Some("copilot")), Some("github"))
    assertEquals(commandProvider(Some("bash")), None)
    assertEquals(commandProvider(Some("./run-claude.sh")), None)
    assertEquals(commandProvider(None), None)

  test("the policy directory reads the rule file, normalized"):
    val dir = Files.createTempDirectory("egress")
    Files.writeString(dir.resolve("rule"), "allow https://ghcr.io/ read\ndeny https://**.example.org/ # a comment\n")
    Files.createFile(dir.resolve(".DS_Store"))
    assertEquals(
      readPolicyFiles(dir),
      Right(Vector("rule" -> "allow https://ghcr.io/ read\ndeny https://**.example.org/")),
    )

  test("a missing policy directory is an empty policy"):
    assertEquals(readPolicyFiles(Paths.get("/nonexistent/egress")), Right(Vector.empty))

  test("the policy directory's refused forms each name their reason"):
    val parent = Files.createTempDirectory("policy-shapes")

    val asFile = parent.resolve("egress")
    Files.writeString(asFile, "allow https://ghcr.io/ read\n")
    assert(readPolicyFiles(asFile).swap.exists(_.contains("is a file")))
    Files.delete(asFile)

    val dir = Files.createDirectory(parent.resolve("egress"))
    Files.writeString(dir.resolve("rules"), "allow https://ghcr.io/ read\n")
    assert(readPolicyFiles(dir).swap.exists(_.contains("not a policy file")))
    Files.delete(dir.resolve("rules"))

    // The retired grammar's files are named as such, with the pointer.
    Vector("allowed", "denied").foreach: retired =>
      Files.writeString(dir.resolve(retired), "+host ghcr.io\n")
      val refusal = readPolicyFiles(dir).swap.getOrElse(fail(s"$retired was read"))
      assert(refusal.contains("retired grammar") && refusal.contains("egress/rule"), refusal)
      Files.delete(dir.resolve(retired))

    Files.createDirectory(dir.resolve("rule"))
    assert(readPolicyFiles(dir).swap.exists(_.contains("not a regular file")))
    Files.delete(dir.resolve("rule"))

    Files.createSymbolicLink(dir.resolve("rule"), parent.resolve("elsewhere"))
    assert(readPolicyFiles(dir).swap.exists(_.contains("symlink")))
    Files.delete(dir.resolve("rule"))

    Files.writeString(dir.resolve("rule"), "# only a comment\n")
    assert(readPolicyFiles(dir).swap.exists(_.contains("lists no entries")))

  test("the policy env args pass the authority selection and each file's variable"):
    assertEquals(
      policyEnvArgs(
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
      policyEnvArgs("deny-unless-model", None, Vector.empty),
      Vector("--env=EGRESS_PROFILE=deny-unless-model", "--env=EGRESS_MODEL_PROVIDER=none"),
    )

  test("the inspected hosts are the allow lines' hosts, a tunnel line never among them"):
    assertEquals(
      inspectedHostsOf(
        "egress profile: allow-unless-denied; default: public HTTPS read\n" +
          "deny https://x.example/\n" +
          "allow https://pypi.org/ read\nallow https://github.com/ read git-fetch\n" +
          "allow https://github.com/login/device/code read git-fetch method=POST\n" +
          "allow https://api.anthropic.com/ tunnel\n" + summary(2, 1, 1),
      ),
      Right(Vector("github.com", "pypi.org")),
    )
    assertEquals(inspectedHostsOf("egress profile: deny-all\n" + summary(0, 0, 0)), Right(Vector.empty))
    assert(inspectedHostsOf("another shape entirely").isLeft)
    assert(inspectedHostsOf("allow https://pypi.org/ read").isLeft)

  test("the widening lines are the proxy's own line, and an image printing none reports none"):
    // Which lines widen is the proxy's classification against the defaults it ships
    // (AgentEgressProxyTest has the classes); the launcher only reads the line back.
    assertEquals(
      wideningEntries(
        "egress profile: deny-unless-allowed\nallow https://a/ read\n" + summary(1, 0, 0, 2) + "\n" +
          "widening lines (2): allow https://api.example/ tunnel; allow https://pypi.org/ git-fetch",
      ),
      Vector("allow https://api.example/ tunnel", "allow https://pypi.org/ git-fetch"),
    )
    assertEquals(
      wideningEntries("egress profile: deny-unless-allowed\nallow https://a/ read\n" + summary(1, 0, 0)),
      Vector.empty,
    )
    // The consumers holding the policy alone get the text up to the first metadata line, whatever
    // follows it, and unchanged when nothing does.
    val policy = "egress profile: deny-unless-allowed\nallow https://a/ read"
    assertEquals(
      policyLinesOf(policy + "\n" + summary(1, 0, 0, 1) + "\nwidening lines (1): allow https://a/ tunnel"),
      policy,
    )
    assertEquals(policyLinesOf(policy), policy)
    MetadataPrefixes.foreach(prefix => assertEquals(policyLinesOf(policy + "\n" + prefix + "x"), policy))

  test("normalizing keeps a # inside a token, so the proxy refuses it instead of reading a wider entry"):
    assertEquals(
      normalizePolicyText(
        "# whole line\nallow https://a.example/ read   # trailing\n  allow https://b.example/x/#y/ read\n" +
          "allow https://c.example/#d read",
      ),
      "allow https://a.example/ read\nallow https://b.example/x/#y/ read\nallow https://c.example/#d read",
    )

  test("a host under several scopes names itself once for the leaf; the banner counts hosts, as the summary does"):
    // The proxy prints one line per scope; the leaf names the host, and a host under two scopes
    // is one name.
    val resolution =
      "egress profile: deny-unless-allowed\n" +
        "allow https://api.anthropic.com/ tunnel\n" +
        "allow https://github.com/login/ read method=POST\nallow https://github.com/owner/ read git-fetch\n" +
        "allow https://pypi.org/ read\nallow https://storage.googleapis.com/my-bucket/ read\n" + summary(3, 1, 0)
    assertEquals(inspectedHostsOf(resolution), Right(Vector("github.com", "pypi.org", "storage.googleapis.com")))
    assertEquals(egressBanner(resolution, color = false), "egress: deny-unless-allowed; 3 inspected, 1 opaque")

  test("log pruning keeps the newest files and leaves room for the new one"):
    val names = Vector(
      "proxy-20260810-090000-aaaaaaaa.log",
      "proxy-20260812-110000-cccccccc.log",
      "proxy-20260811-100000-bbbbbbbb.log",
    )
    // retain 2: the new file plus the newest existing one survive.
    assertEquals(
      logsToPrune(names, 2, Set.empty),
      Seq("proxy-20260810-090000-aaaaaaaa.log", "proxy-20260811-100000-bbbbbbbb.log"),
    )
    // Enough room already: nothing is pruned.
    assertEquals(logsToPrune(names, 4, Set.empty), Seq())
    assertEquals(logsToPrune(Vector(), 20, Set.empty), Seq())

    assertEquals(
      logsToPrune(names, 2, Set("aaaaaaaa")),
      Seq("proxy-20260811-100000-bbbbbbbb.log"),
    )
    assertEquals(logsToPrune(names, 1, Set("aaaaaaaa", "bbbbbbbb", "cccccccc")), Seq())

    // The suffix has to be the whole one: a run whose name is another's tail keeps nothing alive.
    assertEquals(
      logsToPrune(names, 2, Set("aaaaaaa")),
      Seq("proxy-20260810-090000-aaaaaaaa.log", "proxy-20260811-100000-bbbbbbbb.log"),
    )
