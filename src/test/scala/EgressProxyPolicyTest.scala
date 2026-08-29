// The launcher's side of the egress proxy: policy normalization (what the proxy is handed), the
// launch banner's shape, command classification, and audit-log retention.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import EgressProxyPolicy.*

class EgressProxyPolicyTest extends munit.FunSuite:

  test("policy normalization strips comments and collapses whitespace but keeps lines"):
    val text =
      """# Reads public Python documentation.
        |+host docs.python.org
        |
        |-host   pypi.org
        |+model-provider anthropic  # trailing comment
        |""".stripMargin
    assertEquals(
      normalizePolicyText(text),
      "+host docs.python.org\n-host pypi.org\n+model-provider anthropic",
    )

  test("a policy of only comments and blanks normalizes to empty"):
    assertEquals(normalizePolicyText("# nothing\n\n   \n# more\n"), "")

  test("normalization is idempotent, so a normalized policy re-reads unchanged"):
    val normalized = normalizePolicyText("+host a.example\n\n-** # x\n")
    assertEquals(normalizePolicyText(normalized), normalized)

  test("the banner summary joins a file's entries on one line"):
    assertEquals(
      entriesSummary("+host a.example\n-host b.example"),
      "+host a.example; -host b.example",
    )

  test("the launch banner names the profile and the counts, never the host names"):
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-allowed\n" +
          "restricted hosts (2): github.com secret.example\n" +
          "unrestricted hosts (3): a.example b.example c.example\n" +
          "denied rules (0):",
      ),
      "egress: DENY-UNLESS-ALLOWED; 5 effective hosts",
    )
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-model; model provider: anthropic\n" +
          "restricted hosts (0):\nunrestricted hosts (3): a b c\ndenied rules (0):",
      ),
      "egress: DENY-UNLESS-MODEL; model provider anthropic; 3 effective hosts",
    )
    assertEquals(
      egressBanner(
        "egress profile: deny-unless-model; model provider: none\n" +
          "restricted hosts (0):\nunrestricted hosts (0):\ndenied rules (0):",
      ),
      "egress: DENY-UNLESS-MODEL; no provider selected; 0 effective hosts",
    )
    assertEquals(
      egressBanner(
        "egress profile: allow-unless-denied; default: public HTTPS unrestricted\n" +
          "restricted hosts (2): a b\ndenied rules (4): w x y z",
      ),
      "egress: ALLOW-UNLESS-DENIED; public HTTPS; 2 restricted, 4 denied",
    )
    assertEquals(
      egressBanner("egress profile: deny-all\nrestricted hosts (0):\nunrestricted hosts (0):\ndenied rules (1): x"),
      "egress: DENY-ALL; 0 effective hosts",
    )
    assertEquals(egressBanner("some reason instead"), "egress: some reason instead")
    // Whatever the proxy says, no hostname survives into the banner.
    assert(
      !egressBanner(
        "egress profile: deny-all\nrestricted hosts (1): secret.example\ndenied rules (0):",
      ).contains("secret.example"),
    )

  test("only the basename of a recognized agent command selects a provider"):
    assertEquals(commandProvider(Some("claude")), Some("anthropic"))
    assertEquals(commandProvider(Some("/usr/local/bin/codex")), Some("openai"))
    assertEquals(commandProvider(Some("C:\\tools\\agy")), Some("google"))
    assertEquals(commandProvider(Some("copilot")), Some("github"))
    assertEquals(commandProvider(Some("bash")), None)
    assertEquals(commandProvider(Some("./run-claude.sh")), None)
    assertEquals(commandProvider(None), None)

  test("the policy directory reads present files, normalized, in file order"):
    val dir = Files.createTempDirectory("egress")
    Files.writeString(dir.resolve("denied"), "host gitlab.com\nhost **.example.org # a comment\n")
    Files.writeString(dir.resolve("allowed"), "+host ghcr.io\n")
    Files.createFile(dir.resolve(".DS_Store"))
    assertEquals(
      readPolicyFiles(dir),
      Right(
        Vector(
          "allowed" -> "+host ghcr.io",
          "denied" -> "host gitlab.com\nhost **.example.org",
        ),
      ),
    )

  test("a missing policy directory is an empty policy"):
    assertEquals(readPolicyFiles(Paths.get("/nonexistent/egress")), Right(Vector.empty))

  test("the policy directory's refused shapes each name their reason"):
    val parent = Files.createTempDirectory("policy-shapes")

    val asFile = parent.resolve("egress")
    Files.writeString(asFile, "+host ghcr.io\n")
    assert(readPolicyFiles(asFile).swap.exists(_.contains("is a file")))
    Files.delete(asFile)

    val dir = Files.createDirectory(parent.resolve("egress"))
    Files.writeString(dir.resolve("alowed"), "+host ghcr.io\n")
    assert(readPolicyFiles(dir).swap.exists(_.contains("not a policy file")))
    Files.delete(dir.resolve("alowed"))

    Files.createDirectory(dir.resolve("allowed"))
    assert(readPolicyFiles(dir).swap.exists(_.contains("not a regular file")))
    Files.delete(dir.resolve("allowed"))

    Files.createSymbolicLink(dir.resolve("denied"), parent.resolve("elsewhere"))
    assert(readPolicyFiles(dir).swap.exists(_.contains("symlink")))
    Files.delete(dir.resolve("denied"))

    Files.writeString(dir.resolve("allowed"), "# only a comment\n")
    assert(readPolicyFiles(dir).swap.exists(_.contains("lists no entries")))

  test("the policy env args carry the authority selection and each file's variable"):
    assertEquals(
      policyEnvArgs(
        "deny-unless-allowed",
        Some("anthropic"),
        Vector("allowed" -> "+host api.example unrestricted", "denied" -> "host x.example"),
      ),
      Vector(
        "--env=EGRESS_PROFILE=deny-unless-allowed",
        "--env=EGRESS_MODEL_PROVIDER=anthropic",
        "--env=EGRESS_ALLOWED=+host api.example unrestricted",
        "--env=EGRESS_DENIED=host x.example",
      ),
    )
    assertEquals(
      policyEnvArgs("deny-unless-model", None, Vector.empty),
      Vector("--env=EGRESS_PROFILE=deny-unless-model", "--env=EGRESS_MODEL_PROVIDER=none"),
    )

  test("the inspected hosts are the restricted line's names; the allowance lines are not read"):
    assertEquals(
      inspectedHostsOf(
        "egress profile: deny-unless-allowed\n" +
          "restricted hosts (2): github.com pypi.org\n" +
          "restricted allow=git-fetch (1): github.com\n" +
          "unrestricted hosts (0):\ndenied rules (0):",
      ),
      Right(Vector("github.com", "pypi.org")),
    )
    assertEquals(
      inspectedHostsOf("egress profile: deny-all\nrestricted hosts (0):\ndenied rules (0):"),
      Right(Vector.empty),
    )
    assert(inspectedHostsOf("another shape entirely").isLeft)

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
