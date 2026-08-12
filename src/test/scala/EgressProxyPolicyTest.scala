// The launcher's side of the egress proxy: policy flattening (what the proxy is handed), the
// launch banner's shape, and audit-log retention.

package agentsandbox.launcher

import EgressProxyPolicy.*

class EgressProxyPolicyTest extends munit.FunSuite:

  test("policy flattening strips comments and normalizes whitespace"):
    val text =
      """# Reads public Python documentation.
        |api.anthropic.com
        |
        |docs.python.org   pypi.org
        |files.pythonhosted.org  # trailing comment
        |""".stripMargin
    assertEquals(
      flattenPolicy(text),
      "api.anthropic.com docs.python.org pypi.org files.pythonhosted.org"
    )

  test("a policy of only comments and blanks flattens to empty"):
    assertEquals(flattenPolicy("# nothing\n\n   \n# more\n"), "")

  test("flattening is idempotent, so a flattened policy re-reads unchanged"):
    val flattened = flattenPolicy("a.example\n\nb.example # x\n")
    assertEquals(flattenPolicy(flattened), flattened)

  test("the launch banner keeps the shape of the policy and drops the host names"):
    // The banner is read every session; a thousand characters of hostnames is a line people learn
    // to skip, and skipping it is how an unexpected policy goes unnoticed.
    assertEquals(
      policyCounts("allowed hosts (75): a.example b.example\ntls inspection (7): github.com"),
      "allowed hosts (75); tls inspection (7)"
    )
    // A line carrying a reason rather than a list is not shortened — there is nothing to drop.
    assertEquals(
      policyCounts(
        "allowed hosts (2): a.example b.example\n" +
          "tls inspection: none; every allowed host is an opaque tunnel"
      ),
      "allowed hosts (2); tls inspection: none; every allowed host is an opaque tunnel"
    )
    // Whatever the proxy says, no hostname survives into the banner.
    assert(!policyCounts("allowed hosts (1): secret.example").contains("secret.example"))

  test("log pruning keeps the newest files and leaves room for the new one"):
    val names = Vector(
      "proxy-20260810-090000-aaaaaaaa.log",
      "proxy-20260812-110000-cccccccc.log",
      "proxy-20260811-100000-bbbbbbbb.log"
    )
    // retain 2: the new file plus the newest existing one survive.
    assertEquals(
      logsToPrune(names, 2),
      Seq("proxy-20260810-090000-aaaaaaaa.log", "proxy-20260811-100000-bbbbbbbb.log")
    )
    // Enough room already: nothing is pruned.
    assertEquals(logsToPrune(names, 4), Seq())
    assertEquals(logsToPrune(Vector(), 20), Seq())
