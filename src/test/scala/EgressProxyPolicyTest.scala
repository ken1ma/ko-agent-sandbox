// The launcher's side of the egress proxy: policy flattening (what the proxy is handed), the
// launch banner's shape, and audit-log retention.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

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
      policyCounts(
        "read-write hosts (2): a.example b.example\nread-only hosts (1): github.com=git-fetch"
      ),
      "read-write hosts (2); read-only hosts (1)"
    )
    // A line with no count is not shortened — there is nothing to drop.
    assertEquals(policyCounts("some reason instead"), "some reason instead")
    // Whatever the proxy says, no hostname survives into the banner.
    assert(!policyCounts("read-only hosts (1): secret.example").contains("secret.example"))

  test("the policy directory reads present tier files, flattened, in tier order"):
    val dir = Files.createTempDirectory("egress-hosts")
    Files.writeString(dir.resolve("blocked"), "gitlab.com\n**.example.org # a comment\n")
    Files.writeString(dir.resolve("read-only"), "+ghcr.io\n")
    assertEquals(
      readPolicyFiles(dir),
      Right(Vector("read-only" -> "+ghcr.io", "blocked" -> "gitlab.com **.example.org"))
    )

  test("a missing policy directory is an empty policy"):
    assertEquals(readPolicyFiles(Paths.get("/nonexistent/egress-hosts")), Right(Vector.empty))

  test("the policy directory's refused shapes each name their reason"):
    // Every one of these would otherwise be silently ignored or misread config.
    val parent = Files.createTempDirectory("policy-shapes")

    // egress-hosts itself as a file, not a directory: a policy that must never be skipped unseen.
    val asFile = parent.resolve("egress-hosts")
    Files.writeString(asFile, "+ghcr.io\n")
    assert(readPolicyFiles(asFile).swap.exists(_.contains("is a file")))
    Files.delete(asFile)

    // A typo'd tier name configures nothing.
    val dir = Files.createDirectory(parent.resolve("egress-hosts"))
    Files.writeString(dir.resolve("read-onyl"), "+ghcr.io\n")
    assert(readPolicyFiles(dir).swap.exists(_.contains("not a policy file")))
    Files.delete(dir.resolve("read-onyl"))

    // A tier's own name on something the read would skip — the one stray shape the name check
    // cannot see, and the only one that would leave a tier at its built-in list with nothing said.
    Files.createDirectory(dir.resolve("read-only"))
    assert(readPolicyFiles(dir).swap.exists(_.contains("not a regular file")))
    Files.delete(dir.resolve("read-only"))

    // A symlinked tier file: the read must see the bytes the sandbox's mount will show.
    Files.createSymbolicLink(dir.resolve("blocked"), parent.resolve("elsewhere"))
    assert(readPolicyFiles(dir).swap.exists(_.contains("symlink")))
    Files.delete(dir.resolve("blocked"))

    // Present but empty: more likely a forgotten edit than a deliberate no-op.
    Files.writeString(dir.resolve("read-write"), "# only a comment\n")
    assert(readPolicyFiles(dir).swap.exists(_.contains("lists no entries")))

  test("the policy env args carry each file to its tier variable"):
    // The dry run and the proxy container get these same args, so what was vetted is enforced.
    assertEquals(
      policyEnvArgs(Vector("read-write" -> "+api.example", "blocked" -> ".defaults")),
      Vector("--env=EGRESS_READ_WRITE_HOSTS=+api.example", "--env=EGRESS_BLOCKED_HOSTS=.defaults")
    )

  test("log pruning keeps the newest files and leaves room for the new one"):
    val names = Vector(
      "proxy-20260810-090000-aaaaaaaa.log",
      "proxy-20260812-110000-cccccccc.log",
      "proxy-20260811-100000-bbbbbbbb.log"
    )
    // retain 2: the new file plus the newest existing one survive.
    assertEquals(
      logsToPrune(names, 2, Set.empty),
      Seq("proxy-20260810-090000-aaaaaaaa.log", "proxy-20260811-100000-bbbbbbbb.log")
    )
    // Enough room already: nothing is pruned.
    assertEquals(logsToPrune(names, 4, Set.empty), Seq())
    assertEquals(logsToPrune(Vector(), 20, Set.empty), Seq())

    // A live run keeps its log whatever the count says: its proxy still holds that file open, so
    // pruning it would lose the running session's whole record rather than an old one.
    assertEquals(
      logsToPrune(names, 2, Set("aaaaaaaa")),
      Seq("proxy-20260811-100000-bbbbbbbb.log")
    )
    assertEquals(logsToPrune(names, 1, Set("aaaaaaaa", "bbbbbbbb", "cccccccc")), Seq())

    // The suffix has to be the whole one: a run whose name is another's tail keeps nothing alive.
    assertEquals(
      logsToPrune(names, 2, Set("aaaaaaa")),
      Seq("proxy-20260810-090000-aaaaaaaa.log", "proxy-20260811-100000-bbbbbbbb.log")
    )
