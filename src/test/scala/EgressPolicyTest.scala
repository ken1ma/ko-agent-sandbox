// The egress policy a project ships, end to end. A session reads its policy once at startup, so
// each test here launches its own.
//
// Two of these are the refusals no session can demonstrate about itself, because both happen on the
// proxy's *upstream* leg, which inspection moves out of the client's sight: an origin whose
// certificate does not verify, and a name that resolves into private address space. Skipping either
// check is invisible in normal operation — the sandbox sees a valid leaf minted by this project's
// CA whatever the origin presented — which is the classic TLS-interception failure.
//
// Opt-in like the other container-launching suites (IntegrationSession has the gate):
//
//     KO_AGENT_SANDBOX_INTEGRATION=1 sbt "testOnly *EgressPolicyTest"
//
// Hosts outside the built-in policy carry the assertions, and the suite is only as good as their
// reachability from the host running it: `example.com` (a plain addition), `expired.badssl.com` and
// `wrong.host.badssl.com` (origin certificates the proxy must reject, for the two different reasons
// a certificate can be wrong), `127.0.0.1.nip.io` (a public resolver answering with the address
// embedded in the name), and `github.com/octocat/Hello-World.git` (a clone small enough to be a
// fixture).

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import IntegrationSession.*

class EgressPolicyTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(20, "min")

  /** Write this project's policy delta files, as a repository would ship them. */
  private def policy(project: Path, tiers: (String, String)*): Unit =
    val hosts = project.resolve(".ko-agent-sandbox").resolve("egress-hosts")
    Files.createDirectories(hosts)
    tiers.foreach((tier, text) => Files.writeString(hosts.resolve(tier), text))

  private def curl(session: Session, args: String*): Run =
    exec(session, (Vector("curl", "-sS", "--max-time", "25") ++ args)*)

  private def status(session: Session, args: String*): String =
    curl(session, (Vector("-o", "/dev/null", "-w", "%{http_code}") ++ args)*).text.trim

  /** Which CA signed the certificate a host presented, as the sandbox saw it. curl indents its
    * certificate lines under the `*` marker and by more than one space, so this keys on the field
    * name rather than on the shape of the prefix. */
  private def issuer(session: Session, host: String): String =
    curl(session, "-v", "-o", "/dev/null", s"https://$host/").err.linesIterator
      .map(_.trim)
      .collectFirst:
        case line if line.startsWith("*") && line.contains("issuer:") =>
          line.substring(line.indexOf("issuer:") + "issuer:".length).trim
      .getOrElse("(no issuer line)")

  /** A host the policy never admitted, or a name resolving outside public address space: both are
    * refused at the CONNECT, before a tunnel exists, so curl reports the proxy's status as an error
    * rather than as an HTTP code. */
  private def refusedAtConnect(session: Session, url: String, why: String): Unit =
    val attempt = curl(session, "-o", "/dev/null", url)
    assert(!attempt.ok, s"$url was reachable; $why")
    assert(
      attempt.err.contains("403"),
      s"$url failed, but not with a refusal from the proxy: ${attempt.err}"
    )

  /** An admitted host whose *upstream* leg the proxy would not complete. Its CONNECT succeeded and
    * the proxy terminated the client's TLS, so the refusal arrives as a status inside the tunnel
    * and curl exits 0 — which is precisely why an unverified origin would be indistinguishable from
    * a verified one in here, and why the proxy's own audit line is what settles the cause. */
  private def refusedUpstream(session: Session, host: String, markers: Seq[String], why: String): Unit =
    assertEquals(status(session, s"https://$host/"), "502", s"$host: $why")

    val audit = run(podman, "logs", session.proxy)
    val line = (audit.text + "\n" + audit.err).linesIterator.filter(_.contains(host)).mkString("\n")
    assert(
      markers.exists(line.contains),
      s"$host failed upstream, but not over its certificate — the origin may simply be down:\n$line"
    )

  private def withSession(tiers: (String, String)*)(body: Session => Unit): Unit =
    val project = scratchProject()
    var live: Option[Session] = None
    try
      policy(project, tiers*)
      val session = launch(project, project.resolve("session.log"))
      live = Some(session)
      body(session)
    finally
      live.foreach(stop)
      discard(project)

  test("a read-only addition is inspected, verified upstream, and opens nothing else"):
    assume(enabled, requirement)

    withSession(
      "read-only" ->
        """|+example.com
           |+expired.badssl.com
           |+wrong.host.badssl.com
           |+127.0.0.1.nip.io
           |""".stripMargin
    ): session =>
      assertEquals(status(session, "https://example.com/"), "200", "the added host is not reachable")

      // Inspected on the project's own CA, like a built-in read-only host: one leaf, minted at
      // launch from the resolved policy, or the addition would be a tier the proxy does not police.
      assertEquals(
        issuer(session, "example.com"), issuer(session, "pypi.org"),
        "the added host is not inspected by this project's CA"
      )
      assertEquals(status(session, "-X", "POST", "https://example.com/"), "403", "the addition allowed a write")

      // The upstream leg. The sandbox cannot tell a verified origin from an unverified one — both
      // arrive under a leaf it trusts — so the refusal has to come from the proxy or not at all.
      refusedUpstream(
        session, "expired.badssl.com", Seq("PKIX", "validity", "expired"),
        "SECURITY: the proxy accepted an expired origin certificate"
      )
      refusedUpstream(
        session, "wrong.host.badssl.com", Seq("subject alternative", "No name matching", "PKIX"),
        "SECURITY: the proxy accepted an origin certificate issued for another name"
      )

      // Refused before the dial rather than during it: resolution is where the address is vetted.
      refusedAtConnect(
        session, "https://127.0.0.1.nip.io/",
        "SECURITY: a name resolving to loopback was not refused after resolution"
      )

      // The bound: adding four hosts adds four hosts.
      refusedAtConnect(session, "https://www.iana.org/", "a host the policy never named was allowed")

  test("an addition states a host's complete tagging, dropping the built-in tag"):
    assume(enabled, requirement)

    // github.com is `=git-fetch` in the built-in policy: read-only, plus the POST a clone's transfer
    // leg needs. Re-adding it plain is documented to replace that entry outright.
    val clone = Vector(
      "git", "clone", "--depth", "1", "--quiet",
      "https://github.com/octocat/Hello-World.git", "/tmp/hello"
    )

    withSession("read-only" -> "+github.com\n"): session =>
      assertEquals(status(session, "https://github.com/"), "200", "the re-added host lost its read access")
      val attempt = exec(session, clone*)
      assert(!attempt.ok, "SECURITY: the clone succeeded; the built-in git-fetch tag outlived the addition")

    // The control, and the only thing that makes the refusal above evidence: the same clone under
    // the built-in policy, which the project did not touch.
    withSession(): session =>
      assert(exec(session, clone*).ok, "the clone fails under the built-in policy too; this fixture proves nothing")

  test("a .defaults lockdown removes the built-in policy and still signs in"):
    assume(enabled, requirement)

    withSession(
      "blocked" -> ".defaults\n",
      "read-write" -> "+api.anthropic.com\n"
    ): session =>
      // A read-write host is an opaque tunnel: any status means the CONNECT was granted, and the
      // agent endpoint answering at all is what "still signs in" means.
      assert(
        curl(session, "-o", "/dev/null", "https://api.anthropic.com/").ok,
        "the re-added agent endpoint is unreachable under the lockdown"
      )
      // No read-only tier survives, so this session inspects nothing — and the built-ins are gone.
      refusedAtConnect(session, "https://pypi.org/", "a built-in host survived `.defaults`")
      refusedAtConnect(session, "https://github.com/", "a built-in host survived `.defaults`")
