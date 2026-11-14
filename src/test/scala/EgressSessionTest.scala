// Tests the egress rules that a workspace ships, end to end. A session reads its rules once at startup,
// so each test here launches its own session.
//
// Two tests cover refusals that no session can demonstrate about itself. Both refusals happen on the
// proxy's *origin* leg, which inspection moves out of the client's sight:
//
// - an origin whose certificate does not verify;
// - a name that resolves into private address space.
//
// Skipping either check is invisible in normal operation, because the sandbox sees a valid leaf issued
// by this workspace's CA whatever the origin presented. This invisibility is the classic
// TLS-interception failure.
//
// The suite runs only under testWithPodman, like the other container-launching suites (WithPodman has the
// condition):
//
//     sbt "testWithPodman *EgressSessionTest"
//
// The assertions use public hosts, so the suite is only as good as their reachability from the host that
// runs it:
//
// - `example.com`, a plain addition;
// - `expired.badssl.com` and `wrong.host.badssl.com`, origin certificates that the proxy must reject, for
//   the two different reasons a certificate can be wrong;
// - `127.0.0.1.nip.io`, a public resolver that answers with the address embedded in the name;
// - `github.com/octocat/Hello-World.git`, a clone small enough to be a fixture.
//
// One test takes its fixture from the environment instead, and skips when the variable is unset:
// SIGNED_PUT_URL, a presigned upload URL that only a bucket owner can sign. That test's header has the
// signing one-liner.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import WithPodman.*

class EgressSessionTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(20, "min")

  /** Writes this workspace's rule file, as a repository would ship it. */
  private def ruleFile(workspace: Path, rule: Option[String]): Unit =
    val egress = workspace.resolve(".ko-agent-sandbox").resolve("egress")
    Files.createDirectories(egress)
    rule.foreach(text => Files.writeString(egress.resolve("rule"), text))

  private def curl(session: Session, args: String*): Run =
    exec(session, (Vector("curl", "-sS", "--max-time", "25") ++ args)*)

  private def status(session: Session, args: String*): String =
    curl(session, (Vector("-o", "/dev/null", "-w", "%{http_code}") ++ args)*).text.trim

  /** The CA that signed the certificate a host presented, as the sandbox saw it. curl indents its
    * certificate lines under the `*` marker and by more than one space, so this method keys on the
    * field name rather than on the format of the prefix. */
  private def issuer(session: Session, host: String): String =
    curl(session, "-v", "-o", "/dev/null", s"https://$host/").err.linesIterator
      .map(_.trim)
      .collectFirst:
        case line if line.startsWith("*") && line.contains("issuer:") =>
          line.substring(line.indexOf("issuer:") + "issuer:".length).trim
      .getOrElse("(no issuer line)")

  /** Asserts that a host the ruleset never allowed, or a name that resolves outside public address
    * space, is refused at the CONNECT. The refusal comes before a tunnel exists, so curl reports the
    * proxy's status as an error rather than as an HTTP code. */
  private def refusedAtConnect(session: Session, url: String, why: String): Unit =
    val attempt = curl(session, "-o", "/dev/null", url)
    assert(!attempt.ok, s"$url was reachable; $why")
    assert(
      attempt.err.contains("403"),
      s"$url failed, but not with a refusal from the proxy: ${attempt.err}",
    )

  /** Asserts that the proxy does not complete an allowed host's *origin* leg. The host's CONNECT
    * succeeded and the proxy terminated the client's TLS, so the refusal arrives as a status inside
    * the tunnel and curl exits 0. For the same reason, an unverified origin would look like a
    * verified one in here, so the proxy's own audit line settles the cause.
    *
    * badssl.com's server failed 7 of 27 tunnelled handshakes before presenting its certificate
    * (2026-11-14): it closed after the ClientHello, or the connect timed out. Such an attempt
    * proves nothing either way, so the check repeats until the log names a certificate verdict
    * (EgressSessionTest.certificateVerdict). Any attempt that the proxy completes fails at once. */
  private def refusedAtOrigin(session: Session, host: String, markers: Seq[String], why: String): Unit =
    def log: Vector[String] =
      val audit = run(podman, "logs", session.proxy)
      (audit.text + "\n" + audit.err).linesIterator.toVector
    val verdict = Iterator.range(0, OriginAttempts).exists: _ =>
      assertEquals(status(session, s"https://$host/"), "502", s"$host: $why")
      EgressSessionTest.certificateVerdict(log, host, markers)
    assert(
      verdict,
      s"$host never presented its certificate in $OriginAttempts attempts — the origin may be down:\n" +
        log.filter(_.contains(host)).mkString("\n"),
    )

  private val OriginAttempts = 6

  private def withSession(rule: Option[String])(body: Session => Unit): Unit =
    val workspace = scratchWorkspace()
    var live: Option[Session] = None
    try
      ruleFile(workspace, rule)
      val session = launch(workspace, workspace.resolve("session.log"))
      live = Some(session)
      body(session)
    finally
      live.foreach(stop)
      discard(workspace)

  test("a read line is inspected, verified at the origin, and opens nothing else"):
    requireTestWithPodman()

    withSession(
      Some(
        """|allow https://example.com/ read
           |allow https://expired.badssl.com/ read
           |allow https://wrong.host.badssl.com/ read
           |allow https://127.0.0.1.nip.io/ read
           |""".stripMargin,
      ),
    ): session =>
      assertEquals(status(session, "https://example.com/"), "200", "the added host is not reachable")

      // The proxy inspects the added host on the workspace's own CA, like a catalog host: one leaf,
      // issued at launch from the ruleset. Otherwise the addition would get a treatment that the
      // proxy does not police.
      assertEquals(
        issuer(session, "example.com"), issuer(session, "pypi.org"),
        "the added host is not inspected by this workspace's CA",
      )
      assertEquals(status(session, "-X", "POST", "https://example.com/"), "403", "the addition allowed a write")

      // The origin leg. The sandbox cannot tell a verified origin from an unverified one, because
      // both arrive under a leaf that the sandbox trusts. The refusal has to come from the proxy or
      // not at all.
      refusedAtOrigin(
        session, "expired.badssl.com", Seq("PKIX", "validity", "expired"),
        "SECURITY: the proxy accepted an expired origin certificate",
      )
      refusedAtOrigin(
        session, "wrong.host.badssl.com", Seq("subject alternative", "No name matching", "PKIX"),
        "SECURITY: the proxy accepted an origin certificate issued for another name",
      )

      // The proxy refuses the name before the dial rather than during it, because the proxy vets the
      // address at resolution.
      refusedAtConnect(
        session, "https://127.0.0.1.nip.io/",
        "SECURITY: a name resolving to loopback was not refused after resolution",
      )

      // The bound: allowing four hosts allows four hosts. The sentinel is a reserved name (RFC 6761),
      // so no growth of the defaults can ever turn the sentinel into an allowed host.
      refusedAtConnect(session, "https://unlisted.invalid/", "a host the ruleset never named was allowed")

  test("a deny of one grant takes that grant alone: the forge stays readable and stops being clonable"):
    requireTestWithPodman()

    // github.com is `read git-fetch` in the defaults: inspected reads, plus the clone's two
    // requests. One deny line takes the clone back host-wide and leaves the reads.
    val clone = Vector(
      "git", "clone", "--depth", "1", "--quiet",
      "https://github.com/octocat/Hello-World.git", "/tmp/hello",
    )

    withSession(Some("deny https://github.com/ git-fetch\n")): session =>
      assertEquals(status(session, "https://github.com/"), "200", "the deny of git-fetch took the reads too")
      val attempt = exec(session, clone*)
      assert(!attempt.ok, "SECURITY: the clone succeeded; the defaults' git-fetch outlived the deny")
      // The proxy refuses the clone at its first request, and the log records the refusal with the
      // line that refused it.
      val audit = run(podman, "logs", session.proxy)
      assert(
        (audit.text + "\n" + audit.err).linesIterator.exists: line =>
          line.contains(" deny github.com GET /octocat/Hello-World.git/info/refs") &&
            line.endsWith("git fetch ref discovery"),
        "no deny line records the refused clone at ref discovery",
      )

    // This control makes the refusal above evidence: the same clone succeeds under the defaults,
    // which the workspace did not touch.
    withSession(None): session =>
      assert(exec(session, clone*).ok, "the clone fails under the defaults too; this fixture proves nothing")

  test("a host-wide deny with a narrower allow beneath it allows one owner and refuses the rest, clone included"):
    requireTestWithPodman()

    // The rules deny the forge whole, re-grant one owner for the clone, and re-grant the device
    // login's path for its POST; the raw-content host gets the same form. The proxy refuses the
    // requests outside these lines inside the tunnel, so curl reports the proxy's own status, and
    // a clone of another owner fails at ref discovery.
    withSession(
      Some(
        """|deny https://github.com/
           |allow https://github.com/octocat/ read git-fetch
           |allow https://github.com/login/device/code method=POST
           |deny https://raw.githubusercontent.com/
           |allow https://raw.githubusercontent.com/octocat/ read
           |""".stripMargin,
      ),
    ): session =>
      val readme = "https://raw.githubusercontent.com/octocat/Hello-World/master/README"
      assertEquals(status(session, readme), "200", "the read under the prefix is refused")
      assertEquals(
        status(session, "https://raw.githubusercontent.com/github/docs/main/README.md"), "403",
        "SECURITY: a read outside the prefix was allowed",
      )
      assertEquals(
        status(session, "https://raw.githubusercontent.com/octocat/../github/docs/main/README.md"), "403",
        "SECURITY: a dot segment under the prefix was allowed",
      )
      assertEquals(
        status(session, "https://raw.githubusercontent.com/octocat/%2e%2e/github/docs/main/README.md"), "403",
        "SECURITY: a percent-encoded dot segment under the prefix was allowed",
      )
      // The device flow's first POST goes to its own path. GitHub answers with a client-id error,
      // which is the origin speaking; the proxy's refusal would be a 403 with the proxy's own body.
      val login = curl(
        session, "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", "-d", "client_id=x",
        "https://github.com/login/device/code",
      ).text.trim
      assertNotEquals(login, "403", "the login POST at its path is refused")

      def clone(repo: String): Run =
        val target = s"/tmp/${repo.replace('/', '-')}"
        exec(session, "git", "clone", "--depth", "1", "--quiet", s"https://github.com/$repo.git", target)
      assert(clone("octocat/Hello-World").ok, "the clone under the owner's line fails")
      assert(!clone("github/docs").ok, "SECURITY: a clone outside the owner's line succeeded")

      // The boundary refuses the clone at the clone's first request, and the log records the refusal.
      val audit = run(podman, "logs", session.proxy)
      assert(
        (audit.text + "\n" + audit.err).linesIterator.exists: line =>
          line.contains(" deny github.com GET /github/docs.git/info/refs") && line.endsWith("path under no line"),
        "no deny line records the refused clone at ref discovery",
      )

  test("an owner-signed upload URL is refused inside the inspected tunnel"):
    // The inspected treatment exists for this refusal (SECURITY.md, "Reading without being able to write").
    // The rule does not depend on the host, so any bucket that its owner signs for can serve as the fixture.
    // For an S3 bucket, run:
    //
    //     SIGNED_PUT_URL="$(uv run --with 'boto3[crt]' python3 -c 'import boto3, botocore.config
    //     print(boto3.client("s3", config=botocore.config.Config(signature_version="s3v4"))
    //         .generate_presigned_url("put_object",
    //         Params={"Bucket": "YOUR-BUCKET", "Key": "ko-agent-sandbox-probe"}, ExpiresIn=1800))')" \
    //         sbt --server "testWithPodman *EgressSessionTest"
    //
    // - `boto3[crt]`: the credential provider behind `aws login` needs the CRT extra.
    // - s3v4: boto3 still generates deprecated SigV2 URLs in older regions.
    // - `--server`: a resident sbt server would keep the environment it started with, and would skip this
    //   test as if the variable were never set.
    //
    // The URL's query string is a capability, and this run's owner-only audit log records the URL whole.
    // The URL expires on its own, and the probe object is the owner's to delete.
    requireTestWithPodman()
    val signed = env("SIGNED_PUT_URL")
    assume(signed.isDefined, "set SIGNED_PUT_URL to a presigned PUT URL (test header)")
    val url = signed.get
    val bucketHost = java.net.URI(url).getHost

    // The control runs from the unconfined host and shows that the URL genuinely accepts the write.
    // Without the control, the refusal below could be the origin's own answer to a stale or malformed
    // URL. The test keeps the response body, because the body is the diagnosis when the control fails:
    // S3 names AccessDenied, ExpiredToken or SignatureDoesNotMatch there, and nowhere else.
    // The emptied Content-Type removes the header that curl invents for a body. A SigV2-signed URL
    // (boto3's default in older regions) covers Content-Type, and the invented header breaks the URL's
    // signature; SigV4 does not care either way.
    val control = run(
      "curl", "-sS", "--max-time", "25", "-w", "\n%{http_code}",
      "-H", "Content-Type:", "-X", "PUT", "--data-binary", "signed-and-accepted", url,
    )
    val controlLines = control.text.linesIterator.toVector
    assertEquals(
      controlLines.lastOption.getOrElse("").trim, "200",
      s"the signed URL does not accept a PUT from the host: " +
        s"${controlLines.dropRight(1).mkString(" ")} ${control.err}",
    )

    withSession(Some(s"allow https://$bucketHost/ read\n")): session =>
      val attempt = curl(session, "-X", "PUT", "--data-binary", "from-the-sandbox", url)
      assert(
        attempt.text.contains("PUT not granted"),
        s"SECURITY: the signed PUT was not refused by the proxy: ${attempt.text} ${attempt.err}",
      )
      val audit = run(podman, "logs", session.proxy)
      assert(
        (audit.text + "\n" + audit.err).linesIterator
          .exists(line => line.contains(s" deny $bucketHost PUT ")),
        "no deny line records the refused PUT",
      )

  test("a deny defaults lockdown removes the defaults and still signs in"):
    requireTestWithPodman()

    withSession(Some("deny defaults\nallow model-provider anthropic\n")): session =>
      // Any status means that the provider answered, which is what "still signs in" means. Both hosts are inspected,
      // so curl trusted the leaf of each.
      Vector("https://platform.claude.com/", "https://api.anthropic.com/").foreach: url =>
        assert(curl(session, "-o", "/dev/null", url).ok, s"$url is unreachable under the lockdown")
      // The catalog's hosts are gone.
      refusedAtConnect(session, "https://pypi.org/", "a defaults host survived `deny defaults`")
      refusedAtConnect(session, "https://github.com/", "a defaults host survived `deny defaults`")

  test("the defaults inspect Claude Code's, Codex's and Copilot's model hosts; only deny defaults returns a tunnel"):
    requireTestWithPodman()

    // A refused CONNECT or a failed handshake prints no issuer, and "(no issuer line)" differs from any CA.
    def reachedIssuer(session: Session, host: String): String =
      val probe = curl(session, "-o", "/dev/null", s"https://$host/")
      assert(probe.ok, s"$host was not reached: ${probe.err}")
      val origin = issuer(session, host)
      assertNotEquals(origin, "(no issuer line)", s"curl printed no issuer for $host")
      origin
    def caSubject(session: Session): String =
      exec(session, "openssl", "x509", "-noout", "-subject", "-in", "/etc/ko-agent-sandbox/egress-proxy-ca.crt")
        .text.stripPrefix("subject=").trim
    def launched(rule: Option[String])(body: Session => Unit): Unit =
      val workspace = scratchWorkspace()
      var live: Option[Session] = None
      try
        ruleFile(workspace, rule)
        val options = Vector("--egress=deny-unless-allowed", "--model-provider=anthropic,openai,github")
        val session = launchWith(workspace, workspace.resolve("session.log"), options)
        live = Some(session)
        body(session)
      finally
        live.foreach(stop)
        discard(workspace)

    // The leaf names the host through the launcher's reading of the ruleset (EgressRules.inspectedHostsOf).
    launched(None): session =>
      val hosts = Vector("api.anthropic.com", "platform.claude.com", "chatgpt.com", "api.openai.com", "auth.openai.com")
        ++ Vector("api", "api.individual", "api.business", "api.enterprise").map(name => s"$name.githubcopilot.com")
      hosts.foreach: host =>
        assertEquals(reachedIssuer(session, host), caSubject(session), s"$host is not inspected")
      assert(Files.readString(session.log).contains(", 0 tunnel"), Files.readString(session.log))

    // The way back to the tunnel: deny defaults, then the whole ruleset (egress-proxy.md, "The rule file").
    launched(
      Some(
        "deny defaults\nallow model-provider anthropic\ndeny https://api.anthropic.com/\n" +
          "allow https://api.anthropic.com/ tunnel\n",
      ),
    ): session =>
      assertNotEquals(
        reachedIssuer(session, "api.anthropic.com"), caSubject(session), "api.anthropic.com is still inspected",
      )
      // platform.claude.com stays inspected.
      assert(Files.readString(session.log).contains("1 inspected, 1 tunnel"), Files.readString(session.log))

  test("--model-provider selects the providers a session reaches, over the catalog"):
    requireTestWithPodman()

    // The suite's command, `sleep`, selects no provider, so the option alone names one. The launcher
    // passes the option's value to the image as written, and the image resolves the value.
    val workspace = scratchWorkspace()
    var live: Option[Session] = None
    try
      val session = launchWith(workspace, workspace.resolve("session.log"), Vector("--model-provider=openai"))
      live = Some(session)
      assert(
        curl(session, "-o", "/dev/null", "https://api.openai.com/").ok,
        "the selected provider's endpoint is unreachable",
      )
      refusedAtConnect(session, "https://api.anthropic.com/", "an unselected provider's endpoint was admitted")
      assertEquals(status(session, "https://github.com/"), "200", "the catalog's forge read is lost")
    finally
      live.foreach(stop)
      discard(workspace)

    // A name that the image does not define fails the launch under the option's name, before a session
    // starts. The launch fails the same way after a launch without the option warmed the workspace's
    // ruleset cache. There, a stamp shared between no selection and the refused value would skip the
    // dry run and fail at the proxy's start instead.
    val refused = scratchWorkspace()
    try
      def refusal(value: String): Unit =
        val (exit, output) = launchOutcome(refused, refused.resolve("launch.log"), Vector(s"--model-provider=$value"))
        assertNotEquals(exit, 0, output)
        assert(output.contains("error: --model-provider is not valid"), output)
        assert(output.contains(s"'$value'"), output)
      refusal("meta")
      val (warmed, output) = launchOutcome(refused, refused.resolve("launch.log"))
      assertEquals(warmed, 0, output)
      refusal("none")
    finally discard(refused)

  test("the npm audit line allows the audit POST beside an install with a scoped package"):
    requireTestWithPodman()

    // The example's one line comes on top of the defaults' root read. The install's reads under the
    // root keep working with the `%2f` that npm spells a scoped package's name with, and the proxy
    // allows and logs the audit POST at its exact path.
    withSession(Some("allow https://registry.npmjs.org/-/npm/v1/security/advisories/bulk method=POST\n")): session =>
      val install = exec(
        session,
        "sh",
        "-c",
        "mkdir -p /tmp/npm && cd /tmp/npm && npm init -y >/dev/null && npm install @types/node",
      )
      assert(install.ok, s"the install failed: ${install.text} ${install.err}")
      val audit = (
        run(podman, "logs", session.proxy).text + "\n" + run(podman, "logs", session.proxy).err,
      ).linesIterator.toVector
      assert(
        audit.exists(line => line.contains(" allow registry.npmjs.org GET /@types%2fnode")),
        "the scoped package was not read under the root with its %2f spelling",
      )
      assert(
        audit.exists(line => line.contains(" allow registry.npmjs.org POST /-/npm/v1/security/advisories/bulk")),
        "the audit POST was not allowed at its path",
      )

  test("a certificate verdict is an error line's reason for the host, never a transport failure or the host's name"):
    import EgressSessionTest.certificateVerdict
    val expired = Seq("PKIX", "validity", "expired")
    val wrongName = Seq("subject alternative", "No name matching", "PKIX")
    def error(host: String, reason: String) = s"2026-11-14T03:50:16Z error $host GET / origin: $reason"
    // The run that failed: the origin closed the handshake before presenting its certificate.
    assert(!certificateVerdict(
      Vector(error("wrong.host.badssl.com", "Remote host terminated the handshake")), "wrong.host.badssl.com",
      wrongName,
    ))
    // The host's own name holds a marker, and neither a connect failure nor an allow line is a verdict.
    assert(!certificateVerdict(Vector(error("expired.badssl.com", "Connect timed out")), "expired.badssl.com", expired))
    assert(!certificateVerdict(
      Vector("2026-11-14T03:50:08Z allow https://expired.badssl.com/ read"), "expired.badssl.com", expired,
    ))
    assert(certificateVerdict(
      Vector(error("expired.badssl.com", "PKIX path validation failed: validity check failed")), "expired.badssl.com",
      expired,
    ))
    assert(certificateVerdict(
      Vector(error("wrong.host.badssl.com", "No subject alternative DNS name matching wrong.host.badssl.com found.")),
      "wrong.host.badssl.com", wrongName,
    ))
    // Another host's verdict does not count.
    assert(!certificateVerdict(
      Vector(error("expired.badssl.com", "PKIX path validation failed")), "wrong.host.badssl.com", wrongName,
    ))

object EgressSessionTest:

  /** Whether the proxy's log holds an `error` line for the host whose reason holds a marker. The reason alone counts:
    * a host name such as expired.badssl.com holds a marker itself. */
  def certificateVerdict(log: Seq[String], host: String, markers: Seq[String]): Boolean =
    log.flatMap(MeasurementReport.parseLine)
      .exists(line => line.action == "error" && line.host == host && markers.exists(line.why.contains))
