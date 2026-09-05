// The egress rules a project ships, end to end. A session reads its rules once at startup, so
// each test here launches its own.
//
// Two of these are the refusals no session can demonstrate about itself, because both happen on the
// proxy's *origin* leg, which inspection moves out of the client's sight: an origin whose
// certificate does not verify, and a name that resolves into private address space. Skipping either
// check is invisible in normal operation — the sandbox sees a valid leaf minted by this project's
// CA whatever the origin presented — which is the classic TLS-interception failure.
//
// Opt-in like the other container-launching suites (IntegrationSession has the gate):
//
//     KO_AGENT_SANDBOX_INTEGRATION=1 sbt "testOnly *EgressSessionTest"
//
// The assertions use hosts outside the built-in ruleset, and the suite is only as good as their
// reachability from the host running it: `example.com` (a plain addition), `expired.badssl.com` and
// `wrong.host.badssl.com` (origin certificates the proxy must reject, for the two different reasons
// a certificate can be wrong), `127.0.0.1.nip.io` (a public resolver answering with the address
// embedded in the name), and `github.com/octocat/Hello-World.git` (a clone small enough to be a
// fixture). One test takes its fixture from the environment instead — INTEGRATION_SIGNED_PUT_URL,
// a presigned upload URL only a bucket owner can mint — and skips when it is unset; its own header
// has the minting one-liner.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import IntegrationSession.*

class EgressSessionTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(20, "min")

  /** Write this project's rule file, as a repository would ship it. */
  private def ruleFile(project: Path, rule: Option[String]): Unit =
    val egress = project.resolve(".ko-agent-sandbox").resolve("egress")
    Files.createDirectories(egress)
    rule.foreach(text => Files.writeString(egress.resolve("rule"), text))

  private def curl(session: Session, args: String*): Run =
    exec(session, (Vector("curl", "-sS", "--max-time", "25") ++ args)*)

  private def status(session: Session, args: String*): String =
    curl(session, (Vector("-o", "/dev/null", "-w", "%{http_code}") ++ args)*).text.trim

  /** Which CA signed the certificate a host presented, as the sandbox saw it. curl indents its
    * certificate lines under the `*` marker and by more than one space, so this keys on the field
    * name rather than on the format of the prefix. */
  private def issuer(session: Session, host: String): String =
    curl(session, "-v", "-o", "/dev/null", s"https://$host/").err.linesIterator
      .map(_.trim)
      .collectFirst:
        case line if line.startsWith("*") && line.contains("issuer:") =>
          line.substring(line.indexOf("issuer:") + "issuer:".length).trim
      .getOrElse("(no issuer line)")

  /** A host the ruleset never admitted, or a name resolving outside public address space: both are
    * refused at the CONNECT, before a tunnel exists, so curl reports the proxy's status as an error
    * rather than as an HTTP code. */
  private def refusedAtConnect(session: Session, url: String, why: String): Unit =
    val attempt = curl(session, "-o", "/dev/null", url)
    assert(!attempt.ok, s"$url was reachable; $why")
    assert(
      attempt.err.contains("403"),
      s"$url failed, but not with a refusal from the proxy: ${attempt.err}",
    )

  /** An admitted host whose *origin* leg the proxy would not complete. Its CONNECT succeeded and
    * the proxy terminated the client's TLS, so the refusal arrives as a status inside the tunnel
    * and curl exits 0 — which is precisely why an unverified origin would be indistinguishable from
    * a verified one in here, and why the proxy's own audit line is what settles the cause. */
  private def refusedAtOrigin(session: Session, host: String, markers: Seq[String], why: String): Unit =
    assertEquals(status(session, s"https://$host/"), "502", s"$host: $why")

    val audit = run(podman, "logs", session.proxy)
    val line = (audit.text + "\n" + audit.err).linesIterator.filter(_.contains(host)).mkString("\n")
    assert(
      markers.exists(line.contains),
      s"$host failed at the origin, but not over its certificate — the origin may simply be down:\n$line",
    )

  private def withSession(rule: Option[String])(body: Session => Unit): Unit =
    val project = scratchProject()
    var live: Option[Session] = None
    try
      ruleFile(project, rule)
      val session = launch(project, project.resolve("session.log"))
      live = Some(session)
      body(session)
    finally
      live.foreach(stop)
      discard(project)

  test("a read line is inspected, verified at the origin, and opens nothing else"):
    optIn()

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

      // Inspected on the project's own CA, like a catalog host: one leaf, minted at launch
      // from the ruleset, or the addition would be a treatment the proxy does not police.
      assertEquals(
        issuer(session, "example.com"), issuer(session, "pypi.org"),
        "the added host is not inspected by this project's CA",
      )
      assertEquals(status(session, "-X", "POST", "https://example.com/"), "403", "the addition allowed a write")

      // The origin leg. The sandbox cannot tell a verified origin from an unverified one — both
      // arrive under a leaf it trusts — so the refusal has to come from the proxy or not at all.
      refusedAtOrigin(
        session, "expired.badssl.com", Seq("PKIX", "validity", "expired"),
        "SECURITY: the proxy accepted an expired origin certificate",
      )
      refusedAtOrigin(
        session, "wrong.host.badssl.com", Seq("subject alternative", "No name matching", "PKIX"),
        "SECURITY: the proxy accepted an origin certificate issued for another name",
      )

      // Refused before the dial rather than during it: resolution is where the address is vetted.
      refusedAtConnect(
        session, "https://127.0.0.1.nip.io/",
        "SECURITY: a name resolving to loopback was not refused after resolution",
      )

      // The bound: allowing four hosts allows four hosts. A reserved name (RFC 6761), so that no
      // growth of the defaults can ever turn the sentinel into an admitted host.
      refusedAtConnect(session, "https://unlisted.invalid/", "a host the ruleset never named was allowed")

  test("a deny of one grant takes that grant alone: the forge stays readable and stops being clonable"):
    optIn()

    // github.com is `read git-fetch` in the defaults: inspected reads, plus the clone's two
    // requests. One deny line takes the clone back host-wide and leaves the reads.
    val clone = Vector(
      "git", "clone", "--depth", "1", "--quiet",
      "https://github.com/octocat/Hello-World.git", "/tmp/hello"
    )

    withSession(Some("deny https://github.com/ git-fetch\n")): session =>
      assertEquals(status(session, "https://github.com/"), "200", "the deny of git-fetch took the reads too")
      val attempt = exec(session, clone*)
      assert(!attempt.ok, "SECURITY: the clone succeeded; the defaults' git-fetch outlived the deny")
      // Refused at the clone's first request, and the log says so with the line that refused it.
      val audit = run(podman, "logs", session.proxy)
      assert(
        (audit.text + "\n" + audit.err).linesIterator.exists: line =>
          line.contains(" deny github.com GET /octocat/Hello-World.git/info/refs") &&
            line.endsWith("git fetch ref discovery"),
        "no deny line records the refused clone at ref discovery",
      )

    // The control, and the only thing that makes the refusal above evidence: the same clone under
    // the defaults, which the project did not touch.
    withSession(None): session =>
      assert(exec(session, clone*).ok, "the clone fails under the defaults too; this fixture proves nothing")

  test("a host-wide deny with a narrower allow beneath it admits one owner and refuses the rest, clone included"):
    optIn()

    // The forge denied whole, then one owner re-granted for the clone and the device login's path
    // re-granted for its POST; the same shape on the raw-content host. The requests outside are
    // refused inside the tunnel, so curl reports the proxy's own status, and a clone of another
    // owner fails at ref discovery.
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
        "SECURITY: a read outside the prefix was admitted",
      )
      assertEquals(
        status(session, "https://raw.githubusercontent.com/octocat/../github/docs/main/README.md"), "403",
        "SECURITY: a dot segment under the prefix was admitted",
      )
      assertEquals(
        status(session, "https://raw.githubusercontent.com/octocat/%2e%2e/github/docs/main/README.md"), "403",
        "SECURITY: a percent-encoded dot segment under the prefix was admitted",
      )
      // The device flow's first POST, at its own path: GitHub answers a client-id error, which is
      // the origin speaking — the proxy's refusal would be a 403 with its own body.
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

      // The refusal is the boundary's, at the clone's first request, and the log says so.
      val audit = run(podman, "logs", session.proxy)
      assert(
        (audit.text + "\n" + audit.err).linesIterator.exists: line =>
          line.contains(" deny github.com GET /github/docs.git/info/refs") && line.endsWith("path under no line"),
        "no deny line records the refused clone at ref discovery",
      )

  test("an owner-signed upload URL is refused inside the inspected tunnel"):
    // The inspected treatment's reason to exist (SECURITY.md, "Reading without being able to write").
    // The rule is host-independent, which is what lets any owner-minted bucket serve as the fixture.
    // For an S3 bucket:
    //
    // ('boto3[crt]', because the credential provider behind `aws login` needs the CRT extra;
    // s3v4, because in older regions boto3 still mints deprecated SigV2 URLs; `--server`, because
    // a resident sbt server would keep the environment it started with and skip this test as if
    // the variable were never set):
    //
    //     INTEGRATION_SIGNED_PUT_URL="$(uv run --with 'boto3[crt]' python3 -c 'import boto3, botocore.config
    //     print(boto3.client("s3", config=botocore.config.Config(signature_version="s3v4"))
    //         .generate_presigned_url("put_object",
    //         Params={"Bucket": "YOUR-BUCKET", "Key": "ko-agent-sandbox-probe"}, ExpiresIn=1800))')" \
    //         KO_AGENT_SANDBOX_INTEGRATION=1 sbt --server "testOnly *EgressSessionTest"
    //
    // The URL's query string is a capability, and it lands whole in this run's owner-only audit
    // log; it expires on its own, and the probe object is the owner's to delete.
    optIn()
    val signed = env("INTEGRATION_SIGNED_PUT_URL")
    assume(signed.isDefined, "set INTEGRATION_SIGNED_PUT_URL to a presigned PUT URL (test header)")
    val url = signed.get
    val bucketHost = java.net.URI(url).getHost

    // The control, from the unconfined host: the URL genuinely accepts the write. Without it, the
    // refusal below could be the origin's own answer to a stale or malformed URL. The body rides
    // along because it is the diagnosis when this fails — S3 names AccessDenied, ExpiredToken or
    // SignatureDoesNotMatch there, and nowhere else.
    // The emptied Content-Type strips the header curl invents for a body: a SigV2-signed URL
    // (boto3's default in older regions) covers Content-Type, and the invented one breaks its
    // signature; SigV4 does not care either way.
    val control = run(
      "curl", "-sS", "--max-time", "25", "-w", "\n%{http_code}",
      "-H", "Content-Type:", "-X", "PUT", "--data-binary", "minted-and-accepted", url,
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

  test("under allow-unless-denied an unlisted host is an inspected read under this run's CA, a tunnel host opaque"):
    optIn()

    val project = scratchProject()
    var live: Option[Session] = None
    try
      val session = launchWith(project, project.resolve("session.log"), Vector("--egress=allow-unless-denied"))
      live = Some(session)
      // example.com is no defaults host: what it gets is the public default, read and nothing else.
      assertEquals(status(session, "https://example.com/"), "200", "the unlisted host is not readable")
      assertEquals(
        status(session, "-X", "POST", "https://example.com/"), "403", "SECURITY: the unlisted host took a write",
      )
      // The leaf is this run's CA's, the same signer a catalog host's is under this profile, and the
      // CA the sandbox trusts names the run; a tunnel host presents the origin's own chain.
      val runCa = exec(
        session, "openssl", "x509", "-noout", "-subject", "-in", "/etc/ko-agent-sandbox/egress-proxy-ca.crt",
      ).text.stripPrefix("subject=").trim
      assert(runCa.contains("run-"), s"the sandbox trusts a CA other than this run's: $runCa")
      assertEquals(issuer(session, "example.com"), runCa, "the unlisted host is not inspected under the run CA")
      assertEquals(issuer(session, "pypi.org"), runCa, "the catalog host is not inspected under the run CA")
      assertNotEquals(issuer(session, "api.anthropic.com"), runCa, "the tunnel host was inspected")
      // Logged with its target, as every inspected request is.
      val audit = run(podman, "logs", session.proxy)
      assert(
        (audit.text + "\n" + audit.err).linesIterator.exists(_.contains(" allow example.com GET / ")),
        "no allow line records the unlisted host's read with its target",
      )
    finally
      live.foreach(stop)
      discard(project)

  test("a deny defaults lockdown removes the defaults and still signs in"):
    optIn()

    withSession(Some("deny defaults\nallow model-provider anthropic\n")): session =>
      // A tunnel is opaque: any status means the CONNECT was granted, and the agent endpoint
      // answering at all is what "still signs in" means.
      assert(
        curl(session, "-o", "/dev/null", "https://api.anthropic.com/").ok,
        "the group's agent endpoint is unreachable under the lockdown",
      )
      // Nothing inspected survives, so this session inspects nothing — and the defaults are gone.
      refusedAtConnect(session, "https://pypi.org/", "a defaults host survived `deny defaults`")
      refusedAtConnect(session, "https://github.com/", "a defaults host survived `deny defaults`")

  test("the npm audit line admits the audit POST beside an install with a scoped package"):
    optIn()

    // The example's one line, over the defaults' root read: the install's reads under the root
    // keep working with the `%2f` npm spells a scoped package's name with, and the audit POST at
    // its exact path is admitted, logged as such.
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
        "the audit POST was not admitted at its path",
      )
