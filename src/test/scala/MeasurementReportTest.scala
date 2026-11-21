package agentsandbox.launcher

import MeasurementReport.*

class MeasurementReportTest extends munit.FunSuite:

  /** Evidence Markdown whose one `measurement-report` block holds `lines`. */
  private def evidence(lines: String*): String =
    s"# Evidence\n\nProse.\n\n$BlockFence\n${lines.mkString("\n")}\n```\n"

  private val record = parseRecord(
    "example",
    """allow https://api.example/ read method=POST,PUT,PATCH,DELETE
      |allow https://login.example/ read method=POST
      |""".stripMargin,
    evidence(
      "path api.example /v1/messages /api/eval/sdk-<key>",
      "path api.example /api/orgs/<org>/skills",
      "path login.example /token",
      "refused telemetry.example CONNECT",
      "refused cdn<region>.example CONNECT",
      "refused api.example GET /v1/stream",
      "error api.example client:",
    ),
  )

  private def stamped(line: String) = s"2026-11-14T09:00:00Z $line"

  private def reportOf(lines: String*): Report = report(lines.toVector.map(stamped), Vector(record))

  test("since keeps the lines stamped at its time or later, and drops the unstamped ones"):
    val log = Vector(
      "2026-11-14T08:59:59Z error repo.example GET /a.pom relay: client: Broken pipe",
      "egress profile: deny-unless-allowed",
      "2026-11-14T09:00:00Z allow api.example GET /v1/models id=1 -> 1.2.3.4",
      "2026-11-14T09:00:01Z deny other.example CONNECT host not allowed",
    )
    assertEquals(since(log, "2026-11-14T09:00:00Z"), log.drop(2))

  test("a time after the log's last audit line selects nothing and is refused, rather than read as a clean run"):
    val log = Vector("2026-11-14T09:00:00Z allow api.example GET /v1/models id=1 -> 1.2.3.4")
    assertEquals(selected(log, None), Right(log))
    assertEquals(selected(log, Some("2026-11-14T09:00:00Z")), Right(log))
    assert(selected(log, Some("2026-11-14T09:00:01Z")).swap.exists(_.contains("no audit line at or after")))

  test("a record's lines give its hosts, paths, refusals and errors"):
    assertEquals(record.hosts, Set("api.example", "login.example"))
    assertEquals(
      record.paths,
      Vector(
        "api.example" -> "/v1/messages", "api.example" -> "/api/eval/sdk-<key>",
        "api.example" -> "/api/orgs/<org>/skills", "login.example" -> "/token",
      ),
    )
    assertEquals(record.refusals.map(_.path), Vector(None, None, Some("/v1/stream")))
    assertEquals(record.errors, Vector("api.example" -> "client:"))

  test("each <name> stands for one segment or part of one, and one label of a host"):
    assert(record.recordsPath("api.example", "/api/eval/sdk-zAZezfDKGoZuXXKe"))
    assert(record.recordsPath("api.example", "/api/orgs/91cc868a-9b43-4e4b-a135-cb862d6bb2fb/skills"))
    assert(!record.recordsPath("api.example", "/api/orgs/a/b/skills"))
    assert(!record.recordsPath("api.example", "/v1/messages/extra"))
    assertEquals(reportOf("deny cdnwestus2.example CONNECT host not allowed").findings, Vector.empty)
    assertEquals(reportOf("deny cdn.a.example CONNECT host not allowed").findings.size, 1)

  test("lines outside a block are prose; a block line in none of the three forms, or an unclosed block, is refused"):
    val prose = parseRecord(
      "prose",
      "# refused api.example CONNECT\n",
      """The defaults' read-only line for the registry
        |refused npm's audit, and one connection ended in the handshake:
        |path api.example /v1/messages
        |
        |```text
        |error api.example client:
        |```
        |""".stripMargin,
    )
    assertEquals((prose.paths, prose.refusals, prose.errors), (Vector.empty, Vector.empty, Vector.empty))
    for line <- Seq(
        "refused npm's audit, and one connection ended in the handshake:",
        "path api.example /v1/messages (a note after the paths)",
        "paths api.example /v1/messages",
      )
    do
      val refusal = intercept[IllegalArgumentException](parseRecord("typo", "", evidence(line)))
      assert(refusal.getMessage.contains(line), refusal.getMessage)
    val unclosed = intercept[IllegalArgumentException](parseRecord("open", "", s"$BlockFence\npath a.example /\n"))
    assert(unclosed.getMessage.contains("no closing fence"), unclosed.getMessage)

  test("the shipped records parse, each with its paths, and every path names a host that a default file allows"):
    val shipped = records()
    assertEquals(shipped.map(_.preset).toSet, RulesetHelperPresets)
    // A record may name another file's host: Claude Code fetches its plugin marketplace from github.com.
    val catalog = java.nio.file.Files.readString(RecordDirectory.resolveSibling("host"))
    val allowed = shipped.flatMap(_.hosts).toSet ++ parseRecord("host", catalog).hosts
    shipped.foreach: measured =>
      assert(measured.paths.nonEmpty, measured.preset)
      measured.paths.foreach((host, path) => assert(allowed(host), s"${measured.preset}: $host $path"))

  private val RulesetHelperPresets = agentsandbox.egress.RulesetHelper.Presets.toSet

  test("a recorded path, an accepted refusal and an accepted error leave no finding; the query is no part of a path"):
    val clean = reportOf(
      "allow api.example POST /v1/messages?beta=true content-length=323 id=1 client=claude-cli/2.1.323 cred=1 " +
        "-> 1.2.3.4",
      "allow login.example POST /token content-length=325 id=2 client=axios/1.15.2 -> 1.2.3.4",
      "deny telemetry.example CONNECT host not allowed",
      "deny cdnwestus2.example CONNECT host not allowed",
      "deny api.example GET /v1/stream id=3 upgrade=websocket not granted",
      "error api.example POST /v1/messages id=1 client: Connection reset by peer",
    )
    assertEquals(clean.findings, Vector.empty, clean.text)
    assert(clean.text.contains("api.example POST /v1/messages: 1; cred=1; content-length"), clean.text)
    assert(clean.text.contains("login.example POST /token: 1; 1 without cred; content-length"), clean.text)
    assert(clean.text.contains("recorded, not called in this run: api.example /api/eval/sdk-<key>"), clean.text)

  test("an unrecorded path, refusal or error is a finding, counted once per kind"):
    val found = reportOf(
      "allow api.example GET /api/new id=1 cred=1 -> 1.2.3.4",
      "allow api.example GET /api/new id=2 cred=1 -> 1.2.3.4",
      "deny new-telemetry.example CONNECT host not allowed",
      "error api.example POST /v1/messages id=3 origin: Connection reset",
    )
    assertEquals(
      found.findings,
      Vector(
        "api.example GET /api/new (2): example names no such path",
        "deny new-telemetry.example CONNECT host not allowed (1): no record accepts the refusal",
        "error api.example POST /v1/messages origin: Connection reset (1): no record accepts the error",
      ),
    )

  test("a refused line accepts the refusal without naming the host, whose allowed requests are listed apart"):
    assert(!record.names("telemetry.example"))
    val allowed = reportOf("allow telemetry.example GET /v1/events id=1 -> 1.2.3.4")
    assertEquals(allowed.findings, Vector.empty, allowed.text)
    assert(allowed.text.contains("other: telemetry.example GET (1)"), allowed.text)

  test("a host that two records name takes a path that either records, and an unrecorded path is one finding"):
    val other = parseRecord(
      "forge",
      "allow https://forge.example/login read method=POST\n",
      evidence("path forge.example /login"),
    )
    val agent = parseRecord("agent", "", evidence("path forge.example /<owner>/<repo>"))
    val both = report(
      Vector(
        "allow forge.example POST /login content-length=10 id=1 -> 1.2.3.4",
        "allow forge.example HEAD /o/r id=2 client=Go-http-client/1.1 -> 1.2.3.4",
        "allow forge.example GET /o/r/issues id=3 -> 1.2.3.4",
      ).map(stamped),
      Vector(other, agent),
    )
    assertEquals(both.findings, Vector("forge.example GET /o/r/issues (1): forge and agent name no such path"))

  test("curl's uploads are probes: their paths, body ends and errors are shown, never judged"):
    val probed = reportOf(
      "allow api.example POST /v1/files content-length=2000 id=1 client=curl/8.5.0 cred=2 -> 1.2.3.4",
      "allow api.example POST /v1/files chunked id=2 client=curl/8.5.0 cred=2 -> 1.2.3.4",
      "chunked-end api.example POST /v1/files id=2 send=500 incomplete",
      "error api.example POST /v1/files id=2 client: request body: Connection reset",
    )
    assertEquals(probed.findings, Vector.empty, probed.text)
    assertEquals(
      probed.probes,
      Vector(
        Probe("api.example", "POST", "/v1/files", "content-length=2000", Some("2"), ""),
        Probe("api.example", "POST", "/v1/files", "chunked", Some("2"), "send=500 incomplete"),
      ),
    )

  test("ko-sandbox-egress-check's HEAD is a probe, never judged"):
    val checked = reportOf("allow api.example HEAD / id=1 client=ko-sandbox-egress-check -> 1.2.3.4")
    assertEquals(checked.findings, Vector.empty, checked.text)
    assertEquals(checked.probes, Vector(Probe("api.example", "HEAD", "/", "", None, "")))

  test("hosts that no measured record names are listed apart by method; ruleset and startup lines are no events"):
    val unmeasured = parseRecord("forge", "allow https://forge.example/login/token method=POST\n")
    val other = report(
      Vector(
        "egress profile: deny-unless-allowed; egress presets: example",
        "allow https://api.example/ read method=POST,PUT,PATCH,DELETE",
        "allow forge.example GET /org/marketplace.git/info/refs?service=git-upload-pack id=1 client=git/2.47.3 " +
          "-> 1.2.3.4",
        "allow forge.example POST /org/marketplace.git/git-upload-pack content-length=200 id=2 -> 1.2.3.4",
        "allow raw.example CONNECT -> 1.2.3.4",
        "allow raw.example CONNECT -> 1.2.3.4",
      ).map(stamped),
      Vector(record, unmeasured),
    )
    assertEquals(other.findings, Vector.empty, other.text)
    assert(other.text.contains("other: forge.example GET (1)\nother: forge.example POST (1)"), other.text)
    assert(other.text.contains("other: raw.example CONNECT (2)"), other.text)
    assert(!other.text.contains("example:") && !other.text.contains("forge:"), other.text)
