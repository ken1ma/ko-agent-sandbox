package agentsandbox.egress

import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture

import HTTPHelper.HttpRequestHead

class RequestAuditTest extends munit.FunSuite:

  private def head(headers: String*): HttpRequestHead =
    HttpRequestHead.parse(
      s"POST /v1/messages HTTP/1.1\r\nHost: api.example\r\n${headers.map(_ + "\r\n").mkString}\r\n"
        .getBytes(StandardCharsets.ISO_8859_1),
    )

  private def fields(audit: RequestAudit, headers: String*): String =
    val parsed = head(headers*)
    audit.allowFields(parsed, parsed.bodyFraming).text

  test("each field is present only when the request supplies it, in the grammar's order"):
    val audit = RequestAudit()
    assertEquals(fields(audit), "")
    assertEquals(fields(audit, "Content-Length: 0"), "content-length=0 ")
    assertEquals(fields(audit, "Content-Length: 512"), "content-length=512 ")
    assertEquals(fields(audit, "User-Agent: curl/8.5.0"), "client=curl/8.5.0 ")
    assertEquals(fields(audit, "x-api-key: sk-one"), "cred=1 ")
    assertEquals(
      fields(audit, "x-api-key: sk-one", "Transfer-Encoding: chunked", "User-Agent: python-requests/2.32.3"),
      "chunked id=1 client=python-requests/2.32.3 cred=1 ",
    )

  test("client= keeps the User-Agent's start up to the first character outside its set, at most 128 of them"):
    def client(userAgent: String) = RequestAudit.client(head(s"User-Agent: $userAgent"))
    assertEquals(client("claude-cli/2.1.319 (external, cli)"), Some("claude-cli/2.1.319"))
    assertEquals(client("Mozilla/5.0 (X11; Linux)"), Some("Mozilla/5.0"))
    assertEquals(client("a=b"), Some("a"))
    assertEquals(client("(compatible)"), None)
    assertEquals(client("x" * 200), Some("x" * 128))
    assertEquals(RequestAudit.client(head()), None)

  test("only the chunked requests take an id, numbered from 1, distinct under concurrency"):
    val audit = RequestAudit()
    def id(headers: String*) =
      val parsed = head(headers*)
      audit.allowFields(parsed, parsed.bodyFraming).id
    assertEquals(id("Content-Length: 4"), None)
    assertEquals(id(), None)
    val ids = Vector.fill(16)(CompletableFuture.supplyAsync(() => id("Transfer-Encoding: chunked")))
    assertEquals(ids.flatMap(_.join()).sorted, (1L to 16L).toVector)

  test("the index counts static credentials in order of first sight, whatever header carries them"):
    val audit = RequestAudit()
    def index(header: String) = fields(audit, header)
    assertEquals(index("x-api-key: sk-one"), "cred=1 ")
    assertEquals(index("x-goog-api-key: AIza-two"), "cred=2 ")
    assertEquals(index("x-api-key: sk-one"), "cred=1 ")
    // A refreshed bearer is a credential of its own.
    assertEquals(index("Authorization: Bearer token-old"), "cred=3 ")
    assertEquals(index("Authorization: bearer token-new"), "cred=4 ")
    assertEquals(index("Authorization: token token-old"), "cred=3 ")
    assertEquals(index("Authorization: Basic dXNlcjpwYXNz"), "cred=5 ")

  test("a signing scheme, an empty token and a request without a credential print no index"):
    val audit = RequestAudit()
    val sigV4 = "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261112/us-east-1/q/aws4_request, " +
      "SignedHeaders=host, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"
    assertEquals(fields(audit, sigV4), "")
    assertEquals(fields(audit, "Authorization: Bearer"), "")
    assertEquals(fields(audit, "x-api-key:"), "")
    assertEquals(fields(audit, "Cookie: session=abc"), "")
    assertEquals(fields(audit, sigV4, "x-api-key: sk-after"), "cred=1 ")

  test("two concurrent first uses of one credential share an index"):
    val audit = RequestAudit()
    val indexes = Vector.fill(16)(CompletableFuture.supplyAsync(() => audit.credentialIndex("sk-shared")))
    assertEquals(indexes.map(_.join()).distinct, Vector(Some(1)))
    assertEquals(audit.credentialIndex("sk-next"), Some(2))

  test("past MaxCredentials a new credential prints ?, and a known one keeps its index"):
    val audit = RequestAudit()
    (1 to RequestAudit.MaxCredentials).foreach(number => audit.credentialIndex(s"sk-$number"))
    assertEquals(fields(audit, "x-api-key: sk-new"), "cred=? ")
    assertEquals(fields(audit, "x-api-key: sk-7"), "cred=7 ")

  test("the chunked-end line repeats the id, counts the payload, and marks an incomplete body"):
    assertEquals(
      RequestAudit.chunkedEndLine("api.example", "POST", "/v1/files", 3, BodyRelayed(52428800, complete = true)),
      "chunked-end api.example POST /v1/files id=3 send=52428800",
    )
    assertEquals(
      RequestAudit.chunkedEndLine("api.example", "POST", "/v1/files", 4, BodyRelayed(65536, complete = false)),
      "chunked-end api.example POST /v1/files id=4 send=65536 incomplete",
    )
