package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.X509Certificate

import scala.jdk.CollectionConverters.*

class RunOnHostInspectionTest extends munit.FunSuite:

  test("create leaves a leaf naming the hosts, its key, and the CA alone in both trust formats"):
    val proxyLog = Files.createTempDirectory("session").resolve("proxy-sbt-0.log")
    val hosts = Seq("repo1.maven.org", "repo.example.com")
    assertEquals(RunOnHostInspection.create(proxyLog, hosts), Right(()))

    val leafPem = Files.readString(RunOnHostInspection.leafCertificate(proxyLog), UTF_8)
    val keyPem = Files.readString(RunOnHostInspection.leafKey(proxyLog), UTF_8)
    val trust = RunOnHostInspection.trustDirectory(proxyLog)
    val caPem = Files.readString(RunOnHostInspection.caBundle(trust), UTF_8)
    val names =
      CertificateHelper.parseCertificate(leafPem).getSubjectAlternativeNames.asScala.map(_.get(1).toString).toSet
    assertEquals(names, hosts.toSet)
    assert(CertificateHelper.keyMatchesCertificate(leafPem, keyPem))
    assert(CertificateHelper.signedBy(leafPem, caPem))

    val store = KeyStore.getInstance("PKCS12")
    val in = Files.newInputStream(RunOnHostInspection.trustStore(trust))
    try store.load(in, RunOnHostInspection.TrustStorePassword.toCharArray)
    finally in.close()
    val trusted = store.aliases.asScala.toVector.map(store.getCertificate(_).asInstanceOf[X509Certificate])
    assertEquals(trusted, Vector(CertificateHelper.parseCertificate(caPem)))

    // The proxy's profile grants the leaf's directory and the command's the trust directory, so
    // neither holds the other's files, and the CA's key is in neither.
    def entries(directory: java.nio.file.Path) =
      FileHelper.directoryEntries(directory).map(_.getFileName.toString).toSet
    assertEquals(entries(RunOnHostInspection.leafDirectory(proxyLog)), Set("leaf.crt", "leaf.key"))
    assertEquals(entries(trust), Set("ca.crt", "truststore.p12"))
    if FileHelper.posixPermissions(proxyLog.getParent) then
      assertEquals(
        java.nio.file.attribute.PosixFilePermissions.toString(
          Files.getPosixFilePermissions(RunOnHostInspection.leafKey(proxyLog)),
        ),
        "rw-------",
      )

  test("each proxy's CA is its own"):
    val directory = Files.createTempDirectory("session")
    val logs = Seq("proxy-sbt-0.log", "proxy-mill-0.log").map(directory.resolve)
    logs.foreach(log => assertEquals(RunOnHostInspection.create(log, Seq("repo1.maven.org")), Right(())))
    val cas = logs.map(log => Files.readString(RunOnHostInspection.caBundle(RunOnHostInspection.trustDirectory(log))))
    assertNotEquals(cas(0), cas(1))

  test("the proxy accepts the leaf for a program's rules, every host of which it inspects"):
    import agentsandbox.egress.AgentEgressProxy
    for program <- RunOnHostPrereqs.Program.values do
      val proxyLog = Files.createTempDirectory("session").resolve("proxy.log")
      // Each a spelling the rule grammar takes and the proxy's resolution rewrites: a trailing
      // dot, which the JDK refuses in a certificate's name, capitals, a Unicode name, and the
      // program's own Maven Central host restated.
      val fileHosts =
        Vector("repo.example.com.", "Repo.Example.ORG", "b\u00fccher.example", RunOnHostPrereqs.centralHost(program))
      val hosts = RunOnHostInspection.leafNames(RunOnHostPrereqs.egressRuleText(program, fileHosts))
        .fold(reason => fail(s"${program.name}: $reason"), identity)
      assertEquals(
        hosts.toSet,
        Set("repo.example.com", "repo.example.org", "xn--bcher-kva.example", RunOnHostPrereqs.centralHost(program)),
        program.name,
      )
      assertEquals(RunOnHostInspection.create(proxyLog, hosts), Right(()))
      val environment = Map(
        "EGRESS_PROFILE" -> "deny-unless-allowed",
        "EGRESS_RULE" -> RunOnHostPrereqs.egressRuleText(program, fileHosts),
        AgentEgressProxy.CertificateVariable -> RunOnHostInspection.leafCertificate(proxyLog).toString,
        AgentEgressProxy.PrivateKeyVariable -> RunOnHostInspection.leafKey(proxyLog).toString,
      )
      val resolved = AgentEgressProxy.configuredRuleset(environment.get)
      assertEquals(resolved.inspected, hosts.toSet, program.name)
      // Refuses a leaf whose names differ from the inspected set, so this is their equality.
      assert(AgentEgressProxy.loadInspection(resolved, environment.get).nonEmpty, program.name)
