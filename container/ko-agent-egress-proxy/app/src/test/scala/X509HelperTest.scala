package agentsandbox.egress

import java.net.{InetAddress, ServerSocket, Socket}
import java.nio.file.{Files, Path}
import java.security.{KeyStore, PrivateKey}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.{Base64, Date}
import javax.net.ssl.{SNIHostName, SNIServerName, SSLContext, SSLSocket, TrustManagerFactory, X509TrustManager}
import scala.jdk.CollectionConverters.*
import sun.security.x509.*

import TLSHelper.*
import X509Helper.*
import X509HelperTest.*

object X509HelperTest:
  /** A CA of the kind the launcher creates for a run, built here with the same JDK classes: the
    * proxy never creates one, and this build has no BouncyCastle. */
  def testCa(now: Instant, days: Long): (X509Certificate, PrivateKey) =
    val keyPair = newEcKeyPair()
    val name = X500Name("CN=ko-agent-sandbox egress CA (test)")
    val info = X509CertInfo()
    info.setVersion(CertificateVersion(CertificateVersion.V3))
    info.setSerialNumber(CertificateSerialNumber(randomSerial()))
    info.setAlgorithmId(CertificateAlgorithmId(AlgorithmId.get("SHA256withECDSA")))
    info.setIssuer(name)
    info.setValidity(CertificateValidity(Date.from(now), Date.from(now.plus(days, ChronoUnit.DAYS))))
    info.setSubject(name)
    info.setKey(CertificateX509Key(keyPair.getPublic))
    val extensions = CertificateExtensions()
    extensions.setExtension(BasicConstraintsExtension.NAME, BasicConstraintsExtension(true, true, 0))
    val keyUsage = KeyUsageExtension()
    keyUsage.set(KeyUsageExtension.KEY_CERTSIGN, true)
    extensions.setExtension(KeyUsageExtension.NAME, keyUsage)
    extensions.setExtension(
      SubjectKeyIdentifierExtension.NAME,
      SubjectKeyIdentifierExtension(KeyIdentifier(keyPair.getPublic).getIdentifier),
    )
    info.setExtensions(extensions)
    (X509CertImpl.newSigned(info, keyPair.getPrivate, "SHA256withECDSA"), keyPair.getPrivate)

  /** The two files as the launcher writes them: PEM, the key PKCS#8. */
  def writePem(directory: Path, name: String, certificate: X509Certificate, key: PrivateKey): (Path, Path) =
    def pem(label: String, der: Array[Byte]): String =
      s"-----BEGIN $label-----\n${Base64.getMimeEncoder(64, "\n".getBytes).encodeToString(der)}\n-----END $label-----\n"
    val certificateFile = Files.writeString(directory.resolve(s"$name.crt"), pem("CERTIFICATE", certificate.getEncoded))
    val keyFile = Files.writeString(directory.resolve(s"$name.key"), pem("PRIVATE KEY", key.getEncoded))
    (certificateFile, keyFile)

  /** A client's trust in `ca` alone. */
  def trusting(ca: X509Certificate): TrustManagerFactory =
    val store = KeyStore.getInstance("PKCS12")
    store.load(null, null)
    store.setCertificateEntry("ca", ca)
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    factory.init(store)
    factory

class X509HelperTest extends munit.FunSuite:

  /** The check a TLS client makes of a server's chain, with `ca` as its one trust anchor. */
  private def serverTrustedBy(ca: X509Certificate, leaf: X509Certificate): Unit =
    trusting(ca).getTrustManagers.collectFirst { case manager: X509TrustManager => manager }.get
      .checkServerTrusted(Array(leaf), "ECDHE_ECDSA")

  /** The DER bytes read back through the JDK's parser, as every client will read them. */
  private def reparsed(certificate: X509Certificate): X509Certificate =
    CertificateFactory.getInstance("X.509")
      .generateCertificate(java.io.ByteArrayInputStream(certificate.getEncoded))
      .asInstanceOf[X509Certificate]

  test("an issued leaf names its host alone, is a serverAuth non-CA, chains to the CA and matches its key"):
    val now = Instant.now()
    val (ca, caKey) = testCa(now, days = 825)
    val issued = issueLeaf("docs.example", ca, caKey, now)
    val leaf = reparsed(issued.certificate)

    assertEquals(TLSHelper.TlsInspection.subjectAlternativeNames(leaf), Set("docs.example"))
    assertEquals(leaf.getBasicConstraints, -1)
    assertEquals(leaf.getExtendedKeyUsage.asScala.toVector, Vector("1.3.6.1.5.5.7.3.1"))
    assertEquals(leaf.getIssuerX500Principal, ca.getSubjectX500Principal)
    assertEquals(leaf.getSigAlgName, "SHA256withECDSA")
    leaf.verify(ca.getPublicKey)
    serverTrustedBy(ca, leaf)
    intercept[java.security.cert.CertificateException](serverTrustedBy(testCa(now, days = 825)(0), leaf))

    // The key is the leaf's own, and matches the certificate.
    val probe = Array.tabulate[Byte](32)(_.toByte)
    val signer = java.security.Signature.getInstance("SHA256withECDSA")
    signer.initSign(issued.privateKey)
    signer.update(probe)
    val signature = signer.sign()
    val verifier = java.security.Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(leaf.getPublicKey)
    verifier.update(probe)
    assert(verifier.verify(signature))
    assertNotEquals(leaf.getPublicKey, ca.getPublicKey)

  test("the chain has the key identifiers strict verifiers require"):
    val now = Instant.now()
    val (ca, caKey) = testCa(now, days = 825)
    val leaf = reparsed(issueLeaf("docs.example", ca, caKey, now).certificate)
    val SkiOid = "2.5.29.14"
    val AkiOid = "2.5.29.35"
    val caSki = ca.getExtensionValue(SkiOid)
    assert(leaf.getExtensionValue(SkiOid) != null, "leaf Subject Key Identifier")
    val leafAki = leaf.getExtensionValue(AkiOid)
    assert(leafAki != null, "leaf Authority Key Identifier")
    // The SKI extension value is DER octet-string wrapping; its last 20 bytes are the key id, which
    // the AKI must contain verbatim.
    assert(leafAki.toVector.containsSlice(caSki.takeRight(20).toVector), "leaf AKI names the CA's key id")

  test("a leaf never outlives its CA, and two leaves for one host are two certificates"):
    // To the second: X.509 validity carries no finer time.
    val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
    val (ca, caKey) = testCa(now, days = 40)
    val leaf = issueLeaf("docs.example", ca, caKey, now).certificate
    assert(!leaf.getNotAfter.after(ca.getNotAfter))
    val (longCa, longKey) = testCa(now, days = 3650)
    assertEquals(
      issueLeaf("docs.example", longCa, longKey, now).certificate.getNotAfter.toInstant,
      now.plus(LeafValidityDays, ChronoUnit.DAYS),
    )
    val again = issueLeaf("docs.example", ca, caKey, now).certificate
    assertNotEquals(again.getSerialNumber, leaf.getSerialNumber)
    assertNotEquals(again.getPublicKey, leaf.getPublicKey)

  test("a client verifying the host under the run CA accepts the issued leaf, and the next connection reuses it"):
    val now = Instant.now()
    val (ca, caKey) = testCa(now, days = 825)
    val directory = Files.createTempDirectory("run-ca")
    val (certificateFile, keyFile) = writePem(directory, "ca", ca, caKey)
    val inspection = TlsInspection.issuing(certificateFile, keyFile)
    val first = inspection.contextFor("docs.example")
    assert(first eq inspection.contextFor("docs.example"))
    assert(first ne inspection.contextFor("other.example"))
    // The cache is bounded: past LeafCacheCapacity distinct hosts the least recently used host's context is
    // evicted, and its next connection issues another leaf.
    (1 to TlsInspection.LeafCacheCapacity).foreach(i => inspection.contextFor(s"host$i.example"))
    assert(first ne inspection.contextFor("docs.example"))

    val clientContext = SSLContext.getInstance("TLS")
    clientContext.init(null, trusting(ca).getTrustManagers, null)
    val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress)
    try
      // The proxy's side of runEstablishedTunnel: the ClientHello read off the wire, checked against
      // the CONNECT host, then replayed into the handshake with that host's leaf.
      val serving = Thread.startVirtualThread: () =>
        (1 to 2).foreach: _ =>
          val client = server.accept()
          try
            val hello = TlsClientHello.read(client.getInputStream, AgentEgressProxy.MaxClientHelloBytes)
            validateTlsIdentity("docs.example", hello)
            inspection.accept(client, hello.wireBytes, "docs.example").close()
          finally client.close()
      def presented(): X509Certificate =
        val raw = Socket(InetAddress.getLoopbackAddress, server.getLocalPort)
        val tls = clientContext.getSocketFactory.createSocket(raw, "docs.example", 443, true).asInstanceOf[SSLSocket]
        val parameters = tls.getSSLParameters
        parameters.setEndpointIdentificationAlgorithm("HTTPS")
        parameters.setServerNames(java.util.List.of[SNIServerName](SNIHostName("docs.example")))
        tls.setSSLParameters(parameters)
        try
          tls.startHandshake()
          tls.getSession.getPeerCertificates.head.asInstanceOf[X509Certificate]
        finally tls.close()
      val first = presented()
      assertEquals(TlsInspection.subjectAlternativeNames(first), Set("docs.example"))
      assertEquals(presented().getEncoded.toVector, first.getEncoded.toVector)
      serving.join()
    finally server.close()

  test("the run CA is refused at start when its key does not match it or it is no CA"):
    val now = Instant.now()
    val (ca, caKey) = testCa(now, days = 825)
    val (other, otherKey) = testCa(now, days = 825)
    val directory = Files.createTempDirectory("run-ca")
    val (certificateFile, _) = writePem(directory, "ca", ca, caKey)
    val (_, otherKeyFile) = writePem(directory, "other", other, otherKey)
    val mismatched = intercept[IllegalArgumentException](TlsInspection.issuing(certificateFile, otherKeyFile))
    assert(mismatched.getMessage.contains("does not match"), mismatched.getMessage)
    val leaf = issueLeaf("docs.example", ca, caKey, now)
    val (leafFile, leafKeyFile) = writePem(directory, "leaf", leaf.certificate, leaf.privateKey)
    val notCa = intercept[IllegalArgumentException](TlsInspection.issuing(leafFile, leafKeyFile))
    assert(notCa.getMessage.contains("not a CA certificate"), notCa.getMessage)
