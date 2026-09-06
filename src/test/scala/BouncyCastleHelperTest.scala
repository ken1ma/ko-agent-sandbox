// The certificate profile the egress proxy accepts and the sandbox verifies: issuance, PEM,
// fingerprints, expiry.

package agentsandbox.launcher

import java.security.cert.{CertificateFactory, X509Certificate}
import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.jdk.CollectionConverters.*

import BouncyCastleHelper.*

class BouncyCastleHelperTest extends munit.FunSuite:

  private def parse(pem: String): X509Certificate =
    CertificateFactory
      .getInstance("X.509")
      .generateCertificate(java.io.ByteArrayInputStream(pem.getBytes("US-ASCII")))
      .asInstanceOf[X509Certificate]

  test("PEM bodies wrap at 64 characters and round-trip"):
    val der = Array.tabulate[Byte](200)(_.toByte)
    val pem = toPem("CERTIFICATE", der)
    val lines = pem.linesIterator.toVector
    assertEquals(lines.head, "-----BEGIN CERTIFICATE-----")
    assertEquals(lines.last, "-----END CERTIFICATE-----")
    assert(lines.tail.init.forall(_.length <= 64))
    assert(pem.endsWith("-----\n"))
    assert(!pem.contains("\r"))
    assertEquals(pemBody(pem).toVector, der.toVector)

  // -------------------------------------------------------------------------
  // Certificates
  //
  // The profile asserted here is the one the egress proxy accepts and the
  // sandbox verifies.

  test("the CA is a signing-only CA with the project in its name"):
    val ca = parse(createCa("myproj").certificatePem)
    assertEquals(ca.getBasicConstraints, 0) // CA:TRUE, pathlen 0
    val keyUsage = ca.getKeyUsage
    assert(keyUsage(5), "keyCertSign") // KeyUsage bit 5
    assert(keyUsage(6), "cRLSign") // KeyUsage bit 6
    assert(!keyUsage(0), "no digitalSignature")
    assert(ca.getSubjectX500Principal.getName.contains("myproj"))
    ca.verify(ca.getPublicKey) // self-signed

  test("the longest name a launch can ask for, a full slug and a run suffix, fits the common name's 64"):
    val slug = "a" * 32
    val ca = parse(createCa(s"$slug 1a2b3c4d").certificatePem)
    assert(ca.getSubjectX500Principal.getName.contains(slug))

  test("the leaf names exactly the inspected hosts and chains to the CA"):
    val ca = createCa("proj")
    // A sample list: which hosts the leaf must name is the proxy image's to say at launch; this
    // pins the encoding — every requested name arrives as a DNS SAN, in order.
    val hosts = Vector("github.com", "gitlab.com", "docs.example.org")
    val leaf = parse(issueLeaf(ca.certificatePem, ca.privateKeyPem, hosts).certificatePem)
    val sans = leaf.getSubjectAlternativeNames.asScala.map(_.get(1).toString).toVector
    assertEquals(sans, hosts)
    assertEquals(leaf.getBasicConstraints, -1) // CA:FALSE
    val eku = leaf.getExtendedKeyUsage.asScala.toVector
    assertEquals(eku, Vector("1.3.6.1.5.5.7.3.1")) // serverAuth
    leaf.verify(parse(ca.certificatePem).getPublicKey)

  test("the chain has the key identifiers strict verifiers require"):
    // The leaf's AKI must name the CA's SKI, or matching still fails.
    val SkiOid = "2.5.29.14"
    val AkiOid = "2.5.29.35"
    val ca = createCa("proj")
    val caCert = parse(ca.certificatePem)
    val leaf = parse(issueLeaf(ca.certificatePem, ca.privateKeyPem, Vector("github.com")).certificatePem)

    val caSki = caCert.getExtensionValue(SkiOid)
    assert(caSki != null, "CA Subject Key Identifier")
    assert(leaf.getExtensionValue(SkiOid) != null, "leaf Subject Key Identifier")
    val leafAki = leaf.getExtensionValue(AkiOid)
    assert(leafAki != null, "leaf Authority Key Identifier")
    // The SKI extension value is DER octet-string wrapping; its last 20 bytes are the key id,
    // which the AKI must contain verbatim.
    val keyId = caSki.takeRight(20)
    assert(leafAki.toVector.containsSlice(keyId.toVector), "leaf AKI names the CA's key id")


  test("certificates are backdated against VM clock skew"):
    val now = Instant.now()
    val ca = parse(createCa("proj", now).certificatePem)
    assert(ca.getNotBefore.toInstant.isBefore(now.minus(4, ChronoUnit.MINUTES)))

  test("a leaf never outlives its CA"):
    val now = Instant.now()
    val shortCa = createCa("proj", now, days = 40)
    val leaf = parse(
      issueLeaf(shortCa.certificatePem, shortCa.privateKeyPem, Vector("github.com"), now).certificatePem,
    )
    val caNotAfter = parse(shortCa.certificatePem).getNotAfter
    assert(!leaf.getNotAfter.after(caNotAfter))

  test("serials are positive"):
    val ca = parse(createCa("proj").certificatePem)
    assert(ca.getSerialNumber.signum > 0)

  test("fingerprints match the openssl -fingerprint -sha256 format"):
    val fingerprint = certificateFingerprint(pemBody(createCa("proj").certificatePem))
    assert(fingerprint.matches("([0-9A-F]{2}:){31}[0-9A-F]{2}"), fingerprint)

  test("a key matches its own certificate and nothing else — mixed generations are incoherent"):
    val one = createCa("proj")
    val other = createCa("proj")
    assert(keyMatchesCertificate(one.certificatePem, one.privateKeyPem))
    assert(!keyMatchesCertificate(one.certificatePem, other.privateKeyPem))
    assert(!keyMatchesCertificate("", one.privateKeyPem))
    assert(!keyMatchesCertificate(one.certificatePem, ""))
    assert(!keyMatchesCertificate("garbage", "garbage"))

    val leaf = issueLeaf(one.certificatePem, one.privateKeyPem, Vector("github.com"))
    assert(keyMatchesCertificate(leaf.certificatePem, leaf.privateKeyPem))
    // Issuance is checked apart from correspondence.
    assert(signedBy(leaf.certificatePem, one.certificatePem))
    assert(!signedBy(leaf.certificatePem, other.certificatePem))
    assert(!signedBy(leaf.certificatePem, ""))

  test("a leaf the proxy issues from a run CA chains to it, matches its key and names its host alone"):
    // The two builders meet here: the CA BouncyCastle created on the host, the leaf the JDK's own
    // builder issued as the proxy does (X509Helper); curl in the sandbox is the third reader,
    // EgressSessionTest's.
    val ca = createCa("run-1a2b3c4d")
    val issued = agentsandbox.egress.X509Helper.issueLeaf(
      "docs.example", parse(ca.certificatePem), parseEcPrivateKey(ca.privateKeyPem),
    )
    val leafPem = toPem("CERTIFICATE", issued.certificate.getEncoded)
    assert(signedBy(leafPem, ca.certificatePem))
    assert(!signedBy(leafPem, createCa("run-1a2b3c4d").certificatePem))
    assert(keyMatchesCertificate(leafPem, toPem("PRIVATE KEY", issued.privateKey.getEncoded)))
    val leaf = parse(leafPem)
    assertEquals(leaf.getSubjectAlternativeNames.asScala.map(_.get(1).toString).toVector, Vector("docs.example"))
    assertEquals(leaf.getBasicConstraints, -1)

  test("expiring, absent and unparsable certificates all require reissue"):
    val now = Instant.now()
    val deadline = now.plusSeconds(2592000)
    val longLived = createCa("proj", now).certificatePem
    val expiring = createCa("proj", now, days = 7).certificatePem
    assert(certificateExpiresAfter(Some(longLived), deadline))
    assert(!certificateExpiresAfter(Some(expiring), deadline))
    assert(!certificateExpiresAfter(None, deadline))
    assert(!certificateExpiresAfter(Some(""), deadline))
    assert(!certificateExpiresAfter(Some("not a certificate"), deadline))
