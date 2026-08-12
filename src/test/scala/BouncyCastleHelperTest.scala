// The certificate profile the egress proxy accepts and the sandbox verifies: minting, PEM,
// fingerprints, expiry.

package agentsandbox.launcher

import java.security.cert.{CertificateFactory, X509Certificate}
import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.jdk.CollectionConverters.*

import AgentSandboxLauncher.InspectedHosts
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
    val ca = parse(mintCa("myproj").certificatePem)
    assertEquals(ca.getBasicConstraints, 0) // CA:TRUE, pathlen 0
    val keyUsage = ca.getKeyUsage
    assert(keyUsage(5), "keyCertSign") // KeyUsage bit 5
    assert(keyUsage(6), "cRLSign") // KeyUsage bit 6
    assert(!keyUsage(0), "no digitalSignature")
    assert(ca.getSubjectX500Principal.getName.contains("myproj"))
    ca.verify(ca.getPublicKey) // self-signed

  test("the leaf carries exactly the inspected hosts and chains to the CA"):
    val ca = mintCa("proj")
    val leaf = parse(mintLeaf(ca.certificatePem, ca.privateKeyPem, InspectedHosts).certificatePem)
    val sans = leaf.getSubjectAlternativeNames.asScala.map(_.get(1).toString).toVector
    assertEquals(sans, InspectedHosts)
    assertEquals(leaf.getBasicConstraints, -1) // CA:FALSE
    val eku = leaf.getExtendedKeyUsage.asScala.toVector
    assertEquals(eku, Vector("1.3.6.1.5.5.7.3.1")) // serverAuth
    leaf.verify(parse(ca.certificatePem).getPublicKey)

  test("certificates are backdated against VM clock skew"):
    val now = Instant.now()
    val ca = parse(mintCa("proj", now).certificatePem)
    assert(ca.getNotBefore.toInstant.isBefore(now.minus(4, ChronoUnit.MINUTES)))

  test("a leaf never outlives its CA"):
    val now = Instant.now()
    val shortCa = mintCa("proj", now, days = 40)
    val leaf = parse(
      mintLeaf(shortCa.certificatePem, shortCa.privateKeyPem, InspectedHosts, now).certificatePem
    )
    val caNotAfter = parse(shortCa.certificatePem).getNotAfter
    assert(!leaf.getNotAfter.after(caNotAfter))

  test("serials are positive"):
    val ca = parse(mintCa("proj").certificatePem)
    assert(ca.getSerialNumber.signum > 0)

  test("fingerprints match the openssl -fingerprint -sha256 format"):
    val fingerprint = certificateFingerprint(pemBody(mintCa("proj").certificatePem))
    assert(fingerprint.matches("([0-9A-F]{2}:){31}[0-9A-F]{2}"), fingerprint)

  test("expiring, absent and unparsable certificates all require reissue"):
    val now = Instant.now()
    val deadline = now.plusSeconds(2592000)
    val longLived = mintCa("proj", now).certificatePem
    val expiring = mintCa("proj", now, days = 7).certificatePem
    assert(certificateCurrent(Some(longLived), deadline))
    assert(!certificateCurrent(Some(expiring), deadline))
    assert(!certificateCurrent(None, deadline))
    assert(!certificateCurrent(Some(""), deadline))
    assert(!certificateCurrent(Some("not a certificate"), deadline))
