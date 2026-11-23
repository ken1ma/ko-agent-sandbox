package agentsandbox.egress

import java.time.Instant

import CertificateHelper.*
import X509Helper.{createCa, issueLeaf}

class CertificateHelperTest extends munit.FunSuite:

  private val now = Instant.now()

  test("PEM bodies wrap at 64 characters and round-trip through the parser"):
    val ca = createCa("pem", now, days = 825)
    val pem = ca.certificatePem
    val lines = pem.linesIterator.toVector
    assertEquals(lines.head, "-----BEGIN CERTIFICATE-----")
    assertEquals(lines.last, "-----END CERTIFICATE-----")
    assert(lines.tail.init.forall(_.length <= 64))
    assert(pem.endsWith("-----\n"))
    assert(!pem.contains("\r"))
    assertEquals(parseCertificate(pem), ca.certificate)
    assertEquals(parsePrivateKey(ca.privateKeyPem, "the key"), ca.privateKey)

  test("an empty text holds no certificate, and a key needs its PKCS#8 header"):
    val noCertificate = intercept[IllegalArgumentException](parseCertificateChain(Array.emptyByteArray, "leaf.crt"))
    assertEquals(noCertificate.getMessage, "leaf.crt holds no X.509 certificate")
    val noKey = intercept[IllegalArgumentException](parsePrivateKey("garbage", "leaf.key"))
    assertEquals(noKey.getMessage, "leaf.key is not an unencrypted PKCS#8 private key")

  test("serials are positive"):
    assert(createCa("serial", now, days = 825).certificate.getSerialNumber.signum > 0)

  test("a key matches its own certificate and nothing else, and a leaf verifies under its CA alone"):
    val one = createCa("one", now, days = 825)
    val other = createCa("other", now, days = 825)
    assert(keyMatchesCertificate(one.certificatePem, one.privateKeyPem))
    assert(!keyMatchesCertificate(one.certificatePem, other.privateKeyPem))
    assert(!keyMatchesCertificate("", one.privateKeyPem))
    assert(!keyMatchesCertificate(one.certificatePem, ""))
    assert(!keyMatchesCertificate("garbage", "garbage"))

    val leaf = issueLeaf(Vector("github.com"), one.certificate, one.privateKey, now)
    assert(signedBy(leaf.certificatePem, one.certificatePem))
    assert(!signedBy(leaf.certificatePem, other.certificatePem))
    assert(!signedBy(leaf.certificatePem, ""))
