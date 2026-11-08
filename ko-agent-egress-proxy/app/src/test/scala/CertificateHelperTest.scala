package agentsandbox.egress

import java.time.Instant

import CertificateHelper.*
import X509Helper.{createCa, issueLeaf}

class CertificateHelperTest extends munit.FunSuite:

  private val now = Instant.now()
  private val deadline = now.plusSeconds(30L * 24 * 3600)

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

  test("fingerprints match the openssl -fingerprint -sha256 format"):
    val fingerprint = certificateFingerprint(createCa("fingerprint", now, days = 825).certificate)
    assert(fingerprint.matches("([0-9A-F]{2}:){31}[0-9A-F]{2}"), fingerprint)

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

  test("expiring, absent and unparsable certificates all require reissue"):
    assert(certificateExpiresAfter(Some(createCa("long", now, days = 825).certificatePem), deadline))
    assert(!certificateExpiresAfter(Some(createCa("short", now, days = 7).certificatePem), deadline))
    assert(!certificateExpiresAfter(None, deadline))
    assert(!certificateExpiresAfter(Some(""), deadline))
    assert(!certificateExpiresAfter(Some("not a certificate"), deadline))

  test("a stored leaf serves only while it names the hosts, outlives the deadline, matches its key and its CA"):
    val ca = createCa("store", now, days = 3650)
    val hosts = Set("github.com", "gitlab.com")
    val leaf = issueLeaf(hosts.toVector.sorted, ca.certificate, ca.privateKey, now)
    def serves(
      certificate: Option[String] = Some(leaf.certificatePem),
      key: Option[String] = Some(leaf.privateKeyPem),
      names: Set[String] = hosts,
      caPem: String = ca.certificatePem,
    ): Boolean =
      leafServes(certificate, key, names, caPem, deadline)

    assert(serves())
    // A leaf names its hosts in any order, and the names compare as a set.
    val reordered = issueLeaf(Vector("gitlab.com", "github.com"), ca.certificate, ca.privateKey, now)
    assert(serves(certificate = Some(reordered.certificatePem), key = Some(reordered.privateKeyPem)))
    assert(!serves(names = hosts + "docs.example"))
    assert(!serves(names = Set("github.com")))
    assert(!serves(certificate = None))
    assert(!serves(certificate = Some("")))
    assert(!serves(key = None))
    assert(!serves(key = Some(issueLeaf(hosts.toVector, ca.certificate, ca.privateKey, now).privateKeyPem)))
    assert(!serves(caPem = createCa("replaced", now, days = 3650).certificatePem))
    val expiring = issueLeaf(hosts.toVector, ca.certificate, ca.privateKey, now, days = 7)
    assert(!serves(certificate = Some(expiring.certificatePem), key = Some(expiring.privateKeyPem)))
