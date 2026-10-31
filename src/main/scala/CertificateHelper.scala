package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, MessageDigest, PrivateKey}
import java.time.Instant
import agentsandbox.egress.X509Helper

/**
 * This object holds all of the launcher's certificate handling: PEM, X.509 parsing, fingerprints,
 * expiry checks, and the CAs and the leaf as the PEM text the launcher stores. X509Helper builds the
 * certificates; the launcher compiles X509Helper in from the proxy's sources.
 */
object CertificateHelper:

  /** Writes 64-character lines, each ending in `\n`, and no BOM, because the proxy parses the PEM text
    * as ASCII. */
  def toPem(label: String, der: Array[Byte]): String =
    val base64 = java.util.Base64.getEncoder.encodeToString(der)
    val body = base64.grouped(64).mkString("\n")
    s"-----BEGIN $label-----\n$body\n-----END $label-----\n"

  def pemBody(pem: String): Array[Byte] =
    val body = pem.linesIterator
      .filter(line => line.nonEmpty && !line.startsWith("-----"))
      .mkString
    java.util.Base64.getDecoder.decode(body)

  def parseCertificate(pem: String): X509Certificate =
    CertificateFactory
      .getInstance("X.509")
      .generateCertificate(java.io.ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))
      .asInstanceOf[X509Certificate]

  /** Formats the fingerprint as `openssl x509 -noout -fingerprint -sha256` prints it, so a person can
    * check the recorded value by hand. */
  def certificateFingerprint(der: Array[Byte]): String =
    java.util.HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(der))

  /** Whether the certificate expires after `deadline`. An absent, empty or unparsable certificate
    * answers false, as an expiring certificate does. */
  def certificateExpiresAfter(pem: Option[String], deadline: Instant): Boolean =
    pem.filter(_.nonEmpty).exists: text =>
      try parseCertificate(text).getNotAfter.toInstant.isAfter(deadline)
      catch case _: Exception => false

  /**
   * Whether the private key matches this certificate's public key. A sign-and-verify round trip
   * proves the match, and anything unparsable or empty answers false.
   *
   * A launch that died between writing the certificate and the key leaves a key beside a certificate
   * it does not match. The expiry check alone cannot see that state, and such a pair fails every TLS
   * handshake while it looks fine.
   */
  def keyMatchesCertificate(certificatePem: String, privateKeyPem: String): Boolean =
    try
      val certificate = parseCertificate(certificatePem)
      val key = parseEcPrivateKey(privateKeyPem)
      val probe = Array.tabulate[Byte](32)(_.toByte)
      val signer = java.security.Signature.getInstance("SHA256withECDSA")
      signer.initSign(key)
      signer.update(probe)
      val signature = signer.sign()
      val verifier = java.security.Signature.getInstance("SHA256withECDSA")
      verifier.initVerify(certificate.getPublicKey)
      verifier.update(probe)
      verifier.verify(signature)
    catch case _: Exception => false

  /** Whether `certificatePem` verifies under `issuerPem`'s public key; false on any doubt. */
  def signedBy(certificatePem: String, issuerPem: String): Boolean =
    try
      parseCertificate(certificatePem).verify(parseCertificate(issuerPem).getPublicKey)
      true
    catch case _: Exception => false

  case class CertificateMaterial(certificatePem: String, privateKeyPem: String)

  private def material(issued: X509Helper.IssuedCertificate): CertificateMaterial =
    CertificateMaterial(
      toPem("CERTIFICATE", issued.certificate.getEncoded),
      toPem("PRIVATE KEY", issued.privateKey.getEncoded),
    )

  /** `slug` names the workspace inside the CA's common name, which X509Helper.MaxCommonNameLength
    * limits. The fixed wording leaves 42 characters, room for a 32-character workspace slug. */
  def createCa(slug: String, now: Instant = Instant.now(), days: Long = 3650): CertificateMaterial =
    material(X509Helper.createCa(s"ko-agent-sandbox CA ($slug)", now, days))

  def parseEcPrivateKey(pem: String): PrivateKey =
    KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pemBody(pem)))

  def issueLeaf(
    caCertificatePem: String,
    caPrivateKeyPem: String,
    hosts: Seq[String],
    now: Instant = Instant.now(),
    days: Long = X509Helper.LeafValidityDays,
  ): CertificateMaterial =
    material(
      X509Helper.issueLeaf(hosts, parseCertificate(caCertificatePem), parseEcPrivateKey(caPrivateKeyPem), now, days),
    )
