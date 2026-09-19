package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, MessageDigest, PrivateKey}
import java.time.Instant
import agentsandbox.egress.X509Helper

/**
 * All the launcher's certificate handling: PEM, X.509 parsing, fingerprints, expiry checks, and
 * the CAs and the leaf as the PEM text the launcher stores. X509Helper, compiled in from the
 * proxy's sources, builds the certificates.
 */
object CertificateHelper:

  /** 64-character lines, always `\n`, no BOM: the proxy parses this as
    * ASCII. */
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

  /** The format `openssl x509 -noout -fingerprint -sha256` prints, so the
    * recorded value can be checked by hand. */
  def certificateFingerprint(der: Array[Byte]): String =
    MessageDigest
      .getInstance("SHA-256")
      .digest(der)
      .map(b => f"$b%02X")
      .mkString(":")

  /** Whether the certificate expires after `deadline`; an absent, empty or unparsable one
    * answers as an expiring one does. */
  def certificateExpiresAfter(pem: Option[String], deadline: Instant): Boolean =
    pem.filter(_.nonEmpty).exists: text =>
      try parseCertificate(text).getNotAfter.toInstant.isAfter(deadline)
      catch case _: Exception => false

  /**
   * Whether the private key is the one that matches this certificate's public key, proven by a
   * sign-and-verify round trip; false on anything unparsable or empty. The expiry check alone cannot
   * see a key beside a certificate it does not match — the state a launch that died between
   * writing the two leaves behind — and such a pair fails every TLS handshake while looking fine.
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

  /** `slug` names the project, and for a per-run CA its run too, inside a common name of at most
    * X509Helper.MaxCommonNameLength characters: the wording leaves 42 for a 32-character project
    * slug, a space and an 8-hex run suffix. */
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
