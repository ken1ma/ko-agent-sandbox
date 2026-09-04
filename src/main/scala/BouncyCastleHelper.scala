package agentsandbox.launcher

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.{ECGenParameterSpec, PKCS8EncodedKeySpec}
import java.security.{KeyFactory, KeyPairGenerator, MessageDigest, PrivateKey, SecureRandom}
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{
  BasicConstraints, ExtendedKeyUsage, Extension, GeneralName, GeneralNames, KeyPurposeId, KeyUsage
}
import org.bouncycastle.cert.jcajce.{
  JcaX509CertificateConverter, JcaX509ExtensionUtils, JcaX509v3CertificateBuilder
}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/**
 * All the launcher's certificate handling: PEM, X.509 parsing,
 * fingerprints, expiry checks, minting the per-project CA and leaf.
 * Deliberately the only file that imports org.bouncycastle: replacing the
 * dependency makes this file the whole blast radius.
 */
object BouncyCastleHelper:

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
   * Whether the private key is the one this certificate's public key answers, proven by a
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

  case class Minted(certificatePem: String, privateKeyPem: String)

  def newEcKeyPair() =
    val generator = KeyPairGenerator.getInstance("EC")
    generator.initialize(ECGenParameterSpec("secp256r1"))
    generator.generateKeyPair()

  // BigInteger(1, _) is non-negative whatever the bytes; clearing the high bit keeps the DER serial at 16 octets
  // rather than the leading zero octet a set high bit would add.
  def randomSerial(): BigInteger =
    val bytes = new Array[Byte](16)
    SecureRandom().nextBytes(bytes)
    bytes(0) = (bytes(0) & 0x7f).toByte
    BigInteger(1, bytes)

  /**
   * Backdated five minutes: the certificate is verified inside a podman
   * Machine VM whose clock can sit slightly behind the host's, and a
   * notBefore in the future fails there as an unexplained TLS error.
   */
  def notBefore(now: Instant): Date = Date.from(now.minus(5, ChronoUnit.MINUTES))

  def mintCa(slug: String, now: Instant = Instant.now(), days: Long = 3650): Minted =
    val keyPair = newEcKeyPair()
    val name = X500Name(s"CN=ko-agent-sandbox egress CA ($slug)")
    val builder = JcaX509v3CertificateBuilder(
      name,
      randomSerial(),
      notBefore(now),
      Date.from(now.plus(days, ChronoUnit.DAYS)),
      name,
      keyPair.getPublic,
    )
    builder.addExtension(Extension.basicConstraints, true, BasicConstraints(0))
    builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
    // The identifier the leaf's Authority Key Identifier points at; the whys are with the leaf's.
    builder.addExtension(
      Extension.subjectKeyIdentifier,
      false,
      JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic),
    )
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate)
    val certificate = JcaX509CertificateConverter().getCertificate(builder.build(signer))
    Minted(
      toPem("CERTIFICATE", certificate.getEncoded),
      toPem("PRIVATE KEY", keyPair.getPrivate.getEncoded),
    )

  def parseEcPrivateKey(pem: String): PrivateKey =
    KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pemBody(pem)))

  /**
   * The leaf's own key, so what is mounted into the proxy cannot sign.
   * Lifetime clamped to the CA's, so a ten-year CA's last years are not a
   * launch failure; the reissue margin normally keeps the clamp inactive.
   */
  def mintLeaf(
    caCertificatePem: String,
    caPrivateKeyPem: String,
    hosts: Seq[String],
    now: Instant = Instant.now(),
    days: Long = agentsandbox.egress.X509Helper.LeafValidityDays,
  ): Minted =
    val issuer = parseCertificate(caCertificatePem)
    val issuerKey = parseEcPrivateKey(caPrivateKeyPem)
    val keyPair = newEcKeyPair()
    val requestedNotAfter = now.plus(days, ChronoUnit.DAYS)
    val issuerNotAfter = issuer.getNotAfter.toInstant
    val notAfter = if requestedNotAfter.isAfter(issuerNotAfter) then issuerNotAfter else requestedNotAfter
    val builder = JcaX509v3CertificateBuilder(
      X500Name(issuer.getSubjectX500Principal.getName),
      randomSerial(),
      notBefore(now),
      Date.from(notAfter),
      X500Name("CN=ko-agent-sandbox egress"),
      keyPair.getPublic,
    )
    val sans = GeneralNames(hosts.map(h => GeneralName(GeneralName.dNSName, h)).toArray)
    builder.addExtension(Extension.subjectAlternativeName, false, sans)
    builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
    builder.addExtension(
      Extension.keyUsage,
      true,
      KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement),
    )
    builder.addExtension(
      Extension.extendedKeyUsage,
      false,
      ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
    )
    // Strict verifiers refuse a chain without the key identifiers — OpenSSL's X509_STRICT, which
    // Python enables by default since 3.13, fails with "Missing Authority Key Identifier"
    // (measured: the image's own urllib against every inspected host). curl and apt merely
    // tolerate the omission.
    val extensionUtils = JcaX509ExtensionUtils()
    builder.addExtension(
      Extension.subjectKeyIdentifier,
      false,
      extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic),
    )
    builder.addExtension(
      Extension.authorityKeyIdentifier,
      false,
      extensionUtils.createAuthorityKeyIdentifier(issuer),
    )
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey)
    val certificate = JcaX509CertificateConverter().getCertificate(builder.build(signer))
    Minted(
      toPem("CERTIFICATE", certificate.getEncoded),
      toPem("PRIVATE KEY", keyPair.getPrivate.getEncoded),
    )
