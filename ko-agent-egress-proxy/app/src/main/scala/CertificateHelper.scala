// The certificates of TLS inspection as PEM text: parsing, writing, and the checks that decide whether a stored leaf
// still serves. Both the proxy, which loads its leaf, and whoever issues that leaf use this file.
//
// X509Helper builds the certificates with the JDK's internal builder. This file stays outside that module boundary,
// so the proxy's own code path, which reaches this file and never X509Helper, needs no `--add-exports`
// (ko-agent-egress-proxy/app/build.sbt).

package agentsandbox.egress

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.{KeyFactory, MessageDigest, PrivateKey}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.{Base64, Locale}
import scala.jdk.CollectionConverters.*
import scala.util.control.NonFatal

object CertificateHelper:

  /** Writes 64-character lines, each ending in `\n`, and no BOM, because readers parse the PEM text as ASCII. */
  def toPem(label: String, der: Array[Byte]): String =
    val body = Base64.getEncoder.encodeToString(der).grouped(64).mkString("\n")
    s"-----BEGIN $label-----\n$body\n-----END $label-----\n"

  /** Every certificate in `pem`, in order. `source` names the text in the error. */
  def parseCertificateChain(pem: Array[Byte], source: String): Vector[X509Certificate] =
    val certificates =
      CertificateFactory
        .getInstance("X.509")
        .generateCertificates(ByteArrayInputStream(pem))
        .asScala
        .toVector
        .collect { case certificate: X509Certificate => certificate }

    if certificates.isEmpty then
      throw IllegalArgumentException(s"$source holds no X.509 certificate")

    certificates

  def parseCertificate(pem: String): X509Certificate =
    parseCertificateChain(pem.getBytes(StandardCharsets.US_ASCII), "the PEM text").head

  /**
   * An unencrypted PKCS#8 key, which is what JCA's `getEncoded` produces. The PEM header does not name the
   * algorithm, so the candidates are tried in turn rather than guessed from the text. `source` names the text in the
   * error.
   */
  def parsePrivateKey(pem: String, source: String): PrivateKey =
    val begin = "-----BEGIN PRIVATE KEY-----"
    val end = "-----END PRIVATE KEY-----"

    val start = pem.indexOf(begin)
    val stop = pem.indexOf(end)

    if start < 0 || stop < start then
      throw IllegalArgumentException(s"$source is not an unencrypted PKCS#8 private key")

    val spec = PKCS8EncodedKeySpec(Base64.getMimeDecoder.decode(pem.substring(start + begin.length, stop)))

    Vector("EC", "RSA", "Ed25519")
      .flatMap: algorithm =>
        try Some(KeyFactory.getInstance(algorithm).generatePrivate(spec))
        catch case NonFatal(_) => None
      .headOption
      .getOrElse(throw IllegalArgumentException(s"$source holds an unsupported key type"))

  /** Formats the fingerprint as `openssl x509 -noout -fingerprint -sha256` prints it, so a person can check the
    * recorded value by hand. */
  def certificateFingerprint(certificate: X509Certificate): String =
    java.util.HexFormat.ofDelimiter(":").withUpperCase()
      .formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded))

  /** Whether the certificate expires after `deadline`. An absent, empty or unparsable certificate answers false, as
    * an expiring certificate does. */
  def certificateExpiresAfter(pem: Option[String], deadline: Instant): Boolean =
    pem.filter(_.nonEmpty).exists: text =>
      try parseCertificate(text).getNotAfter.toInstant.isAfter(deadline)
      catch case NonFatal(_) => false

  /**
   * Whether the private key matches this certificate's public key, for the P-256 keys that X509Helper issues. A
   * sign-and-verify round trip proves the match, and anything unparsable or empty answers false.
   *
   * A writer that died between writing the certificate and the key leaves a key beside a certificate it does not
   * match. The expiry check alone cannot see that state, and such a pair fails every TLS handshake while it looks
   * fine.
   */
  def keyMatchesCertificate(certificatePem: String, privateKeyPem: String): Boolean =
    try keyMatches(parseCertificate(certificatePem), parsePrivateKey(privateKeyPem, "the key"))
    catch case NonFatal(_) => false

  private def keyMatches(certificate: X509Certificate, key: PrivateKey): Boolean =
    try
      val probe = Array.tabulate[Byte](32)(_.toByte)
      val signer = java.security.Signature.getInstance("SHA256withECDSA")
      signer.initSign(key)
      signer.update(probe)
      val signature = signer.sign()
      val verifier = java.security.Signature.getInstance("SHA256withECDSA")
      verifier.initVerify(certificate.getPublicKey)
      verifier.update(probe)
      verifier.verify(signature)
    catch case NonFatal(_) => false

  /** Whether `certificatePem` verifies under `issuerPem`'s public key; false on any doubt. */
  def signedBy(certificatePem: String, issuerPem: String): Boolean =
    try verifiesUnder(parseCertificate(certificatePem), parseCertificate(issuerPem))
    catch case NonFatal(_) => false

  private def verifiesUnder(certificate: X509Certificate, issuer: X509Certificate): Boolean =
    try
      certificate.verify(issuer.getPublicKey)
      true
    catch case NonFatal(_) => false

  def subjectAlternativeNames(certificate: X509Certificate): Set[String] =
    val DnsName = 2

    Option(certificate.getSubjectAlternativeNames) match
      case None => Set.empty
      case Some(names) =>
        names.asScala.toVector
          .collect:
            case entry if entry.size == 2 && entry.get(0) == DnsName =>
              entry.get(1).toString.toLowerCase(Locale.ROOT)
          .toSet

  /** Why a leaf naming `covered` does not match a ruleset inspecting `required` (SECURITY.md, "Who holds the CA
    * key"). */
  def inspectedNamesError(covered: Set[String], required: Set[String]): Option[String] =
    if covered == required then None
    else
      val missing = (required -- covered).toVector.sorted
      val extra = (covered -- required).toVector.sorted
      val reasons =
        Option.when(missing.nonEmpty)(s"does not cover ${missing.mkString(" ")}") ++
          Option.when(extra.nonEmpty)(
            s"names ${extra.mkString(" ")}, which this proxy does not inspect",
          )
      Some(s"must name exactly the hosts this ruleset inspects; it ${reasons.mkString(", and ")}")

  /**
   * Whether a stored leaf can keep serving `hosts` past `deadline`: it names exactly those hosts, matches its key,
   * and verifies under the CA `caCertificatePem`. A leaf issued under a CA since replaced is internally consistent
   * and still fails every handshake, so the chain test is needed beside the key test.
   */
  def leafServes(
    certificatePem: Option[String],
    privateKeyPem: Option[String],
    hosts: Set[String],
    caCertificatePem: String,
    deadline: Instant,
  ): Boolean =
    (certificatePem.filter(_.nonEmpty), privateKeyPem) match
      case (Some(certificateText), Some(keyText)) =>
        try
          val certificate = parseCertificate(certificateText)
          certificate.getNotAfter.toInstant.isAfter(deadline)
            && inspectedNamesError(subjectAlternativeNames(certificate), hosts).isEmpty
            && keyMatches(certificate, parsePrivateKey(keyText, "the key"))
            && verifiesUnder(certificate, parseCertificate(caCertificatePem))
        catch case NonFatal(_) => false
      case _ => false
