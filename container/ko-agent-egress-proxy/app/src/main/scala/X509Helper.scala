// The certificates of TLS inspection, from one builder so that every chain has one profile: the CA
// the launcher creates for a project or a run, the leaf it issues for deny-unless-allowed's
// inspected hosts (the launcher compiles this file in; its CertificateHelper.scala calls it), and
// the leaves the proxy issues under allow-unless-denied from the run CA the launcher hands it
// (SECURITY.md, "Who holds the CA key", has the profile's exception and its trade). The
// builder is the JDK's own internal one — the classes keytool and CertificateFactory run — because
// JCA has no public certificate builder and every library that has one is a dependency neither
// program carries: BouncyCastle is 12 MB of jars, against a launcher jar of 12 MB and a native
// image that holds nothing it does not run, WildFly Elytron's `x500-cert` brings an application
// server's logging facade, and a DER encoder written here would be a second X.509 implementation
// to keep correct. The package is not exported, so the JDK major is part of this file's source
// contract: the proxy build pins its GraalVM, the launcher requires Java 25, and the
// `--add-exports` the build passes is what lets it run.

package agentsandbox.egress

import java.math.BigInteger
import java.security.{KeyPair, KeyPairGenerator, PrivateKey, PublicKey, SecureRandom}
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import sun.security.util.{KnownOIDs, ObjectIdentifier}
import sun.security.x509.*

object X509Helper:

  /** The longest validity Apple's TLS trust evaluation accepts for a server certificate from a CA
    * outside its own root store, this one included (its shipped roots are held to 398 days). The
    * run CA the launcher creates has the same, so issueLeaf's clamp ends every leaf under it when
    * the CA ends. */
  val LeafValidityDays = 825L

  /** RFC 5280's bound on a common name (ub-common-name), which the JDK's builder does not enforce. */
  val MaxCommonNameLength = 64

  private val SignatureAlgorithm = "SHA256withECDSA"

  case class IssuedCertificate(certificate: X509Certificate, privateKey: PrivateKey)

  /** A self-signed P-256 CA that signs certificates and CRLs and nothing else, with no CA below
    * it (path length 0). Its Subject Key Identifier is what a leaf's Authority Key Identifier points
    * at; the whys are with the leaf's. */
  def createCa(commonName: String, now: Instant = Instant.now(), days: Long): IssuedCertificate =
    require(
      commonName.length <= MaxCommonNameLength,
      s"the CA's common name '$commonName' is over $MaxCommonNameLength characters; shorten it",
    )
    val keyPair = newEcKeyPair()
    val name = X500Name(s"CN=$commonName")
    val extensions = CertificateExtensions()
    extensions.setExtension(BasicConstraintsExtension.NAME, BasicConstraintsExtension(true, true, 0))
    val keyUsage = KeyUsageExtension()
    keyUsage.set(KeyUsageExtension.KEY_CERTSIGN, true)
    keyUsage.set(KeyUsageExtension.CRL_SIGN, true)
    extensions.setExtension(KeyUsageExtension.NAME, keyUsage)
    extensions.setExtension(
      SubjectKeyIdentifierExtension.NAME,
      SubjectKeyIdentifierExtension(KeyIdentifier(keyPair.getPublic).getIdentifier),
    )
    val certificate =
      sign(name, keyPair.getPublic, name, keyPair.getPrivate, now, now.plus(days, ChronoUnit.DAYS), extensions)
    IssuedCertificate(certificate, keyPair.getPrivate)

  /**
   * A leaf naming `hosts` and nothing else, signed by `ca` with `caKey`: P-256, `serverAuth`, and
   * a fresh key of its own, so the leaf key the launcher mounts into the proxy under
   * deny-unless-allowed cannot issue certificates. Its lifetime is clamped to the CA's, so a
   * ten-year project CA's last years are not a launch failure; the launcher's reissue margin
   * normally keeps the clamp inactive under that CA.
   */
  def issueLeaf(
    hosts: Seq[String],
    ca: X509Certificate,
    caKey: PrivateKey,
    now: Instant = Instant.now(),
    days: Long = LeafValidityDays,
  ): IssuedCertificate =
    val keyPair = newEcKeyPair()
    val requestedNotAfter = now.plus(days, ChronoUnit.DAYS)
    val caNotAfter = ca.getNotAfter.toInstant
    val notAfter = if requestedNotAfter.isAfter(caNotAfter) then caNotAfter else requestedNotAfter

    val extensions = CertificateExtensions()
    val names = GeneralNames()
    hosts.foreach(host => names.add(GeneralName(DNSName(host))))
    extensions.setExtension(SubjectAlternativeNameExtension.NAME, SubjectAlternativeNameExtension(false, names))
    extensions.setExtension(BasicConstraintsExtension.NAME, BasicConstraintsExtension(true, false, -1))
    val keyUsage = KeyUsageExtension()
    keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true)
    keyUsage.set(KeyUsageExtension.KEY_AGREEMENT, true)
    extensions.setExtension(KeyUsageExtension.NAME, keyUsage)
    val serverAuth = java.util.Vector[ObjectIdentifier]()
    serverAuth.add(ObjectIdentifier.of(KnownOIDs.serverAuth))
    extensions.setExtension(ExtendedKeyUsageExtension.NAME, ExtendedKeyUsageExtension(serverAuth))
    // Strict verifiers refuse a chain without the key identifiers — OpenSSL's X509_STRICT, which
    // Python enables by default since 3.13, fails with "Missing Authority Key Identifier"
    // (measured: the image's own urllib against every inspected host). curl and apt merely
    // tolerate the omission.
    extensions.setExtension(
      SubjectKeyIdentifierExtension.NAME,
      SubjectKeyIdentifierExtension(KeyIdentifier(keyPair.getPublic).getIdentifier),
    )
    extensions.setExtension(
      AuthorityKeyIdentifierExtension.NAME,
      AuthorityKeyIdentifierExtension(KeyIdentifier(ca.getPublicKey), null, null),
    )

    val certificate = sign(
      X500Name("CN=ko-agent-sandbox egress"),
      keyPair.getPublic,
      X500Name(ca.getSubjectX500Principal.getEncoded),
      caKey,
      now,
      notAfter,
      extensions,
    )
    IssuedCertificate(certificate, keyPair.getPrivate)

  /**
   * Backdated five minutes: the launcher issues on the host and the sandbox verifies inside a
   * podman Machine VM whose clock can run slightly behind the host's, where a notBefore in the
   * future fails as an unexplained TLS error. The proxy issues inside that VM, and its leaves are
   * backdated only so that all leaves have one profile.
   */
  def notBefore(now: Instant): Date = Date.from(now.minus(5, ChronoUnit.MINUTES))

  private def sign(
    subject: X500Name,
    subjectKey: PublicKey,
    issuer: X500Name,
    issuerKey: PrivateKey,
    now: Instant,
    notAfter: Instant,
    extensions: CertificateExtensions,
  ): X509Certificate =
    val info = X509CertInfo()
    info.setVersion(CertificateVersion(CertificateVersion.V3))
    info.setSerialNumber(CertificateSerialNumber(randomSerial()))
    info.setAlgorithmId(CertificateAlgorithmId(AlgorithmId.get(SignatureAlgorithm)))
    info.setIssuer(issuer)
    info.setValidity(CertificateValidity(notBefore(now), Date.from(notAfter)))
    info.setSubject(subject)
    info.setKey(CertificateX509Key(subjectKey))
    info.setExtensions(extensions)
    X509CertImpl.newSigned(info, issuerKey, SignatureAlgorithm)

  def newEcKeyPair(): KeyPair =
    val generator = KeyPairGenerator.getInstance("EC")
    generator.initialize(ECGenParameterSpec("secp256r1"))
    generator.generateKeyPair()

  // BigInteger(1, _) is non-negative whatever the bytes; clearing the high bit keeps the DER serial at
  // 16 octets rather than the leading zero octet a set high bit would add.
  def randomSerial(): BigInteger =
    val bytes = new Array[Byte](16)
    SecureRandom().nextBytes(bytes)
    bytes(0) = (bytes(0) & 0x7f).toByte
    BigInteger(1, bytes)
