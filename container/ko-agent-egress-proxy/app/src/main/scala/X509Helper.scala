// Leaf certificates minted in the proxy, under allow-unless-denied, from the run CA the launcher
// hands it (SECURITY.md, "Who holds the CA key", has the profile's exception and its trade). The
// builder is the JDK's own internal one — the classes keytool and CertificateFactory run — because
// JCA has no public certificate builder and every library that has one is a dependency this image
// does not carry: BouncyCastle is 12 MB of jars in a native image that holds nothing it does not
// run, WildFly Elytron's `x500-cert` brings an application server's logging facade, and a DER
// encoder written here would be a second X.509 implementation to keep correct. The package is not
// exported, so the JDK major is part of this file's source contract: the proxy build pins its
// GraalVM, the launcher requires Java 25, and the `--add-exports` the build passes is what lets it
// run.

package agentsandbox.egress

import java.math.BigInteger
import java.security.{KeyPair, KeyPairGenerator, PrivateKey, SecureRandom}
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import sun.security.util.{KnownOIDs, ObjectIdentifier}
import sun.security.x509.*

object X509Helper:

  /** The longest validity Apple's TLS trust evaluation accepts for a server certificate from a CA
    * outside its own root store, this one included (its shipped roots are held to 398 days); the
    * run CA the launcher mints has the same, so the clamp to the CA's end below is inactive. */
  val LeafValidityDays = 825L

  case class MintedLeaf(certificate: X509Certificate, privateKey: PrivateKey)

  /**
   * A leaf naming `host` and nothing else, signed by `ca` with `caKey`: P-256, `SHA256withECDSA`,
   * `serverAuth`, its own fresh key. The extensions are the launcher's leaf's
   * (BouncyCastleHelper.mintLeaf), key identifiers included: strict verifiers refuse a chain
   * without them.
   */
  def mintLeaf(host: String, ca: X509Certificate, caKey: PrivateKey, now: Instant = Instant.now()): MintedLeaf =
    val keyPair = newEcKeyPair()
    val requestedNotAfter = now.plus(LeafValidityDays, ChronoUnit.DAYS)
    val caNotAfter = ca.getNotAfter.toInstant
    val notAfter = if requestedNotAfter.isAfter(caNotAfter) then caNotAfter else requestedNotAfter

    val info = X509CertInfo()
    info.setVersion(CertificateVersion(CertificateVersion.V3))
    info.setSerialNumber(CertificateSerialNumber(randomSerial()))
    info.setAlgorithmId(CertificateAlgorithmId(AlgorithmId.get("SHA256withECDSA")))
    info.setIssuer(X500Name(ca.getSubjectX500Principal.getEncoded))
    info.setValidity(CertificateValidity(Date.from(now), Date.from(notAfter)))
    info.setSubject(X500Name("CN=ko-agent-sandbox egress"))
    info.setKey(CertificateX509Key(keyPair.getPublic))

    val extensions = CertificateExtensions()
    extensions.setExtension(
      SubjectAlternativeNameExtension.NAME,
      SubjectAlternativeNameExtension(false, GeneralNames().add(GeneralName(DNSName(host)))),
    )
    extensions.setExtension(BasicConstraintsExtension.NAME, BasicConstraintsExtension(true, false, -1))
    val keyUsage = KeyUsageExtension()
    keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true)
    keyUsage.set(KeyUsageExtension.KEY_AGREEMENT, true)
    extensions.setExtension(KeyUsageExtension.NAME, keyUsage)
    val serverAuth = java.util.Vector[ObjectIdentifier]()
    serverAuth.add(ObjectIdentifier.of(KnownOIDs.serverAuth))
    extensions.setExtension(ExtendedKeyUsageExtension.NAME, ExtendedKeyUsageExtension(serverAuth))
    extensions.setExtension(
      SubjectKeyIdentifierExtension.NAME,
      SubjectKeyIdentifierExtension(KeyIdentifier(keyPair.getPublic).getIdentifier),
    )
    extensions.setExtension(
      AuthorityKeyIdentifierExtension.NAME,
      AuthorityKeyIdentifierExtension(KeyIdentifier(ca.getPublicKey), null, null),
    )
    info.setExtensions(extensions)

    MintedLeaf(X509CertImpl.newSigned(info, caKey, "SHA256withECDSA"), keyPair.getPrivate)

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
