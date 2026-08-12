// Making JVMs trust the inspection CA: locating the image's JDK, and the trust-store merge that
// must keep every root the image shipped.

package agentsandbox.launcher

import java.security.KeyStore
import java.security.cert.{CertificateFactory, X509Certificate}

import BouncyCastleHelper.*
import JdkTrust.*

class JdkTrustTest extends munit.FunSuite:

  private def parse(pem: String): X509Certificate =
    CertificateFactory
      .getInstance("X.509")
      .generateCertificate(java.io.ByteArrayInputStream(pem.getBytes("US-ASCII")))
      .asInstanceOf[X509Certificate]

  test("the JDK's home comes from the image's own declaration, or is absent"):
    // podman image inspect prints Config.Env one entry per line. Reading JAVA_HOME from there is
    // what keeps the launcher from needing a symlink the image would have to agree to maintain.
    val env = "PATH=/usr/bin\nJAVA_HOME=/usr/lib/jvm/temurin-25-jdk-arm64\nLANG=C.UTF-8"
    assertEquals(javaHomeOf(env), Some("/usr/lib/jvm/temurin-25-jdk-arm64"))
    // An image with no JDK is an absence, not an error: nothing to merge a CA into.
    assertEquals(javaHomeOf("PATH=/usr/bin\nLANG=C.UTF-8"), None)
    assertEquals(javaHomeOf(""), None)
    assertEquals(javaHomeOf("JAVA_HOME="), None)
    // Not a prefix match on some other variable that happens to end in JAVA_HOME.
    assertEquals(javaHomeOf("XJAVA_HOME=/nope"), None)

  test("the JDK trust store gains this project's CA and keeps every root it shipped with"):
    // The JVM reads `cacerts`, not the PEM bundle, so this merge is what lets a JVM tool verify an
    // inspected forge host. Dropping a shipped root would be the silent half of getting it wrong:
    // the sandbox would keep working until something needed a public CA.
    val shipped = KeyStore.getInstance("PKCS12")
    shipped.load(null, CacertsPassword)
    shipped.setCertificateEntry("a-public-root", parse(mintCa("a-public-root").certificatePem))
    shipped.setCertificateEntry("another-root", parse(mintCa("another-root").certificatePem))
    val asShipped = java.io.ByteArrayOutputStream()
    shipped.store(asShipped, CacertsPassword)

    val ca = mintCa("proj")
    val merged = KeyStore.getInstance("PKCS12")
    merged.load(
      java.io.ByteArrayInputStream(
        mergeCacerts(asShipped.toByteArray, ca.certificatePem, "ko-agent-sandbox-egress")
      ),
      CacertsPassword
    )

    assert(merged.containsAlias("a-public-root"), "a shipped root was dropped")
    assert(merged.containsAlias("another-root"), "a shipped root was dropped")
    assertEquals(merged.getCertificate("ko-agent-sandbox-egress"), parse(ca.certificatePem))
    assertEquals(merged.size, 3)

  test("a keystore the launcher cannot read is refused rather than replaced"):
    // The store is the image's; if it arrives in a shape neither type reads, the launch has to say
    // so. Writing a fresh keystore holding only our CA would strip every public root instead.
    intercept[IllegalArgumentException]:
      mergeCacerts("not a keystore".getBytes("UTF-8"), mintCa("proj").certificatePem, "x")
