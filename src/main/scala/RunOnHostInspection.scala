// A host proxy's TLS inspection files (SECURITY.md "Run on host"): the leaf the proxy serves its
// rules' hosts with, and what the command trusts that leaf through.

package agentsandbox.launcher

import java.io.{ByteArrayOutputStream, IOException}
import java.nio.file.{Files, Path}
import java.security.KeyStore

import CertificateHelper.{createCa, issueLeaf, parseCertificate}
import FileHelper.{writePrivate, writeReadable}

object RunOnHostInspection:

  /** The proxy's two directories, siblings of its log as its profile is
    * (RunOnHostSandbox.proxyProfileFile), so a runtime's log names them for whoever attaches to
    * it. Two, because each is one profile's grant: `leaf` the proxy's, `trust` the command's. */
  private def sibling(proxyLog: Path, suffix: String): Path =
    proxyLog.resolveSibling(proxyLog.getFileName.toString.stripSuffix(".log") + suffix)

  def leafDirectory(proxyLog: Path): Path = sibling(proxyLog, ".leaf")
  def trustDirectory(proxyLog: Path): Path = sibling(proxyLog, ".trust")

  def leafCertificate(proxyLog: Path): Path = leafDirectory(proxyLog).resolve("leaf.crt")
  def leafKey(proxyLog: Path): Path = leafDirectory(proxyLog).resolve("leaf.key")

  /** The CA certificate as PEM, for the programs that read a variable (CaBundleVariables). */
  def caBundle(trust: Path): Path = trust.resolve("ca.crt")

  /** The same certificate as a PKCS12 store, for `javax.net.ssl.trustStore`. */
  def trustStore(trust: Path): Path = trust.resolve("truststore.p12")

  /** No secret: the store holds a certificate, and the value is the one the JDK's own `cacerts`
    * has. A JVM given no password loads no certificate from a PKCS12 store (measured, JDK 25:
    * "the trustAnchors parameter must be non-empty"), so the command's JVMs are given it. */
  val TrustStorePassword = "changeit"

  /** The variables that name a PEM bundle, as the sandbox container gets them (SECURITY.md, "Who
    * holds the CA key"). run-on-host.md, "The command's lifetime and environment", lists which
    * programs read each. */
  val CaBundleVariables: Vector[String] =
    Vector("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO")

  /**
   * The names the proxy's leaf must have: the hosts its rules inspect, as the proxy's own
   * resolution of those rules spells them — a trailing dot removed, case folded, a Unicode name
   * in its ASCII form. A rule file may spell a host any of those ways; the proxy refuses a leaf
   * whose names differ from its inspected set, and the JDK refuses a name with a trailing dot.
   * The sandbox session's leaf takes its names the same way (SECURITY.md, "Who holds the CA key").
   */
  def leafNames(ruleText: String): Either[String, Vector[String]] =
    val environment = Map(
      agentsandbox.egress.RulesetHelper.ProfileVariable -> agentsandbox.egress.RulesetHelper.DefaultProfile,
      agentsandbox.egress.RulesetHelper.RuleVariable -> ruleText,
    )
    try Right(agentsandbox.egress.AgentEgressProxy.configuredRuleset(environment.get).inspected.toVector.sorted)
    catch case ex: IllegalArgumentException => Left(s"the proxy's rules: ${ex.getMessage}")

  /**
   * A CA of this proxy's own, the leaf it signs for `hosts`, and the CA's certificate in both
   * trust formats. The CA's key is never written and is dropped here, so nothing signs a second
   * leaf under it; the sandbox container trusts another CA, so whoever holds this leaf's key can
   * answer as its hosts to this proxy's host commands and to nothing else. The store and the PEM
   * file hold the CA certificate alone: the proxy inspects every host it allows, so no origin's
   * own certificate reaches the command.
   */
  def create(proxyLog: Path, hosts: Seq[String]): Either[String, Unit] =
    try
      val ca = createCa("run-on-host", days = agentsandbox.egress.X509Helper.LeafValidityDays)
      val leaf = issueLeaf(ca.certificatePem, ca.privateKeyPem, hosts)
      val trust = trustDirectory(proxyLog)
      Seq(leafDirectory(proxyLog), trust).foreach(Files.createDirectories(_))
      writePrivate(leafKey(proxyLog), leaf.privateKeyPem)
      writePrivate(leafCertificate(proxyLog), leaf.certificatePem)
      writeReadable(caBundle(trust), ca.certificatePem)
      val store = KeyStore.getInstance("PKCS12")
      store.load(null, null)
      store.setCertificateEntry("ko-agent-sandbox-run-on-host", parseCertificate(ca.certificatePem))
      val bytes = ByteArrayOutputStream()
      store.store(bytes, TrustStorePassword.toCharArray)
      writeReadable(trustStore(trust), bytes.toByteArray)
      Right(())
    catch
      case ex: (IOException | java.security.GeneralSecurityException | IllegalArgumentException) =>
        Left(s"creating the proxy's inspection certificate: ${ex.getMessage}")
      // A JVM started without RunOnHostSandbox.CertificateBuilderExports. An Error, which no
      // caller's NonFatal handler takes. Measured: a broker started without them logged the
      // request and nothing after it, and the requester waited out the row's 1800 s bound.
      case ex: IllegalAccessError =>
        Left(
          "creating the proxy's inspection certificate: this JVM was started without " +
            s"${RunOnHostSandbox.CertificateBuilderExports.mkString(" ")}: ${ex.getMessage}",
        )
