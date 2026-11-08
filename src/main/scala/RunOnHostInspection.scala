// The TLS inspection files of a host proxy (SECURITY.md, "Run on host"):
//
// - the leaf certificate the proxy serves for its rules' hosts;
// - the CA certificate through which the command trusts that leaf.

package agentsandbox.launcher

import java.io.{ByteArrayOutputStream, IOException}
import java.nio.file.{Files, Path}
import java.security.KeyStore
import agentsandbox.egress.X509Helper

import FileHelper.{writePrivate, writeReadable}

object RunOnHostInspection:

  /** A path beside the proxy's log, where the proxy's profile also lies (RunOnHostProxy.proxyProfileFile). A
    * runtime's log thus names the proxy's two directories for whoever attaches to the runtime. The proxy has
    * two directories because each directory is the grant of one profile: the proxy's profile grants `leaf`, and the
    * command's profile grants `trust`. */
  private[launcher] def sibling(proxyLog: Path, suffix: String): Path =
    proxyLog.resolveSibling(proxyLog.getFileName.toString.stripSuffix(".log") + suffix)

  def leafDirectory(proxyLog: Path): Path = sibling(proxyLog, ".leaf")
  def trustDirectory(proxyLog: Path): Path = sibling(proxyLog, ".trust")

  def leafCertificate(proxyLog: Path): Path = leafDirectory(proxyLog).resolve("leaf.crt")
  def leafKey(proxyLog: Path): Path = leafDirectory(proxyLog).resolve("leaf.key")

  /** The CA certificate as PEM, for the programs that read a variable (AgentSandboxLauncher.CaBundleVariables). */
  def caBundle(trust: Path): Path = trust.resolve("ca.crt")

  /** The same certificate as a PKCS12 store, for `javax.net.ssl.trustStore`. */
  def trustStore(trust: Path): Path = trust.resolve("truststore.p12")

  /** The password is no secret: the store holds a certificate and no key, and the JDK's own `cacerts` uses the
    * same value. The command's JVMs are given the password because a JVM given none loads no certificate from a
    * PKCS12 store. JDK 25 then fails with "the trustAnchors parameter must be non-empty" (measured). */
  val TrustStorePassword = "changeit"

  /**
   * The names the proxy's leaf must have: the hosts the proxy's rules inspect, spelled as the proxy's own
   * resolution of the rules spells them.
   *
   *   - The resolution removes a trailing dot, folds case and gives a Unicode name in its ASCII form. A rule file
   *     may spell a host in any of those ways.
   *   - The proxy refuses a leaf whose names differ from its inspected set.
   *   - The JDK refuses a name with a trailing dot.
   *   - The sandbox session's leaf takes its names the same way (SECURITY.md, "Who holds the CA key").
   */
  def leafNames(ruleText: String): Either[String, Vector[String]] =
    val environment = Map(
      agentsandbox.egress.RulesetHelper.ProfileVariable -> agentsandbox.egress.RulesetHelper.DefaultProfile,
      agentsandbox.egress.RulesetHelper.RuleVariable -> ruleText,
    )
    try Right(agentsandbox.egress.AgentEgressProxy.configuredRuleset(environment.get).inspected.toVector.sorted)
    catch case ex: IllegalArgumentException => Left(proxyRulesRefusal(ex.getMessage))

  /** A refusal of the proxy's rule parser, as the launcher's messages give it. */
  def proxyRulesRefusal(reason: String): String = s"the proxy's rules: $reason"

  /**
   * Creates a CA for this proxy alone, the leaf the CA signs for `hosts`, and the CA's certificate in both trust
   * formats.
   *
   *   - This method drops the CA's key without writing it, so nothing signs a second leaf under that CA.
   *   - The sandbox container trusts a different CA. Whoever holds this leaf's key can therefore answer as the
   *     leaf's hosts to this proxy's host commands, and to nothing else.
   *   - The store and the PEM file hold the CA certificate alone. The proxy inspects every host it allows, so no
   *     origin's own certificate reaches the command.
   */
  def create(proxyLog: Path, hosts: Seq[String]): Either[String, Unit] =
    try
      val ca = InspectionCa.create("run-on-host", days = X509Helper.LeafValidityDays)
      val leaf = X509Helper.issueLeaf(hosts, ca.certificate, ca.privateKey)
      val trust = trustDirectory(proxyLog)
      Seq(leafDirectory(proxyLog), trust).foreach(Files.createDirectories(_))
      writePrivate(leafKey(proxyLog), leaf.privateKeyPem)
      writePrivate(leafCertificate(proxyLog), leaf.certificatePem)
      writeReadable(caBundle(trust), ca.certificatePem)
      val store = KeyStore.getInstance("PKCS12")
      store.load(null, null)
      store.setCertificateEntry("ko-agent-sandbox-run-on-host", ca.certificate)
      val bytes = ByteArrayOutputStream()
      store.store(bytes, TrustStorePassword.toCharArray)
      writeReadable(trustStore(trust), bytes.toByteArray)
      Right(())
    catch
      case ex: (IOException | java.security.GeneralSecurityException | IllegalArgumentException) =>
        Left(s"creating the proxy's inspection certificate: ${ex.getMessage}")
      // The JVM was started without RunOnHostSandbox.CertificateBuilderExports. IllegalAccessError is an Error, so
      // no caller's NonFatal handler takes it. A runner started without those exports logged the request and
      // nothing after it, and the requester waited out the row's 1800 s bound (measured).
      case ex: IllegalAccessError =>
        Left(
          "creating the proxy's inspection certificate: this JVM was started without " +
            s"${RunOnHostSandbox.CertificateBuilderExports.mkString(" ")}: ${ex.getMessage}",
        )
