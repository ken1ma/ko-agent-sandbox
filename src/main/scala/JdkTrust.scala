// Making the image's JVM usable: trusting the egress proxy's inspection CA, and reaching the proxy
// at all. A JVM reads a `cacerts` keystore and a `net.properties` file, so the PEM bundle and the
// SSL_CERT_FILE / HTTPS_PROXY families that cover everything else in the sandbox mean nothing to
// it. Both halves are the same move: locate the image's JDK, take its own file, add this session's
// part, and hand the launch a mount that puts the result back. The one JVM the launcher cannot
// reach — installed by the agent itself — gets both from inside, via `sandbox-prepare-jdk`.
//
// Java 25's standard library alone, deliberately: KeyStore and CertificateFactory are JCA, and
// BouncyCastleHelper's contract is to be the only file that imports org.bouncycastle. What
// BouncyCastle is actually for is *building* certificates, which JCA cannot do; reading and
// storing them it can.

package agentsandbox.launcher

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.security.KeyStore

import BouncyCastleHelper.parseCertificate
import HostCommands.*

object JdkTrust:

  /**
   * The JDK's home as the image itself declares it, out of `podman image inspect`'s `Config.Env`.
   * Read rather than agreed: the launcher needs somewhere to mount a merged trust store, and the
   * image already says where its JDK is. A symlink at a fixed path would work too and would be a
   * second name to keep in step — and it would miss a JDK entirely if someone pointed
   * KO_AGENT_SANDBOX_IMAGE at an image of their own.
   *
   * None means no JVM in the image, which is an absence rather than an error: the PEM bundle still
   * covers everything else, and there is no keystore to merge into.
   */
  def javaHomeOf(imageEnv: String): Option[String] =
    imageEnv.linesIterator
      .map(_.trim)
      .collectFirst:
        case line if line.startsWith("JAVA_HOME=") => line.stripPrefix("JAVA_HOME=")
      .filter(_.nonEmpty)

  /** The password every JDK ships `cacerts` under. Not a secret — the store holds only public
    * certificates — and tools would not find it under any other. */
  val CacertsPassword: Array[Char] = "changeit".toCharArray

  /**
   * The image's JDK trust store with this project's CA added, written back in the format it
   * arrived in. The store's type is probed rather than assumed: a JDK's shipped `cacerts` was JKS
   * historically and is PKCS12 now, and which one a given Temurin build ships is not this
   * launcher's to pin. Whatever it was, it is written back as that, so the JVM reads what it
   * expects.
   */
  def mergeCacerts(store: Array[Byte], caCertificatePem: String, alias: String): Array[Byte] =
    val keystore = loadKeystore(store, CacertsPassword)
    keystore.setCertificateEntry(alias, parseCertificate(caCertificatePem))
    val merged = ByteArrayOutputStream()
    keystore.store(merged, CacertsPassword)
    merged.toByteArray

  private def loadKeystore(bytes: Array[Byte], password: Array[Char]): KeyStore =
    Vector("PKCS12", "JKS")
      .flatMap: kind =>
        try
          val keystore = KeyStore.getInstance(kind)
          keystore.load(ByteArrayInputStream(bytes), password)
          Some(keystore)
        catch case _: Exception => None
      .headOption
      .getOrElse(throw IllegalArgumentException("not a readable PKCS12 or JKS keystore"))

  /**
   * The mount that makes the image's JDK trust this project's CA — the bundle's technique one
   * layer over: read the image's own store, add the CA, mount the result back over it. The same
   * two inputs as the bundle, so it shares the bundle's stamp; where the store lives is the
   * image's to say — the caller hands in the image's environment, since the inspect that answers
   * the bundle's image id answers this too (javaHomeOf) — and no JDK yields no mount at all.
   * Returned as (host file, container path) rather than a --volume argument, because what podman
   * mounts is the launch's per-run copy of the file, not this shared cache.
   */
  def jdkTrustMount(
    podman: String,
    image: String,
    imageEnv: String,
    tlsDir: Path,
    bundleStamp: String,
    caCertFile: Path,
  ): Option[(Path, String)] =
    javaHomeOf(imageEnv).map: javaHome =>
      val cacertsPath = s"$javaHome/lib/security/cacerts"
      val cacertsFile = tlsDir.resolve("cacerts")
      val cacertsStampFile = tlsDir.resolve("cacerts.stamp")

      if !Files.isRegularFile(cacertsFile) || Files.size(cacertsFile) == 0L
        || firstLine(cacertsStampFile) != bundleStamp
      then
        val imageCacerts = run(
          podman, "run", "--rm", "--pull=never", "--network=none", image, "cat", cacertsPath,
        )
        if !imageCacerts.ok || imageCacerts.out.isEmpty then
          fail(s"error: could not read $cacertsPath out of $image\n${imageCacerts.err}")
        try
          writeReadable(
            cacertsFile,
            mergeCacerts(imageCacerts.out, Files.readString(caCertFile), "ko-agent-sandbox-egress"),
          )
          writeReadable(cacertsStampFile, bundleStamp + "\n")
        catch
          case ex: Exception =>
            fail(s"error: could not add this project's CA to the image's $cacertsPath\n$ex")

      (cacertsFile, cacertsPath)

  /**
   * The mount that makes the image's JDK reach the egress proxy. A JVM ignores `HTTPS_PROXY` and
   * wants `https.proxyHost`/`https.proxyPort`, which `$JAVA_HOME/conf/net.properties` supplies to
   * the default `ProxySelector` — without setting a system property, so unlike `JAVA_TOOL_OPTIONS`
   * it adds no banner to every JVM start for build output to trip over. Measured: with these lines
   * in place the selector answers the proxy and `System.getProperty("https.proxyHost")` is still
   * null.
   *
   * Appended rather than substituted into the commented-out lines a JDK ships: a properties file
   * takes the last assignment of a key, so this holds whatever the image's own file says and needs
   * no pattern to match against it. `http.nonProxyHosts` is left as shipped — it already spells
   * the loopback exemptions NO_PROXY carries.
   *
   * Keyed on the image and the address alone: unlike the trust store this has nothing per-project
   * in it, so the CA rotating does not rebuild it. (host file, container path), like
   * jdkTrustMount and for the same reason.
   */
  def jdkProxyMount(
    podman: String,
    image: String,
    imageEnv: String,
    tlsDir: Path,
    imageId: String,
    proxyHost: String,
    proxyPort: Int,
  ): Option[(Path, String)] =
    javaHomeOf(imageEnv).map: javaHome =>
      val netPropertiesPath = s"$javaHome/conf/net.properties"
      val netPropertiesFile = tlsDir.resolve("net.properties")
      val stampFile = tlsDir.resolve("net.properties.stamp")
      val stamp = s"$imageId $proxyHost:$proxyPort"

      if !Files.isRegularFile(netPropertiesFile) || Files.size(netPropertiesFile) == 0L
        || firstLine(stampFile) != stamp
      then
        val shipped = run(
          podman, "run", "--rm", "--pull=never", "--network=none", image, "cat", netPropertiesPath,
        )
        if !shipped.ok || shipped.out.isEmpty then
          fail(s"error: could not read $netPropertiesPath out of $image\n${shipped.err}")
        writeReadable(
          netPropertiesFile,
          String(shipped.out, StandardCharsets.UTF_8).stripLineEnd + "\n"
            + netProxyProperties(proxyHost, proxyPort),
        )
        writeReadable(stampFile, stamp + "\n")

      (netPropertiesFile, netPropertiesPath)

  /** The lines appended to the JDK's `net.properties`; separated so a test can read them without a
    * podman image. */
  def netProxyProperties(proxyHost: String, proxyPort: Int): String =
    s"""
       |# ko-agent-sandbox: the proxy is the only route out, and a JVM reads none of the
       |# HTTPS_PROXY family.
       |http.proxyHost=$proxyHost
       |http.proxyPort=$proxyPort
       |https.proxyHost=$proxyHost
       |https.proxyPort=$proxyPort
       |""".stripMargin
