// Making JVMs trust the egress proxy's inspection CA. A JVM reads a `cacerts` keystore, so the PEM
// bundle and the SSL_CERT_FILE family that cover everything else in the sandbox mean nothing to it.
// This file locates the image's JDK, merges the CA into that JDK's own store, and hands the launch
// the mount that puts the result back. The one JVM the launcher cannot reach — installed by the
// agent itself — gets the same CA from inside, via the image's ko-agent-sandbox-trust-ca script.
//
// Java 25's standard library alone, deliberately: KeyStore and CertificateFactory are JCA, and
// BouncyCastleHelper's contract is to be the only file that imports org.bouncycastle. What
// BouncyCastle is actually for is *building* certificates, which JCA cannot do; reading and
// storing them it can.

package agentsandbox.launcher

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.nio.file.{Files, Path}
import java.nio.file.attribute.PosixFilePermissions
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
   */
  def jdkTrustArgs(
    podman: String,
    image: String,
    imageEnv: String,
    tlsDir: Path,
    bundleStamp: String,
    caCertFile: Path
  ): Vector[String] =
    javaHomeOf(imageEnv) match
      case None => Vector.empty
      case Some(javaHome) =>
        val cacertsPath = s"$javaHome/lib/security/cacerts"
        val cacertsFile = tlsDir.resolve("cacerts")
        val cacertsStampFile = tlsDir.resolve("cacerts.stamp")

        if !Files.isRegularFile(cacertsFile) || Files.size(cacertsFile) == 0L
          || firstLine(cacertsStampFile) != bundleStamp
        then
          val imageCacerts = run(
            podman, "run", "--rm", "--pull=never", "--network=none", image, "cat", cacertsPath
          )
          if !imageCacerts.ok || imageCacerts.out.isEmpty then
            fail(s"error: could not read $cacertsPath out of $image\n${imageCacerts.err}")
          try
            Files.write(
              cacertsFile,
              mergeCacerts(imageCacerts.out, Files.readString(caCertFile), "ko-agent-sandbox-egress")
            )
            if posixPermissions(cacertsFile) then
              Files.setPosixFilePermissions(cacertsFile, PosixFilePermissions.fromString("rw-r--r--"))
            writeReadable(cacertsStampFile, bundleStamp + "\n")
          catch
            case ex: Exception =>
              fail(s"error: could not add this project's CA to the image's $cacertsPath\n$ex")

        Vector(s"--volume=$cacertsFile:$cacertsPath:ro")
