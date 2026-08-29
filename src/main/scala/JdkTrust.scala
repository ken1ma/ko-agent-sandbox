// Making the image's JVM usable: trusting the egress proxy's inspection CA, and reaching the proxy
// at all. A JVM reads a `cacerts` keystore and a `net.properties` file, so the PEM bundle and the
// SSL_CERT_FILE / HTTPS_PROXY families that cover everything else in the sandbox mean nothing to
// it. The image ships `sandbox-jdk-use-proxy`, which writes both into one JDK from inside a
// container; the launcher runs it on the image's own JDK in a throwaway container and hands the
// launch mounts that put the two files it wrote back. The one JVM the launcher cannot reach —
// installed by the agent itself — gets the same script by hand. A GraalVM native image (the `cs`
// and `scala-cli` launchers) has neither file and reads no variable at all: it takes the same
// facts as `-D` options on its command line, which is what KO_AGENT_SANDBOX_JAVA_OPTS carries
// (jdkJavaOpts).

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*

object JdkTrust:

  /**
   * The JDK's home as the image itself declares it, out of `podman image inspect`'s `Config.Env`.
   * Read rather than agreed: the launcher needs somewhere to mount a merged trust store, and the
   * image already says where its JDK is. A symlink at a fixed path would work too and would be a
   * second name to keep in step. An image of the user's own (KO_AGENT_SANDBOX_IMAGE) that declares
   * a JDK must also ship sandbox-jdk-use-proxy, which prepares it; the launch fails saying so
   * rather than mounting nothing over a JDK that then cannot reach the proxy.
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

  /** The CA's path inside a container: sandbox-jdk-use-proxy reads it there, in a session and in
    * the launcher's throwaway run alike. Use .crt for the Linux/BSD convention; keytool accepts it
    * despite its usual .cer examples. */
  val SandboxEgressCaPath = "/etc/ko-agent-sandbox/egress-ca.crt"

  /**
   * The mounts that make the image's JDK trust this project's CA and reach the proxy — the
   * bundle's technique one layer over: take the image's own files, add this session's part, mount
   * the results back over them. The adding is `sandbox-jdk-use-proxy`'s, run in a container of the
   * image with no network, as root so the image's files are writable, with the CA mounted where a
   * session mounts it and the proxy in HTTPS_PROXY as a session has it; the two files it wrote are
   * copied out before the container goes. Where the JDK lives is the image's to say — the caller
   * hands in the image's environment (javaHomeOf) — and no JDK yields no mounts at all.
   *
   * Keyed on everything the script consumes: the image, the CA, and the address. Returned as
   * (host file, container path) pairs rather than --volume arguments, because what podman mounts
   * is the launch's per-run copy of each file, not this shared cache.
   */
  def jdkMounts(
    podman: String,
    image: String,
    imageEnv: String,
    tlsDir: Path,
    bundleStamp: String,
    caCertFile: Path,
    proxyHost: String,
    proxyPort: Int,
  ): Vector[(Path, String)] =
    javaHomeOf(imageEnv).toVector.flatMap: javaHome =>
      val cacertsPath = s"$javaHome/lib/security/cacerts"
      val netPropertiesPath = s"$javaHome/conf/net.properties"
      val files = Vector(cacertsPath, netPropertiesPath).map(at => (tlsDir.resolve(Path.of(at).getFileName), at))
      val stampFile = tlsDir.resolve("jdk.stamp")
      val stamp = s"$bundleStamp $proxyHost:$proxyPort"

      if files.exists((file, _) => !Files.isRegularFile(file) || Files.size(file) == 0L)
        || firstLine(stampFile) != stamp
      then
        // `cp -L` first: the Debian Temurin packages link `cacerts` into /etc/ssl/certs, and a copy
        // out of the container must carry the store, not the link.
        val prepared = "/prepared-jdk"
        // --entrypoint=: this container depends on nothing but sh and the script. The stock
        // sandbox-entrypoint would come through — it skips seeding when the root this runs as has
        // no $HOME/persistent-volume — but that guard is the stock image's, and a
        // KO_AGENT_SANDBOX_IMAGE promises only to ship sandbox-jdk-use-proxy, not an ENTRYPOINT
        // that tolerates this container or execs its arguments at all. Nothing an entrypoint does
        // is for this container anyway.
        val created = run(
          podman, "create", "--pull=never", "--network=none", "--user=0", "--entrypoint=",
          s"--volume=$caCertFile:$SandboxEgressCaPath:ro",
          s"--env=HTTPS_PROXY=http://$proxyHost:$proxyPort",
          image, "sh", "-euc",
          s"""sandbox-jdk-use-proxy "$$1" >&2 && mkdir $prepared"""
            + s""" && cp -L "$$1/lib/security/cacerts" "$$1/conf/net.properties" $prepared""",
          "sh", javaHome,
        )
        if !created.ok then fail(s"error: could not create a container of $image to prepare its JDK\n${created.err}")
        val container = created.text
        try
          val ran = run(podman, "start", "--attach", container)
          if !ran.ok then fail(s"error: sandbox-jdk-use-proxy failed on the image's JDK at $javaHome\n${ran.err}")
          files.foreach: (file, at) =>
            val copied = run(podman, "cp", s"$container:$prepared/${file.getFileName}", file.toString)
            if !copied.ok || !Files.isRegularFile(file) || Files.size(file) == 0L then
              fail(s"error: could not copy the prepared $at out of $image\n${copied.err}")
          writeReadable(stampFile, stamp + "\n")
        finally run(podman, "rm", "--force", container)

      files

  /** What `net.properties` cannot say for itself: the route. `http.*` too, as HTTP_PROXY is set —
    * an `http://` attempt then lands in the proxy log instead of failing unexplained. */
  def proxyProperties(proxyHost: String, proxyPort: Int): Vector[(String, String)] =
    Vector(
      "http.proxyHost" -> proxyHost,
      "http.proxyPort" -> proxyPort.toString,
      "https.proxyHost" -> proxyHost,
      "https.proxyPort" -> proxyPort.toString,
    )

  /** The value of KO_AGENT_SANDBOX_JAVA_OPTS: the route as `-D` options, and the image JDK's
    * prepared `cacerts` as the trust store, for a JVM that reads no `conf/` — a native image, or a
    * JDK the agent installed. Space-separated words with no quoting, so `$VAR` unquoted in a
    * shell splits into them. */
  def jdkJavaOpts(javaHome: String, proxyHost: String, proxyPort: Int): String =
    (proxyProperties(proxyHost, proxyPort)
      :+ ("javax.net.ssl.trustStore" -> s"$javaHome/lib/security/cacerts"))
      .map((key, value) => s"-D$key=$value").mkString(" ")
