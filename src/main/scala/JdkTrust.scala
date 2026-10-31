// This file makes the image's JVM trust the workspace's CA and reach the proxy.
//
// - The launcher runs the image's `ko-sandbox-jdk-use-proxy` on the image's own JDK in a throwaway
//   container.
// - The launcher then mounts the two files that the script wrote back over the JDK's own files.
// - The script's header explains why a JVM needs this and which JVMs the script is for.
// - jdkJavaOpts covers the JVMs that read neither file.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import FileHelper.*

object JdkTrust:

  /**
   * The script makes the JDK at `$1` use the proxy, then copies the JDK's two files into `prepared`.
   *
   * The steps form one `&&` chain, because `set -e` does not end a script when the left side of `&&`
   * fails. A copy placed after the chain would run after a failed ko-sandbox-jdk-use-proxy. An image
   * may ship a `prepared` directory. Where one exists, that copy would hand the launcher an unprepared
   * store, which the launcher would stamp as prepared.
   */
  def prepareScript(prepared: String): String =
    s"""set -eu
       |ko-sandbox-jdk-use-proxy "$$1" >&2 && mkdir $prepared \\
       |  && cp -L "$$1/lib/security/cacerts" "$$1/conf/net.properties" $prepared""".stripMargin

  /**
   * The JDK's home as the image itself declares it in `podman image inspect`'s `Config.Env`.
   *
   * - The launcher reads the home rather than agree on one with the image. The launcher needs a place
   *   to mount a merged trust store, and the image already says where its JDK is.
   * - A symlink at a fixed path would work too, but the symlink would be a second name to keep in step.
   * - An image of the user's own (--image) that declares a JDK must also ship
   *   ko-sandbox-jdk-use-proxy, which prepares the JDK. Without the script, the launch fails and says
   *   so, rather than mount nothing over a JDK that then cannot reach the proxy.
   *
   * None means that the image has no JVM. The absence is no error: the PEM bundle still covers
   * everything else, and there is no keystore to merge into.
   */
  def javaHomeOf(imageEnv: String): Option[String] =
    imageEnv.linesIterator
      .map(_.trim)
      .collectFirst:
        case line if line.startsWith("JAVA_HOME=") => line.stripPrefix("JAVA_HOME=")
      .filter(_.nonEmpty)

  /** The CA's path inside a container. ko-sandbox-jdk-use-proxy reads the CA there, both in a session
    * and in the launcher's throwaway run. The extension .crt follows the Linux/BSD convention; keytool
    * accepts .crt, although its examples usually use .cer. */
  val SandboxEgressProxyCaPath = "/etc/ko-agent-sandbox/egress-proxy-ca.crt"

  /**
   * The mounts that make the image's JDK trust this workspace's CA and reach the proxy.
   *
   * - The mounts apply the PEM bundle's technique to the JDK: take the image's own files, add this
   *   session's part, and mount the results back over the image's files.
   * - `ko-sandbox-jdk-use-proxy` adds the session's part. The script runs as root in a throwaway
   *   container of the image, so the image's files are writable.
   * - The cache of prepared files is keyed on everything the script consumes: the image, the CA and
   *   the proxy address.
   * - The method returns (host file, container path) pairs rather than --volume arguments, because
   *   podman mounts the launch's per-run copy of each file, not this shared cache.
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
    selinuxEnforcing: Boolean,
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
        // The script copies with `cp -L` before `podman cp` runs: the Debian Temurin packages link
        // `cacerts` into /etc/ssl/certs, and a copy out of the container must contain the store, not
        // the link.
        val prepared = "/prepared-jdk"
        val created = run(
          jdkPreparationCreateCommand(
            podman, image, caCertFile, proxyHost, proxyPort, selinuxEnforcing,
            quoteFreeSh(prepareScript(prepared), javaHome),
          )*
        )
        if !created.ok then fail(s"error: could not create a container of $image to prepare its JDK\n${created.err}")
        val container = created.text
        // The code raises the failure after it removes the container. `fail` exits the JVM, which
        // skips a `finally`, and no --reset would find the unnamed container.
        val failure =
          try
            val ran = run(podman, "start", "--attach", container)
            if !ran.ok then Some(s"error: ko-sandbox-jdk-use-proxy failed on the image's JDK at $javaHome\n${ran.err}")
            else
              files.iterator.map: (file, at) =>
                val copied = run(podman, "cp", s"$container:$prepared/${file.getFileName}", file.toString)
                Option.when(!copied.ok || !Files.isRegularFile(file) || Files.size(file) == 0L):
                  s"error: could not copy the prepared $at out of $image\n${copied.err}"
              .flatten.nextOption()
          finally run(podman, "rm", "--force", container)
        failure.foreach(message => fail(message))
        writeReadable(stampFile, stamp + "\n")

      files

  /**
   * `--entrypoint=` makes this container depend on nothing but sh and the script.
   *
   * - The stock ko-sandbox-entrypoint would work here: the entrypoint skips seeding when root, the
   *   user this container runs as, has no $HOME/persistent-volume.
   * - That guard belongs to the stock image. An --image promises only to ship
   *   ko-sandbox-jdk-use-proxy, not an ENTRYPOINT that tolerates this container or execs its
   *   arguments at all.
   * - Nothing an entrypoint does is for this container anyway.
   */
  def jdkPreparationCreateCommand(
    podman: String,
    image: String,
    caCertFile: Path,
    proxyHost: String,
    proxyPort: Int,
    selinuxEnforcing: Boolean,
    containerCommand: Vector[String],
  ): Vector[String] =
    Vector(
      podman, "create", "--pull=never", "--network=none", "--user=0", "--entrypoint=",
      fileBind(caCertFile, SandboxEgressProxyCaPath, "ro", selinuxEnforcing),
      s"--env=HTTPS_PROXY=http://$proxyHost:$proxyPort",
      image,
    ) ++ containerCommand

  /** The route, which `net.properties` cannot state for itself. The properties set `http.*` too,
    * because HTTP_PROXY is set: the proxy log then records an `http://` attempt, which would otherwise
    * fail unexplained. */
  def proxyProperties(proxyHost: String, proxyPort: Int): Vector[(String, String)] =
    Vector(
      "http.proxyHost" -> proxyHost,
      "http.proxyPort" -> proxyPort.toString,
      "https.proxyHost" -> proxyHost,
      "https.proxyPort" -> proxyPort.toString,
    )

  /** The value of KO_AGENT_SANDBOX_JAVA_OPTS: the route as `-D` options, and the image JDK's prepared
    * `cacerts` as the trust store. The value serves a JVM that reads no `conf/`, such as a native image
    * or a JDK the agent installed. The words are space-separated with no quoting, so an unquoted `$VAR`
    * in a shell splits into them. */
  def jdkJavaOpts(javaHome: String, proxyHost: String, proxyPort: Int): String =
    (proxyProperties(proxyHost, proxyPort)
      :+ ("javax.net.ssl.trustStore" -> s"$javaHome/lib/security/cacerts"))
      .map((key, value) => s"-D$key=$value").mkString(" ")
