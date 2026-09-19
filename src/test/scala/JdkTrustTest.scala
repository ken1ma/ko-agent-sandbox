// Making JVMs reach the proxy: locating the image's JDK, and the -D spelling of what
// ko-sandbox-jdk-use-proxy writes into a JDK's files. That script itself is exercised by
// SessionBoundaryTest, on the image's JDK it prepared.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import JdkTrust.*

class JdkTrustTest extends munit.FunSuite:

  test("the -D words state every fact ko-sandbox-jdk-use-proxy writes, plus the trust store"):
    // Two spellings of one route, for the JVMs that read the file and the ones that read none; a
    // key in one and not the other is a JVM that reaches the proxy and one that does not. The
    // script's spelling is read from its source: the properties block it appends is the one
    // consumed by the JDK's ProxySelector.
    val properties = proxyProperties("egress-proxy", 3128)
    val script = Files.readString(Paths.get("container/ko-agent-sandbox/ko-sandbox-jdk-use-proxy"))
    val appended = script.linesIterator
      .filter(line => line.matches("""https?\.proxy(Host|Port)=.*"""))
      .map(_.replace("$PROXY_HOST", "egress-proxy").replace("$PROXY_PORT", "3128"))
    assertEquals(appended.toVector, properties.map((key, value) => s"$key=$value"))
    val words = jdkJavaOpts("/opt/jdk", "egress-proxy", 3128).split(" ").toVector
    assertEquals(
      words,
      properties.map((key, value) => s"-D$key=$value") :+ "-Djavax.net.ssl.trustStore=/opt/jdk/lib/security/cacerts",
    )

  test("a failed ko-sandbox-jdk-use-proxy copies nothing, even into a destination the image already has"):
    assume(!scala.util.Properties.isWin, "runs the receiving shell, which a POSIX host has")
    val work = Files.createTempDirectory("jdk-prepare")
    val jdk = work.resolve("jdk")
    Files.createDirectories(jdk.resolve("lib/security"))
    Files.createDirectories(jdk.resolve("conf"))
    Files.writeString(jdk.resolve("lib/security/cacerts"), "unprepared")
    Files.writeString(jdk.resolve("conf/net.properties"), "unprepared")
    // The words podman is given after the image, with ko-sandbox-jdk-use-proxy a stub first on PATH.
    def prepare(stubExit: Int, prepared: java.nio.file.Path): Int =
      val bin = Files.createTempDirectory(work, "bin")
      val stub = Files.writeString(bin.resolve("ko-sandbox-jdk-use-proxy"), s"#!/bin/sh\nexit $stubExit\n")
      stub.toFile.setExecutable(true)
      val builder = ProcessBuilder(HostCommands.quoteFreeSh(prepareScript(prepared.toString), jdk.toString)*)
      builder.environment.put("PATH", s"$bin:${System.getenv("PATH")}")
      builder.redirectErrorStream(true).start().waitFor()
    val existing = Files.createDirectories(work.resolve("existing"))
    assertNotEquals(prepare(stubExit = 1, existing), 0)
    assertEquals(FileHelper.directoryEntries(existing), Vector.empty)
    val fresh = work.resolve("fresh")
    assertEquals(prepare(stubExit = 0, fresh), 0)
    assertEquals(
      FileHelper.directoryEntries(fresh).map(_.getFileName.toString).sorted,
      Vector("cacerts", "net.properties"),
    )

  test("the JDK's home comes from the image's own declaration, or is absent"):
    // SECURITY.md, "Who holds the CA key", has why the store is merged and why JAVA_HOME comes
    // from the image. podman image inspect prints Config.Env one entry per line.
    val env = "PATH=/usr/bin\nJAVA_HOME=/usr/lib/jvm/temurin-25-jdk-arm64\nLANG=C.UTF-8"
    assertEquals(javaHomeOf(env), Some("/usr/lib/jvm/temurin-25-jdk-arm64"))
    // An image with no JDK is an absence, not an error: nothing to merge a CA into.
    assertEquals(javaHomeOf("PATH=/usr/bin\nLANG=C.UTF-8"), None)
    assertEquals(javaHomeOf(""), None)
    assertEquals(javaHomeOf("JAVA_HOME="), None)
    // Not a prefix match on some other variable that happens to end in JAVA_HOME.
    assertEquals(javaHomeOf("XJAVA_HOME=/nope"), None)
