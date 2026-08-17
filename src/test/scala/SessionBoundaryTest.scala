// The boundary as a session sees it — the half of doc/TODO.md's black-box rows whose evidence is
// inside the container rather than on the host.
//
// It runs itself: `sbt testFull` from inside a session executes it, and `assume` skips it
// everywhere else, so there is no separate command to remember. KO_AGENT_SANDBOX_EGRESS_POLICY is
// the gate because the launcher sets it for every session and nothing else does — a host checkout
// that happens to have a /workspace directory is not a session.
//
// The network checks drive `curl` and `getent` as processes rather than Java's own HTTP and TLS:
// the proxy meets those clients in practice, and a JDK client would be testing a different one.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardOpenOption}
import scala.jdk.CollectionConverters.*

import HostCommands.*

class SessionBoundaryTest extends munit.FunSuite:

  private val insideSession =
    Files.isDirectory(Paths.get("/workspace")) && env("KO_AGENT_SANDBOX_EGRESS_POLICY").isDefined

  private def inSession(): Unit =
    assume(insideSession, "not inside a sandbox session")

  private val ProxyVariables = Vector("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")

  /** HostCommands.run with the environment altered, which it deliberately does not expose. */
  private def runWithout(removed: Seq[String], command: String*): Run =
    val builder = ProcessBuilder(command*)
    removed.foreach(builder.environment().remove)
    val process = builder.start()
    process.getOutputStream.close()
    var err: Array[Byte] = Array.emptyByteArray
    val draining = Thread(() => err = process.getErrorStream.readAllBytes())
    draining.start()
    val out = process.getInputStream.readAllBytes()
    draining.join()
    Run(process.waitFor(), out, String(err, StandardCharsets.UTF_8).stripLineEnd)

  private def curl(args: String*): Run =
    run((Vector("curl", "-sS", "--max-time", "25") ++ args)*)

  /** The HTTP status, or "000" when the connection never became one — which is what a refusal at
    * the CONNECT gate looks like, as opposed to a 403 handed back inside a tunnel. */
  private def status(args: String*): String =
    curl((Vector("-o", "/dev/null", "-w", "%{http_code}") ++ args)*).text.trim

  /** `EPERM` specifically — the filter's policy denial — rather than merely "an error", which is
    * the same distinction the mounted Rust suites draw. Java surfaces `EPERM` as a bare
    * `FileSystemException`; `AccessDeniedException` is `EACCES`, a different answer that would mean
    * the tree was shaped differently than the test assumed. */
  private def deniedByPolicy(what: String)(thunk: => Any): Unit =
    val refusal = intercept[java.nio.file.FileSystemException](thunk)
    assert(
      refusal.getMessage.contains("Operation not permitted"),
      s"$what failed with '${refusal.getMessage}', but not as a policy denial (EPERM)"
    )

  private def procLines(path: String): Vector[String] =
    Files.readAllLines(Paths.get(path)).asScala.toVector

  private def field(status: String, name: String): String =
    procLines("/proc/self/status")
      .find(_.startsWith(name))
      .map(_.split("\\s+").last)
      .getOrElse(s"($name absent from $status)")

  private def mountPoints: Vector[String] =
    procLines("/proc/self/mountinfo").map(_.split(" ")(4))

  private def mountOptions(at: String): Option[String] =
    procLines("/proc/self/mountinfo").collectFirst {
      case line if line.split(" ")(4) == at => line.split(" ")(5)
    }

  test("the container is the unprivileged one the image declares"):
    inSession()
    assertEquals(run("id", "-u").text, "65532")
    assertEquals(run("id", "-g").text, "65532")
    assertEquals(field("/proc/self/status", "NoNewPrivs"), "1")

    // "All capabilities dropped" is the wrong assertion: the nesting opt-in prices exactly one, so
    // demanding an empty set fails a correctly configured nested session while missing the failure
    // that matters — a capability arriving without the variable that pays for it.
    val nesting = env(AgentSandboxLauncher.NestingVariable).getOrElse("none")
    val priced = nesting match
      case "none"     => "0000000000000000"
      case "same-uid" => "0000000000040000" // cap_sys_chroot, and only that
      case other      => fail(s"unknown nesting mode $other")
    assertEquals(field("/proc/self/status", "CapEff"), priced, s"nesting=$nesting")

    assert(mountOptions("/").exists(_.startsWith("ro")), "the root filesystem is writable")
    assertEquals(Files.readString(Paths.get("/sys/fs/cgroup/pids.max")).trim, "2048")

    env("KO_AGENT_SANDBOX_MEMORY") match
      case Some(_) =>
        assertNotEquals(Files.readString(Paths.get("/sys/fs/cgroup/memory.max")).trim, "max")
      case None => ()

  test("the network has one interface and no route off it"):
    inSession()
    val interfaces = procLines("/proc/net/dev").drop(2).count(!_.trim.startsWith("lo:"))
    assertEquals(interfaces, 1, "more than the one internal network is attached")

    // The structural reason the proxy variables are advisory: the internal network has no gateway,
    // so nothing outside its /24 is addressable at all.
    val defaultRoutes = procLines("/proc/net/route").drop(1).count(_.split("\\s+")(1) == "00000000")
    assertEquals(defaultRoutes, 0, "a default route exists")

    assert(
      Files.readString(Paths.get("/etc/hosts")).linesIterator.exists(_.endsWith("\tegress-proxy")),
      "the proxy is not named in /etc/hosts, so it is being learned from a resolver"
    )

    // NO_PROXY names exemptions rather than a proxy; every variable that does name one must name
    // this run's.
    val foreign = System.getenv().asScala.toMap
      .filter((name, _) => name.toLowerCase.endsWith("proxy"))
      .filterNot((name, _) => name.equalsIgnoreCase("NO_PROXY"))
      .filterNot((_, value) => value.contains("egress-proxy:3128"))
    assertEquals(foreign, Map.empty[String, String])

  test("unsetting the proxy variables restores nothing"):
    inSession()
    assert(!runWithout(ProxyVariables, "curl", "-sS", "--max-time", "10", "https://pypi.org/").ok)
    assert(!runWithout(ProxyVariables, "curl", "-sS", "--max-time", "10", "https://1.1.1.1/").ok)

    // The sharper form: the failure is immediate and structural, not a timeout.
    val reached =
      try
        val socket = java.net.Socket()
        try socket.connect(java.net.InetSocketAddress("1.1.1.1", 443), 5000)
        finally socket.close()
        "connected"
      catch case ex: java.io.IOException => ex.getMessage
    assertEquals(reached, "Network is unreachable")

    Vector("example.com", "secret-payload.attacker.example").foreach: name =>
      assert(!run("getent", "hosts", name).ok, s"$name resolved; a resolver is reachable")

  test("the CONNECT gate refuses everything but an allowlisted host on 443"):
    inSession()
    // A refusal here fails the CONNECT rather than answering inside a tunnel, so curl reports it
    // as an error carrying the proxy's status instead of as an HTTP code.
    Vector(
      "https://example.com/",
      "https://8.8.8.8/",
      "https://169.254.169.254/",
      "https://10.0.0.1/",
      "https://pypi.org:8443/"
    ).foreach: url =>
      val attempt = curl("-o", "/dev/null", url)
      assert(!attempt.ok, s"$url was not refused")
      assert(attempt.err.contains("403"), s"$url was refused, but not by the proxy: ${attempt.err}")

    assertEquals(status("http://pypi.org/"), "400", "plain http reached a tunnel")

  test("the two tiers are told apart by the certificate each host presents"):
    inSession()
    // The decisive in-session test for "a read-write host is still an opaque tunnel": an inspected
    // host presents a leaf this project's CA signed, an opaque one the origin's own chain.
    val ca = run("openssl", "x509", "-noout", "-subject", "-in", "/etc/ko-agent-sandbox/egress-ca.crt")
      .text.stripPrefix("subject=").trim

    // curl indents its certificate lines under the `*` marker, and by more than one space, so this
    // keys on the field name rather than on the shape of the prefix.
    def issuer(host: String): String =
      curl("-v", "-o", "/dev/null", s"https://$host/").err.linesIterator
        .map(_.trim)
        .collectFirst:
          case line if line.startsWith("*") && line.contains("issuer:") =>
            line.substring(line.indexOf("issuer:") + "issuer:".length).trim
        .getOrElse("(no issuer line)")

    Vector("pypi.org", "github.com").foreach: host =>
      assertEquals(issuer(host), ca, s"$host is not inspected")
    Vector("api.anthropic.com", "chatgpt.com").foreach: host =>
      assertNotEquals(issuer(host), ca, s"$host was inspected; the read-write tier must stay opaque")

  test("an inspected tunnel permits reading and refuses writing"):
    inSession()
    assertEquals(status("https://docs.python.org/3/"), "200")
    assertEquals(status("-X", "PUT", "https://docs.python.org/3/"), "403")
    assertEquals(status("https://github.com/"), "200")
    assertEquals(status("-X", "POST", "https://github.com/"), "403")
    assertEquals(
      status("https://github.com/git/git.git/info/refs?service=git-upload-pack"), "200",
      "fetch ref discovery"
    )
    assertEquals(
      status("https://github.com/o/r.git/info/refs?service=git-receive-pack"), "403",
      "push ref discovery"
    )
    assertEquals(status("-X", "POST", "https://api.github.com/graphql"), "403")
    assertEquals(status("-X", "POST", "https://github.com/o/r.git/info/lfs/objects/batch"), "403")
    assertEquals(
      status("-X", "POST", "-H", "Content-Type: application/json", "-d", "{}",
             "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"), "200",
      "npm's audit endpoint"
    )
    assertEquals(status("-X", "POST", "-d", "{}", "https://registry.npmjs.org/lodash"), "403")

  test("a JVM reaches an allowed host with no proxy variable of its own"):
    inSession()
    // A JVM reads none of the HTTPS_PROXY family, so the image's JDK is pointed at the proxy
    // through its own net.properties instead (JdkTrust.jdkProxyMount). Driven as a program rather
    // than asserted against the mounted file, because what matters is that the default
    // ProxySelector acts on it — and that it does so without setting a system property, which is
    // the whole reason this is not JAVA_TOOL_OPTIONS.
    val probe = Files.createTempDirectory("jvm-proxy-probe")
    try
      val source = probe.resolve("Probe.java")
      Files.writeString(
        source,
        """import java.net.*;
          |public class Probe { public static void main(String[] a) throws Exception {
          |  URI target = URI.create("https://repo1.maven.org/maven2/");
          |  var connection = (HttpURLConnection) target.toURL().openConnection();
          |  connection.setConnectTimeout(20000);
          |  connection.setReadTimeout(20000);
          |  System.out.println(ProxySelector.getDefault().select(target)
          |    + " property=" + System.getProperty("https.proxyHost")
          |    + " status=" + connection.getResponseCode());
          |}}
          |""".stripMargin
      )
      val answer = run("java", source.toString)
      assert(answer.ok, s"the probe did not run: ${answer.err}")
      assert(answer.text.contains("status=200"), s"a JVM could not reach the host: ${answer.text}")
      assert(
        answer.text.contains("property=null"),
        s"the proxy arrived as a system property, which prints a banner on every JVM: ${answer.text}"
      )
    finally deleteRecursively(probe)

  test("a git host serves an anonymous clone"):
    inSession()
    // Under /tmp, never /workspace: cloning into the workspace is refused by the filter itself,
    // which would make this a test of the wrong thing.
    val into = Files.createTempDirectory("clone-probe")
    try
      val clone = run(
        "git", "clone", "--quiet", "--depth", "1",
        "https://github.com/octocat/Hello-World.git", into.resolve("repo").toString
      )
      assert(clone.ok, s"an anonymous clone failed: ${clone.err}")
    finally deleteRecursively(into)

  test("the workspace is filtered, writable, and its policy directory is not"):
    inSession()
    val filtered = run("stat", "-f", "-c", "%T", "/workspace").text == "fuse"

    val work = Files.createTempDirectory(Paths.get("/workspace"), ".boundary-test-")
    try
      Files.writeString(work.resolve("ordinary"), "x")
      assert(Files.exists(work.resolve("ordinary")), "/workspace is not writable")

      if filtered then
        val deep = Files.createDirectories(work.resolve("deep/nested"))
        Vector(work, deep).foreach: at =>
          deniedByPolicy(s"creating .git under ${at.getFileName}"):
            Files.createDirectory(at.resolve(".git"))

        val config = Paths.get("/workspace/.git/config")
        if Files.exists(config) then
          // Appending nothing rather than truncating: the question is whether a write is
          // permitted, and asking it must not perform one on the user's own repository.
          deniedByPolicy("opening this repository's .git/config for writing"):
            Files.newOutputStream(config, StandardOpenOption.APPEND).close()
    finally deleteRecursively(work)

  test("the policy directory is mounted read-only over the workspace"):
    inSession()
    // Its own test, and asserted through the mount table first. A different mechanism from the rest
    // of the workspace, so a different answer: `.ko-agent-sandbox` is refused by the read-only bind
    // the launcher lays over it, not by the filter's policy. The mount table is what says the
    // launcher established that bind — the only evidence that separates "this session has the
    // boundary" from "this session ran a launcher that never built it", which no probe of the path
    // can tell apart.
    val policyDir = "/workspace/.ko-agent-sandbox"
    val options = mountOptions(policyDir)
    assert(options.nonEmpty, s"required policy mount absent: nothing is mounted at $policyDir")
    assert(
      options.exists(_.split(",").contains("ro")),
      s"the policy mount is not read-only: ${options.get}"
    )

    // Reachable as well as mounted. A host that deletes the source under a live session leaves the
    // mount in the table and the path unresolvable, since /workspace is served by the filter and
    // the name is looked up in the backing tree on every access — `git clean -xdf` on the host does
    // exactly this. The boundary still holds (creating the name is refused too), but the session is
    // no longer running what it was launched with, and that is a fact to report rather than skip.
    assert(
      Files.isDirectory(Paths.get(policyDir)),
      s"$policyDir is mounted but does not resolve: its host source was removed mid-session"
    )
    val readOnly = intercept[java.nio.file.FileSystemException]:
      Files.newOutputStream(Paths.get(s"$policyDir/probe")).close()
    assert(
      readOnly.getMessage.contains("Read-only file system"),
      s"the policy directory refused a write with '${readOnly.getMessage}', not as a read-only mount"
    )

  test("no host path is mounted into the session beyond the launcher's set"):
    inSession()
    // Existence proves nothing — the session's home is its own writable volume, and any tool it
    // runs may create `.config` there. What matters is whether a host path was *mounted*.
    val home = env("HOME").getOrElse("/home/nonroot")
    Vector(s"$home/.ssh", s"$home/.aws", s"$home/.config",
           "/var/run/docker.sock", "/run/podman/podman.sock")
      .foreach(path => assert(!mountPoints.contains(path), s"$path is mounted into the session"))

    val expected =
      raw"^/$$|^/(proc|sys|dev|run|tmp|var/tmp|workspace|home/nonroot)($$|/)".r.unanchored
    // `/etc/ssl/certs` covers two mounts, not one: the PEM bundle, and the merged JDK trust store —
    // which the launcher mounts at `$JAVA_HOME/lib/security/cacerts` (JdkTrust) but which lands
    // here, because Temurin's Debian packaging symlinks that path to
    // /etc/ssl/certs/adoptium/cacerts and podman resolves a bind target before mounting it.
    val alsoExpected =
      raw"^/etc/(hosts|hostname|resolv\.conf)$$|^/etc/(ko-agent-sandbox|ssl/certs)($$|/)".r.unanchored
    // The JDK's proxy configuration, the other half of jdkTrustMount's technique. Unlike `cacerts`
    // this one is a real file, so its mount stays where the launcher put it and is named from
    // JAVA_HOME rather than matched by a fixed prefix.
    val netProperties = env("JAVA_HOME").map(_ + "/conf/net.properties")
    val unexpected = mountPoints.distinct.filterNot: at =>
      expected.matches(at) || alsoExpected.matches(at) || netProperties.contains(at)
    assertEquals(unexpected, Vector.empty[String], "a mount outside the launcher's set is present")

  test("no private key is mounted into the session"):
    inSession()
    // The certificate this session trusts is public by construction; the key that signs with it
    // stays on the host.
    //
    // Listed rather than walked, and every entry accounted for: a mount whose host source the user
    // removed mid-session leaves the name in place but unresolvable, which a walk reports as an
    // opaque UncheckedIOException. Naming it is the same diagnosis the policy-directory test above
    // gives, and refusing to skip it is what keeps this assertion about every file that is there.
    val entries = Files.list(Paths.get("/etc/ko-agent-sandbox")).iterator().asScala.toVector
    val unresolvable = entries.filterNot(Files.exists(_))
    assertEquals(
      unresolvable, Vector.empty[Path],
      "mounted but does not resolve: the host source was removed mid-session"
    )
    val material = entries
      .filter(Files.isRegularFile(_))
      .filter(path => Files.readString(path).contains("PRIVATE KEY"))
    assertEquals(material, Vector.empty[Path])
