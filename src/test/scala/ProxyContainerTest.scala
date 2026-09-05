// The egress proxy's own container, inspected from the host — the half of the hardening rows that
// no session can see, because from inside the sandbox the proxy is reachable and opaque, which is
// the point of it.
//
// Opt-in like the other container-launching suites (IntegrationSession has the gate):
//
//     KO_AGENT_SANDBOX_INTEGRATION=1 sbt "testOnly *ProxyContainerTest"

package agentsandbox.launcher

import java.io.IOException
import java.net.{ServerSocket, Socket}
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference

import HostCommands.*
import IntegrationSession.*

class ProxyContainerTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(10, "min")

  test("this run's proxy is hardened, on its own networks, holding only this run's material"):
    optIn()

    val project = scratchProject()
    var session: Option[Session] = None
    try
      val live = launch(project, project.resolve("session.log"))
      session = Some(live)
      val proxy = live.proxy

      // The effective set, not the `--cap-drop` flag: podman expands `ALL` into the concrete list
      // it dropped, so asserting the flag's spelling would be asserting how the request was phrased
      // rather than what the container ended up with — the distinction doc/TODO.md's "test the
      // resulting boundary, not merely the code that asks podman to create it" is about.
      assertEquals(inspect(proxy, "{{.EffectiveCaps}}"), "[]", "effective capabilities")
      assert(
        inspect(proxy, "{{.HostConfig.SecurityOpt}}").contains("no-new-privileges"),
        s"no-new-privileges is not set: ${inspect(proxy, "{{.HostConfig.SecurityOpt}}")}",
      )
      assertEquals(inspect(proxy, "{{.HostConfig.ReadonlyRootfs}}"), "true", "read-only rootfs")
      assertEquals(inspect(proxy, "{{.HostConfig.Memory}}"), (256L << 20).toString, "memory ceiling")
      assertEquals(inspect(proxy, "{{.HostConfig.MemorySwap}}"), (256L << 20).toString, "swap ceiling")
      assertEquals(inspect(proxy, "{{json .HostConfig.Tmpfs}}"), "{}", "explicit tmpfs mounts")
      assert(
        inspect(proxy, "{{json .Config.CreateCommand}}").contains("\"--read-only-tmpfs=false\""),
        "podman's implicit writable temporary filesystems are not disabled",
      )
      assertEquals(
        inspect(proxy, "{{json .Config.Entrypoint}}"),
        "[\"/usr/local/bin/agent-egress-proxy\"]",
        "native entrypoint",
      )

      // The two builds spell the ready line separately; this session launched, so the launcher's
      // spelling was matched against the image's — asserted here so a drift fails a test and not
      // every launch, by its bound.
      val said = run(podman, "logs", proxy).err
      assert(
        said.linesIterator.exists(AgentSandboxLauncher.isProxyReadyLine),
        s"the proxy image's ready line is not the launcher's:\n$said",
      )

      // Exactly this run's two networks: the internal one it shares with its sandbox, and its own
      // route out. A proxy on any third network would be reachable from somewhere nobody chose.
      val attached = inspect(proxy, "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}}\n{{end}}")
        .linesIterator.map(_.trim).filter(_.nonEmpty).toVector.sorted
      assertEquals(attached, Vector(live.egressNetwork, live.sandboxNetwork).sorted)

      // What is mounted in: the leaf certificate and its own key, and this run's audit log. The
      // project CA's key stays on the host — "Who holds the CA key" is the whole of SECURITY.md's
      // argument — and an earlier run's log would hand this proxy a record it never wrote.
      val binds = inspect(proxy, "{{range .HostConfig.Binds}}{{println .}}{{end}}")
        .linesIterator.map(_.trim).filter(_.nonEmpty).toVector
      val sources = binds.map(_.takeWhile(_ != ':'))
      val writableMounts = inspect(proxy, "{{range .Mounts}}{{if .RW}}{{println .Destination}}{{end}}{{end}}")
        .linesIterator.map(_.trim).filter(_.nonEmpty).toVector

      assert(sources.exists(_.endsWith("leaf.crt")), s"no leaf certificate is mounted: $binds")
      assert(sources.exists(_.endsWith("leaf.key")), s"no leaf key is mounted: $binds")
      assert(!sources.contains(projectCaKey(live).toString), s"SECURITY: the CA private key is mounted: $binds")
      assert(!sources.exists(_.endsWith("ca.key")), s"a CA key is mounted under the default profile: $binds")
      assertEquals(writableMounts, Vector("/var/log/agent-egress-proxy/proxy.log"))

      val logs = sources.filter(_.endsWith(".log"))
      assertEquals(logs.size, 1, s"expected exactly this run's audit log, got $logs")
      assert(
        logs.head.contains(live.suffix),
        s"the mounted log ${logs.head} belongs to another run, not ${live.suffix}",
      )

    finally
      session.foreach(stop)
      discard(project)

  /** The project CA's key, by its path: what no proxy of any profile may mount. */
  private def projectCaKey(live: Session): java.nio.file.Path =
    AgentSandboxLauncher.tlsStateRoot(currentOs).resolve(live.id).resolve("ca.key")

  test("under allow-unless-denied the proxy holds this run's own CA and key, and no leaf"):
    optIn()

    val project = scratchProject()
    var session: Option[Session] = None
    try
      val live = launchWith(project, project.resolve("session.log"), Vector("--egress=allow-unless-denied"))
      session = Some(live)
      val sources = inspect(live.proxy, "{{range .HostConfig.Binds}}{{println .}}{{end}}")
        .linesIterator.map(_.trim).filter(_.nonEmpty).map(_.takeWhile(_ != ':')).toVector
      val runCaDir = AgentSandboxLauncher.tlsStateRoot(currentOs).resolve(live.id)
        .resolve(s"run-${live.suffix}").resolve("agent-egress-proxy").resolve("allow-unless-denied")
      assert(sources.contains(runCaDir.resolve("ca.crt").toString), s"the run CA is not mounted: $sources")
      assert(sources.contains(runCaDir.resolve("ca.key").toString), s"the run CA's key is not mounted: $sources")
      assert(!sources.contains(projectCaKey(live).toString), s"SECURITY: the project CA's key is mounted: $sources")
      assert(!sources.exists(_.endsWith("leaf.crt")), s"a leaf is mounted beside the run CA: $sources")
    finally
      session.foreach(stop)
      discard(project)

  /**
   * A CONNECT proxy on this host for the proxy container to leave through: it records each request
   * head, dials the authority itself and relays the bytes, which is an upstream proxy's whole
   * contract. Bound on every interface, since the container reaches this host by the name podman
   * gives it, never by loopback. It dials the origin directly, so this test needs a host with a
   * direct route out.
   */
  private class HostProxy:
    private val server = ServerSocket(0, 8)
    val port: Int = server.getLocalPort
    val received = AtomicReference(Vector.empty[String])
    private val accepting = Thread.startVirtualThread: () =>
      try
        while true do
          val client = server.accept()
          Thread.startVirtualThread(() => serve(client))
      catch case _: IOException => ()

    private def serve(client: Socket): Unit =
      try
        val head = agentsandbox.egress.HTTPHelper.readHttpHeader(client.getInputStream, 64 * 1024)
        received.updateAndGet(_ :+ String(head, StandardCharsets.ISO_8859_1))
        val request = agentsandbox.egress.HTTPHelper.ConnectRequest.parse(head)
        val origin = Socket(request.host, request.port)
        try
          val established = "HTTP/1.1 200 Connection established\r\n\r\n"
          client.getOutputStream.write(established.getBytes(StandardCharsets.US_ASCII))
          client.getOutputStream.flush()
          agentsandbox.egress.AgentEgressProxy.tunnel(client, origin)
        finally origin.close()
      catch case _: Exception => ()
      finally client.close()

    def close(): Unit =
      server.close()
      accepting.join()

  test("HTTPS_PROXY reaches the proxy container by name, and every origin connection leaves through it"):
    optIn()

    val upstream = HostProxy()
    val project = scratchProject()
    var session: Option[Session] = None
    try
      val endpoint = s"http://host.containers.internal:${upstream.port}"
      val value = s"http://alice:s3cret@host.containers.internal:${upstream.port}"
      val basic = "Basic " + Base64.getEncoder.encodeToString("alice:s3cret".getBytes(StandardCharsets.UTF_8))
      val live = launch(project, project.resolve("session.log"), "HTTPS_PROXY" -> value)
      session = Some(live)

      // The value-less pass-through resolved on this platform: the variable is in the proxy's
      // environment, and the create command carries its name alone.
      val environment = inspect(live.proxy, "{{range .Config.Env}}{{println .}}{{end}}")
      assert(environment.linesIterator.contains(s"HTTPS_PROXY=$value"), environment)
      val created = inspect(live.proxy, "{{json .Config.CreateCommand}}")
      assert(created.contains("\"--env=HTTPS_PROXY\"") && !created.contains("s3cret"), created)

      // The banner names the endpoint, from the proxy's own parse, and never the credential.
      val banner = live.output
      assert(banner.contains(s"egress transport: upstream proxy $endpoint -> "), banner)
      assert(!banner.contains("s3cret") && !banner.contains("alice"), banner)

      // An inspected host reached through the tunnel: opened to a numeric address, never the name,
      // with the credential on that CONNECT alone; the sandbox's own variables still name this
      // run's proxy.
      val checked = exec(live, "sandbox-egress-check", "docs.python.org")
      assert(checked.ok, s"${checked.text}\n${checked.err}")
      assert(checked.text.startsWith("CONNECT docs.python.org:443: 200; HEAD / -> HTTP/1.1"), checked.text)
      val heads = upstream.received.get
      assert(heads.nonEmpty, "the upstream proxy saw no CONNECT")
      heads.foreach: head =>
        assert(head.matches("(?s)CONNECT (\\d+\\.\\d+\\.\\d+\\.\\d+|\\[[0-9a-f:]+\\]):443 HTTP/1\\.1\\r\\n.*"), head)
        assert(!head.contains("docs.python.org"), head)
        assert(head.contains(s"Proxy-Authorization: $basic\r\n"), head)
      assertEquals(exec(live, "sh", "-c", "echo $HTTPS_PROXY").text, "http://egress-proxy:3128")

      // The audit line records the origin's address, not the upstream proxy's, and the log holds
      // the credential nowhere.
      val audit = run(podman, "logs", live.proxy).err
      assert(audit.linesIterator.exists(_.matches(".* allow docs.python.org HEAD / -> [0-9a-f.:]+")), audit)
      assert(!audit.contains("s3cret") && !audit.contains(basic), audit)
    finally
      session.foreach(stop)
      upstream.close()
      discard(project)
