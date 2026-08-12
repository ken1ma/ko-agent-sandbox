// The egress proxy: policy, connection handling, and the flow from CONNECT to tunnel. The HTTP surface lives in
// HTTPHelper.scala, the TLS surface in TLSHelper.scala, git protocol knowledge in GitHelper.scala, and hostname/address
// vetting in IPAddrHelper.scala.

package agentsandbox.egress

import java.io.{FileOutputStream, IOException, InputStream, OutputStream, PrintStream}
import java.net.{InetAddress, InetSocketAddress, ServerSocket, Socket, SocketException}
import java.nio.file.Path
import java.security.GeneralSecurityException
import java.util.concurrent.{CountDownLatch, Executors, Semaphore}
import javax.net.ssl.SSLSocket
import scala.annotation.tailrec
import scala.util.control.NonFatal

import GitHelper.*
import HTTPHelper.*
import IPAddrHelper.*
import TLSHelper.*

object AgentEgressProxy:

  val ListenPort = 3128
  val ConnectTimeoutMillis = 10_000
  val HandshakeTimeoutMillis = 10_000
  val MaxHttpHeaderBytes = 16 * 1024
  val MaxClientHelloBytes = 64 * 1024
  val MaxConcurrentConnections = 256

  /*
   * An inspected session is one HTTP request and its response, so this bounds
   * inactivity rather than total duration: a `git clone` of a large repository
   * transfers continuously and never approaches it, while GitHub counting
   * objects before the first byte can legitimately take minutes.
   */
  val InspectedIdleTimeoutMillis = 300_000

  /*
   * Exact hostnames only. Deliberately no regex or wildcard matching.
   *
   * Every allowed host is a GET-based exfiltration channel: a permitted GET carries its URL, and a URL is a message.
   *
   * The forge hosts are read access to GitHub, GitLab and Codeberg: agents
   * routinely read issues, release notes and upstream sources from them.
   * Unlike every other entry here they are not opaque tunnels — they are in
   * DefaultInspectedHosts below, so the proxy terminates TLS and admits only
   * the requests that reading needs. `git push` is refused inside the tunnel
   * rather than merely being expected to fail for want of a credential.
   *
   * A project whose checkout holds a forge token should still remove that
   * forge's hosts in its own .ko-agent-sandbox/egress-hosts: inspection bounds
   * the method and the path, not what a permitted GET can be pointed at.
   *
   * This is the default, not the last word: EGRESS_ALLOWED_HOSTS overrides
   * it — a whole replacement list, or a +/- delta against it (resolvePolicy
   * below) — so the operator can widen or narrow the policy per project
   * through .ko-agent-sandbox/egress-hosts without rebuilding the image.
   * Whichever list is in force is printed at startup and every denial is
   * logged, which is how you find out what an agent actually wanted.
   *
   * Before adding a host here, answer all five: why does an arbitrary
   * project need it by default; what sandbox data could be sent to it; does
   * it expose an unauthenticated write endpoint; is an opaque tunnel
   * acceptable, or does it need protocol-aware inspection; and could it be
   * project-specific (egress-hosts) instead? This list should stay a small
   * set of intentional data recipients, never grow by accumulation.
   */
  val DefaultAllowedHosts: Set[String] =
    Set(
      // Claude Code
      "api.anthropic.com",  // model traffic
      "claude.ai", "platform.claude.com",  // for interactive login

      // Codex
      "api.openai.com",   //  API-key use
      "auth.openai.com",  // issues the device code and the tokens
      "chatgpt.com",      // model traffic for a ChatGPT plan
      // ab.chatgpt.com — A/B configuration and telemetry — is absent: codex works without it, and a refusal is a log
      // line here, never a silent gap.

      // Antigravity
      "accounts.google.com",          // printed sign-in URL
      "oauth2.googleapis.com",        // exchanges the pasted code and refreshes tokens
      "cloudcode-pa.googleapis.com",  // model traffic and account state
      // play.googleapis.com — telemetry and experiment polling — is absent for the same reason ab.chatgpt.com is.

      // public documents / repositories
      "www.rfc-editor.org",
      "www.w3.org",
      "developer.mozilla.org",  // HTTP / HTML / CSS / JavaScript / Web APIs
      // WHATWG specs are per-spec subdomains; a project adds the exact host it reads (+html.spec.whatwg.org)

      "www.scala-lang.org",
      "docs.scala-lang.org",

      "http4s.org",
      "fs2.io",
      "typelevel.org",

      "www.scala-sbt.org",
      "mill-build.org",
      "get-coursier.io",
      "docs.gradle.org",
      "services.gradle.org",  // gradlew
      "plugins.gradle.org",
      // api.adoptium.net (`cs java` fetching an extra JDK) is not needed: the image bakes its Temurin in

      "scala-cli.virtuslab.org",
      "scalameta.org",
      "javadoc.io",

      "docs.oracle.com",
      "openjdk.org",  // JEPs
      "repo.maven.apache.org",  // provides javadoc too
      "repo1.maven.org",

      "developer.android.com",
      "kotlinlang.org",
      "developer.apple.com",
      "www.swift.org",
      "docs.swift.org",  // the Swift book
      // mobile references only; builds stay outside — no Android SDK in the image (dl.google.com absent), and Xcode
      // needs macOS

      "doc.rust-lang.org",
      "docs.rs",
      "crates.io",         // package pages and cargo search
      "index.crates.io",   // cargo's sparse registry index
      "static.crates.io",  // crate downloads

      "docs.astral.sh",  // uv
      "docs.python.org",
      "pypi.org",
      "files.pythonhosted.org",

      "nodejs.org",
      "www.typescriptlang.org",
      "registry.npmjs.org",
      // docs.npmjs.com is declined: npm's supply-chain record does not earn optional entries

      "go.dev",
      "pkg.go.dev",
      // the Go toolchain waits on an image block plus proxy.golang.org

      "www.postgresql.org",
      "www.sqlite.org",

      "docs.aws.amazon.com",  // AWS
      "cloud.google.com",     // GCP
      "learn.microsoft.com",  // Azure

      "kubernetes.io",
      "containerd.io",
      "docs.podman.io",
      "docs.docker.com",

      "git-scm.com",
      "man7.org",
      "manpages.debian.org",
      "deb.debian.org",  // apt package

      "www.pulumi.com",
      "registry.terraform.io",  // provider docs, and the API `terraform init` queries
      "developer.hashicorp.com",
      // provider binaries (releases.hashicorp.com, get.pulumi.com) wait for a real need
      "docs.spring.io",

      // forges: TLS-inspected, read-only — see DefaultInspectedHosts.
      "github.com",
      "raw.githubusercontent.com",
      "objects.githubusercontent.com",
      "codeload.github.com",
      "api.github.com",
      "codeberg.org",
      "gitlab.com",

      // GitHub content hosts serving pre-signed GETs: opaque tunnels, deliberately not TLS inspected
      "release-assets.githubusercontent.com",  // release downloads
      "media.githubusercontent.com",  // LFS files, one URL per file
    ).map(normalizeHost)

  /*
   * The hosts whose TLS this proxy terminates, so that it can allow reading
   * and refuse writing. Everything else in the allowlist stays an opaque
   * tunnel, deliberately: api.anthropic.com carries the conversation by
   * design, and a package registry gains nothing from being read in clear.
   *
   * These seven are the ones where the shortest path out of /workspace lives
   * — `git push`, an issue comment, a gist — and where reading is exactly the
   * thing that has to keep working. What is permitted once TLS is terminated
   * is in authorizeInspectedRequest.
   *
   * Inspection is off unless the launcher supplies a certificate and key
   * covering these names; see TlsInspection. The effective set is this list
   * intersected with the allowlist in force, so removing a forge from a
   * project's .ko-agent-sandbox/egress-hosts removes it from here too rather
   * than leaving a rule for a host that can no longer be reached.
   *
   * The launcher (AgentSandboxLauncher.scala, in the repository root's
   * src/) names these
   * same hosts when it mints the leaf certificate's subjectAltName list. The
   * two lists have to agree exactly, and TlsInspection.load refuses to start
   * when they differ in either direction: a leaf missing a name would be a
   * TLS error inside the sandbox that nobody can explain, and a leaf naming
   * a host absent here would leave a host the launcher meant to inspect as
   * an opaque, writable tunnel.
   */
  val DefaultInspectedHosts: Set[String] =
    Set(
      "github.com",
      "raw.githubusercontent.com",
      "objects.githubusercontent.com",
      "codeload.github.com",
      "api.github.com",
      "codeberg.org",
      "gitlab.com",
    ).map(normalizeHost)

  val AllowedHostsVariable = "EGRESS_ALLOWED_HOSTS"
  val CertificateVariable = "EGRESS_TLS_CERTIFICATE"
  val PrivateKeyVariable = "EGRESS_TLS_PRIVATE_KEY"
  val LogFileVariable = "EGRESS_LOG_FILE"

  val executor = Executors.newVirtualThreadPerTaskExecutor()
  val connectionSlots = Semaphore(MaxConcurrentConnections)

  def main(args: Array[String]): Unit =
    args.toList match
      case Nil                     => serve()
      case "--print-policy" :: Nil => printPolicy()
      case _ =>
        System.err.println(
          "agent-egress-proxy takes no arguments, or --print-policy to " +
            "resolve the policy, print it, and exit"
        )
        sys.exit(2)

  /*
   * The dry run behind --proxy-allowed and every launch: no port, no log, a
   * pure computation the launcher runs --network=none to read back what would
   * be enforced.
   *
   * The inspection line is what the built-in set intersected with this policy
   * *would* be inspected, not what a given run will inspect: unlike serve()
   * this reads no certificate, because the dry run is not given one. Every
   * launch mounts the leaf, so the two agree there; only the standalone image
   * run without EGRESS_TLS_CERTIFICATE prints a set it would then log as
   * "none".
   */
  def printPolicy(): Unit =
    try
      val allowedHosts = configuredAllowedHosts()
      val inspected = DefaultInspectedHosts.intersect(allowedHosts)
      println(
        s"allowed hosts (${allowedHosts.size}): ${allowedHosts.toVector.sorted.mkString(" ")}"
      )
      println(
        if inspected.nonEmpty then
          s"tls inspection (${inspected.size}): ${inspected.toVector.sorted.mkString(" ")}"
        else "tls inspection: none; every allowed host is an opaque tunnel"
      )
    catch
      case ex: IllegalArgumentException =>
        System.err.println(ex.getMessage)
        sys.exit(2)

  /** The allowlist EGRESS_ALLOWED_HOSTS asks for, or the built-in list. */
  def configuredAllowedHosts(): Set[String] =
    Option(System.getenv(AllowedHostsVariable)) match
      case Some(value) => resolvePolicy(value, DefaultAllowedHosts)
      case None        => DefaultAllowedHosts

  def serve(): Unit =
    /*
     * Everything reported goes to stderr and, with EGRESS_LOG_FILE set, to
     * that host file too. Set up first so the startup lines land in it, and
     * failing loudly: an enforcement point whose audit trail cannot be
     * written should not start.
     */
    Option(System.getenv(LogFileVariable)).filter(_.nonEmpty).foreach: path =>
      System.setErr(PrintStream(teeOutput(System.err, FileOutputStream(path, true)), true))

    /*
     * Resolved before binding the port: a malformed policy is a container
     * that fails to start, with the one-line reason — a stack trace would
     * read as a proxy bug. Launches never get here (the launcher dry-runs
     * the same string first); this is the standalone-image path, or
     * inspection material that cannot be read or no longer names the
     * inspected set.
     */
    val policy =
      try
        val allowedHosts = configuredAllowedHosts()
        EgressPolicy(allowedHosts, loadInspection(allowedHosts))
      catch
        case ex: IllegalArgumentException =>
          System.err.println(ex.getMessage)
          sys.exit(2)

        // What TlsInspection.load throws for material that exists but cannot be read or parsed.
        case ex: (IOException | GeneralSecurityException) =>
          System.err.println(s"cannot load the TLS inspection material: ${ex.getMessage}")
          sys.exit(2)

    val server = ServerSocket()
    server.setReuseAddress(true)
    server.bind(InetSocketAddress(ListenPort))

    System.err.println(s"agent-egress-proxy listening on :$ListenPort")
    System.err.println(
      s"allowed hosts (${policy.allowedHosts.size}): ${policy.allowedHosts.toVector.sorted.mkString(" ")}"
    )
    System.err.println(policy.inspectionSummary)

    acceptForever(server, policy)

  /*
   * Read before the port binds: unloadable material must not become a proxy
   * quietly tunnelling the forges opaquely. Both variables absent is not an
   * error — the image runs on its own, inspection off and said so.
   */
  def loadInspection(allowedHosts: Set[String]): Option[TlsInspection] =
    val hosts = DefaultInspectedHosts.intersect(allowedHosts)

    val certificate = Option(System.getenv(CertificateVariable)).filter(_.nonEmpty)
    val privateKey = Option(System.getenv(PrivateKeyVariable)).filter(_.nonEmpty)

    (certificate, privateKey) match
      case (Some(certificatePath), Some(privateKeyPath)) =>
        val inspection = TlsInspection.load(
          Path.of(certificatePath), Path.of(privateKeyPath), hosts, DefaultInspectedHosts
        )
        // A policy admitting no forge is a narrower policy, not a misconfigured one: inspection off. The material was
        // still vetted above, so a launcher/proxy drift refuses the start even on a run that inspects nothing.
        Option.when(hosts.nonEmpty)(inspection)

      case (None, None) => None

      case _ =>
        throw IllegalArgumentException(
          s"$CertificateVariable and $PrivateKeyVariable must be set together"
        )

  case class EgressPolicy(
    allowedHosts: Set[String],
    inspection: Option[TlsInspection]
  ):
    def inspectionSummary: String =
      inspection match
        case Some(active) =>
          s"tls inspection (${active.hosts.size}): ${active.hosts.toVector.sorted.mkString(" ")}"
        case None =>
          // The same line printPolicy prints, so the dry-run banner and the runtime log stay grep-compatible.
          "tls inspection: none; every allowed host is an opaque tunnel"

  /**
   * Two forms, never mixed. Replacement: bare hostnames are the whole
   * allowlist. Delta: every entry `+host` / `-host` / `-**.domain`,
   * `effective = (builtin ∖ removed) ∪ added` with the two sets forbidden
   * to overlap, so order cannot matter.
   *
   * Fails closed on every ambiguity: mixed forms (a forgotten prefix must
   * not flip a line's meaning unseen); a host both added and removed,
   * a `+host` under a `-**.domain` included; a removal matching nothing
   * built in, which would read as a narrowing that silently is not there;
   * an empty policy, more likely a typo than a deliberate deny-everything —
   * a proxy refusing everything is indistinguishable from a broken one.
   * A `+` for a built-in host stays legal, so a defensive add keeps working
   * when the image adopts it. The only wildcard is the removal-side
   * `-**.domain`; SECURITY.md ("Adding hosts, not patterns") records the
   * asymmetry.
   */
  def resolvePolicy(value: String, builtin: Set[String]): Set[String] =
    val entries = value.split("[\\s,]+").toVector.filter(_.nonEmpty)

    if entries.isEmpty then
      throw IllegalArgumentException(s"$AllowedHostsVariable is empty")

    val prefixed = entries.count(e => e.startsWith("+") || e.startsWith("-"))
    if prefixed == 0 then entries.map(normalizeEntry).toSet
    else if prefixed == entries.size then resolveDelta(entries, builtin)
    else
      throw IllegalArgumentException(
        s"$AllowedHostsVariable mixes delta entries (+host / -host) with plain " +
          "replacement entries; a file is one form or the other, never both"
      )

  /**
   * One removal in a delta: an exact host, or a `**.domain` subtree covering
   * the domain and everything under it. The spelling is kept for messages.
   */
  private enum Removal:
    case Exact(host: String)
    case Subtree(base: String)

    def matches(host: String): Boolean = this match
      case Exact(h)   => host == h
      // The pattern's own dot is the label boundary: `**.foo.com` covers foo.com and api.foo.com, never barfoo.com.
      case Subtree(b) => host == b || host.endsWith("." + b)

    def describe: String = this match
      case Exact(h)   => h
      case Subtree(b) => s"$b and everything under it"

  private def parseRemoval(entry: String): Removal =
    if entry.startsWith("**.") then Removal.Subtree(normalizeEntry(entry.drop(3)))
    else Removal.Exact(normalizeEntry(entry))

  private def resolveDelta(entries: Vector[String], builtin: Set[String]): Set[String] =
    val (adds, removes) = entries.partition(_.startsWith("+"))
    val added = adds.map(e => normalizeEntry(e.drop(1))).toSet
    val removals = removes.map(e => parseRemoval(e.drop(1)))

    def isRemoved(host: String): Boolean = removals.exists(_.matches(host))

    val contradicted = added.filter(isRemoved)
    if contradicted.nonEmpty then
      throw IllegalArgumentException(
        s"$AllowedHostsVariable both adds and removes ${contradicted.toVector.sorted.mkString(", ")}"
      )

    removals.foreach: removal =>
      if !builtin.exists(removal.matches) then
        throw IllegalArgumentException(
          s"$AllowedHostsVariable removes ${removal.describe}, which matches nothing " +
            "in the built-in list; a '-' that removes nothing is refused"
        )

    val effective = builtin.filterNot(isRemoved) ++ added
    if effective.isEmpty then
      throw IllegalArgumentException(s"$AllowedHostsVariable removes every host")

    effective

  /** One entry, prefix stripped: normalized like a CONNECT target, IP
    * literals refused. */
  private def normalizeEntry(entry: String): String =
    val host =
      try normalizeHost(entry)
      catch
        case ex: BadRequest =>
          throw IllegalArgumentException(
            s"$AllowedHostsVariable contains an invalid hostname '$entry': ${ex.getMessage}"
          )

    if isIpLiteral(host) then
      throw IllegalArgumentException(
        s"$AllowedHostsVariable contains an IP literal '$entry'; only hostnames are allowed"
      )

    host

  @tailrec
  def acceptForever(server: ServerSocket, policy: EgressPolicy): Unit =
    /*
     * A failed accept must not take the proxy down: every agent behind it
     * would lose network access until someone noticed. A closed listening
     * socket is the one unrecoverable case, and ends the loop rather than
     * spinning on it.
     */
    val accepted =
      try Some(server.accept())
      catch
        case ex: IOException =>
          System.err.println(s"accept failed: ${ex.getMessage}")
          None

    accepted.foreach(client => dispatch(client, policy))

    if !server.isClosed then acceptForever(server, policy)

  def dispatch(client: Socket, policy: EgressPolicy): Unit =
    if !connectionSlots.tryAcquire() then
      try respondQuietly(client, 503, "Service Unavailable")
      finally closeQuietly(client)
    else
      try
        executor.execute(() =>
          try handle(client, policy)
          finally connectionSlots.release()
        )
      catch
        case NonFatal(ex) =>
          // The permit was acquired above and this connection will never run.
          connectionSlots.release()
          closeQuietly(client)
          System.err.println(s"could not start connection handler: ${ex.getMessage}")

  def handle(client: Socket, policy: EgressPolicy): Unit =
    try
      // An IO failure while reading the request is the client's, not upstream's; rethrown as a
      // BadRequest so the log does not blame an upstream the proxy never dialled, with a 502.
      val request =
        try
          client.setSoTimeout(HandshakeTimeoutMillis)
          client.setTcpNoDelay(true)
          ConnectRequest.parse(
            readHttpHeader(client.getInputStream, MaxHttpHeaderBytes)
          )
        catch
          case ex: IOException =>
            throw BadRequest(s"could not read the CONNECT request: ${ex.getMessage}")

      val host = authorizeRequest(request, policy.allowedHosts)
      val addresses = resolvePublic(host)
      val upstream = connect(addresses, request.port)

      try runEstablishedTunnel(client, upstream, host, policy)
      finally closeQuietly(upstream)

    catch
      case ex: BadRequest =>
        logDenied(client, s"bad request: ${ex.getMessage}")
        respondQuietly(client, 400, "Bad Request")

      case ex: PolicyViolation =>
        logDenied(client, ex.getMessage)
        respondQuietly(client, 403, "Forbidden")

      case ex: IOException =>
        logDenied(client, s"upstream error: ${ex.getMessage}")
        respondQuietly(client, 502, "Bad Gateway")

      case NonFatal(ex) =>
        logDenied(client, s"internal error: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
        respondQuietly(client, 500, "Internal Server Error")

    finally
      closeQuietly(client)

  def runEstablishedTunnel(
    client: Socket,
    upstream: Socket,
    connectHost: String,
    policy: EgressPolicy
  ): Unit =
    writeAscii(client.getOutputStream, "HTTP/1.1 200 Connection Established\r\n\r\n")

    try
      val hello =
        TlsClientHello.read(
          client.getInputStream,
          MaxClientHelloBytes
        )

      validateTlsIdentity(connectHost, hello)

      policy.inspection.filter(_.inspects(connectHost)) match
        case Some(inspection) =>
          runInspectedSession(client, upstream, connectHost, hello, inspection)

        case None =>
          System.err.println(
            s"${client.getRemoteSocketAddress}: allow $connectHost " +
              s"-> ${upstream.getInetAddress.getHostAddress}"
          )

          /*
           * TlsClientHello.read consumed the records needed to inspect the
           * ClientHello. Forward those exact bytes unchanged before switching
           * to an opaque bidirectional tunnel.
           */
          upstream.getOutputStream.write(hello.wireBytes)
          upstream.getOutputStream.flush()

          client.setSoTimeout(0)
          upstream.setSoTimeout(0)

          tunnel(client, upstream)

    catch
      /*
       * HTTP 200 has already been sent, so an HTTP error response would be
       * protocol garbage at this point. Fail closed by dropping the tunnel.
       */
      case ex: BadTls =>
        logDenied(client, s"TLS rejected for $connectHost: ${ex.getMessage}")

      case ex: BadRequest =>
        logDenied(client, s"TLS rejected for $connectHost: ${ex.getMessage}")

      case ex: PolicyViolation =>
        logDenied(client, s"TLS rejected for $connectHost: ${ex.getMessage}")

      case ex: IOException =>
        logDenied(client, s"tunnel error for $connectHost: ${ex.getMessage}")

      case NonFatal(ex) =>
        logDenied(
          client,
          s"internal error for $connectHost: ${ex.getClass.getSimpleName}: ${ex.getMessage}"
        )

  /*
   * One request and its response, then the connection ends. Keeping it
   * alive would mean agreeing with the origin about where each message ends
   * — request smuggling's exact surface. The body is framed once,
   * forwarded, and the client never read again; `Connection: close`
   * upstream makes end-of-stream the response's framing. Cost: a handshake
   * per request — `git fetch` is two.
   */
  def runInspectedSession(
    client: Socket,
    upstream: Socket,
    host: String,
    hello: TlsClientHello,
    inspection: TlsInspection
  ): Unit =
    /*
     * The client's ClientHello has already been read off the socket to check
     * its SNI, so it is replayed into the TLS engine here rather than being
     * forwarded upstream as it is for an opaque tunnel.
     */
    val clientTls = inspection.accept(client, hello.wireBytes)

    try
      try
        val head =
          HttpRequestHead.parse(
            readHttpHeader(clientTls.getInputStream, MaxHttpHeaderBytes)
          )

        authorizeInspectedRequest(host, head)

        val upstreamTls = inspection.connect(upstream, host)

        try
          System.err.println(
            s"${client.getRemoteSocketAddress}: allow $host ${head.method} ${head.target} " +
              s"-> ${upstream.getInetAddress.getHostAddress}"
          )

          relayInspected(clientTls, upstreamTls, head)
        finally closeQuietly(upstreamTls)

      catch
        case ex: BadRequest =>
          logDenied(client, s"deny $host: ${ex.getMessage}")
          respondInsideTls(clientTls, 400, "Bad Request", ex.getMessage)

        case ex: PolicyViolation =>
          logDenied(client, s"deny $host: ${ex.getMessage}")
          respondInsideTls(clientTls, 403, "Forbidden", ex.getMessage)

        case ex: IOException =>
          logDenied(client, s"upstream error for $host: ${ex.getMessage}")
          respondInsideTls(clientTls, 502, "Bad Gateway", ex.getMessage)

    finally closeQuietly(clientTls)

  /*
   * Up to the request body an IOException is still reportable as a 502 and
   * left to the caller; once the response flows there is no status to send,
   * so a failure just ends the connection.
   */
  def relayInspected(
    clientTls: SSLSocket,
    upstreamTls: SSLSocket,
    head: HttpRequestHead
  ): Unit =
    val toUpstream = upstreamTls.getOutputStream

    clientTls.setSoTimeout(InspectedIdleTimeoutMillis)
    upstreamTls.setSoTimeout(InspectedIdleTimeoutMillis)

    toUpstream.write(head.toUpstreamBytes)
    forwardRequestBody(clientTls.getInputStream, toUpstream, head.bodyFraming)
    toUpstream.flush()

    try
      upstreamTls.getInputStream.transferTo(clientTls.getOutputStream)
      clientTls.getOutputStream.flush()
    catch
      case ex: IOException =>
        System.err.println(s"response relay ended: ${ex.getMessage}")

  /**
   * What "read access to a forge" means: GET and HEAD to any path; POST to
   * the git-upload-pack path — without it, "read access" would silently
   * exclude `git clone` — and nothing else.
   *
   * Receive-pack ref discovery, a GET and so otherwise permitted, is
   * refused too: `git push` fails at its first request with a reason in
   * the log, not at its second.
   *
   * The LFS batch endpoint stays closed: a POST whose body chooses between
   * download and upload, and git-lfs being absent from the image is no
   * boundary — it is one static binary away. Content stays readable per
   * file through media.githubusercontent.com; SECURITY.md has the trade.
   *
   * GraphQL is a POST even to read and is refused with the rest. GitHub's
   * has no unauthenticated tier anyway; gitlab.com's does, and its REST
   * reads remain (SECURITY.md).
   */
  def authorizeInspectedRequest(
    host: String,
    head: HttpRequestHead
  ): Unit =
    if !head.target.startsWith("/") then
      throw PolicyViolation(
        "only origin-form request targets are allowed"
      )

    if head.values("Upgrade").nonEmpty then
      throw PolicyViolation("HTTP Upgrade is not allowed")

    head.values("Host") match
      case Vector(value) =>
        val declared = normalizeHostHeader(value)

        if declared != host then
          throw PolicyViolation(
            s"Host header $declared does not match the connection to $host"
          )

      case Vector() => throw BadRequest("missing Host header")
      case _        => throw BadRequest("duplicate Host header")

    // Rejects the ambiguous framings before anything is forwarded.
    head.bodyFraming

    head.method match
      case "GET" | "HEAD" =>
        // a body on a read method would be an unbounded, unlogged client-to-server channel
        if head.bodyFraming != BodyFraming.Empty then
          throw PolicyViolation(
            s"${head.method} to a forge must not carry a request body"
          )

        if isReceivePackDiscovery(head) then
          throw PolicyViolation(
            s"${head.method} ${head.target} is git push ref discovery, which is not allowed"
          )

      case "POST" =>
        requireUnambiguousPath(head.path)

        if !isUploadPack(head.path) then
          throw PolicyViolation(
            s"POST ${head.path} is not allowed; " +
              "the only permitted POST is git fetch to .../git-upload-pack"
          )

      case other =>
        throw PolicyViolation(
          s"$other is not allowed; this host admits GET, HEAD and git fetch only"
        )

  /*
   * The IP-literal rejection is defence in depth — the allowlist cannot
   * contain one and resolvePublic rejects private answers — kept for the
   * clear refusal message.
   */
  def authorizeRequest(
    request: ConnectRequest,
    allowedHosts: Set[String]
  ): String =
    if request.port != 443 then
      throw PolicyViolation("only CONNECT port 443 is allowed")

    val host = normalizeHost(request.host)

    if isIpLiteral(host) then
      throw PolicyViolation("IP-literal CONNECT targets are not allowed")

    if !allowedHosts.contains(host) then
      throw PolicyViolation(s"host not allowed: $host")

    host

  def connect(
    addresses: Vector[InetAddress],
    port: Int
  ): Socket =
    @tailrec
    def loop(
      remaining: List[InetAddress],
      lastFailure: Option[IOException]
    ): Socket =
      remaining match
        case Nil =>
          throw lastFailure.getOrElse(
            IOException("no resolved address could be connected")
          )

        case address :: rest =>
          val socket = Socket()
          try
            socket.connect(
              InetSocketAddress(address, port),
              ConnectTimeoutMillis
            )
            socket.setTcpNoDelay(true)
            socket
          catch
            case ex: IOException =>
              closeQuietly(socket)
              loop(rest, Some(ex))

    loop(addresses.toList, None)

  def tunnel(client: Socket, upstream: Socket): Unit =
    val done = CountDownLatch(2)

    def pump(
      in: InputStream,
      out: OutputStream,
      halfClose: () => Unit
    ): Unit =
      try
        in.transferTo(out)
        out.flush()
      catch
        case _: SocketException => ()
        case _: IOException     => ()
      finally
        try halfClose()
        catch case _: IOException => ()
        done.countDown()

    executor.execute(() =>
      pump(
        client.getInputStream,
        upstream.getOutputStream,
        () => upstream.shutdownOutput()
      )
    )

    executor.execute(() =>
      pump(
        upstream.getInputStream,
        client.getOutputStream,
        () => client.shutdownOutput()
      )
    )

    try done.await()
    catch
      case _: InterruptedException =>
        Thread.currentThread().interrupt()

  def logDenied(client: Socket, message: String): Unit =
    System.err.println(s"${client.getRemoteSocketAddress}: $message")

  /**
   * Both sinks, flushes included; line-currency matters because the reaper
   * removes this container the moment its sandbox exits.
   */
  def teeOutput(a: OutputStream, b: OutputStream): OutputStream = new OutputStream:
    override def write(byte: Int): Unit =
      a.write(byte)
      b.write(byte)
    override def write(bytes: Array[Byte], offset: Int, length: Int): Unit =
      a.write(bytes, offset, length)
      b.write(bytes, offset, length)
    override def flush(): Unit =
      a.flush()
      b.flush()

  def closeQuietly(socket: Socket): Unit =
    try socket.close()
    catch case _: IOException => ()

case class BadRequest(message: String) extends RuntimeException(message)

case class PolicyViolation(message: String) extends RuntimeException(message)

case class BadTls(message: String) extends RuntimeException(message)
