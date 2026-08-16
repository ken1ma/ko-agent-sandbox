// The egress proxy: policy, connection handling, and the flow from CONNECT to tunnel. The HTTP surface lives in
// HTTPHelper.scala, the TLS surface in TLSHelper.scala, git protocol knowledge in GitHelper.scala, and hostname/address
// vetting in IPAddrHelper.scala.

package agentsandbox.egress

import java.io.{FileOutputStream, IOException, InputStream, OutputStream, PrintStream}
import java.net.{InetAddress, InetSocketAddress, ServerSocket, Socket, SocketException}
import java.nio.file.Path
import java.security.GeneralSecurityException
import java.util.concurrent.{CountDownLatch, Executors, Semaphore}
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
   * The allowlist is two tiers, each a built-in list below:
   *
   *   - read-write: opaque tunnels — nothing seen or logged past the CONNECT.
   *   - read-only: TLS-inspected; only GET and HEAD — except that a tagged entry also admits
   *     its tag's one POST: `=git-fetch` the git-upload-pack transfer, so cloning works while
   *     `git push` is refused inside the tunnel rather than merely being expected to fail for
   *     want of a credential; `=npm-audit` npm's install-time audit, so dependency-vulnerability
   *     warnings keep working.
   *
   * A tag names one of the fixed treatments this proxy defines (KnownTags); it never describes a
   * rule, and an unknown tag is a refused start — the guardrail DESIGN.md ("No general HTTP
   * method/path policy language") sets on this syntax.
   *
   * These are defaults, not the last word: each tier takes a +/- delta from its environment
   * variable, and EGRESS_BLOCKED_HOSTS takes hosts away from both (resolveTiers below) — so
   * the operator can widen or narrow the policy per project through
   * .ko-agent-sandbox/egress-hosts/ without rebuilding the image. Whichever lists are in force
   * are printed at startup and every denial is logged, which is how you find out what an agent
   * actually wanted.
   *
   * Inspection is off unless the launcher supplies a certificate and key naming exactly the
   * resolved read-only hosts. The launcher keeps no copy of the lists: it reads the resolved
   * tiers from this image's own --print-policy when minting the leaf certificate's
   * subjectAltName list — tags stripped, since which treatment a host gets is this proxy's
   * business and the leaf only names it — and TlsInspection.load refuses a mismatch in either
   * direction.
   *
   * Before adding a host here, answer all five: why does an arbitrary project need it by
   * default; what sandbox data could be sent to it; does it expose an unauthenticated write
   * endpoint; which tier — and which tags — do its operations call for; and could it be
   * project-specific (egress-hosts/) instead? These lists should stay a small set of intentional
   * data recipients, never grow by accumulation.
   */

  /*
   * The read-write tier: the agent endpoints, and by default nothing else. They stay opaque
   * because terminating their TLS means reading the conversation — privacy is why this tier
   * exists at all. The flip side is that a host here is unbounded, unlogged write access, which
   * makes this the tier to extend last.
   */
  val DefaultReadWriteHosts: Set[String] =
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
    ).map(normalizeHost)

  /** The treatments a read-only entry may carry — a closed set: a tag names one of the fixed
    * rule-sets in authorizeInspectedRequest, never describes one. Each is named tool-operation,
    * for the single operation it opens. */
  val KnownTags: Set[String] = Set("git-fetch", "npm-audit")

  /** The audit endpoint the image's npm POSTs at install time — measured on the bundled Node
    * 24.19.0 / npm 11.17.0, not guessed. An older npm's /-/npm/v1/security/audits/quick is
    * refused and logged: the contract is the shipped client, and npm treats the refusal as
    * non-fatal. */
  val NpmAuditPath = "/-/npm/v1/security/advisories/bulk"

  /**
   * The read-only tier: GET and HEAD with no body, and no POST — except a tagged entry's own
   * (KnownTags). The `=git-fetch` hosts serve git fetch besides: agents routinely read issues,
   * release notes and upstream sources from them, and they are where the shortest path out of
   * /workspace lives — `git push`, an issue comment, a gist — so reading is exactly the thing
   * that has to keep working while writing is refused. What is permitted once TLS is terminated
   * is in authorizeInspectedRequest. A project whose checkout holds a forge token should still
   * block that forge's hosts in its own .ko-agent-sandbox/egress-hosts/blocked: inspection
   * bounds the method and the path, not what a permitted GET can be pointed at.
   *
   * An allowance must stay a tag, never every host's rule: on an object store a path is a
   * name anyone can choose, so an attacker-signed upload URL for an object literally named
   * .../git-upload-pack would pass the git path rule on an untagged host.
   *
   * The bulk package registries are in although an inspected session is one request per
   * connection, so a dependency resolve pays a handshake per request — an accepted cost, because
   * security is not traded for performance (DESIGN.md's principles). What that buys at a
   * registry is refusal of its write API and a method-and-target log line per fetch; npm's
   * install-time audit POST, the one recurring legitimate write, is the =npm-audit allowance
   * rather than a casualty — its body names the project's dependencies, a priced trade a project
   * revokes by restating the entry untagged (SECURITY.md, "Reading without being able to
   * write").
   *
   * storage.googleapis.com is the member that *needs* the tier rather than merely wearing it:
   * all of Google Cloud Storage, where an attacker-signed URL accepts a PUT from anyone holding
   * it — the one unauthenticated write surface the built-in list ever had.
   */
  val DefaultReadOnlyHosts: Map[String, Set[String]] =
    Set(
      // git hosts: reading plus git fetch — the =git-fetch tag
      "github.com=git-fetch",
      "raw.githubusercontent.com=git-fetch",
      "objects.githubusercontent.com=git-fetch",
      "codeload.github.com=git-fetch",
      "api.github.com=git-fetch",
      "codeberg.org=git-fetch",
      "gitlab.com=git-fetch",

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
      "registry.npmjs.org=npm-audit",  // install-time vulnerability warnings (NpmAuditPath)
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

      // Container-image pulls, for nested sessions (KO_AGENT_SANDBOX_NESTING). None of these
      // hosts exposes an unauthenticated write of its own — except storage.googleapis.com, whose attacker-signed
      // PUT the tier comment above carries. The CDN hosts are convention, not contract: when a
      // provider moves one, pulls stall and the log names the successor.
      "registry-1.docker.io",              // Docker Hub API
      "auth.docker.io",                    // its token issuer — anonymous pulls need it too
      "production.cloudfront.docker.com",  // blob CDN https://docs.docker.com/docker-hub/release-notes/#2026-05-20
      "production.cloudflare.docker.com",  // blob CDN
      "gcr.io",                            // distroless
      "storage.googleapis.com",            // gcr blobs
      "public.ecr.aws",                    // Amazon Linux
      "d5l0dvt14r5h8.cloudfront.net",      // blob CDN
      "d2glxqk2uabbnd.cloudfront.net",     // blob CDN
      // ghcr.io and quay.io wait for a real need: a project adds them in egress-hosts/read-only,
      // and the proxy log names a refused one.

      "git-scm.com",
      "man7.org",
      "manpages.debian.org",
      "deb.debian.org",  // apt package

      "www.pulumi.com",
      "registry.terraform.io",  // provider docs, and the API `terraform init` queries
      "developer.hashicorp.com",
      // provider binaries (releases.hashicorp.com, get.pulumi.com) wait for a real need
      "docs.spring.io",

      // GitHub content hosts serving pre-signed GETs; untagged like the doc sites — no
      // git-upload-pack endpoint lives on them
      "release-assets.githubusercontent.com",  // release downloads
      "media.githubusercontent.com",  // LFS files, one URL per file
    ).map(entry => parseTaggedEntry("the built-in read-only list", entry)).toMap

  /** Every built-in host: each is declared in exactly one tier above, never here. */
  val DefaultAllowedHosts: Set[String] =
    DefaultReadWriteHosts ++ DefaultReadOnlyHosts.keySet

  val ReadWriteHostsVariable = "EGRESS_READ_WRITE_HOSTS"
  val ReadOnlyHostsVariable = "EGRESS_READ_ONLY_HOSTS"
  val BlockedHostsVariable = "EGRESS_BLOCKED_HOSTS"

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
   * The dry run behind --proxy-effective and every launch: no port, no log, a
   * pure computation the launcher runs --network=none to read back what would
   * be enforced. The read-only line is also where the launcher reads the
   * leaf certificate's names from, tags stripped.
   *
   * The tier lines say what this policy *would* inspect, not what a given
   * run will: unlike serve() this reads no certificate, because the dry run
   * is not given one. Every launch mounts the leaf, so the two agree there;
   * only the standalone image run without EGRESS_TLS_CERTIFICATE logs the
   * inspected tier as opaque.
   */
  def printPolicy(): Unit =
    try tierLines(configuredHostTiers()).foreach(println)
    catch
      case ex: IllegalArgumentException =>
        System.err.println(ex.getMessage)
        sys.exit(2)

  /**
   * The tiers in force, one line each — printed by --print-policy and
   * logged by serve() in the same shape, so the dry-run banner, the runtime
   * log and the launcher's leaf minting all read one format. A read-only
   * entry carries its tags (`github.com=git-fetch`).
   */
  def tierLines(tiers: HostTiers): Vector[String] =
    val readOnlyEntries = tiers.readOnly.toVector
      .map((host, tags) => host + tags.toVector.sorted.map("=" + _).mkString)
      .sorted
    Vector(
      s"read-write hosts (${tiers.readWrite.size}):"
        + tiers.readWrite.toVector.sorted.map(" " + _).mkString,
      s"read-only hosts (${readOnlyEntries.size}):" + readOnlyEntries.map(" " + _).mkString,
    )

  /** The tiers the three variables ask for, or the built-in lists. */
  def configuredHostTiers(): HostTiers =
    def read(variable: String): Option[String] = Option(System.getenv(variable))
    resolveTiers(
      read(ReadWriteHostsVariable),
      read(ReadOnlyHostsVariable),
      read(BlockedHostsVariable),
    )

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
     * the same variables first); this is the standalone-image path, or
     * inspection material that cannot be read or no longer names the
     * inspected set.
     */
    val policy =
      try
        val tiers = configuredHostTiers()
        EgressPolicy(tiers, loadInspection(tiers))
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
    tierLines(policy.tiers).foreach(System.err.println)
    System.err.println(policy.inspectionSummary)

    acceptForever(server, policy)

  /*
   * Read before the port binds: unloadable material must not become a proxy
   * quietly tunnelling the inspected hosts opaquely. Both variables absent is
   * not an error — the image runs on its own, inspection off and said so.
   * Material for a policy that inspects nothing is an error, not a narrower
   * policy: the launcher never mints a leaf for such a policy, so a supplied
   * one means the two disagree about what this policy is.
   */
  def loadInspection(tiers: HostTiers): Option[TlsInspection] =
    val certificate = Option(System.getenv(CertificateVariable)).filter(_.nonEmpty)
    val privateKey = Option(System.getenv(PrivateKeyVariable)).filter(_.nonEmpty)

    (certificate, privateKey) match
      case (Some(certificatePath), Some(privateKeyPath)) =>
        if tiers.inspected.isEmpty then
          throw IllegalArgumentException(
            s"$CertificateVariable is set, but this policy leaves the read-only tier empty; " +
              "with nothing to inspect the material can only be a mistake"
          )
        Some(TlsInspection.load(Path.of(certificatePath), Path.of(privateKeyPath), tiers.inspected))

      case (None, None) => None

      case _ =>
        throw IllegalArgumentException(
          s"$CertificateVariable and $PrivateKeyVariable must be set together"
        )

  /** The two tiers in force. What each means is the allowlist comment's enumeration; how the
    * read-only rules are enforced once TLS is terminated is authorizeInspectedRequest. A
    * read-only value is that host's complete tagging — KnownTags members only. */
  case class HostTiers(
    readWrite: Set[String],
    readOnly: Map[String, Set[String]]
  ):
    val allowed: Set[String] = readWrite ++ readOnly.keySet
    val inspected: Set[String] = readOnly.keySet
    /** The hosts carrying one tag — the =git-fetch hosts, the =npm-audit hosts. */
    def tagged(tag: String): Set[String] =
      readOnly.collect { case (host, tags) if tags.contains(tag) => host }.toSet

  case class EgressPolicy(
    tiers: HostTiers,
    inspection: Option[TlsInspection]
  ):
    def inspectionSummary: String =
      inspection match
        case Some(active) =>
          s"tls inspection: active for the ${active.hosts.size} read-only hosts"
        case None =>
          "tls inspection: off; every allowed host is an opaque, writable tunnel"

  /**
   * The three variables resolved to the tiers in force. Per tier,
   * `effective = ((builtin ∪ added) ∖ removed) ∖ blocked`: the tier's own
   * variable is a `+host` / `-host` / `-**.domain` delta against its built-in
   * list, and EGRESS_BLOCKED_HOSTS is applied last, across both. Taking away
   * always wins — a removal or blocked entry beats an addition, exact or
   * wildcard alike.
   *
   * A read-only addition may carry tags (`+mirror.example=git-fetch`). The entry
   * states its host's complete tagging and overrides a built-in entry for
   * the same host — retagging a built-in host is one restated entry, printed
   * as written at every launch. Never a merge: merging would widen a host to
   * a treatment no single line says, and leave no way to take one tag away.
   * Two *project* entries for one host with different taggings have no such
   * author's-last-word to prefer and are refused; restating a built-in entry
   * identically stays the legal defensive no-op, so a policy that names a
   * host keeps working when the image adopts it.
   *
   * Fails closed on every ambiguity: an entry without its `+`/`-` prefix in
   * a tier delta (whole-list replacement is spelled `.defaults` in
   * blocked); a host both added and removed, or a `+host`
   * under a `-**.domain`, within one tier — under taking-away-wins that `+`
   * could never take effect, and a dead entry is a config error, not a
   * precedence to resolve silently; a removal matching nothing in its
   * tier's built-in list, which would read as a narrowing that silently is
   * not there; a blocked entry matching nothing the policy would otherwise
   * allow; a host that both effective tiers claim; an unknown tag; a tag
   * anywhere but on a read-only addition; an empty effective allowlist, more
   * likely a typo than a deliberate deny-everything — a proxy refusing
   * everything is indistinguishable from a broken one. The only wildcard is
   * the taking-away side's `**.domain`; SECURITY.md ("Adding hosts, not
   * patterns") records the asymmetry.
   */
  def resolveTiers(
    readWriteDelta: Option[String],
    readOnlyDelta: Option[String],
    blocked: Option[String]
  ): HostTiers =
    val readWrite = readWriteDelta
      .map(value => resolveDelta(ReadWriteHostsVariable, value, DefaultReadWriteHosts))
      .getOrElse(DeltaResult(DefaultReadWriteHosts, Set.empty))
    val readOnly = readOnlyDelta
      .map(value => resolveTaggedDelta(ReadOnlyHostsVariable, value, DefaultReadOnlyHosts))
      .getOrElse(TaggedDeltaResult(DefaultReadOnlyHosts, Set.empty))

    val pre = HostTiers(readWrite.hosts, readOnly.hosts)
    val added = readWrite.added ++ readOnly.added

    val tiers = blocked.map(value => applyBlocked(value, pre, added)).getOrElse(pre)

    val overlap = (tiers.readWrite intersect tiers.readOnly.keySet).toVector.sorted
    if overlap.nonEmpty then
      throw IllegalArgumentException(
        "a host has exactly one tier: " +
          overlap.map(host => s"$host is in both read-write and read-only").mkString("; ")
      )

    if tiers.allowed.isEmpty then
      throw IllegalArgumentException("this policy allows no host at all")

    tiers

  /**
   * One taken-away entry: an exact host, or a `**.domain` subtree covering
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

  private def parseRemoval(variable: String, entry: String): Removal =
    if entry.startsWith("**.") then Removal.Subtree(normalizeEntry(variable, entry.drop(3)))
    else Removal.Exact(normalizeEntry(variable, entry))

  /**
   * One addition split at `=`: the hostname, then its tags — KnownTags
   * members only, so a tag names a fixed treatment. The port habit fails
   * closed here too: `host=8443` is an unknown tag with the tag list in
   * hand (`host:8443` is already refused as a hostname).
   */
  private def parseTaggedEntry(variable: String, entry: String): (String, Set[String]) =
    val parts = entry.split("=", -1).toVector
    val host = normalizeEntry(variable, parts.head)
    parts.tail.foreach: tag =>
      if !KnownTags.contains(tag) then
        throw IllegalArgumentException(
          s"$variable tags '$host' with '$tag', which is no treatment this proxy defines; " +
            s"the tags are: ${KnownTags.toVector.sorted.mkString(", ")}"
        )
    (host, parts.tail.toSet)

  /** A tier delta's outcome. `added` is kept apart because blocked's `.defaults` subtracts the
    * built-in contribution, `builtin ∖ added` — an explicit `+host` is the project's own entry
    * even when the host is also built in, and only the added set can tell the two apart. */
  private case class DeltaResult(hosts: Set[String], added: Set[String])
  private case class TaggedDeltaResult(hosts: Map[String, Set[String]], added: Set[String])

  private def resolveDelta(variable: String, value: String, builtin: Set[String]): DeltaResult =
    val entries = splitEntries(variable, value)
    refuseBare(variable, entries)

    val tagged = entries.filter(_.contains('='))
    if tagged.nonEmpty then
      throw IllegalArgumentException(
        s"$variable contains ${tagged.mkString(", ")}; a =tag belongs on " +
          s"$ReadOnlyHostsVariable additions only"
      )

    val (adds, removes) = entries.partition(_.startsWith("+"))
    val added = adds.map(e => normalizeEntry(variable, e.drop(1))).toSet
    val removals = removes.map(e => parseRemoval(variable, e.drop(1)))

    def isRemoved(host: String): Boolean = removals.exists(_.matches(host))
    refuseDeadAndIdleEntries(variable, added, removals, builtin, isRemoved)

    DeltaResult((builtin ++ added).filterNot(isRemoved), added)

  private def resolveTaggedDelta(
    variable: String,
    value: String,
    builtin: Map[String, Set[String]]
  ): TaggedDeltaResult =
    val entries = splitEntries(variable, value)
    refuseBare(variable, entries)

    val (adds, removes) = entries.partition(_.startsWith("+"))

    // A removal takes no tag: taking away removes the host whole, whatever it carries.
    val taggedRemovals = removes.filter(_.contains('='))
    if taggedRemovals.nonEmpty then
      throw IllegalArgumentException(
        s"$variable removes ${taggedRemovals.mkString(", ")}; a removal takes no =tag — " +
          "it removes the host whole"
      )
    val removals = removes.map(e => parseRemoval(variable, e.drop(1)))

    val parsed = adds.map(e => parseTaggedEntry(variable, e.drop(1)))
    val conflicted = parsed.groupBy(_(0)).filter(_._2.map(_(1)).distinct.sizeIs > 1)
    if conflicted.nonEmpty then
      throw IllegalArgumentException(
        s"$variable adds ${conflicted.keys.toVector.sorted.mkString(", ")} with two different " +
          "taggings; an entry states its host's complete tagging, once"
      )
    val added = parsed.toMap

    def isRemoved(host: String): Boolean = removals.exists(_.matches(host))
    refuseDeadAndIdleEntries(variable, added.keySet, removals, builtin.keySet, isRemoved)

    // `++` is the override: a project entry states its host's complete tagging (doc at
    // resolveTiers), so on a shared key the project's tags replace the built-in's.
    TaggedDeltaResult((builtin ++ added).filter((host, _) => !isRemoved(host)), added.keySet)

  private def refuseBare(variable: String, entries: Vector[String]): Unit =
    val bare = entries.filterNot(e => e.startsWith("+") || e.startsWith("-"))
    if bare.nonEmpty then
      throw IllegalArgumentException(
        s"$variable contains ${bare.mkString(", ")} without a +/- prefix; a tier delta's " +
          "entries are +host, -host or -**.domain (deny-by-default is .defaults in " +
          s"$BlockedHostsVariable, plus the + entries kept)"
      )

  /** The two per-delta refusals shared by both tiers: an add a removal would kill (a dead
    * entry is a config error), and a removal matching nothing built in (a narrowing that
    * silently is not there). */
  private def refuseDeadAndIdleEntries(
    variable: String,
    added: Set[String],
    removals: Vector[Removal],
    builtin: Set[String],
    isRemoved: String => Boolean
  ): Unit =
    val contradicted = added.filter(isRemoved)
    if contradicted.nonEmpty then
      throw IllegalArgumentException(
        s"$variable both adds and removes ${contradicted.toVector.sorted.mkString(", ")}"
      )

    removals.foreach: removal =>
      if !builtin.exists(removal.matches) then
        throw IllegalArgumentException(
          s"$variable removes ${removal.describe}, which matches nothing in this tier's " +
            "built-in list; a '-' that removes nothing is refused"
        )

  /**
   * A blocked host or `**.domain` entry matches by name and beats everything,
   * additions included. `.defaults` is not a host matcher: it names the
   * built-in lists themselves, so what it subtracts is the built-in
   * contribution — `builtin ∖ added` — which turns the rest of the policy
   * into a replacement: block the defaults, then `+` back what the project
   * needs, in the tiers it needs them in. (A host matcher could not express
   * that: the hosts a lockdown re-adds are themselves built in, and matching
   * them by name would kill every re-add.) No `+`/`-` prefixes here, and no
   * plain-entry ambiguity for their absence to create: blocked only ever
   * takes away — which is also why its entries take no `=tag`.
   */
  private def applyBlocked(value: String, pre: HostTiers, added: Set[String]): HostTiers =
    val entries = splitEntries(BlockedHostsVariable, value)

    val prefixed = entries.filter(e => e.startsWith("+") || e.startsWith("-"))
    if prefixed.nonEmpty then
      throw IllegalArgumentException(
        s"$BlockedHostsVariable contains ${prefixed.mkString(", ")}; blocked entries carry " +
          "no +/- prefix — host, **.domain or .defaults"
      )

    val tagged = entries.filter(_.contains('='))
    if tagged.nonEmpty then
      throw IllegalArgumentException(
        s"$BlockedHostsVariable contains ${tagged.mkString(", ")}; blocked entries take no " +
          "=tag — blocking removes the host whole"
      )

    val (defaults, removalEntries) = entries.partition(_ == ".defaults")
    val removals = removalEntries.map(entry => parseRemoval(BlockedHostsVariable, entry))

    def blockedByDefaults(host: String): Boolean =
      defaults.nonEmpty && DefaultAllowedHosts.contains(host) && !added.contains(host)

    removals.foreach: removal =>
      if !pre.allowed.exists(removal.matches) then
        throw IllegalArgumentException(
          s"$BlockedHostsVariable blocks ${removal.describe}, which matches nothing this " +
            "policy otherwise allows; an entry that blocks nothing is refused"
        )
    if defaults.nonEmpty && !pre.allowed.exists(blockedByDefaults) then
      throw IllegalArgumentException(
        s"$BlockedHostsVariable blocks .defaults, but no built-in host is left for it to " +
          "block; an entry that blocks nothing is refused"
      )

    def blockedName(host: String): Boolean =
      blockedByDefaults(host) || removals.exists(_.matches(host))
    HostTiers(
      pre.readWrite.filterNot(blockedName),
      pre.readOnly.filter((host, _) => !blockedName(host))
    )

  private def splitEntries(variable: String, value: String): Vector[String] =
    // Whitespace only, matching the policy files' grammar — never comma: a comma-joined pair
    // would silently become two entries here after surviving the launcher's whitespace
    // flattening as one, so it stays inside its token and fails hostname validation instead.
    val entries = value.split("\\s+").toVector.filter(_.nonEmpty)
    if entries.isEmpty then throw IllegalArgumentException(s"$variable is empty")
    entries

  /** One entry, prefix stripped: normalized like a CONNECT target, IP
    * literals refused. */
  private def normalizeEntry(variable: String, entry: String): String =
    val host =
      try normalizeHost(entry)
      catch
        case ex: BadRequest =>
          throw IllegalArgumentException(
            s"$variable contains an invalid hostname '$entry': ${ex.getMessage}"
          )

    if isIpLiteral(host) then
      throw IllegalArgumentException(
        s"$variable contains an IP literal '$entry'; only hostnames are allowed"
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
    // The audit context, filled in as parsing learns it: a `-` in the line marks a field the
    // connection ended before revealing. The host is the target as the sandbox requested it —
    // what was asked for, not a name the policy vouches for. auditLine has the grammar.
    var host = "-"
    var addresses = Vector.empty[InetAddress]
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
            throw BadRequest(s"unreadable CONNECT request: ${ex.getMessage}")

      host = request.host // as requested; replaced by the normalized form once authorized
      host = authorizeRequest(request, policy.tiers.allowed)
      addresses = resolvePublic(host)
      val upstream = connect(addresses, request.port)

      try runEstablishedTunnel(client, upstream, host, policy)
      finally closeQuietly(upstream)

    catch
      case _: ClosedWithoutRequest =>
        // The plaintext twin of the inspected case: a connection opened and closed silently.
        System.err.println(auditLine("error", host, "-", "", "client closed before sending a request"))

      case ex: BadRequest =>
        // Parse failures keep `-` in the method field: it never holds a token the proxy did not
        // admit, so a refused method is named in the text, not promoted to the vocabulary.
        System.err.println(auditLine("deny", host, "-", "", ex.getMessage))
        respondQuietly(client, 400, "Bad Request")

      case ex: PolicyViolation =>
        System.err.println(auditLine("deny", host, "CONNECT", "", ex.getMessage))
        respondQuietly(client, 403, "Forbidden")

      case ex: IOException =>
        val stage =
          if addresses.isEmpty then "resolution:"
          else s"tried ${addresses.map(_.getHostAddress).mkString(" ")}:"
        System.err.println(auditLine("error", host, "CONNECT", "", s"$stage ${ex.getMessage}"))
        respondQuietly(client, 502, "Bad Gateway")

      case NonFatal(ex) =>
        System.err.println(
          auditLine("error", host, "CONNECT", "", s"internal: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
        )
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
          runInspectedSession(
            client, upstream, connectHost, hello, inspection,
            policy.tiers.readOnly.getOrElse(connectHost, Set.empty)
          )

        case None =>
          System.err.println(
            auditLine("allow", connectHost, "CONNECT", "", s"-> ${upstream.getInetAddress.getHostAddress}")
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
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: BadRequest =>
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: PolicyViolation =>
        System.err.println(auditLine("deny", connectHost, "CONNECT", "", ex.getMessage))

      case ex: IOException =>
        System.err.println(auditLine("error", connectHost, "CONNECT", "", s"tunnel: ${ex.getMessage}"))

      case NonFatal(ex) =>
        System.err.println(
          auditLine(
            "error", connectHost, "CONNECT", "",
            s"internal: ${ex.getClass.getSimpleName}: ${ex.getMessage}"
          )
        )

  /*
   * One request and its response, then the connection ends — and both peers are told: the
   * request goes upstream with `Connection: close` (end-of-stream then frames the response),
   * and the response reaches the client with this proxy's own `Connection: close`, whatever the
   * origin's hop said (toClientBytes). Keeping the connection alive would mean agreeing with
   * the origin about where each message ends — request smuggling's exact surface. After the
   * response the client is only drained (drainClient), never answered again. Cost: a handshake
   * per request — `git fetch` is two.
   */
  def runInspectedSession(
    client: Socket,
    upstream: Socket,
    host: String,
    hello: TlsClientHello,
    inspection: TlsInspection,
    hostTags: Set[String]
  ): Unit =
    /*
     * The client's ClientHello has already been read off the socket to check
     * its SNI, so it is replayed into the TLS engine here rather than being
     * forwarded upstream as it is for an opaque tunnel.
     */
    val clientTls = inspection.accept(client, hello.wireBytes)

    // The in-tunnel audit context, like handle()'s: `-` until the request head parses. The allow
    // line prints only after the origin leg connects, so a failing request's method and target
    // must ride the deny/error line or they would never be recorded.
    var method = "-"
    var target = ""

    try
      try
        val head =
          HttpRequestHead.parse(
            readHttpHeader(clientTls.getInputStream, MaxHttpHeaderBytes)
          )
        method = head.method
        target = head.target

        authorizeInspectedRequest(host, head, hostTags)

        val upstreamTls = inspection.connect(upstream, host)

        try
          System.err.println(
            auditLine("allow", host, method, target, s"-> ${upstream.getInetAddress.getHostAddress}")
          )

          relayInspected(clientTls, upstreamTls, host, head)
        finally closeQuietly(upstreamTls)

      catch
        case _: ClosedWithoutRequest =>
          // Routine — pooled clients open spares and drop them unused (apt does) — but logged:
          // a TLS-handshaked connection must not vanish without a line. No response; peer gone.
          System.err.println(
            auditLine("error", host, method, target, "client closed before sending a request")
          )

        case ex: TruncatedResponse =>
          System.err.println(auditLine("error", host, method, target, s"relay: ${ex.getMessage}"))
          // The head already reached the client, so there is no 502 to send; the abortive close
          // (linger 0: RST, no clean TLS end) is what keeps the stump from reading as the whole.
          try client.setSoLinger(true, 0)
          catch case _: SocketException => ()

        case ex: BadRequest =>
          System.err.println(auditLine("deny", host, method, target, ex.getMessage))
          respondInsideTls(clientTls, 400, "Bad Request", ex.getMessage)

        case ex: PolicyViolation =>
          System.err.println(auditLine("deny", host, method, target, ex.getMessage))
          respondInsideTls(clientTls, 403, "Forbidden", ex.getMessage)

        case ex: IOException =>
          System.err.println(auditLine("error", host, method, target, s"origin: ${ex.getMessage}"))
          respondInsideTls(clientTls, 502, "Bad Gateway", ex.getMessage)

    finally closeQuietly(clientTls)

  /*
   * Up to and including the response head, an IOException is still reportable as a 502 and left
   * to the caller — which is why the head is parsed here before a byte of it reaches the client:
   * its framing is what tells a completed body from a truncated one. Once the head is forwarded
   * there is no status to send; a body failure is logged here, except a framing violation, which
   * escapes as TruncatedResponse for the caller's abortive close.
   */
  // Socket rather than SSLSocket: nothing here is TLS-specific — the sockets arrive already
  // inside the tunnel — and plain sockets are what lets the relay be tested on loopback pairs.
  def relayInspected(
    clientTls: Socket,
    upstreamTls: Socket,
    host: String,
    head: HttpRequestHead
  ): Unit =
    val toUpstream = upstreamTls.getOutputStream

    clientTls.setSoTimeout(InspectedIdleTimeoutMillis)
    upstreamTls.setSoTimeout(InspectedIdleTimeoutMillis)

    toUpstream.write(head.toUpstreamBytes)
    // The 100 the client is waiting for is this proxy's to send: the Expect never goes upstream
    // (toUpstreamBytes has the why), and without an answer the client stalls before its body.
    if head.expectsContinue then
      writeAscii(clientTls.getOutputStream, "HTTP/1.1 100 Continue\r\n\r\n")
    forwardRequestBody(clientTls.getInputStream, toUpstream, head.bodyFraming)
    toUpstream.flush()

    val fromUpstream = upstreamTls.getInputStream
    val toClient = clientTls.getOutputStream

    @tailrec
    def finalResponseHead(): HttpResponseHead =
      val bytes =
        try readHttpHeader(fromUpstream, MaxHttpHeaderBytes)
        catch
          case _: ClosedWithoutRequest => throw IOException("origin closed before the response head")
          case ex: BadRequest          => throw IOException(s"origin response head: ${ex.getMessage}")

      val response = HttpResponseHead.parse(bytes)
      if response.status / 100 == 1 then
        // Informational; the final head follows on the same connection.
        toClient.write(response.rawBytes)
        finalResponseHead()
      else response

    val response = finalResponseHead()
    val framing = response.bodyFraming(head.method) // before the head is forwarded: still 502able

    toClient.write(response.toClientBytes)
    try
      forwardResponseBody(fromUpstream, toClient, framing)
      toClient.flush()
      drainClient(clientTls)
    catch
      case ex: IOException =>
        System.err.println(
          auditLine("error", host, head.method, head.target, s"relay: ${ex.getMessage}")
        )

  val DrainTimeoutMillis = 2_000

  /**
   * Consume whatever the client still sends, until its EOF, bounded: closing with unread bytes
   * in the receive buffer turns the close into an RST, and an RST destroys the just-written
   * response's unread tail in the client's stack. A request pipelined past `Connection: close`
   * lands here and is discarded unanswered; a client still flooding at the cap gets the RST it
   * asked for.
   */
  def drainClient(clientTls: Socket): Unit =
    try
      clientTls.setSoTimeout(DrainTimeoutMillis)
      val buffer = new Array[Byte](8 * 1024)

      @tailrec
      def loop(remaining: Int): Unit =
        if remaining > 0 then
          val read = clientTls.getInputStream.read(buffer, 0, math.min(buffer.length, remaining))
          if read >= 0 then loop(remaining - read)

      loop(64 * 1024)
    catch case _: IOException => ()

  /**
   * What "read access" means once TLS is terminated. Everywhere: GET and
   * HEAD to any path, bodyless. Each of the host's tags additionally admits
   * its one POST: `=git-fetch` the git-upload-pack path, without which "read
   * access" would silently exclude `git clone`; `=npm-audit` the audit
   * endpoint npm hits during install (NpmAuditPath). On an untagged host, no
   * POST at all: a path there is an object name anyone can choose, so a
   * path rule authorizes nothing (DefaultReadOnlyHosts has the type case).
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
   * accepts no unauthenticated query anyway; gitlab.com's does, and its
   * REST reads remain (SECURITY.md).
   */
  def authorizeInspectedRequest(
    host: String,
    head: HttpRequestHead,
    hostTags: Set[String]
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
          throw PolicyViolation(s"Host header $declared")

      case Vector() => throw BadRequest("missing Host header")
      case _        => throw BadRequest("duplicate Host header")

    // Rejects the ambiguous framings before anything is forwarded.
    head.bodyFraming

    head.method match
      case "GET" | "HEAD" =>
        // a body on a read method would be an unbounded, unlogged client-to-server channel
        if head.bodyFraming != BodyFraming.Empty then
          throw PolicyViolation("request body")

        if isReceivePackDiscovery(head) then
          throw PolicyViolation("git push ref discovery")

      case "POST" =>
        requireUnambiguousPath(head.path)

        // Each POST allowance is its tag's alone: on a host without the tag a path is a name
        // anyone can choose, so a path rule authorizes nothing.
        val opened =
          (hostTags.contains("git-fetch") && isUploadPack(head.path))
            || (hostTags.contains("npm-audit") && head.path == NpmAuditPath)
        if !opened then
          throw PolicyViolation(if hostTags.isEmpty then "read-only host" else "read-only path")

      case _ =>
        throw PolicyViolation("read-only host")

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
      throw PolicyViolation(s"port ${request.port}")

    val host = normalizeHost(request.host)

    if isIpLiteral(host) then
      throw PolicyViolation("IP-literal target")

    if !allowedHosts.contains(host) then
      throw PolicyViolation("host not allowed")

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

  /**
   * One connection event of the audit log: `verb host method [target] tail` — the grammar
   * SECURITY.md ("The audit line grammar") declares stable through field 3. A `-` fills a field
   * the connection ended before revealing; the target appears exactly when a parsed inspected
   * request exists; the tail is human text with no field structure. No peer address: the per-run
   * internal network has exactly one client, so the field would be a constant.
   */
  def auditLine(verb: String, host: String, method: String, target: String, tail: String): String =
    (Vector(verb, host, method) ++ Vector(target, tail).filter(_.nonEmpty)).mkString(" ")

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

/** A connection that closed after zero bytes: routine pooled-client behavior, logged as `error`
  * — the world moved on, nothing was refused (SECURITY.md, "The audit line grammar"). */
case class ClosedWithoutRequest() extends RuntimeException("closed without sending a request")

/** An upstream EOF where response framing promised more. Distinct from IOException because the
  * response head has already been forwarded by then: no 502 can follow, and the handler must end
  * the client connection abortively so the stump cannot read as a completed response. */
case class TruncatedResponse(message: String) extends RuntimeException(message)

case class PolicyViolation(message: String) extends RuntimeException(message)

case class BadTls(message: String) extends RuntimeException(message)
