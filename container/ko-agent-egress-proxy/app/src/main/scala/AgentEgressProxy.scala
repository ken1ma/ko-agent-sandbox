// The egress proxy: policy, connection handling, and the flow from CONNECT to tunnel. The HTTP surface lives in
// HTTPHelper.scala, the TLS surface in TLSHelper.scala, git protocol knowledge in GitHelper.scala, and hostname/address
// vetting in IPAddrHelper.scala.

package agentsandbox.egress

import java.io.{FileOutputStream, IOException, InputStream, OutputStream, PrintStream}
import java.net.{InetAddress, InetSocketAddress, ServerSocket, Socket, SocketException}
import java.nio.file.Path
import java.time.Instant
import java.time.format.DateTimeFormatter
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
   * Exact hostnames only. Deliberately no regex or wildcard matching on the granting side.
   *
   * Every allowed host is a GET-based exfiltration channel: a permitted GET carries its URL, and a URL is a message.
   *
   * A host's treatment is one of two:
   *
   *   - unrestricted: an opaque tunnel — nothing seen or logged past the CONNECT.
   *   - restricted: TLS-inspected; only GET and HEAD — except that an entry with an allowance also
   *     admits its one POST: `allow=git-fetch` the git-upload-pack transfer, so cloning works while
   *     `git push` is refused inside the tunnel rather than merely being expected to fail for
   *     want of a credential; `allow=github-login-device` GitHub's OAuth device flow, so Copilot
   *     signs in on a forge that stays read-only otherwise; `allow=npm-audit` npm's install-time
   *     audit, so dependency-vulnerability warnings keep working.
   *
   * A tag names one of the fixed treatments this proxy defines (KnownTags); it never describes a
   * rule, and an unknown tag is a refused start — the guardrail DESIGN.md ("No general HTTP
   * method/path policy language") sets on this syntax.
   *
   * Which hosts are in force is the selected profile's answer (resolvePolicy below): the
   * launcher-owned baseline — every model-provider group plus the curated restricted catalog —
   * shaped by the project's `allowed` delta and `denied` rules. Whichever policy is in force is
   * printed at startup and every denial is logged, which is how you find out what an agent
   * actually wanted.
   *
   * Inspection is off unless the launcher supplies a certificate and key naming exactly the
   * resolved restricted hosts. The launcher keeps no copy of the lists: it reads the resolved
   * policy from this image's own --print-policy when minting the leaf certificate's
   * subjectAltName list — tags stripped, since which treatment a host gets is this proxy's
   * business and the leaf only names it — and TlsInspection.load refuses a mismatch in either
   * direction.
   *
   * Before adding a host here, answer all five: why does an arbitrary project need it by
   * default; what sandbox data could be sent to it; does it expose an unauthenticated write
   * endpoint; which treatment — and which tags — do its operations call for; and could it be
   * project-specific (.ko-agent-sandbox/egress/) instead? These lists should stay a small set of
   * intentional data recipients, never grow by accumulation.
   */

  /** A host's effective treatment. Restricted is inspected HTTPS limited to the closed set of
    * read and fetch operations (authorizeInspectedRequest); unrestricted is an opaque tunnel. */
  enum Treatment:
    case Restricted(tags: Set[String])
    case Unrestricted

  /*
   * The model-provider groups: each names the party trusted to receive project data, and expands
   * only to the launcher-maintained model, authentication and control-plane endpoints operated
   * by that provider — never every domain the provider owns. The model endpoints stay opaque
   * (unrestricted) because terminating their TLS means reading the conversation — privacy is why
   * the treatment exists at all. The flip side is that such a host is unbounded, unlogged write
   * access, which makes these the groups to extend last, and why an endpoint that is a forge as
   * well carries the restricted treatment inside its group: the group is what deny-unless-model
   * admits, and it must not admit `git push`.
   */
  val ModelProviderHosts: Map[String, Map[String, Treatment]] =
    def opaque(hosts: String*): Map[String, Treatment] = hosts.map(_ -> Treatment.Unrestricted).toMap
    Map(
      // Claude Code
      "anthropic" -> opaque(
        "api.anthropic.com",  // model traffic
        "claude.ai", "platform.claude.com",  // for interactive login
      ),

      // Codex
      "openai" -> opaque(
        "api.openai.com",   //  API-key use
        "auth.openai.com",  // issues the device code and the tokens
        "chatgpt.com",      // model traffic for a ChatGPT plan
        // ab.chatgpt.com — A/B configuration and telemetry — is absent: codex works without it, and a refusal is a
        // log line here, never a silent gap.
      ),

      // Antigravity
      "google" -> opaque(
        "accounts.google.com",          // printed sign-in URL
        "oauth2.googleapis.com",        // exchanges the pasted code and refreshes tokens
        "cloudcode-pa.googleapis.com",  // model traffic and account state
        // play.googleapis.com — telemetry and experiment polling — is absent for the same reason ab.chatgpt.com is.
      ),

      // Copilot CLI. Its model endpoint doubles as its GitHub MCP server (/mcp on the same host),
      // a write path to the forge that opacity cannot separate from model traffic — the trade
      // SECURITY.md prices under "The web reached through the model provider".
      "github" -> (opaque(
        "api.githubcopilot.com",  // model traffic, the plan-specific hosts below being what the token names instead
        "api.individual.githubcopilot.com",
        "api.business.githubcopilot.com",
        "api.enterprise.githubcopilot.com",
      ) ++ Map(
        // The two forge hosts stay inspected here as in the catalog: the login tag's two POSTs are
        // all sign-in needs, and the Copilot token exchange (/copilot_internal/v2/token) is a GET.
        "github.com" -> Treatment.Restricted(Set("github-login-device")),
        "api.github.com" -> Treatment.Restricted(Set.empty),
      )),
    ).map((provider, hosts) => provider -> hosts.map((host, treatment) => normalizeHost(host) -> treatment))

  /** The tags a restricted entry may carry — a closed set: a tag names one of the fixed
    * rule-sets in authorizeInspectedRequest, never describes one. Each is named tool-operation,
    * for the single operation it opens. */
  val KnownTags: Set[String] = Set("git-fetch", "npm-audit", "github-login-device")

  /** The audit endpoint the image's npm POSTs at install time — measured on the bundled Node
    * 24.19.0 / npm 11.17.0, not guessed. An older npm's /-/npm/v1/security/audits/quick is
    * refused and logged: the contract is the shipped client, and npm treats the refusal as
    * non-fatal. */
  val NpmAuditPath = "/-/npm/v1/security/advisories/bulk"

  /** GitHub's OAuth device flow, as Copilot CLI 1.0.80 drives it: the first mints the user code the
    * agent prints, the second polls for the token once the browser has approved. Both bodies are
    * fixed forms naming a client id, so the allowance carries no project data. */
  val GithubLoginDevicePaths: Set[String] = Set("/login/device/code", "/login/oauth/access_token")

  /**
   * The curated restricted catalog: GET and HEAD with no body, and no POST — except an
   * allowance's own (KnownTags). The `allow=git-fetch` hosts serve git fetch besides: agents routinely
   * read issues, release notes and upstream sources from them, and they are where the shortest
   * path out of /workspace lives — `git push`, an issue comment, a gist — so reading is exactly
   * the thing that has to keep working while writing is refused. What is permitted once TLS is
   * terminated is in authorizeInspectedRequest. A project whose checkout holds a forge token
   * should still deny that forge's hosts in its own .ko-agent-sandbox/egress/denied: inspection
   * bounds the method and the path, not what a permitted GET can be pointed at.
   *
   * An allowance must stay a tag, never every host's rule: on an object store a path is a
   * name anyone can choose, so an attacker-signed upload URL for an object literally named
   * .../git-upload-pack would pass the git path rule on a host without the allowance.
   *
   * The bulk package registries are in although an inspected session is one request per
   * connection, so a dependency resolve pays a handshake per request — an accepted cost, because
   * security is not traded for performance (DESIGN.md's principles). What that buys at a
   * registry is refusal of its write API and a method-and-target log line per fetch; npm's
   * install-time audit POST, the one recurring legitimate write, is the allow=npm-audit allowance
   * rather than a casualty — its body names the project's dependencies, a priced trade a project
   * revokes by restating the entry without it (SECURITY.md, "Reading without being able to
   * write").
   *
   * storage.googleapis.com is the member that *needs* the treatment rather than merely wearing
   * it: all of Google Cloud Storage, where an attacker-signed URL accepts a PUT from anyone
   * holding it — the one unauthenticated write surface the built-in list ever had.
   */
  val CuratedRestrictedHosts: Map[String, Set[String]] =
    Set(
      // git hosts: reading plus git fetch — the allow=git-fetch tag
      "github.com allow=git-fetch",
      "raw.githubusercontent.com allow=git-fetch",
      "objects.githubusercontent.com allow=git-fetch",
      "codeload.github.com allow=git-fetch",
      "api.github.com allow=git-fetch",
      "codeberg.org allow=git-fetch",
      "gitlab.com allow=git-fetch",

      // the agent docs
      "code.claude.com",        // claude
      "developers.openai.com",  // codex
      "antigravity.google",     // agy

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
      "registry.npmjs.org allow=npm-audit",  // install-time vulnerability warnings (NpmAuditPath)
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
      // PUT the catalog comment above carries. The CDN hosts are convention, not contract: when a
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
      // ghcr.io and quay.io wait for a real need: a project adds them in egress/allowed,
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

      // GitHub content hosts serving pre-signed GETs; no allowance, like the doc sites — no
      // git-upload-pack endpoint lives on them
      "release-assets.githubusercontent.com",  // release downloads
      "media.githubusercontent.com",  // LFS files, one URL per file
    ).map(entry => parseCatalogEntry(entry.split(" ").toVector)).toMap

  /**
   * Baseline `B`: every model-provider group plus the curated restricted catalog. A host in both
   * is restricted in both — a group never widens the catalog — and carries the union of its tags
   * (github.com: `allow=git-fetch` from the catalog, `allow=github-login-device` from its group). What each
   * profile admits of it is resolvePolicy's equation.
   */
  val BaselineHosts: Map[String, Treatment] =
    (ModelProviderHosts.values.flatten
      ++ CuratedRestrictedHosts.map((host, tags) => host -> Treatment.Restricted(tags)))
      .groupMapReduce(_(0))(_(1)):
        case (Treatment.Restricted(a), Treatment.Restricted(b)) => Treatment.Restricted(a ++ b)
        case (a, b) =>
          throw IllegalStateException(s"a provider group and the catalog disagree on a host's treatment: $a, $b")

  val ProfileVariable = "EGRESS_PROFILE"
  val ModelProviderVariable = "EGRESS_MODEL_PROVIDER"
  val AllowedVariable = "EGRESS_ALLOWED"
  val DeniedVariable = "EGRESS_DENIED"

  /** The four authority profiles, weakest-to-widest; deny-unless-allowed is what an unset
    * EGRESS_PROFILE means — the launcher-owned baseline, every entry restricted or a model
    * provider's own endpoints, so the default is useful without opening the open internet. */
  val Profiles = Vector("deny-all", "deny-unless-model", "deny-unless-allowed", "allow-unless-denied")
  val DefaultProfile = "deny-unless-allowed"

  val CertificateVariable = "EGRESS_TLS_CERTIFICATE"
  val PrivateKeyVariable = "EGRESS_TLS_PRIVATE_KEY"
  val LogFileVariable = "EGRESS_LOG_FILE"

  val executor = Executors.newVirtualThreadPerTaskExecutor()
  val connectionSlots = Semaphore(MaxConcurrentConnections)

  def main(args: Array[String]): Unit =
    args.toList match
      case Nil                                       => serve()
      case "--print-policy" :: Nil                   => printPolicy(provenance = false)
      case "--print-policy" :: "--provenance" :: Nil => printPolicy(provenance = true)
      case "--check-host" :: host :: Nil             => checkHost(host)
      case _ =>
        System.err.println(
          "agent-egress-proxy takes no arguments, --print-policy [--provenance] to " +
            "resolve the policy, print it, and exit, or --check-host <host> to report " +
            "one host's policy decision and current resolution",
        )
        sys.exit(2)

  /*
   * The dry run behind --egress-effective and every launch: no port, no log, a
   * pure computation the launcher runs --network=none to read back what would
   * be enforced. The restricted line is also where the launcher reads the
   * leaf certificate's names from, tags stripped. Warnings — an idle denial,
   * a selected provider the profile does not fully admit — go to stderr, so
   * the data lines pipe cleanly.
   *
   * The lines say what this policy *would* inspect, not what a given
   * run will: unlike serve() this reads no certificate, because the dry run
   * is not given one. Every launch mounts the leaf, so the two agree there;
   * only the standalone image run without EGRESS_TLS_CERTIFICATE logs the
   * restricted hosts as opaque.
   */
  def printPolicy(provenance: Boolean): Unit =
    try
      val resolved = configuredPolicy()
      policyLines(resolved).foreach(println)
      if provenance then provenanceLines(resolved).foreach(println)
      resolved.warnings.foreach(warning => System.err.println(s"warning: $warning"))
    catch
      case ex: IllegalArgumentException =>
        System.err.println(ex.getMessage)
        sys.exit(2)

  /*
   * One host's fate under the resolved policy, plus the current resolution
   * evidence — separately, because the policy decision is fixed per run
   * while a connection resolves and validates the destination again when it
   * is made. Run by the launcher's --egress-check through a one-shot
   * container on an egress-shaped network, so the resolver path is
   * enforcement's, never the launcher host's.
   */
  def checkHost(rawHost: String): Unit =
    val resolved =
      try configuredPolicy()
      catch
        case ex: IllegalArgumentException =>
          System.err.println(ex.getMessage)
          sys.exit(2)

    val host =
      try normalizeHost(rawHost)
      catch
        case ex: BadRequest =>
          System.err.println(s"'$rawHost' is not a hostname: ${ex.getMessage}")
          sys.exit(2)

    // The decision is authorizeRequest's own — the very function a CONNECT meets — so this
    // diagnostic cannot disagree with enforcement: an IP-literal target, a denied rule and a
    // non-admitted host all answer here exactly as they would on the wire, in enforcement's
    // words. Only an accepted host's treatment is looked up on top.
    val decision =
      try
        val authorized = authorizeRequest(ConnectRequest(host, 443), resolved)
        resolved.hosts.get(authorized) match
          case Some(treatment) => spelled(treatment)
          case None            => "unrestricted (the public-HTTPS default)"
      catch case ex: PolicyViolation => s"refused: ${ex.getMessage}"
    println(s"policy: $host $decision")

    try println(s"resolves: ${resolvePublic(host).map(_.getHostAddress).mkString(" ")}")
    catch
      case ex: PolicyViolation => println(s"resolves: refused: ${ex.getMessage}")
      case ex: IOException     => println(s"resolves: failed: ${ex.getMessage}")

  /** A treatment as the policy file spells it: `unrestricted`, or `restricted` with its allowances. */
  def spelled(treatment: Treatment): String = treatment match
    case Treatment.Restricted(tags) if tags.nonEmpty => s"restricted allow=${tags.toVector.sorted.mkString(",")}"
    case Treatment.Restricted(_)                     => "restricted"
    case Treatment.Unrestricted                      => "unrestricted"

  /**
   * The resolved policy, one line each — printed by --print-policy and
   * logged by serve() in the same shape, so the dry-run banner, the runtime
   * log and the launcher's leaf minting all read one format. The restricted
   * line is the whole inspected set — what the leaf certificate names — and
   * each allowance in force gets a line of its own (`restricted allow=git-fetch
   * (7): ...`), so which hosts carry which exception is read off directly.
   * Under allow-unless-denied there is no finite unrestricted line to print —
   * the profile line carries the public-HTTPS default instead, and no host
   * count is invented.
   */
  def policyLines(resolved: ResolvedEgress): Vector[String] =
    val profileLine = resolved.profile match
      case "deny-unless-model" =>
        s"egress profile: deny-unless-model; model provider: ${resolved.provider.getOrElse("none")}"
      case "allow-unless-denied" =>
        "egress profile: allow-unless-denied; default: public HTTPS unrestricted"
      case other => s"egress profile: $other"

    val restrictedHosts = resolved.restricted.keys.toVector.sorted
    val allowanceLines = resolved.restricted.values.flatten.toVector.distinct.sorted.map: tag =>
      val hosts = resolved.tagged(tag).toVector.sorted
      s"restricted allow=$tag (${hosts.size}):" + hosts.map(" " + _).mkString
    val unrestrictedLine = Option.when(!resolved.ambient)(
      s"unrestricted hosts (${resolved.unrestrictedHosts.size}):"
        + resolved.unrestrictedHosts.toVector.sorted.map(" " + _).mkString,
    )

    Vector(
      profileLine,
      s"restricted hosts (${restrictedHosts.size}):" + restrictedHosts.map(" " + _).mkString,
    ) ++ allowanceLines ++ unrestrictedLine ++ Vector(
      s"denied rules (${resolved.denied.size}):"
        + resolved.denied.map(" " + _.spelled).mkString,
    ) ++ Option.when(resolved.idleDenied.nonEmpty)(
      s"idle denied rules (${resolved.idleDenied.size}):"
        + resolved.idleDenied.map(" " + _.spelled).mkString,
    )

  /**
   * Where each effective entry came from — built-in provider group or curated catalog, `allowed`
   * addition, `denied` — and what overrode what: a removal or denial that costs a host is a line
   * here, never a silent subtraction. Printed by `--print-policy --provenance`, which is what
   * `--egress-effective` runs.
   */
  def provenanceLines(resolved: ResolvedEgress): Vector[String] =
    def sourceOf(host: String): String = resolved.sources(host)

    val hostLines = resolved.hosts.toVector.sorted(using Ordering.by(_(0))).map: (host, treatment) =>
      s"  $host: ${spelled(treatment)}; ${sourceOf(host)}"
    val deniedOverrides = resolved.deniedAdmitted.toVector.sortBy(_(0)).map: (host, rule) =>
      s"  $host: denied by ${rule.spelled}; ${sourceOf(host)}"
    val removalLines = resolved.removedSpellings.map(spelling => s"  $spelling: removed by allowed")
    val idleLines = resolved.idleDenied.map(rule => s"  ${rule.spelled}: denies nothing this profile admits (idle)")

    Vector("provenance:") ++ hostLines ++ deniedOverrides ++ removalLines ++ idleLines

  /** The policy the four variables ask for. */
  def configuredPolicy(): ResolvedEgress =
    def read(variable: String): Option[String] = Option(System.getenv(variable))
    resolvePolicy(
      read(ProfileVariable),
      read(ModelProviderVariable),
      read(AllowedVariable),
      read(DeniedVariable),
    )

  def serve(): Unit =
    /*
     * Everything reported goes to stderr and, with EGRESS_LOG_FILE set, to
     * that host file too. Set up first so the startup lines land in it, and
     * failing loudly: an enforcement point whose audit trail cannot be
     * written should not start.
     */
    val sinks = Option(System.getenv(LogFileVariable)).filter(_.nonEmpty) match
      case Some(path) => teeOutput(System.err, FileOutputStream(path, true))
      case None       => System.err
    System.setErr(PrintStream(stampLines(sinks, () => Instant.now()), true))

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
        val resolved = configuredPolicy()
        EgressPolicy(resolved, loadInspection(resolved))
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
    val lines = policyLines(policy.resolved)
    lines.foreach(System.err.println)
    // The digest gives the audit log one stable, grep-able line naming which policy this run
    // enforced, comparable across runs without diffing the lines above.
    System.err.println(s"resolved-policy digest: ${sha256Hex(lines.mkString("\n"))}")
    policy.resolved.warnings.foreach(warning => System.err.println(s"warning: $warning"))
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
  def loadInspection(resolved: ResolvedEgress): Option[TlsInspection] =
    val certificate = Option(System.getenv(CertificateVariable)).filter(_.nonEmpty)
    val privateKey = Option(System.getenv(PrivateKeyVariable)).filter(_.nonEmpty)

    (certificate, privateKey) match
      case (Some(certificatePath), Some(privateKeyPath)) =>
        if resolved.inspected.isEmpty then
          throw IllegalArgumentException(
            s"$CertificateVariable is set, but this policy restricts no host; " +
              "with nothing to inspect the material can only be a mistake",
          )
        Some(
          TlsInspection.load(Path.of(certificatePath), Path.of(privateKeyPath), resolved.inspected),
        )

      case (None, None) => None

      case _ =>
        throw IllegalArgumentException(
          s"$CertificateVariable and $PrivateKeyVariable must be set together",
        )

  /**
   * One `denied` rule, or an entry of the launcher-owned internal denials. Every form is
   * removal-only, so none can widen authority; the provider form keeps a denied provider denied
   * when its concrete endpoints change, because it matches whatever the group expands to now.
   */
  enum DenyRule:
    case Exact(host: String)
    case Subtree(base: String)
    case Provider(name: String)

    def matches(host: String): Boolean = this match
      case Exact(h) => host == h
      // The pattern's own dot is the label boundary: `**.foo.com` covers foo.com and api.foo.com, never barfoo.com.
      case Subtree(b)  => host == b || host.endsWith("." + b)
      case Provider(p) => ModelProviderHosts(p).contains(host)

    def spelled: String = this match
      case Exact(h)    => h
      case Subtree(b)  => s"**.$b"
      case Provider(p) => s"model-provider:$p"

  /**
   * The policy in force: the selected profile's finite host map — under allow-unless-denied,
   * the restricted exceptions, with `ambient` admitting every other public hostname on port 443
   * as unrestricted — and the denied rules, which win over both treatments. What each treatment
   * means is the policy comment's enumeration; how the restricted rules are enforced once TLS
   * is terminated is authorizeInspectedRequest. The provenance fields exist for presentation
   * only — `sources` labels each pre-denial host with the rule that last changed it,
   * `deniedAdmitted` the hosts a denial cost, `removedSpellings` the allowed-delta rules that
   * actually removed something; enforcement reads `hosts`, `ambient` and `denied`.
   */
  case class ResolvedEgress(
    profile: String,
    provider: Option[String],
    ambient: Boolean,
    hosts: Map[String, Treatment],
    denied: Vector[DenyRule],
    idleDenied: Vector[DenyRule],
    warnings: Vector[String],
    sources: Map[String, String],
    deniedAdmitted: Map[String, DenyRule],
    removedSpellings: Vector[String],
  ):
    val restricted: Map[String, Set[String]] =
      hosts.collect { case (host, Treatment.Restricted(tags)) => host -> tags }
    val unrestrictedHosts: Set[String] =
      hosts.collect { case (host, Treatment.Unrestricted) => host }.toSet
    val inspected: Set[String] = restricted.keySet
    /** The hosts carrying one tag — the allow=git-fetch hosts, the allow=npm-audit hosts. */
    def tagged(tag: String): Set[String] =
      restricted.collect { case (host, tags) if tags.contains(tag) => host }.toSet

  case class EgressPolicy(
    resolved: ResolvedEgress,
    inspection: Option[TlsInspection],
  ):
    def inspectionSummary: String =
      inspection match
        case Some(active) =>
          s"tls inspection: active for the ${active.hosts.size} restricted hosts"
        case None =>
          "tls inspection: off; every allowed host is an opaque, writable tunnel"

  /**
   * The four variables resolved to the policy in force.
   *
   * Let `M` be the selected provider's group, `B` the baseline (BaselineHosts), `A` the result
   * of applying the `allowed` delta to `B`, `N` the restricted narrowing set — `B`'s restricted
   * entries plus restricted exact-host additions; removals, `-**` and unrestricted
   * additions cannot subtract from it — `D` the `denied` rules expanded, and `U` the implicit
   * map from every public hostname on port 443 to unrestricted:
   *
   *   deny-all            = empty
   *   deny-unless-model   = M - D
   *   deny-unless-allowed = A - D
   *   allow-unless-denied = narrow(U, N) - D
   *
   * A provider group is a contribution, not a replacement: `+model-provider` merges a group's
   * restricted tags into a host the catalog restricts too, and `-model-provider` takes back only
   * those — `+` then `-` is the identity, and over the baseline `+` alone is a no-op. `D`'s
   * `model-provider` form is the one that removes such a host outright.
   *
   * The internal-network denials of the security model are not host rules here: they are
   * IPAddrHelper's address vetting, applied to every resolved destination at connection time,
   * ambient hosts included, so no policy file can spell them away.
   *
   * Fails closed on every ambiguity: an unknown profile, provider, tag or entry shape; duplicate
   * exact-host additions with different treatments; a host both added and removed — a `+host`
   * under a `-host **.domain` included; an addition that would widen a restricted baseline host
   * to unrestricted, which has no delta spelling short of `-**` plus a complete
   * replacement; a removal matching neither the baseline nor an addition. A `denied` entry
   * matching nothing the selected profile admits is a startup warning, not an error: it can
   * still apply under another profile or a future provider expansion, and a typo cannot be
   * distinguished from a proactive denial against the ambient host universe. An empty effective
   * map is valid and reported as such — deny-all resolves empty by design, as does
   * deny-unless-model with no provider selected. The only wildcard is the taking-away side's
   * `**.domain`; SECURITY.md ("Adding hosts, not patterns") records the asymmetry.
   */
  def resolvePolicy(
    profileValue: Option[String],
    providerValue: Option[String],
    allowedText: Option[String],
    deniedText: Option[String],
  ): ResolvedEgress =
    val profile = profileValue.getOrElse(DefaultProfile)
    if !Profiles.contains(profile) then
      throw IllegalArgumentException(
        s"$ProfileVariable is '$profile'; the profiles are ${Profiles.mkString(", ")}",
      )
    val provider =
      providerValue.filterNot(_ == "none").map(requireProvider(ModelProviderVariable, _))

    val delta = parseAllowed(allowedText.getOrElse(""))
    val denied = parseDenied(deniedText.getOrElse(""))

    delta.addedHosts.foreach: (host, treatment) =>
      val widens = !delta.clearsBaseline && treatment == Treatment.Unrestricted &&
        BaselineHosts.get(host).exists {
          case Treatment.Restricted(_) => true
          case Treatment.Unrestricted  => false
        }
      if widens then
        throw IllegalArgumentException(
          s"$AllowedVariable re-adds the restricted baseline host $host as unrestricted; " +
            "treatment widening has no delta spelling — use -** and state the complete " +
            "replacement policy",
        )

    val contradicted =
      delta.addedHosts.keySet.filter(host => delta.removals.exists(_.matches(host)))
    if contradicted.nonEmpty then
      throw IllegalArgumentException(
        s"$AllowedVariable both adds and removes ${contradicted.toVector.sorted.mkString(", ")}",
      )

    delta.removals.foreach: removal =>
      if !(BaselineHosts.keySet ++ delta.addedHosts.keySet).exists(removal.matches) then
        throw IllegalArgumentException(
          s"$AllowedVariable removes ${removal.spelled}, which matches neither the baseline " +
            "nor an addition; a '-' that removes nothing is refused",
        )

    // Provenance rides along with the transformation itself: each host carries the label of the
    // last rule that actually changed it, and a delta rule is reported as a removal only when it
    // removed a host that was present when it applied. A rule the profile never consults, or one
    // that restates what already held — re-adding a baseline host with its baseline treatment,
    // removing under -** what -** already cleared — shapes nothing and is reported
    // nowhere.
    // A host in the catalog and a group names both: its tags came from both.
    def baselineSource(host: String): String =
      (Option.when(CuratedRestrictedHosts.contains(host))("curated baseline")
        ++ ModelProviderHosts.collect { case (name, hosts) if hosts.contains(host) => s"model-provider $name" })
        .mkString(", ")

    def overlay(
      current: Map[String, (Treatment, String)],
      host: String,
      treatment: Treatment,
      source: String,
    ): Map[String, (Treatment, String)] =
      current.get(host) match
        case Some((standing, _)) if standing == treatment => current
        case _ => current.updated(host, (treatment, source))

    // A group's restricted entry contributes its tags to a host the catalog already restricts, as
    // BaselineHosts merged them: `+model-provider github` over the baseline is a no-op, not a
    // re-allowancing of github.com. Removing the group takes back only what it contributed.
    def addGroup(current: Map[String, (Treatment, String)], name: String, source: String) =
      ModelProviderHosts(name).foldLeft(current):
        case (current, (host, Treatment.Restricted(tags))) =>
          current.get(host) match
            case Some((Treatment.Restricted(standing), _)) if tags.subsetOf(standing) => current
            case Some((Treatment.Restricted(standing), _)) =>
              current.updated(host, (Treatment.Restricted(standing ++ tags), source))
            case _ => current.updated(host, (Treatment.Restricted(tags), source))
        case (current, (host, treatment)) => overlay(current, host, treatment, source)
    def removeGroup(current: Map[String, (Treatment, String)], name: String) =
      ModelProviderHosts(name).keys.foldLeft(current): (current, host) =>
        CuratedRestrictedHosts.get(host) match
          case Some(tags) if current.contains(host) =>
            current.updated(host, (Treatment.Restricted(tags), "curated baseline"))
          case _ => current - host

    // A: the allowed delta applied to B, in the delta's fixed order. Additions land last, so an
    // exact entry overrides the baseline's treatment of the same host (the widening direction was
    // refused above).
    val cleared: Map[String, (Treatment, String)] =
      if delta.clearsBaseline then Map.empty
      else BaselineHosts.map((host, treatment) => host -> (treatment, baselineSource(host)))
    val afterProviderRemovals = delta.removedProviders.toVector.sorted.foldLeft(cleared)(removeGroup)
    val withAddedProviders =
      delta.addedProviders.toVector.sorted.foldLeft(afterProviderRemovals): (current, name) =>
        addGroup(current, name, s"allowed +model-provider $name")
    // Sequentially, each rule judged against the map as the rules before it left it: of two
    // overlapping removals, only the first removes anything, and only it is reported.
    val (afterRemovals, effectiveHostRemovals) =
      delta.removals.foldLeft((withAddedProviders, Vector.empty[String])):
        case ((current, effective), rule) =>
          val remaining = current.filterNot((host, _) => rule.matches(host))
          (remaining, if remaining.size < current.size then effective :+ rule.spelled else effective)
    val admitted = delta.addedHosts.toVector.sortBy(_(0)).foldLeft(afterRemovals):
      case (current, (host, treatment)) => overlay(current, host, treatment, "allowed +host")

    val effectiveRemovals =
      Option.when(delta.clearsBaseline)("-** (baseline cleared)").toVector
        ++ delta.removedProviders.toVector.sorted
          .filter(name => cleared.keys.exists(ModelProviderHosts(name).contains))
          .map(name => s"model-provider:$name")
        ++ effectiveHostRemovals

    // N: what stays restricted under allow-unless-denied — every restricted baseline entry, a
    // group's included, so github.com keeps allow=github-login-device. Only additions extend it; nothing in
    // the delta subtracts from it, so a removal or `-**` cannot widen an ambient host.
    val narrowed: Map[String, (Treatment, String)] =
      delta.addedHosts.toVector.sortBy(_(0))
        .filter((_, treatment) => treatment != Treatment.Unrestricted)
        .foldLeft(
          BaselineHosts.collect { case (host, treatment @ Treatment.Restricted(_)) =>
            host -> ((treatment: Treatment) -> baselineSource(host))
          },
        ):
          case (current, (host, treatment)) => overlay(current, host, treatment, "allowed +host")

    val (preDenyWithSources, ambient) = profile match
      case "deny-all" => (Map.empty[String, (Treatment, String)], false)
      case "deny-unless-model" =>
        (
          provider.fold(Map.empty[String, (Treatment, String)])(name =>
            ModelProviderHosts(name).map((host, treatment) => host -> (treatment, s"model-provider $name")),
          ),
          false,
        )
      case "deny-unless-allowed" => (admitted, false)
      case "allow-unless-denied" => (narrowed, true)

    val preDeny = preDenyWithSources.view.mapValues(_(0)).toMap
    val sources = preDenyWithSources.view.mapValues(_(1)).toMap

    val deniedAdmitted: Map[String, DenyRule] =
      preDeny.keys.toVector.flatMap(host => denied.find(_.matches(host)).map(host -> _)).toMap

    // deny-all warns about nothing: its denials are idle by definition. Under
    // allow-unless-denied every syntactically valid rule matches the ambient universe.
    val idleDenied =
      if profile == "deny-all" || ambient then Vector.empty
      else denied.filterNot(rule => preDeny.keys.exists(rule.matches))

    val hosts = preDeny.filterNot((host, _) => deniedAdmitted.contains(host))

    val warnings =
      provider.toVector.flatMap: selected =>
        val unreachable = ModelProviderHosts(selected).keys.toVector.sorted.filterNot: host =>
          !denied.exists(_.matches(host)) && (hosts.contains(host) || ambient)
        Option.when(unreachable.nonEmpty)(
          s"the selected model provider '$selected' is not fully reachable under $profile: " +
            unreachable.mkString(" "),
        )
      ++ Option.when(idleDenied.nonEmpty)(
        "denied rules matching nothing this profile admits (kept: they can apply under " +
          s"another profile or a future provider expansion): ${idleDenied.map(_.spelled).mkString(" ")}",
      )

    // Only deny-unless-allowed consults the removal side of the delta; under every other profile
    // even an effective-looking removal shaped nothing.
    val activeRemovals =
      if profile == "deny-unless-allowed" then effectiveRemovals else Vector.empty[String]

    ResolvedEgress(
      profile, provider, ambient, hosts, denied, idleDenied, warnings,
      sources, deniedAdmitted, activeRemovals,
    )

  private def requireProvider(variable: String, name: String): String =
    if !ModelProviderHosts.contains(name) then
      throw IllegalArgumentException(
        s"$variable names the model provider '$name', which this proxy does not define; " +
          s"the providers are ${ModelProviderHosts.keys.toVector.sorted.mkString(", ")}",
      )
    name

  /**
   * The allowances of one `allow=<tag>,...` word: KnownTags members only, so a tag names a fixed
   * treatment, and never empty — `allow=` saying nothing is refused, not read as none.
   */
  private def parseAllowances(variable: String, host: String, word: String): Set[String] =
    val tags = word.stripPrefix("allow=").split(",", -1).toVector
    tags.foreach: tag =>
      if !KnownTags.contains(tag) then
        throw IllegalArgumentException(
          s"$variable allows '$host' the operation '$tag', which is none this proxy defines; " +
            s"the allowances are: ${KnownTags.toVector.sorted.mkString(", ")}",
        )
    tags.toSet

  /** A catalog entry, `<host> [allow=<tag>,...]` — the `+host` tail's restricted forms, in the code. */
  private def parseCatalogEntry(words: Vector[String]): (String, Set[String]) =
    val variable = "the curated restricted catalog"
    val host = normalizeEntry(variable, words.head)
    words.tail match
      case Vector()                                 => (host, Set.empty)
      case Vector(word) if word.startsWith("allow=") => (host, parseAllowances(variable, host, word))
      case other => throw IllegalArgumentException(s"$variable follows $host with '${other.mkString(" ")}'")

  private enum AllowedEntry:
    case ClearBaseline
    case AddProvider(name: String)
    case RemoveProvider(name: String)
    case AddHost(host: String, treatment: Treatment)
    case RemoveHost(removal: DenyRule)

  private case class AllowedDelta(
    clearsBaseline: Boolean,
    addedProviders: Set[String],
    removedProviders: Set[String],
    addedHosts: Map[String, Treatment],
    removals: Vector[DenyRule],
  )

  /**
   * The `allowed` delta's grammar, one entry per line, `#` comments:
   *
   *   +model-provider <name>            -model-provider <name>
   *   +host <host>                      restricted, the default: TLS-inspected, GET and HEAD
   *   +host <host> allow=<tag>,...      restricted, plus the named allowances (KnownTags)
   *   +host <host> unrestricted         an opaque tunnel — the one word that widens
   *   -host <host | **.domain>
   *   -**                               removes the whole baseline, wherever it appears
   *
   * The safe treatment has no word, so the dangerous one is the only entry with an extra word;
   * `restricted` spelled out is refused rather than accepted as a second spelling. `-**` is a
   * flag, not a rule in sequence — the file is not applied top to bottom (resolvePolicy) — so
   * the file's own additions stand above or below it.
   *
   * An entry outside the grammar is refused, never skipped: a stray line configures nothing,
   * which is the silent-weakening failure mode this file must not have. An addition states its
   * host's complete allowances and overrides the baseline entry for the same host — never a
   * merge, which would widen a host to a treatment no single line says. Two entries for one
   * host with different treatments or allowances are refused; restating a baseline entry
   * identically stays the legal defensive no-op, so a policy that names a host keeps working
   * when the image adopts it.
   */
  private def parseAllowed(text: String): AllowedDelta =
    import AllowedEntry.*
    val entries = policyEntries(text).map:
      case Vector("-**")                   => ClearBaseline
      case Vector("+model-provider", name) => AddProvider(requireProvider(AllowedVariable, name))
      case Vector("-model-provider", name) => RemoveProvider(requireProvider(AllowedVariable, name))
      case "+host" +: entry +: words =>
        val host = normalizeEntry(AllowedVariable, entry)
        words match
          case Vector()               => AddHost(host, Treatment.Restricted(Set.empty))
          case Vector("unrestricted") => AddHost(host, Treatment.Unrestricted)
          case Vector(word) if word.startsWith("allow=") =>
            AddHost(host, Treatment.Restricted(parseAllowances(AllowedVariable, host, word)))
          case _ if words.contains("unrestricted") =>
            throw IllegalArgumentException(
              s"$AllowedVariable gives the unrestricted host $host an allowance; allow= opens one " +
                "restricted operation, so it belongs on a restricted entry only",
            )
          case _ if words.contains("restricted") =>
            throw IllegalArgumentException(
              s"$AllowedVariable spells $host's treatment 'restricted', which is the default and " +
                "has no word: +host <host>, or +host <host> allow=<tag>,...",
            )
          case other =>
            throw IllegalArgumentException(
              s"$AllowedVariable follows $host with '${other.mkString(" ")}'; the forms are " +
                "+host <host>, +host <host> allow=<tag>,..., +host <host> unrestricted",
            )
      case Vector("-host", entry) => RemoveHost(parseHostRule(AllowedVariable, entry))
      case tokens =>
        throw IllegalArgumentException(
          s"$AllowedVariable contains '${tokens.mkString(" ")}', which is no entry of the " +
            "allowed grammar: +model-provider <name>, -model-provider <name>, " +
            "+host <host> [allow=<tag>,... | unrestricted], -host <host | **.domain>, -**",
        )

    val added = entries.collect { case AddHost(host, treatment) => (host, treatment) }.distinct
    val conflicted = added.groupBy(_(0)).filter(_._2.sizeIs > 1).keys.toVector.sorted
    if conflicted.nonEmpty then
      throw IllegalArgumentException(
        s"$AllowedVariable adds ${conflicted.mkString(", ")} with two different treatments; " +
          "an entry states its host's complete treatment, once",
      )

    val addedProviders = entries.collect { case AddProvider(name) => name }.toSet
    val removedProviders = entries.collect { case RemoveProvider(name) => name }.toSet
    val bothWays = (addedProviders intersect removedProviders).toVector.sorted
    if bothWays.nonEmpty then
      throw IllegalArgumentException(
        s"$AllowedVariable both adds and removes model-provider ${bothWays.mkString(", ")}",
      )

    AllowedDelta(
      entries.contains(ClearBaseline),
      addedProviders,
      removedProviders,
      added.toMap,
      entries.collect { case RemoveHost(removal) => removal },
    )

  /**
   * The `denied` file's grammar, one entry per line, `#` comments — no `+`/`-` prefixes and no
   * `allow=`, because denied only ever takes away, the host whole, under every profile:
   *
   *   model-provider <name>
   *   host <host | **.domain>
   */
  private def parseDenied(text: String): Vector[DenyRule] =
    policyEntries(text)
      .map:
        case Vector("model-provider", name) =>
          DenyRule.Provider(requireProvider(DeniedVariable, name))
        case Vector("host", entry) => parseHostRule(DeniedVariable, entry)
        case tokens =>
          throw IllegalArgumentException(
            s"$DeniedVariable contains '${tokens.mkString(" ")}', which is no entry of the " +
              "denied grammar: model-provider <name>, host <host | **.domain>",
          )
      .distinct

  private def parseHostRule(variable: String, entry: String): DenyRule =
    if entry.startsWith("**.") then DenyRule.Subtree(normalizeEntry(variable, entry.drop(3)))
    else DenyRule.Exact(normalizeEntry(variable, entry))

  /** A policy file's lines as token vectors: `#` starts a comment, blank lines vanish, tokens
    * split on whitespace — never comma, which stays inside its token and fails hostname
    * validation instead of silently becoming two entries. */
  private def policyEntries(text: String): Vector[Vector[String]] =
    text.linesIterator
      .map(_.takeWhile(_ != '#'))
      .map(_.split("\\s+").toVector.filter(_.nonEmpty))
      .filter(_.nonEmpty)
      .toVector

  /** One entry, prefix stripped: normalized like a CONNECT target, IP
    * literals refused. */
  private def normalizeEntry(variable: String, entry: String): String =
    val host =
      try normalizeHost(entry)
      catch
        case ex: BadRequest =>
          throw IllegalArgumentException(
            s"$variable contains an invalid hostname '$entry': ${ex.getMessage}",
          )

    if isIpLiteral(host) then
      throw IllegalArgumentException(
        s"$variable contains an IP literal '$entry'; only hostnames are allowed",
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
          finally connectionSlots.release(),
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
            readHttpHeader(client.getInputStream, MaxHttpHeaderBytes),
          )
        catch
          case ex: IOException =>
            throw BadRequest(s"unreadable CONNECT request: ${ex.getMessage}")

      host = request.host // as requested; replaced by the normalized form once authorized
      host = authorizeRequest(request, policy.resolved)
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
          auditLine("error", host, "CONNECT", "", s"internal: ${ex.getClass.getSimpleName}: ${ex.getMessage}"),
        )
        respondQuietly(client, 500, "Internal Server Error")

    finally
      closeQuietly(client)

  def runEstablishedTunnel(
    client: Socket,
    upstream: Socket,
    connectHost: String,
    policy: EgressPolicy,
  ): Unit =
    writeAscii(client.getOutputStream, "HTTP/1.1 200 Connection Established\r\n\r\n")

    try
      val hello =
        TlsClientHello.read(
          client.getInputStream,
          MaxClientHelloBytes,
        )

      validateTlsIdentity(connectHost, hello)

      policy.inspection.filter(_.inspects(connectHost)) match
        case Some(inspection) =>
          runInspectedSession(
            client, upstream, connectHost, hello, inspection,
            policy.resolved.restricted.getOrElse(connectHost, Set.empty),
          )

        case None =>
          System.err.println(
            auditLine("allow", connectHost, "CONNECT", "", s"-> ${upstream.getInetAddress.getHostAddress}"),
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
            s"internal: ${ex.getClass.getSimpleName}: ${ex.getMessage}",
          ),
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
    hostTags: Set[String],
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
            readHttpHeader(clientTls.getInputStream, MaxHttpHeaderBytes),
          )
        method = head.method
        target = head.target

        authorizeInspectedRequest(host, head, hostTags)

        val upstreamTls = inspection.connect(upstream, host)

        try
          System.err.println(
            auditLine("allow", host, method, target, s"-> ${upstream.getInetAddress.getHostAddress}"),
          )

          relayInspected(clientTls, upstreamTls, host, head)
        finally closeQuietly(upstreamTls)

      catch
        case _: ClosedWithoutRequest =>
          // Routine — pooled clients open spares and drop them unused (apt does) — but logged:
          // a TLS-handshaked connection must not vanish without a line. No response; peer gone.
          System.err.println(
            auditLine("error", host, method, target, "client closed before sending a request"),
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
    head: HttpRequestHead,
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
          auditLine("error", host, head.method, head.target, s"relay: ${ex.getMessage}"),
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
   * its POSTs: `allow=git-fetch` the git-upload-pack path, without which "read
   * access" would silently exclude `git clone`; `allow=npm-audit` the audit
   * endpoint npm hits during install (NpmAuditPath); `allow=github-login-device` the
   * device-flow pair (GithubLoginDevicePaths). On a host without it, no
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
    hostTags: Set[String],
  ): Unit =
    if !head.target.startsWith("/") then
      throw PolicyViolation(
        "only origin-form request targets are allowed",
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
            || (hostTags.contains("github-login-device") && GithubLoginDevicePaths.contains(head.path))
        if !opened then
          throw PolicyViolation(if hostTags.isEmpty then "restricted host" else "restricted path")

      case _ =>
        throw PolicyViolation("restricted host")

  /*
   * The IP-literal rejection is defence in depth for the finite profiles — their maps cannot
   * contain one and resolvePublic rejects private answers — and load-bearing clarity under the
   * ambient profile, where it is the named refusal a literal target gets. Denial wins over both
   * treatments and over the ambient default.
   */
  def authorizeRequest(
    request: ConnectRequest,
    resolved: ResolvedEgress,
  ): String =
    if request.port != 443 then
      throw PolicyViolation(s"port ${request.port}")

    val host = normalizeHost(request.host)

    if isIpLiteral(host) then
      throw PolicyViolation("IP-literal target")

    resolved.denied.find(_.matches(host)).foreach: rule =>
      throw PolicyViolation(s"host denied (${rule.spelled})")

    if !resolved.hosts.contains(host) && !resolved.ambient then
      throw PolicyViolation("host not allowed")

    host

  def connect(
    addresses: Vector[InetAddress],
    port: Int,
  ): Socket =
    @tailrec
    def loop(
      remaining: List[InetAddress],
      lastFailure: Option[IOException],
    ): Socket =
      remaining match
        case Nil =>
          throw lastFailure.getOrElse(
            IOException("no resolved address could be connected"),
          )

        case address :: rest =>
          val socket = Socket()
          try
            socket.connect(
              InetSocketAddress(address, port),
              ConnectTimeoutMillis,
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
      halfClose: () => Unit,
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
        () => upstream.shutdownOutput(),
      ),
    )

    executor.execute(() =>
      pump(
        upstream.getInputStream,
        client.getOutputStream,
        () => client.shutdownOutput(),
      ),
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
   * Every line the proxy reports, prefixed with the instant it was written, as
   * `2026-08-26T11:59:38Z `. UTC with the zone spelled out: a run's file spans
   * days and is read on machines in other zones, and the container has no
   * zone of its own to be local to. Prefixing at the byte level, on the first
   * byte after a newline, so a line printed in pieces is stamped once.
   */
  def stampLines(out: OutputStream, now: () => Instant): OutputStream = new OutputStream:
    private var lineStart = true
    private def stamp(): Unit =
      out.write(DateTimeFormatter.ISO_INSTANT.format(now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)).getBytes)
      out.write(' ')
      lineStart = false
    override def write(byte: Int): Unit =
      if lineStart then stamp()
      out.write(byte)
      lineStart = byte == '\n'
    override def write(bytes: Array[Byte], offset: Int, length: Int): Unit =
      var from = offset
      val end = offset + length
      while from < end do
        if lineStart then stamp()
        val newline = bytes.indexOf('\n'.toByte, from)
        val to = if newline < 0 || newline >= end then end else newline + 1
        out.write(bytes, from, to - from)
        lineStart = bytes(to - 1) == '\n'
        from = to
    override def flush(): Unit = out.flush()

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

  def sha256Hex(text: String): String =
    java.security.MessageDigest
      .getInstance("SHA-256")
      .digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8))
      .map(byte => f"$byte%02x")
      .mkString

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
