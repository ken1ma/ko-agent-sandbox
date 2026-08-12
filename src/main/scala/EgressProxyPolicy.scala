// The egress proxy as the launcher deals with it: reading this project's policy, asking the proxy
// image what that policy resolves to, and keeping the audit log. The proxy *container's* lifecycle
// is not here — it is a dozen flags in AgentSandboxLauncher.launch, and moving it would drag the
// launch with it.
//
// The proxy owns the built-in list and the +/- arithmetic; nothing here re-implements either, so
// there is no second opinion about what is allowed. See container/ko-agent-egress-proxy.

package agentsandbox.launcher

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*

import HostCommands.*

object EgressProxyPolicy:

  /**
   * One space-separated line: the shape the environment variable carries
   * and the launch banner prints back. What is in force is the proxy's to
   * say — for a delta file its resolved list is not this text.
   */
  def flattenPolicy(text: String): String =
    text.linesIterator
      .map(_.takeWhile(_ != '#'))
      .flatMap(_.split("\\s+"))
      .filter(_.nonEmpty)
      .mkString(" ")

  /**
   * The dry run's answer with the host names dropped — `allowed hosts (75)`
   * rather than the seventy-five. The launch banner is read every session, so
   * a thousand characters of hostnames there is a line people learn to skip,
   * and skipping it is how a policy nobody expected goes unnoticed. The names
   * are one `--proxy-allowed` away, and the proxy writes them into this
   * session's own log as its second and third lines.
   *
   * A line with no list to drop — "tls inspection: none" carries a reason
   * rather than a count — is printed whole rather than guessed at.
   */
  def policyCounts(resolved: String): String =
    resolved.linesIterator
      .map: line =>
        line.indexOf("): ") match
          case -1 => line
          case at => line.take(at + 1)
      .mkString("; ")

  /**
   * Everything but the newest retain-1, so the new file makes retain; names
   * embed a UTC stamp and sort chronologically. Accepted edge: retention
   * counts sessions, not liveness, so more than RetainedProxyLogs
   * interleaved sessions of one project prune a live session's file from
   * under it.
   */
  def logsToPrune(names: Seq[String], retain: Int): Seq[String] =
    names.sorted.dropRight((retain - 1).max(0))

  val RetainedProxyLogs = 20

  /**
   * The policy file flattened to the EGRESS_ALLOWED_HOSTS shape; "" means
   * no file. Present-but-empty is refused: more likely a forgotten edit
   * than a deliberate deny-everything.
   */
  def readPolicyHosts(policyFile: Path): String =
    readIfPresent(policyFile).map(flattenPolicy) match
      case Some("") =>
        fail(
          s"error: $policyFile lists no hosts\nDelete the file to use the proxy's built-in policy instead."
        )
      case Some(hosts) => hosts
      case None        => ""

  /**
   * A --print-policy dry run of the proxy image (--rm, --network=none,
   * nothing mounted): the effective allowlist and inspected set, or the
   * reason the policy is invalid. The proxy owns the built-in list and the
   * +/- arithmetic; this one dry run is the authority both --proxy-allowed
   * and every launch consult.
   */
  def resolvedPolicy(podman: String, proxyImage: String, policyHosts: String): Run =
    val policyEnvArgs =
      if policyHosts.nonEmpty then Vector(s"--env=EGRESS_ALLOWED_HOSTS=$policyHosts")
      else Vector.empty
    run(
      (Vector(podman, "run", "--rm", "--pull=never", "--network=none")
        ++ policyEnvArgs ++ Vector(proxyImage, "--print-policy"))*
    )

  /** This project's retained proxy log files, in chronological (name) order. */
  def retainedLogs(logDir: Path): Vector[Path] =
    if !Files.isDirectory(logDir) then Vector.empty
    else
      Files
        .list(logDir)
        .iterator()
        .asScala
        .filter(p => p.getFileName.toString.startsWith("proxy-"))
        .filter(p => p.getFileName.toString.endsWith(".log"))
        .toVector
        .sortBy(_.getFileName.toString)
