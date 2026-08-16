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
   * The dry run's answer with the host names dropped — `allowed hosts (N)`
   * rather than the N names. The launch banner is read every session, so
   * a thousand characters of hostnames there is a line people learn to skip,
   * and skipping it is how a policy nobody expected goes unnoticed. The names
   * are one `--proxy-effective` away, and the proxy writes them into this
   * session's own log as its second and third lines.
   *
   * A line with no count to keep is printed whole rather than guessed at.
   */
  def policyCounts(resolved: String): String =
    resolved.linesIterator
      .map: line =>
        line.indexOf("):") match
          case -1 => line
          case at => line.take(at + 1)
      .mkString("; ")

  /**
   * Everything but the newest retain-1, so the new file makes retain; names
   * embed a UTC stamp and sort chronologically.
   *
   * A run still holding its log open is never pruned, however old the file
   * is: its proxy is appending to that inode, and unlinking it would leave
   * the session writing where nothing can read, losing the whole record at
   * exit — which is what a retention rule counting sessions rather than
   * liveness does to a project running more than `retain` of them at once.
   * So `retain` is a floor on what is kept, not a ceiling.
   */
  def logsToPrune(names: Seq[String], retain: Int, liveRuns: Set[String]): Seq[String] =
    names.sorted
      .dropRight((retain - 1).max(0))
      .filterNot(name => liveRuns.exists(run => name.endsWith(s"-$run.log")))

  val RetainedProxyLogs = 20

  /**
   * The files .ko-agent-sandbox/egress-hosts/ may hold, each paired with
   * the proxy variable that carries it. The order is the proxy's tier order,
   * which the launch banner reuses.
   */
  val PolicyTierFiles: Vector[(String, String)] = Vector(
    "read-write" -> "EGRESS_READ_WRITE_HOSTS",
    "read-only" -> "EGRESS_READ_ONLY_HOSTS",
    "blocked" -> "EGRESS_BLOCKED_HOSTS",
  )

  /**
   * The policy directory's files as (name, flattened text), present files
   * only. Refused shapes, each of which would otherwise be silently ignored
   * or misread config: egress-hosts as a regular file rather than a
   * directory, fatal so a policy written that way is never skipped unseen; a
   * filename that is no tier file (a typo'd tier configures nothing); a
   * symlinked tier file (podman resolves mount sources on the host, and
   * this read must see the bytes the sandbox's mount will show); a tier name
   * that is not a regular file, which would leave its tier silently at the
   * built-in list; a present-but-empty file, more likely a forgotten edit
   * than a deliberate no-op.
   */
  def readPolicyFiles(hostsDir: Path): Either[String, Vector[(String, String)]] =
    def symlinkRefusal(path: Path): String =
      s"error: $path must not be a symlink\nRefusing to read this project's egress policy through one."

    if Files.isSymbolicLink(hostsDir) then Left(symlinkRefusal(hostsDir))
    else if !Files.exists(hostsDir) then Right(Vector.empty)
    else if !Files.isDirectory(hostsDir) then
      Left(
        s"""error: $hostsDir is a file
           |egress-hosts is a directory of per-tier delta files:
           |${PolicyTierFiles.map(_(0)).mkString(", ")}. Split the entries by tier and remove the
           |file; README ("Modifying the egress policy") has the grammar.""".stripMargin
      )
    else
      val entries = Files
        .list(hostsDir)
        .iterator()
        .asScala
        .toVector
        .sortBy(_.getFileName.toString)

      val refusal = entries
        .collectFirst:
          case entry if !PolicyTierFiles.exists(_(0) == entry.getFileName.toString) =>
            s"error: $entry is not a policy file\negress-hosts/ holds only " +
              s"${PolicyTierFiles.map(_(0)).mkString(", ")}; a stray name would be ignored config."
          case entry if Files.isSymbolicLink(entry) => symlinkRefusal(entry)
          // The one stray shape the name check cannot see: a tier's own name on something the read
          // below skips, which would leave that tier at its built-in list with nothing said.
          case entry if !Files.isRegularFile(entry) =>
            s"error: $entry is not a regular file\negress-hosts/ holds a text file per tier; " +
              "anything else would leave this tier silently at its built-in list."
        .orElse:
          PolicyTierFiles
            .map(_(0))
            .collectFirst:
              case name if readIfPresent(hostsDir.resolve(name)).map(flattenPolicy).contains("") =>
                s"error: ${hostsDir.resolve(name)} lists no entries\n" +
                  "Delete the file to leave this tier at its built-in list."

      refusal.toLeft(
        PolicyTierFiles.flatMap: (name, _) =>
          readIfPresent(hostsDir.resolve(name)).map(flattenPolicy).map(name -> _)
      )

  /**
   * A --print-policy dry run of the proxy image (--rm, --network=none,
   * nothing mounted): the effective tier lists, or the reason the policy is
   * invalid. The proxy owns the built-in lists and the delta/blocked
   * arithmetic; this one dry run is the authority both --proxy-effective and
   * every launch consult — for the banner and for the leaf certificate's
   * names alike.
   */
  def resolvedPolicy(podman: String, proxyImage: String, policyFiles: Vector[(String, String)]): Run =
    run(
      (Vector(podman, "run", "--rm", "--pull=never", "--network=none")
        ++ policyEnvArgs(policyFiles) ++ Vector(proxyImage, "--print-policy"))*
    )

  /** The --env arguments carrying the policy files to the proxy — the dry run and the real
    * container get identical ones, so what was vetted is what is enforced. */
  def policyEnvArgs(policyFiles: Vector[(String, String)]): Vector[String] =
    policyFiles.map: (name, text) =>
      val variable = PolicyTierFiles.find(_(0) == name).fold(fail(s"error: no policy tier $name"))(_(1))
      s"--env=$variable=$text"

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

  /**
   * The inspected hosts out of a --print-policy answer: its `read-only hosts
   * (N): ...` line, `=tag`s stripped — the leaf names hosts; which treatment
   * each gets is the proxy's business. This is how the launcher learns which
   * names the leaf certificate must carry — the proxy image's own answer
   * under this project's policy, so no second copy of any list exists to
   * drift, and a proxy image or policy of the user's choosing gets a
   * matching leaf too. Empty means the policy inspects nothing; the launcher
   * then mints no leaf and hands the proxy no inspection material.
   */
  def inspectedHostsOf(printPolicyOutput: String): Either[String, Vector[String]] =
    printPolicyOutput.linesIterator.find(_.startsWith("read-only hosts (")) match
      case None =>
        Left(
          "error: the proxy image's --print-policy has no 'read-only hosts' line\n" +
            "An image built by another launcher version prints another shape; rebuild with --build."
        )
      case Some(line) =>
        line.indexOf("):") match
          case -1 =>
            Left(
              s"error: unparseable tier line: $line\n" +
                "An image built by another launcher version prints another shape; rebuild with --build."
            )
          case at =>
            Right(
              line
                .drop(at + 2)
                .trim
                .split(" ")
                .toVector
                .filter(_.nonEmpty)
                .map(_.takeWhile(_ != '='))
                .sorted
            )
