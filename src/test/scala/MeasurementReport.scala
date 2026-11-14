// Reads one run's proxy log against the measurement records in defaults/model-provider (doc/agent-measurement.md,
// "The measurement suite"). src/test/measurement/MeasureAgents.scala runs the modes that need no person; the manual
// items add to the same run. On the host:
//
//     sbt "Test/runMain agentsandbox.launcher.MeasurementReport [<proxy.log>]"
//
// Without an argument, the report reads the latest run of the workspace that sbt runs in. It prints the report and
// writes it to log/measurement-report.log, and exits 1 when a line matches no record.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.util.regex.Pattern

import scala.jdk.CollectionConverters.*
import scala.util.Using

import agentsandbox.egress.LogHelper

object MeasurementReport:

  val RecordDirectory: Path = Paths.get("ko-agent-egress-proxy/app/src/main/resources/defaults/model-provider")

  /** A refusal that a record accepts: a host's CONNECT, or a request's method at a path. */
  final case class AcceptedRefusal(host: String, method: String, path: Option[String]):
    def accepts(line: AuditLine): Boolean =
      matches(host, line.host, HostPart) && method == line.method &&
        path.forall(pattern => line.target.exists(target => matches(pattern, pathOf(target), PathPart)))

  /**
   * One provider's record, as its file states it.
   *
   * - `hosts` are the hosts of the file's `allow` lines.
   * - `paths`, `refusals` and `errors` come from the comment lines `path <host> </path>...`, `refused <host> <method>
   *   [</path>]` and `error <host> <why prefix>`. A `<name>` in a host or path stands for one label or segment, or
   *   part of one.
   * - The record names the hosts of its `allow` and `path` lines, and judges every path on them. A `refused` line
   *   accepts a refusal without naming its host: OpenCode is refused at registry.npmjs.org, where every session's
   *   npm installs read packages that no record lists.
   */
  final case class Record(
    provider: String,
    hosts: Set[String],
    paths: Vector[(String, String)],
    refusals: Vector[AcceptedRefusal],
    errors: Vector[(String, String)],
  ):
    def names(host: String): Boolean =
      hosts(host) || paths.exists((pattern, _) => matches(pattern, host, HostPart))

    def recordsPath(host: String, path: String): Boolean = paths.exists(pathMatches(_, host, path))

  private val AllowLine = raw"allow https://([^/\s]+)/.*".r
  private val PathLine = raw"#\s+path (\S+) (.+)".r
  private val RefusedLine = raw"#\s+refused (\S+) (\S+)(?: (/\S*))?\s*".r
  private val ErrorLine = raw"#\s+error (\S+) (.+)".r

  def parseRecord(provider: String, text: String): Record =
    val lines = text.linesIterator.toVector
    Record(
      provider,
      lines.collect { case AllowLine(host) => host }.toSet,
      lines.flatMap:
        case PathLine(host, rest) => rest.trim.split("\\s+").toVector.takeWhile(_.startsWith("/")).map(host -> _)
        case _                    => Vector.empty,
      lines.collect { case RefusedLine(host, method, path) => AcceptedRefusal(host, method, Option(path)) },
      lines.collect { case ErrorLine(host, why) => host -> why.trim },
    )

  def records(directory: Path = RecordDirectory): Vector[Record] =
    Using.resource(Files.list(directory))(_.iterator.asScala.toVector).sortBy(_.getFileName.toString)
      .map(file => parseRecord(file.getFileName.toString, Files.readString(file, UTF_8)))

  private val HostPart = "[^./]+"
  private val PathPart = "[^/]+"

  /** Whether `value` is `pattern` whole, each `<name>` in it standing for `part`. */
  def matches(pattern: String, value: String, part: String): Boolean =
    val regex = pattern.split("(?=<)|(?<=>)").map: piece =>
      if piece.startsWith("<") && piece.endsWith(">") then part else Pattern.quote(piece)
    value.matches(regex.mkString)

  /** Whether a record's `path` line, as its host and path patterns, lists the path on the host. */
  private def pathMatches(recorded: (String, String), host: String, path: String): Boolean =
    matches(recorded(0), host, HostPart) && matches(recorded(1), path, PathPart)

  private def pathOf(target: String): String = target.takeWhile(_ != '?')

  /**
   * One event line of the audit log (SECURITY.md, "The audit line grammar").
   *
   * - `target` is absent on a `CONNECT` and on a line that the connection ended before revealing (`-`).
   * - `fields` hold an `allow` line's `key=value` fields; `words` its bare ones (`chunked`) and an end line's
   *   `incomplete`.
   * - `why` is a `deny` or `error` line's reason, after the `id=` that a line after its request's `allow` line carries.
   */
  final case class AuditLine(
    action: String,
    host: String,
    method: String,
    target: Option[String],
    fields: Map[String, String],
    words: Set[String],
    why: String,
    id: Option[String],
  )

  private val Actions = Set("allow", "deny", "error", "chunked-end", "websocket-end")
  private val IdField = raw"id=(\d+) (.*)".r

  def parseLine(line: String): Option[AuditLine] =
    LogHelper.auditFields(line).filter(fields => Actions(fields.action) && !fields.host.contains("://")).map: parsed =>
      val revealed = parsed.method != "CONNECT" && parsed.method != "-"
      val (target, rest) =
        if revealed then
          parsed.rest.split(" ", 2) match
            case Array(target, rest) => (Some(target), rest)
            case Array(target)       => (Some(target), "")
        else (None, parsed.rest)
      parsed.action match
        case "deny" | "error" =>
          val (id, why) = rest match
            case IdField(id, why) => (Some(id), why)
            case _                => (None, rest)
          AuditLine(parsed.action, parsed.host, parsed.method, target, Map.empty, Set.empty, why, id)
        case _ =>
          val tokens = rest.split(" ").toVector.takeWhile(_ != "->").filter(_.nonEmpty)
          val (pairs, bare) = tokens.partition(_.contains("="))
          val fields = pairs.map(token => token.takeWhile(_ != '=') -> token.dropWhile(_ != '=').drop(1)).toMap
          AuditLine(parsed.action, parsed.host, parsed.method, target, fields, bare.toSet, "", fields.get("id"))

  /** A foreign credential's upload that MeasureAgents.scala sent with curl, and how its body ended. */
  final case class Probe(host: String, method: String, path: String, framing: String, cred: Option[String], end: String)

  /** What the reader found. `findings` are the lines that no record accepts; the rest is for a person to read. */
  final case class Report(text: String, findings: Vector[String], probes: Vector[Probe])

  def report(log: Vector[String], all: Vector[Record]): Report =
    val lines = log.flatMap(parseLine)
    val requests = lines.filter(line => line.action == "allow" && line.target.nonEmpty)
    val probeIds = requests.filter(_.fields.get("client").exists(client =>
      client.startsWith("curl/") || client == "ko-sandbox-egress-check",
    )).flatMap(_.id).toSet
    def probe(line: AuditLine): Boolean = line.id.exists(probeIds)
    val ends = lines.filter(line => line.action.endsWith("-end")).flatMap(line => line.id.map(_ -> line)).toMap
    // A record without path lines was never measured, so its hosts' requests are listed with the other hosts.
    val measured = all.filter(_.paths.nonEmpty)
    def recordOf(host: String): Option[Record] = measured.find(_.names(host))

    val out = Vector.newBuilder[String]
    val findings = Vector.newBuilder[String]
    def counted(entries: Vector[String]): Vector[String] =
      entries.groupBy(identity).toVector.sortBy(_._1).map((entry, same) => s"$entry (${same.size})")

    measured.filter(record => lines.exists(line => record.names(line.host))).foreach: record =>
      out += s"${record.provider}:"
      val own = requests.filter(line => record.names(line.host) && !probe(line))
      own.groupBy(line => (line.host, line.method, pathOf(line.target.get))).toVector.sortBy(_._1).foreach:
        case ((host, method, path), same) =>
          val creds = same.flatMap(_.fields.get("cred")).distinct.sorted
          val bare = same.count(_.fields.get("cred").isEmpty)
          val framing = same.flatMap(line => line.fields.get("content-length").map(_ => "content-length") ++
            line.words.find(_ == "chunked") ++ line.fields.get("upgrade").map(_ => "upgrade=websocket")).distinct
          val credText = (creds.map(c => s"cred=$c") ++ Option.when(bare > 0)(s"$bare without cred")).mkString(", ")
          out += s"  $host $method $path: ${same.size}${if credText.isEmpty then "" else s"; $credText"}" +
            s"${if framing.isEmpty then "" else s"; ${framing.mkString(", ")}"}"
          // A host that two records name, such as github.com, takes a path that either records. The first record
          // that names the host reports the finding, so that it shows once.
          val namers = measured.filter(_.names(host))
          if recordOf(host).contains(record) && !namers.exists(_.recordsPath(host, path)) then
            val names = namers.map(_.provider)
            findings += s"$host $method $path (${same.size}): ${names.mkString(" and ")} " +
              s"${if names.size == 1 then "names" else "name"} no such path"
      val called = own.map(line => (line.host, pathOf(line.target.get)))
      val uncalled = record.paths.filterNot(recorded => called.exists(pathMatches(recorded, _, _)))
      if uncalled.nonEmpty then
        out += s"  recorded, not called in this run: ${uncalled.map((host, path) => s"$host $path").mkString(", ")}"
      own.flatMap(_.id).flatMap(ends.get).filter(_.action == "websocket-end").foreach: end =>
        out += s"  websocket-end ${end.host} ${end.target.fold("")(pathOf)} ${end.fields.view.filterKeys(_ != "id")
            .map((key, value) => s"$key=$value").mkString(" ")}"

    // Every refusal and error must be one that a record accepts, wherever its host belongs.
    def spelled(line: AuditLine): String =
      s"${line.action} ${line.host} ${line.method}${line.target.fold("")(target => s" ${pathOf(target)}")} ${line.why}"
    val refusals = lines.filter(_.action == "deny")
    counted(refusals.map(spelled)).foreach(entry => out += entry)
    val unaccepted = refusals.filterNot(line => all.exists(_.refusals.exists(_.accepts(line))))
    counted(unaccepted.map(spelled)).foreach(entry => findings += s"$entry: no record accepts the refusal")
    // A probe's own errors, such as the cut upload's, are the probe's to show.
    val errors = lines.filter(line => line.action == "error" && !probe(line))
    def accepted(line: AuditLine): Boolean =
      all.exists(_.errors.exists((host, prefix) => matches(host, line.host, HostPart) && line.why.startsWith(prefix)))
    counted(errors.map(spelled)).foreach(entry => out += entry)
    counted(errors.filterNot(accepted).map(spelled))
      .foreach(entry => findings += s"$entry: no record accepts the error")

    val probes = requests.filter(probe).map: line =>
      val end = line.id.flatMap(ends.get).fold("")(end =>
        (end.fields.get("send").map(bytes => s"send=$bytes").toVector ++ end.words).mkString(" "),
      )
      val framing = line.fields.get("content-length").fold(line.words.find(_ == "chunked").getOrElse(""))(bytes =>
        s"content-length=$bytes",
      )
      Probe(line.host, line.method, pathOf(line.target.get), framing, line.fields.get("cred"), end)
    probes.foreach: probe =>
      out += s"probe: ${probe.host} ${probe.method} ${probe.path} ${probe.framing}" +
        s"${probe.cred.fold("")(c => s" cred=$c")}${if probe.end.isEmpty then "" else s" -> ${probe.end}"}"

    val others = lines.filter(line => line.action == "allow" && recordOf(line.host).isEmpty)
      .map(line => s"${line.host} ${line.method}")
    counted(others).foreach(entry => out += s"other: $entry")

    val found = findings.result()
    out += (if found.isEmpty then "findings: none" else s"findings: ${found.size}")
    found.foreach(finding => out += s"  $finding")
    Report(out.result().mkString("\n"), found, probes)

  /** The proxy log of the latest run of the workspace that holds the working directory. */
  def latestProxyLog(): Option[Path] =
    val os = HostCommands.currentOs
    val root = SandboxWorkspace.resolveWorkspaceRoot(os)
    val logDir = LauncherState.logStateRoot(os).resolve(SandboxWorkspace.workspaceIdOf(root, os))
    EgressRules.runLogDirs(logDir).lastOption.map(_.resolve("proxy.log")).filter(Files.isRegularFile(_))

  def main(args: Array[String]): Unit =
    val log = args.headOption.map(Paths.get(_)).orElse(latestProxyLog()).getOrElse:
      System.err.println("measurement report: no proxy log; name one, or run sbt in a workspace that ran a session")
      sys.exit(2)
    val result = report(Files.readAllLines(log, UTF_8).asScala.toVector, records())
    val text = s"proxy log: $log\n${result.text}"
    println(text)
    println(s"report: ${saved(ReportFile, text)}")
    sys.exit(if result.findings.isEmpty then 0 else 1)

  /** The workspace's log/ is ignored by git, and a session's agent reads it there. */
  val ReportFile: Path = Paths.get("log/measurement-report.log")

  def saved(file: Path, text: String): Path =
    Files.createDirectories(file.toAbsolutePath.getParent)
    Files.writeString(file, text + "\n", UTF_8)
    file.toAbsolutePath
