// What a launch's runner publishes about each runtime it owns, so that another launch on the same workspace can
// attach its commands to the runtime (RunnerRuntimes.attached).
//
// - The descriptor is the file `runtime-<program>-<hash>` in the owner's session directory.
// - No confined process can write the descriptor, since the profiles grant `tmp/` and nothing else of the session.
// - The runner publishes the descriptor by rename once the server or daemon is up. The runner deletes the
//   descriptor before it discards any record of the runtime, and so republishes it with every replacement.
// - The owner's teardown renames the whole session out of the root, where an attaching launch never looks.
// - The fingerprint covers the server's or daemon's confinement and environment: the profile's inputs, the closed
//   environment and the proxy's rules.
//   - Equal fingerprints mean that the attaching launch would start a server or daemon under the same confinement
//     and environment.
//   - The fingerprint covers the forwarded values, since a launch that forwards a secret must not serve a launch
//     that does not.
//   - The fingerprint is a hash, so that none of the forwarded values is persisted.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import agentsandbox.egress.LogHelper.sha256Hex

import RunOnHostPrereqs.Program
import RunOnHostSession.{parseRecord, Record}

/** One runtime as its owner describes it.
  *
  *   - `proxy` and `group` are the owner's `proxy-<program>-<hash>` record and its `server-sbt-<hash>` or
  *     `daemon-mill-<hash>` record, as the records read at publication. A descriptor left from a replaced runtime
  *     therefore fails against the successor's records.
  *   - Only a mill runtime has `daemon` and `daemonConfig`: the daemon's pid and start time, taken at the daemon's
  *     start, and the digest of `RunOnHostPrereqs.millDaemonConfig`. */
case class RunOnHostRuntimeDescriptor(
  fingerprint: String,
  proxyPort: Int,
  proxy: Record,
  group: Record,
  daemon: Option[RunOnHostMillDaemons.Daemon],
  daemonConfig: Option[String],
)

object RunOnHostRuntimeDescriptor:

  val Prefix = "runtime-"

  /** The first line. This launcher does not read a descriptor under another format. */
  val Format = "ko-agent-runtime 1"

  def file(sessionDirectory: Path, program: Program, hash: String): Path =
    sessionDirectory.resolve(s"$Prefix${program.name}-$hash")

  def render(descriptor: RunOnHostRuntimeDescriptor): String =
    val lines = Seq(
      Format,
      s"fingerprint ${descriptor.fingerprint}",
      s"proxy-port ${descriptor.proxyPort}",
      s"proxy ${descriptor.proxy.pgid} ${descriptor.proxy.leaderStart}",
      s"group ${descriptor.group.pgid} ${descriptor.group.leaderStart}",
    ) ++ descriptor.daemon.map(daemon => s"daemon ${daemon.pid} ${daemon.port} ${daemon.start}")
      ++ descriptor.daemonConfig.map(digest => s"daemon-config $digest")
    lines.mkString("", "\n", "\n")

  /** None for any other format, or for a missing or malformed line. The start times carry spaces, so each record is
    * the rest of its line. */
  def parse(text: String): Option[RunOnHostRuntimeDescriptor] =
    val lines = text.linesIterator.toVector
    def value(key: String): Option[String] =
      lines.collectFirst { case line if line.startsWith(s"$key ") => line.drop(key.length + 1) }
    def daemon: Option[Option[RunOnHostMillDaemons.Daemon]] = value("daemon") match
      case None => Some(None)
      case Some(rest) =>
        rest.split(" ", 3) match
          case Array(pid, port, start) if start.nonEmpty =>
            for
              pid <- pid.toLongOption
              port <- port.toIntOption
            yield Some(RunOnHostMillDaemons.Daemon(pid, start, port))
          case _ => None
    if lines.headOption.map(_.trim) != Some(Format) then None
    else
      for
        fingerprint <- value("fingerprint")
        proxyPort <- value("proxy-port").flatMap(_.toIntOption)
        proxy <- value("proxy").flatMap(parseRecord)
        group <- value("group").flatMap(parseRecord)
        daemon <- daemon
      yield RunOnHostRuntimeDescriptor(fingerprint, proxyPort, proxy, group, daemon, value("daemon-config"))

  def publish(file: Path, descriptor: RunOnHostRuntimeDescriptor): Either[String, Unit] =
    try Right(RunOnHostSession.publishByRename(file, render(descriptor)))
    catch case ex: IOException => Left(s"publishing ${file.getFileName}: ${ex.getMessage}")

  /** None when absent, unreadable or not this launcher's format. */
  def read(file: Path): Option[RunOnHostRuntimeDescriptor] =
    try Option.when(Files.isRegularFile(file))(Files.readString(file, UTF_8)).flatMap(parse)
    catch case _: IOException => None

  /** The hex SHA-256 of two inputs:
    *
    *   - the confinement and environment under which the runtime's server or daemon is started
    *     (RunOnHostSandbox.runtimeInputs);
    *   - the rule text the runtime's proxy was created with. The text holds the rules as captured then, since a warm
    *     proxy keeps them. A launch that reads the rule file afresh fingerprints what its own proxy would get.
    *
    * The fingerprint leaves out the request's own launcher flags, which an sbt server is started with
    * (RunOnHostSbtServer.serverCommand).
    *
    *   - Within one launch, the warm server keeps the flags of the command that started it, and every later command
    *     attaches regardless. Stock sbt's thin client likewise attaches to whatever server holds the portfile.
    *     Attaching across launches follows the same rule.
    *   - The flags widen nothing this fingerprint guards:
    *     - The profile is rendered from the assembly and the session, never from the request.
    *     - The supervisor's properties ride `_JAVA_OPTIONS`, which HotSpot applies after argv. A `-D` flag therefore
    *       moves neither the global base nor the socket directory.
    *     - A bind under the sbt profile gets EPERM, so `-jvm-debug` listens nowhere.
    *     - A cache flag that names a path outside the grants fails the server at its first write.
    *     - The flags that name a program are dropped before the start.
    *   - The flags still affect the attaching launch's build: the properties the build sees and the memory it gets.
    *     The owner's own later commands see the same, which SECURITY.md, "Run on host", accepts for every request.
    *
    * Each field is length-framed, so no two inputs render alike. This method names every profile input, so a field
    * added to `ProfileInputs` or `CommandPrereqs` fails to compile here until it is fingerprinted. */
  def fingerprint(inputs: RunOnHostSandbox.RuntimeInputs, rules: String): String =
    val SeatbeltProfile.ProfileInputs(
      prereqs, sessionTmp, distribution, sbtGlobal, ivyHome, gradleUserHome, m2Repository, proxyPort, trust,
      systemPaths, network, fileRules,
    ) = inputs.profile
    val RunOnHostPrereqs.CommandPrereqs(workspaceRoot, jdkHome, coursierV1, program, executable) = prereqs
    val SeatbeltProfile.SystemPaths(reads, executes) = systemPaths
    val networkName = network match
      case SeatbeltProfile.Network.ProxyOnly             => "proxy-only"
      case SeatbeltProfile.Network.SbtClient(tmp)        => s"sbt-client $tmp"
      case SeatbeltProfile.Network.MillDaemon            => "mill-daemon"
      case SeatbeltProfile.Network.MillClient(port, pid) => s"mill-client $port $pid"
      case SeatbeltProfile.Network.Gradle                => "gradle"
    val fields =
      Seq(
        program.name, workspaceRoot.toString, jdkHome.toString, coursierV1.toString, executable.toString,
        distribution.fold("")(_.toString), sbtGlobal.fold("")(_.toString), ivyHome.fold("")(_.toString),
        gradleUserHome.fold("")(_.toString), m2Repository.fold("")(_.toString), sessionTmp.toString,
        proxyPort.toString, trust.toString, networkName,
      ) ++ reads.map(_.toString) ++ Seq("executes") ++ executes.map(_.toString)
        ++ Seq("environment") ++ inputs.environment.toSeq.sorted.flatMap((name, value) => Seq(name, value))
        ++ Seq("rules", rules, "file rules", fileRules.text)
    sha256Hex(fields.map(field => s"${field.length}:$field").mkString)
