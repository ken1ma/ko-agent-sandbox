// What a launch's broker publishes about each runtime it owns, for another launch on the same
// project to attach its commands to (RunOnHostSandbox.BrokerRuntimes.attached): the file
// `runtime-<program>-<hash>` in the owner's session directory, which no confined process can
// write, since the profiles grant `tmp/` and nothing else of the session. Published by rename once
// the server or daemon is up, deleted before any record of the runtime is discarded, and so
// republished with every replacement; the owner's teardown renames the whole session out of the
// root, where an attaching launch never looks. The fingerprint is over the server's or daemon's
// confinement and environment — the profile's inputs, the closed environment and the proxy's rules
// — so equal fingerprints mean the attaching launch would start one under the same confinement and
// environment; the forwarded values are in it, since a launch that forwards a secret must not serve
// one that does not, and it is a hash so that none of them is persisted.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption}

import RunOnHostPrereqs.Program
import RunOnHostSession.{parseRecord, Record}

/** One runtime as its owner describes it: `proxy` and `group` are the owner's `proxy-<program>-<hash>`
  * and `server-sbt-<hash>` or `daemon-mill-<hash>` records as they read at publication, so a
  * descriptor left from a replaced runtime fails against the successor's records; `daemon` and
  * `daemonConfig` — the daemon proved at its start and `RunOnHostPrereqs.millDaemonConfig`
  * digested — are a mill runtime's. */
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

  /** The first line; a descriptor under another format is one this launcher does not read. */
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

  /** None for any other format or a missing or malformed line: the start times carry spaces, so
    * each record is the line's rest. */
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
    try
      val pending = file.resolveSibling(s"${file.getFileName}.pending")
      Files.writeString(pending, render(descriptor), UTF_8)
      Files.move(pending, file, StandardCopyOption.ATOMIC_MOVE)
      Right(())
    catch case ex: IOException => Left(s"publishing ${file.getFileName}: ${ex.getMessage}")

  /** None when absent, unreadable or not this launcher's format. */
  def read(file: Path): Option[RunOnHostRuntimeDescriptor] =
    try Option.when(Files.isRegularFile(file))(Files.readString(file, UTF_8)).flatMap(parse)
    catch case _: IOException => None

  /** SHA-256, hex, of the confinement and environment the runtime's server or daemon is started
    * under (RunOnHostSandbox.runtimeInputs) and of the rule text its proxy was created with — the
    * rules as captured then, since a warm proxy keeps them: a launch reading the file afresh
    * fingerprints what its own proxy would get.
    *
    * Not in it: the request's own launcher flags, which an sbt server is started with
    * (RunOnHostSandbox.serverCommand). Within one launch the warm server keeps the flags of the
    * command that started it and every later command attaches regardless, as stock sbt's thin
    * client attaches to whatever server holds the portfile; attaching across launches follows
    * the same rule. They widen nothing this fingerprint guards: the profile is rendered from the
    * assembly and the session, never from the request; the wrapper's properties ride
    * `_JAVA_OPTIONS`, which HotSpot applies after argv, so a `-D` moves neither the global base
    * nor the socket directory; a bind under the sbt profile gets EPERM, so `-jvm-debug` listens
    * nowhere; a cache flag naming a path outside the grants fails the server at its first write;
    * and the flags naming a program are dropped before the start. What remains of them for the
    * attaching launch's build — the properties it sees, the memory it gets — is what the owner's
    * own later commands see, the behaviour SECURITY.md "Run on host" accepts for every request.
    *
    * Each field is length-framed, so no two inputs render alike. Every profile input is named, so
    * a field added to `ProfileInputs` or `CommandPrereqs` fails to compile here until it is
    * fingerprinted. */
  def fingerprint(inputs: RunOnHostSandbox.RuntimeInputs, rules: String): String =
    val SeatbeltProfile.ProfileInputs(
      prereqs, sessionTmp, distribution, sbtGlobal, ivyHome, gradleUserHome, m2Repository, proxyPort, authority,
      network,
    ) = inputs.profile
    val RunOnHostPrereqs.CommandPrereqs(project, jdkHome, coursierV1, program, executable) = prereqs
    val SeatbeltProfile.RuntimeAuthority(reads, executes) = authority
    val networkName = network match
      case SeatbeltProfile.Network.ProxyOnly        => "proxy-only"
      case SeatbeltProfile.Network.SbtClient(tmp)   => s"sbt-client $tmp"
      case SeatbeltProfile.Network.MillDaemon       => "mill-daemon"
      case SeatbeltProfile.Network.MillClient(port) => s"mill-client $port"
      case SeatbeltProfile.Network.Gradle           => "gradle"
    val fields =
      Seq(
        program.name, project.toString, jdkHome.toString, coursierV1.toString, executable.toString,
        distribution.fold("")(_.toString), sbtGlobal.fold("")(_.toString), ivyHome.fold("")(_.toString),
        gradleUserHome.fold("")(_.toString), m2Repository.fold("")(_.toString), sessionTmp.toString,
        proxyPort.toString, networkName,
      ) ++ reads.map(_.toString) ++ Seq("executes") ++ executes.map(_.toString)
        ++ Seq("environment") ++ inputs.environment.toSeq.sorted.flatMap((name, value) => Seq(name, value))
        ++ Seq("rules", rules)
    digest(fields.map(field => s"${field.length}:$field").mkString)

  def digest(text: String): String =
    java.security.MessageDigest.getInstance("SHA-256").digest(text.getBytes(UTF_8)).map(byte => f"$byte%02x").mkString
