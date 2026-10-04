// The runner's sbt server (run-on-host.md "sbt"): its command line from a client request, its start
// under the server profile, and the user's own server holding the build directory's portfile, found
// and shut down before the runner starts one. The shutdown's protocol is RunOnHostSbtServerShutdown.scala.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*

import RunOnHostSandbox.*
import RunOnHostSession.{serverRecordName, ServerAnswer, Session}
import FileHelper.realPath

object RunOnHostSbtServer:

  /**
   * The live server a build directory's portfile names, if any: SECURITY.md "Run on host"
   * records the one-server rule it serves. A thin client attaches to whatever server the
   * portfile names and then runs with that server's environment and confinement, so before the
   * runner starts its own server, a live one here is ended (RunnerRuntimes.noForeignServer), and
   * while the runner's runs, a live socket inside the runner's `tmp/` is that server. Live means
   * connectable; a stale portfile is left for sbt, which replaces it. The socket here is wherever
   * the portfile points, uncontained on purpose — the user's own server runs outside any
   * sandbox — and the probe only connects and closes, writing nothing to what it reaches.
   */
  def livePortfileServer(buildDirectory: Path): Option[Path] =
    val portfile = buildDirectory.resolve("project").resolve("target").resolve("active.json")
    if !Files.isRegularFile(portfile) then None
    else
      try
        RunOnHostSession.portfileSocket(Files.readString(portfile, UTF_8)).filter: socket =>
          Files.exists(socket) && connectable(socket)
      catch case _: IOException => None

  private def connectable(socket: Path): Boolean =
    try
      val channel = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.UNIX)
      try
        channel.connect(java.net.UnixDomainSocketAddress.of(socket))
        true
      finally channel.close()
    catch case _: IOException => false

  def foreignServerRefusal(socket: Path): String =
    s"a live sbt server holds this build directory's portfile (socket $socket); " +
      "run `sbt shutdown` there and retry"

  /**
   * Where the user's own sbt 2 keeps this project's server socket:
   * `<serverDir>/<half SHA-1 hex of the portfile path's Path.toUri spelling>/sock`, with
   * serverDir `$SBT_GLOBAL_SERVER_DIR`, else the global base versioned `/2`, then `/server`.
   * Each input is taken as sbt takes it, because a divergence here is a divergence in what gets
   * shut down: `SBT_GLOBAL_SERVER_DIR` verbatim, present-but-empty included
   * (`CommandExchange.scala`), while the global base's own sources are trimmed and empty-filtered
   * — `SBT_CONFIG_HOME`, else `XDG_CONFIG_HOME/sbt`, else `user.home/.config/sbt`
   * (`SysProp.defaultGlobalBaseDirectory`). `user.home`, not `$HOME`: sbt reads the property, and
   * the two can differ. `-Dsbt.global.base`, first in sbt's order, is set in the user's JVM and is
   * invisible from this process, so a server launched with it derives elsewhere and is never
   * found at this socket — the refusal below, not a wrong shutdown.
   */
  def sbtServerSocket(buildDirectory: Path, env: String => Option[String], userHome: Path): Path =
    // java.io.File joins throughout, as sbt's `/` does: an empty parent resolves against the
    // root, where Path.resolve would keep the result relative.
    def file(value: String) = java.io.File(value)
    extension (parent: java.io.File) def /(child: String) = java.io.File(parent, child)
    def trimmed(name: String): Option[java.io.File] =
      env(name).filter(_.nonEmpty).map(value => file(value.trim))
    val uri = buildDirectory.resolve("project").resolve("target").resolve("active.json").toUri.toString
    val digest = java.security.MessageDigest.getInstance("SHA-1").digest(uri.getBytes(UTF_8))
    val hash = digest.map(byte => f"$byte%02x").mkString.take(20)
    val globalBase =
      trimmed("SBT_CONFIG_HOME")
        .orElse(trimmed("XDG_CONFIG_HOME").map(_ / "sbt"))
        .getOrElse(file(userHome.toString) / ".config" / "sbt")
        .getAbsoluteFile
    val serverDir = env("SBT_GLOBAL_SERVER_DIR").map(file).getOrElse(globalBase / "2" / "server")
    (serverDir / hash / "sock").toPath

  /** A chain longer than this is a cycle or an attempt at one; either way, unanswerable. */
  private val MaxSymlinkHops = 40

  /**
   * Whether a path the supervisor is about to send to could have been planted by a command. The
   * question is not where the path ends but whether resolving it ever *enters* somewhere a command
   * writes: from the first component inside, the command chooses what every later component means,
   * and a link there can send the rest anywhere — including straight back out, which is why the
   * fully resolved endpoint answers nothing. So the walk follows one hop at a time, checking
   * where each link *is located* before reading where it points, and answers yes the moment a step
   * resolves into a writable root — the leaf included, since the socket itself may be the planted
   * link. It stops at the first component absent even as a link: nothing exists beneath it, and
   * creating it would need a write to the last resolved prefix, outside every writable root by
   * then.
   *
   * The roots are the profile's writable set (`SeatbeltProfile.render`): the project, and the
   * per-project caches that persist across sessions, so a socket an *earlier* agent's command
   * planted in a cache is caught as well. Each is compared in both of its macOS spellings, the
   * firmlink aliasing every containment check here shares
   * (`SandboxProject.withMacDataVolumeAliases`). A cache that does not resolve holds nothing and
   * is skipped; the project is mandatory, so its silence, a relative target, and any unanswerable
   * walk all count as reachable. A target already lexically inside a root is reachable whatever
   * the filesystem currently shows, so that is answered before the walk begins.
   */
  def reachableThroughCommandWritable(target: Path, project: Path, caches: Seq[Path]): Boolean =
    realPath(project) match
      case None => true
      case Some(projectRoot) =>
        val roots =
          SandboxProject.withMacDataVolumeAliases(projectRoot +: caches.flatMap(realPath))
        def inside(path: Path) = roots.exists(path.normalize.startsWith)
        if target.getRoot == null || inside(target) then true
        else
          try
            var resolved = target.getRoot
            var pending = target.iterator.asScala.map(_.toString).toList
            var hops = 0
            var reachable = false
            var absent = false
            while pending.nonEmpty && !reachable && !absent do
              val name = pending.head
              pending = pending.tail
              if name == "." then ()
              else if name == ".." then Option(resolved.getParent).foreach(resolved = _)
              else
                val step = resolved.resolve(name)
                if inside(step) then reachable = true
                else if !Files.exists(step, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
                  absent = true
                else if Files.isSymbolicLink(step) then
                  hops += 1
                  if hops > MaxSymlinkHops then reachable = true
                  else
                    // One hop only: its target's own components are walked, and checked, next.
                    val link = Files.readSymbolicLink(step)
                    if link.isAbsolute then resolved = link.getRoot
                    pending = link.iterator.asScala.map(_.toString).toList ++ pending
                else resolved = step
            reachable
          catch case _: IOException => true

  /**
   * The user's own server, ended before the runner starts its own: a protocol shutdown, which
   * the server runs after the exec it is on, so a build in flight there completes first. The
   * socket the shutdown is sent to is derived from the build directory the way sbt derives it,
   * never read from the portfile, and the portfile's word is only compared against it: workspace
   * content must not choose where an unconfined write-and-parse goes. The derivation is
   * authorization, so it is checked as well as computed — a derived socket the project could
   * have planted is refused, since the project chooses its own content and would then be
   * choosing the target. Every doubt falls back to the refusal, naming what stopped the shutdown.
   */
  def shutdownForeignServer(
    project: Path,
    buildDirectory: Path,
    portfileSocket: Path,
    env: String => Option[String],
    log: String => Unit,
    runOnHostCaches: Seq[Path] = Seq.empty,
    userHome: Path = Path.of(System.getProperty("user.home")),
    shutdownDeadlineMillis: Long = 120_000,
    releaseDeadlineMillis: Long = 10_000,
  ): Either[String, Unit] =
    def refused(cause: String) = Left(s"${foreignServerRefusal(portfileSocket)} — $cause")
    val derived = sbtServerSocket(buildDirectory, env, userHome)
    if reachableThroughCommandWritable(derived, project, runOnHostCaches) then
      refused(
        s"the socket sbt derives for this build directory ($derived) is reachable through what a " +
          "command writes, so no shutdown is sent to it",
      )
    else if !samePath(derived, portfileSocket) then
      refused(s"its socket is not the one sbt derives for this build directory ($derived)")
    else
      log(s"shutting down the sbt server at $derived: it holds the portfile of $buildDirectory")
      RunOnHostSbtServerShutdown.shutdown(derived, shutdownDeadlineMillis) match
        case ServerAnswer.Unanswered(reason) => refused(s"the shutdown went unanswered: $reason")
        // Unreachable is the server gone between the liveness probe and now — the outcome sought.
        case ServerAnswer.ShutDown | ServerAnswer.Unreachable(_) =>
          val deadline = System.nanoTime + releaseDeadlineMillis * 1_000_000
          while livePortfileServer(buildDirectory).isDefined && System.nanoTime < deadline do
            Thread.sleep(50)
          if livePortfileServer(buildDirectory).isEmpty then Right(())
          else refused("the server answered the shutdown but still holds the portfile")

  private def samePath(a: Path, b: Path): Boolean =
    a == b || (try a.toRealPath() == b.toRealPath() catch case _: IOException => false)

  // The thin client's own classes of launcher flag (NetworkClient.parseArgs, v2.0.9): a value
  // flag takes the next argument or an `=` value; a no-value flag and an `=`-prefixed one are
  // the client's own and reach no server; the empty-build flags are launcher flags even after
  // the first command.
  private val LauncherValueFlags = Set(
    "-mem", "--mem", "-jvm-debug", "--jvm-debug", "-sbt-jar", "--sbt-jar", "-sbt-cache", "--sbt-cache",
    "-sbt-version", "--sbt-version", "-java-home", "--java-home", "-ivy", "--ivy", "-sbt-boot", "--sbt-boot",
    "-sbt-dir", "--sbt-dir",
  )
  private val LauncherNoValueFlags = Set(
    "-client", "--client", "--server", "--jvm-client", "-h", "-help", "--help", "-v", "-verbose", "--verbose",
    "-V", "-version", "--version", "--numeric-version", "--script-version", "-d", "-debug", "--debug",
    "-debug-inc", "--debug-inc", "-batch", "--batch", "--no-hide-jdk-warnings", "-no-colors", "--no-colors",
    "-timings", "--timings", "-traces", "--traces", "-no-share", "--no-share", "-no-global", "--no-global",
    "shutdownall", "-bsp", "--bsp", "bsp", "-no-server", "--no-server",
  )
  private val LauncherEqPrefixes =
    Seq("--supershell=", "-supershell=", "--color=", "-color=", "--autostart=", "-autostart=")
  private val EmptyBuildFlags = Set("-allow-empty", "--allow-empty", "-sbt-create", "--sbt-create")

  /** Flags naming a program to run — the JVM, the launcher jar, the runner script — which the
    * profile's grants decide and no request may: the JDK is the launcher's, the script the
    * validated one, and `sbt.script` is what a server forks later. */
  private val ProgramFlags = Set("-java-home", "--java-home", "-sbt-jar", "--sbt-jar")

  /**
   * The server command line as sbt's thin client issues it when it starts a server
   * (NetworkClient.serverCommand, v1.13.0 and v2.0.9): the request's launcher flags as the client
   * classifies them — its `-D` properties, its value flags with their values, the empty-build
   * flags wherever they stand, and any other flag the client does not keep for itself — before
   * `--detach-stdio --server`. As the client, it drops `-J`, which the runner applies to the JVM
   * it starts, the client's; the no-value and `=`-form flags of the client's own; and the
   * commands, which the client sends over the socket. Beyond the client it drops the program
   * flags (ProgramFlags). `.sbtopts` and `.jvmopts` the script reads from the build directory as
   * it always does.
   */
  def serverCommand(executable: Path, sbtGlobal: Path, arguments: Seq[String]): Seq[String] =
    val forwarded = Vector.newBuilder[String]
    var commands = false
    var index = 0
    while index < arguments.length do
      val argument = arguments(index)
      val flag = argument.takeWhile(_ != '=')
      if commands then
        if EmptyBuildFlags(argument) then forwarded += argument
      else if argument.startsWith("--sbt-script=") || argument.startsWith("--sbt-launch-jar=") then ()
      else if (argument == "--sbt-script" || argument == "--sbt-launch-jar") && index + 1 < arguments.length then
        index += 1
      else if LauncherValueFlags(argument) then
        if index + 1 < arguments.length then
          if !ProgramFlags(argument) then forwarded ++= Seq(argument, arguments(index + 1))
          index += 1
      else if LauncherValueFlags(flag) && argument.length > flag.length + 1 then
        if !ProgramFlags(flag) then forwarded ++= Seq(flag, argument.drop(flag.length + 1))
      else if LauncherNoValueFlags(argument) || LauncherEqPrefixes.exists(argument.startsWith) then ()
      else if argument.startsWith("-J") || argument.startsWith("-Dsbt.script=") then ()
      else if !argument.startsWith("-") then commands = true
      else forwarded += argument
      index += 1
    sbtCommand(executable, sbtGlobal) ++ Seq(s"-Dsbt.script=$executable") ++
      forwarded.result() ++ Seq("--detach-stdio", "--server")

  /** The socket sbt derives for a build directory's server under this session's `tmp/`: the
    * server runs with `SBT_GLOBAL_SERVER_DIR` set to `tmp/`, so its portfile names
    * `<tmp>/<SHA-1 of the portfile URI>/sock` (sbtServerSocket). The reuse and startup checks
    * compare the portfile against this exact path, not merely "a socket under tmp/", so a
    * portfile copied from another build directory never authorizes reuse or "up". */
  def expectedServerSocket(sessionTmp: Path, buildDirectory: Path): Path =
    val serverDir: String => Option[String] =
      name => Option.when(name == "SBT_GLOBAL_SERVER_DIR")(sessionTmp.toString)
    sbtServerSocket(buildDirectory, serverDir, Path.of("/"))

  /** Where a server's output goes, stdout and stderr: in the session directory, which the profile
    * grants no process, rather than under `tmp/`, where the server could replace the file with a
    * link or a FIFO before the runner opens it for the next server; RunOnHostSandbox.appendSessionLogs keeps it
    * there with the session's other logs. Appended to across the servers of one build directory. */
  def serverLog(session: Session, hash: String): Path = session.directory.resolve(s"${serverRecordName(hash)}.log")

  /** The server (run-on-host.md "sbt") under the server profile, its output to serverLog and the
    * runner's `tmp/` its temporary and socket directory. Up when the build directory's portfile
    * names a connectable socket under that `tmp/`. */
  private[launcher] def startSbtServer(
    session: Session,
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
    fileRules: FileRules.Resolved,
    start: ServerStart,
  ): Either[String, Unit] =
    val assembled = start.assembled
    val prereqs = assembled.prereqs
    val output = serverLog(session, start.hash)
    val inputs = runtimeInputs(
      assembled, session.tmp, start.runtime.proxyPort, start.runtime.trust, systemPaths, forwards,
      SeatbeltProfile.Network.ProxyOnly, fileRules,
    )
    for
      profile <- SeatbeltProfile.render(inputs.profile)
      leader <-
        try
          val profileFile = runtimeProfileFile(session, serverRecordName(start.hash))
          Files.writeString(profileFile, profile, UTF_8)
          Right(startRuntimeStarter(
            start.record, profileFile, serverCommand(prereqs.executable, assembled.sbtGlobal, start.arguments),
            start.buildDirectory, inputs.environment, output,
          ))
        catch case ex: IOException => Left(s"starting the sbt server: ${ex.getMessage}")
      _ <- awaitServer(session, start, leader, output)
    yield ()

  private def awaitServer(session: Session, start: ServerStart, leader: Process, output: Path): Either[String, Unit] =
    val exit = RunOnHostSession.exitRecord(start.record)
    def said = s"its output:\n${starterOutputTail(output)}"
    val watch = StartWatch(output, start.runtime.proxyLog)
    var result: Option[Either[String, Unit]] = None
    while result.isEmpty do
      val leaderEnded = !leader.isAlive // read before the file: a leader dying after its rename still answers
      if Files.exists(exit) then
        val status = try Files.readString(exit, UTF_8).trim catch case _: IOException => "?"
        result = Some(Left(s"the sbt server exited ($status) before publishing its portfile; $said"))
      else if leaderEnded then
        result = Some(Left(s"the sbt server's leader ended (exit ${leader.exitValue}) without registering it"))
      else
        livePortfileServer(start.buildDirectory) match
          case Some(socket)
              if socket == expectedServerSocket(session.tmp, start.buildDirectory)
                && !Files.isSymbolicLink(socket) && !Files.isSymbolicLink(socket.getParent) =>
            result = Some(Right(()))
          case Some(socket) =>
            result = Some(Left(
              s"a live sbt server holds the portfile of ${start.buildDirectory} at $socket, and it is not the " +
                "unredirected socket this launch's server derives",
            ))
          case None =>
            watch.poll() match
              case StartProgress.Grew => ()
              case StartProgress.Silent =>
                result = Some(Left(
                  s"the sbt server published no portfile, and neither its output nor the proxy log grew, for " +
                    s"${ServerStartSilenceMillis / 1000}s; $said",
                ))
              case StartProgress.Waiting => Thread.sleep(100)
    result.get
