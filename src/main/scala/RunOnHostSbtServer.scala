// The runner's sbt server (run-on-host.md, "sbt"):
//
// - the server's command line, built from a client request;
// - the server's start under the server profile;
// - the user's own server that holds the build directory's portfile. The runner finds that server and shuts it down
//   before the runner starts its own. RunOnHostSbtServerShutdown.scala speaks the shutdown's protocol.

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
   * The live server that a build directory's portfile names, if any. This method serves the one-server rule that
   * SECURITY.md, "Run on host", records.
   *
   *   - A thin client attaches to whatever server the portfile names, and then runs with that server's environment
   *     and confinement.
   *   - Before the runner starts its own server, a live server found here is ended (RunnerRuntimes.noForeignServer).
   *     While the runner's server runs, a live socket inside the runner's `tmp/` is that server.
   *   - Live means connectable. A stale portfile is left for sbt, which replaces it.
   *   - The socket is wherever the portfile points, uncontained on purpose: the user's own server runs outside any
   *     sandbox. The probe only connects and closes, and writes nothing to what it reaches.
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
   * Where the user's own sbt 2 keeps this build's server socket:
   * `<serverDir>/<half SHA-1 hex of the portfile path's Path.toUri spelling>/sock`. serverDir is
   * `$SBT_GLOBAL_SERVER_DIR`, or else the global base versioned `/2`, then `/server`.
   *
   * This method takes each input as sbt takes it, because a divergence here is a divergence in what gets shut down:
   *
   *   - `SBT_GLOBAL_SERVER_DIR` is taken verbatim, even when present but empty (`CommandExchange.scala`).
   *   - The global base's own sources are trimmed and empty-filtered: `SBT_CONFIG_HOME`, else `XDG_CONFIG_HOME/sbt`,
   *     else `user.home/.config/sbt` (`SysProp.defaultGlobalBaseDirectory`).
   *   - The base uses `user.home`, not `$HOME`: sbt reads the property, and the two can differ.
   *   - `-Dsbt.global.base` comes first in sbt's order, but it is set in the user's JVM and invisible from this
   *     process. A server launched with it derives its socket elsewhere and is never found at this socket. The
   *     result is the refusal in shutdownForeignServer, not a wrong shutdown.
   */
  def sbtServerSocket(buildDirectory: Path, env: String => Option[String], userHome: Path): Path =
    // java.io.File joins throughout, as sbt's `/` does. An empty parent then resolves against the root, where
    // Path.resolve would keep the result relative.
    def file(value: String) = java.io.File(value)
    extension (parent: java.io.File) def /(child: String) = java.io.File(parent, child)
    def trimmed(name: String): Option[java.io.File] =
      env(name).filter(_.nonEmpty).map(value => file(value.trim))
    val uri = buildDirectory.resolve("project").resolve("target").resolve("active.json").toUri.toString
    val digest = java.security.MessageDigest.getInstance("SHA-1").digest(uri.getBytes(UTF_8))
    val hash = java.util.HexFormat.of().formatHex(digest).take(20)
    val globalBase =
      trimmed("SBT_CONFIG_HOME")
        .orElse(trimmed("XDG_CONFIG_HOME").map(_ / "sbt"))
        .getOrElse(file(userHome.toString) / ".config" / "sbt")
        .getAbsoluteFile
    val serverDir = env("SBT_GLOBAL_SERVER_DIR").map(file).getOrElse(globalBase / "2" / "server")
    (serverDir / hash / "sock").toPath

  /** A chain longer than this is a cycle or an attempt at one. Either way, the walk cannot answer. */
  private val MaxSymlinkHops = 40

  /**
   * Whether a command could have planted a path that the supervisor is about to send to.
   *
   * The question is not where the path ends, but whether resolving the path ever *enters* a place a command writes.
   *
   *   - From the first component inside such a place, the command chooses what every later component means. A link
   *     there can send the rest anywhere, even straight back out. The fully resolved endpoint therefore answers
   *     nothing.
   *   - The walk therefore follows one hop at a time. The walk checks where each link *is located* before reading where
   *     the link points.
   *   - The walk answers yes as soon as a step resolves into a writable root. The leaf counts too, since the socket
   *     itself may be the planted link.
   *   - The walk stops at the first component that is absent even as a link. Nothing exists beneath that component,
   *     and creating it would need a write to the last resolved prefix, which by then lies outside every writable
   *     root.
   *
   * The roots are the profile's writable set (`SeatbeltProfile.render`):
   *
   *   - The roots are the workspace and the per-workspace caches that persist across sessions. The walk thus also
   *     catches a socket that an *earlier* agent's command planted in a cache.
   *   - Each root is compared in both of its macOS spellings. Every containment check here shares this firmlink
   *     aliasing (`SandboxWorkspace.withMacDataVolumeAliases`).
   *   - A cache that does not resolve holds nothing and is skipped.
   *   - The workspace is mandatory. An unresolvable workspace, a relative target and any walk that cannot answer
   *     therefore all count as reachable.
   *   - A target already lexically inside a root is reachable whatever the filesystem currently shows. This method
   *     answers that case before the walk begins.
   */
  def reachableThroughCommandWritable(target: Path, workspaceRoot: Path, caches: Seq[Path]): Boolean =
    realPath(workspaceRoot) match
      case None => true
      case Some(realWorkspaceRoot) =>
        val roots =
          SandboxWorkspace.withMacDataVolumeAliases(realWorkspaceRoot +: caches.flatMap(realPath))
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
                    // One hop only: the walk checks the link target's own components next.
                    val link = Files.readSymbolicLink(step)
                    if link.isAbsolute then resolved = link.getRoot
                    pending = link.iterator.asScala.map(_.toString).toList ++ pending
                else resolved = step
            reachable
          catch case _: IOException => true

  /**
   * Ends the user's own server before the runner starts its own.
   *
   *   - The shutdown goes through the protocol. The server runs it after its current exec, so a build in flight there
   *     completes first.
   *   - This method derives the socket from the build directory the way sbt derives it, and never reads the socket
   *     from the portfile. The portfile's socket is only compared against the derived one. Workspace content must
   *     not choose where an unconfined write-and-parse goes.
   *   - The derivation is an authorization, so this method checks it as well as computing it. This method refuses a
   *     derived socket that the workspace could have planted: the workspace chooses its own content, so it would
   *     then choose the target.
   *   - Every doubt falls back to the refusal, which names what stopped the shutdown.
   */
  def shutdownForeignServer(
    workspaceRoot: Path,
    buildDirectory: Path,
    portfileSocket: Path,
    env: String => Option[String],
    log: String => Unit,
    runOnHostCaches: Seq[Path] = Seq.empty,
    userHome: Path = Path.of(System.getProperty("user.home")),
    shutdownDeadlineMillis: Long = 120_000,
    releaseDeadlineMillis: Long = 10_000,
  ): Either[String, Unit] =
    def refused(cause: String) = Left(s"${foreignServerRefusal(portfileSocket)} ($cause)")
    val derived = sbtServerSocket(buildDirectory, env, userHome)
    if reachableThroughCommandWritable(derived, workspaceRoot, runOnHostCaches) then
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
        // Unreachable means that the server went away between the liveness probe and now, which is the outcome
        // sought.
        case ServerAnswer.ShutDown | ServerAnswer.Unreachable(_) =>
          val deadline = System.nanoTime + releaseDeadlineMillis * 1_000_000
          while livePortfileServer(buildDirectory).isDefined && System.nanoTime < deadline do
            Thread.sleep(50)
          if livePortfileServer(buildDirectory).isEmpty then Right(())
          else refused("the server answered the shutdown but still holds the portfile")

  private def samePath(a: Path, b: Path): Boolean =
    a == b || (try a.toRealPath() == b.toRealPath() catch case _: IOException => false)

  // The thin client's own classes of launcher flag (NetworkClient.parseArgs, v2.0.9):
  //
  // - A value flag takes the next argument or an `=` value.
  // - A no-value flag and an `=`-prefixed flag belong to the client and reach no server.
  // - The empty-build flags are launcher flags even after the first command.
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

  /** Flags that name a program to run: the JVM, the launcher jar or the runner script. The profile's grants decide
    * those programs, and no request may. The JDK is the launcher's, the script is the validated one, and
    * `sbt.script` names what a server forks later. */
  private val ProgramFlags = Set("-java-home", "--java-home", "-sbt-jar", "--sbt-jar")

  /**
   * The server command line as sbt's thin client issues it when it starts a server (NetworkClient.serverCommand,
   * v1.13.0 and v2.0.9).
   *
   *   - The request's launcher flags come before `--detach-stdio --server`, as the client classifies them: the `-D`
   *     properties, the value flags with their values, the empty-build flags wherever they stand, and any other flag
   *     the client does not keep for itself.
   *   - Like the client, this method drops three kinds of argument:
   *     - `-J`, which the runner applies to the JVM it starts, the client's JVM;
   *     - the client's own no-value and `=`-form flags;
   *     - the commands, which the client sends over the socket.
   *   - Beyond the client, this method drops the program flags (ProgramFlags).
   *   - The script reads `.sbtopts` and `.jvmopts` from the build directory as it always does.
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

  /** The socket sbt derives for a build directory's server under this session's `tmp/`.
    *
    *   - The server runs with `SBT_GLOBAL_SERVER_DIR` set to `tmp/`, so its portfile names
    *     `<tmp>/<SHA-1 of the portfile URI>/sock` (sbtServerSocket).
    *   - The reuse and startup checks compare the portfile against this exact path, not merely against "a socket
    *     under tmp/". A portfile copied from another build directory therefore never authorizes reuse or "up". */
  def expectedServerSocket(sessionTmp: Path, buildDirectory: Path): Path =
    val serverDir: String => Option[String] =
      name => Option.when(name == "SBT_GLOBAL_SERVER_DIR")(sessionTmp.toString)
    sbtServerSocket(buildDirectory, serverDir, Path.of("/"))

  /** Where a server's stdout and stderr go.
    *
    *   - The file lies in the session directory, which the profile grants no process. Under `tmp/`, the server could
    *     replace the file with a link or a FIFO before the runner opens it for the next server.
    *   - RunOnHostSandbox.appendSessionLogs keeps the file there with the session's other logs.
    *   - The servers of one build directory append to the same file. */
  def serverLog(session: Session, hash: String): Path = session.directory.resolve(s"${serverRecordName(hash)}.log")

  /** Starts the server (run-on-host.md, "sbt") under the server profile. The server's output goes to serverLog, and
    * the runner's `tmp/` is its temporary and socket directory. The server is up when the build directory's
    * portfile names a connectable socket under that `tmp/`. */
  private[launcher] def startSbtServer(session: Session, start: RuntimeStart): Either[String, Unit] =
    val assembled = start.assembled
    val output = serverLog(session, start.hash)
    for
      profileFile <- writeRuntimeProfile(session, serverRecordName(start.hash), start.inputs)
      leader <-
        try
          Right(startRuntimeStarter(
            start.record, profileFile,
            serverCommand(assembled.prereqs.executable, assembled.sbtGlobal, start.arguments),
            start.buildDirectory, start.inputs.environment, output,
          ))
        catch case ex: IOException => Left(s"starting the sbt server: ${ex.getMessage}")
      _ <- awaitServer(session, start, leader, output)
    yield ()

  private def awaitServer(session: Session, start: RuntimeStart, leader: Process, output: Path): Either[String, Unit] =
    val exit = RunOnHostSession.exitRecord(start.record)
    def said = s"its output:\n${starterOutputTail(output)}"
    val watch = StartWatch(output, start.runtime.proxyLog)
    var result: Option[Either[String, Unit]] = None
    while result.isEmpty do
      val leaderEnded = !leader.isAlive // read before the file, so a leader that dies after its rename still answers
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
