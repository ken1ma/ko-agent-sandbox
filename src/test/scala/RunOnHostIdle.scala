// The run-on-host checks' test that no live run-on-host runner claims the workspaces they use, and their cleanup of a
// process that no runner claims. The shell probes still use run-on-host-acceptance-setup.sh (doc/TODO.md, "the shell
// probes as Scala CLI scripts"). The Scala CLI drivers under src/test/run-on-host/ pull this file in with
// `//> using file`.
//
// The file depends on the JDK alone, so that a driver compiles without the launcher's sources. It therefore copies
// the session layout's names from RunOnHostSession, and RunOnHostIdleTest checks the copies against the originals.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*
import scala.jdk.OptionConverters.*
import scala.util.Using

object RunOnHostIdle:

  /** RunOnHostSession.root. */
  def supervisorRoot(uid: Int): Path = Path.of(s"/private/tmp/ko-agent-$uid")

  private[launcher] val LockFile = "lock"
  private[launcher] val WorkspaceFile = "workspace"
  private[launcher] val RunFile = "run"
  private[launcher] val CondemnedDir = "condemned"
  private[launcher] val BuildFilePrefix = "build-"
  private[launcher] val PendingSuffix = ".pending"
  private[launcher] val RunnerPrefix = "r"

  /** The pids that hold the file open, as `lsof -t` lists them. */
  def lockHolders(file: Path): Vector[Long] =
    commandLines("/usr/sbin/lsof", "-t", file.toString).flatMap(_.toLongOption)

  /** The working directory of the process, as lsof reports it. */
  def workingDirectory(pid: Long): Option[Path] =
    commandLines("/usr/sbin/lsof", "-a", "-p", pid.toString, "-d", "cwd", "-Fn")
      .collectFirst { case line if line.startsWith("n") => Path.of(line.drop(1)) }

  /** The process's start, as the JDK reports it. The value is compared for equality alone. */
  def startOf(pid: Long): Option[String] =
    ProcessHandle.of(pid).toScala.flatMap(_.info.startInstant.toScala).map(_.toString)

  /**
   * The refusal when a live runner claims one of the workspaces, or Right.
   *
   *   - A runner keeps its claims on build directories after its sbt server ends. So ending sbt alone does not free
   *     a claim, and the check reads the claims, not the servers.
   *   - A runner is live while a process holds its session lock open. The check runs before a driver starts an
   *     unconfined sbt in the checkout.
   *   - A claim is the session's workspace file or one of its published build files. A claim covers every workspace
   *     at or below its directory.
   */
  def requireIdle(root: Path, workspaces: Seq[Path], holders: Path => Vector[Long] = lockHolders)
      : Either[String, Unit] =
    val sessions =
      (sessionDirectories(root) ++ sessionDirectories(root.resolve(CondemnedDir))).filter(dir =>
        Files.isRegularFile(dir.resolve(LockFile)))
    val claims =
      for
        session <- sessions.iterator
        pids = holders(session.resolve(LockFile))
        if pids.nonEmpty
        claim <- claimFiles(session)
        directory <- readTrimmed(claim).filter(_.nonEmpty)
      yield (session, pids, directory)
    claims
      .find((_, _, directory) => workspaces.exists(workspace => s"$workspace/".startsWith(s"$directory/")))
      .map((session, pids, directory) => refusal(session, pids, directory))
      .toLeft(())

  /** Ends the process only when no live runner claims its working directory. A session can start after the
    * preflight, so a process whose directory matches a workspace can belong to that session rather than to the
    * driver. The start is read before and after the check, so a recycled pid is never signalled. Returns whether the
    * process was signalled; a process left alone is reported through `report`. */
  def endUnclaimed(
    root: Path, pid: Long, report: String => Unit,
    start: Long => Option[String] = startOf,
    cwd: Long => Option[Path] = workingDirectory,
    holders: Path => Vector[Long] = lockHolders,
    terminate: Long => Unit = pid => ProcessHandle.of(pid).ifPresent(_.destroy()),
  ): Boolean =
    start(pid) match
      case None => false
      case Some(started) =>
        val unclaimed = cwd(pid).exists(dir => requireIdle(root, Seq(dir), holders).isRight)
        if !unclaimed then
          report(s"left process $pid: its working directory is unknown or claimed by a live runner")
          false
        else if !start(pid).contains(started) then false
        else
          terminate(pid)
          true

  private def refusal(session: Path, pids: Vector[Long], directory: String): String =
    val container = readTrimmed(session.resolve(RunFile)).getOrElse("")
    val remedy =
      if container.isEmpty || container.startsWith("-") || !container.forall(safeContainerChar) then
        s"end that sandbox session first ($session)"
      else s"End that session before retrying; this stops its agent and host builds:\n  podman stop $container"
    Seq(
      s"a sandbox session has a run-on-host runner (pid ${pids.mkString(" ")}) for $directory",
      remedy,
      "While this runs, omit --run-on-host (including --run-on-host=sbt,mill) for this workspace.",
    ).mkString("\n")

  /** A container name that the refusal may print as a command to run: podman's own name characters. */
  private def safeContainerChar(char: Char): Boolean =
    char.isLetterOrDigit && char < 128 || "_.-".contains(char)

  private def sessionDirectories(dir: Path): Vector[Path] =
    listed(dir).filter: entry =>
      val name = entry.getFileName.toString
      name.length > RunnerPrefix.length && name.startsWith(RunnerPrefix)
        && name.drop(RunnerPrefix.length).forall(_.isDigit) && Files.isDirectory(entry)

  private def claimFiles(session: Path): Vector[Path] =
    (session.resolve(WorkspaceFile) +: listed(session).filter: entry =>
      val name = entry.getFileName.toString
      name.startsWith(BuildFilePrefix) && !name.endsWith(PendingSuffix)
    ).filter(Files.isRegularFile(_))

  private def listed(dir: Path): Vector[Path] =
    try Using.resource(Files.list(dir))(_.iterator.asScala.toVector.sorted)
    catch case _: java.io.IOException => Vector.empty

  private def readTrimmed(file: Path): Option[String] =
    try Some(Files.readString(file, UTF_8).trim)
    catch case _: java.io.IOException => None

  private def commandLines(command: String*): Vector[String] =
    try
      val process = ProcessBuilder(command*).redirectError(ProcessBuilder.Redirect.DISCARD).start()
      process.getOutputStream.close()
      val text = String(process.getInputStream.readAllBytes(), UTF_8)
      process.waitFor()
      text.linesIterator.map(_.trim).filter(_.nonEmpty).toVector
    catch case _: java.io.IOException => Vector.empty
