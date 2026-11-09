#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../scala/HostDriver.scala
//> using file ../scala/RunOnHostIdle.scala
//> using file ../scala/RunOnHostChecks.scala

/*
  The run-on-host command lifecycle check: whether the supervisor runs commands side by side, cleans up behind a
  command that it is told to end, and recovers what a killed supervisor left behind (RunOnHostSession).

  Run it on the macOS HOST, from the repository root, with no sandbox session of this workspace running with
  --run-on-host:

      src/test/run-on-host/CommandLifecycleCheck.scala

  - The rows run one at a time: each reads the supervisor's root and the process table, which any concurrent command
    would change.
  - The rows build this repository and fixtures/mill. The files go to src/test/run-on-host/out-macos/command-lifecycle/,
    which each run empties first.

  The rows:

  - two concurrent commands, one sbt and one mill, each with its own directory and proxy;
  - SIGTERM mid-command: the supervisor's shutdown hook ends the groups and removes the command's directory before the
    JVM exits;
  - SIGKILL mid-command: the leader survives the supervisor, so the next start ends the whole running group while its
    leader is alive;
  - SIGKILL with the leaders gone too: the next start condemns and collects the session, and ends the leaderless sbt
    server by the portfile's attribution (RunOnHostSession.collectServers);
  - last, no proxy, sbt server, mill daemon, gradle daemon or command directory survives.
*/

import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.*

import java.nio.file.{Files, Path}

import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration.Duration
import scala.jdk.CollectionConverters.*

@main def check(args: String*): Unit = CommandLifecycleCheck.run(args)

object CommandLifecycleCheck:
  val usage = "usage: src/test/run-on-host/CommandLifecycleCheck.scala"

  def run(args: Seq[String]): Unit =
    val root = orExit(repositoryRoot(ChecksPath))
    orExit(Either.cond(args.isEmpty, (), usage))
    val hostPaths = orExit(HostPaths.of(sys.env.get))
    orExit(Either.cond(scala.util.Properties.isMac, (), "Run this on macOS."))
    val checkout = Checkout(root)
    val out = checkOut(root, "command-lifecycle")
    val transcript = Transcript(out / "transcript.log", timestamps = true)
    val programs = Set(Program.Sbt, Program.Mill)
    val checkRun = CheckRun(transcript, checkout, out, programs, hostPaths)
    runMeasured(transcript, checkRun.cleanup):
      val targets = Vector(Target("sbt", Program.Sbt, root), Target("mill", Program.Mill, checkout.millFixture))
      val measured =
        for
          _ <- checkRun.preflight(targets.map(_.workspace))
          _ = checkRun.machine()
          _ <- checkRun.setup(targets)
        yield CommandLifecycleRows(checkRun).measure()
      measured.fold(identity, identity)

class CommandLifecycleRows(run: CheckRun):
  private val transcript = run.transcript
  private val checkout = run.checkout
  private val root = checkout.root

  def measure(): Int =
    run.cleanup.add("end what the rows started")(run.endUnclaimed(
      run.leftovers(Seq(root), Seq(checkout.millFixture)).flatMap(_._2)))
    concurrent()
    sigterm()
    sigkillMidCommand()
    sigkillLeaderless()
    transcript.step("after every row")
    run.checkNothingSurvives(Seq(root), Seq(checkout.millFixture))
    if transcript.failed == 0 then 0 else 1

  /** One sbt and one mill command overlap, each with its own directory and proxy. */
  private def concurrent(): Unit =
    transcript.step("two concurrent commands")
    given ExecutionContext = ExecutionContext.global
    val sbt = Future(run.supervisor("concurrent-sbt", Program.Sbt, root, Seq("compile")))
    val mill = Future(run.supervisor("concurrent-mill", Program.Mill, checkout.millFixture, Seq("__.compile")))
    var peak = 0
    within(600, intervalMillis = 500):
      peak = peak.max(run.commandsNow)
      sbt.isCompleted && mill.isCompleted
    val sbtResult = Await.result(sbt, Duration.Inf)
    val millResult = Await.result(mill, Duration.Inf)
    run.check("two concurrent commands", sbtResult.ok && millResult.ok,
      if sbtResult.ok && millResult.ok then s"both built; peak concurrent command directories: $peak"
      else s"sbt exit ${sbtResult.status}, mill exit ${millResult.status}")

  /** A supervisor of an sbt compile, started in the background, whose pid is the supervisor JVM's: perl takes the
    * build lock and execs it (CheckRun.supervisorCommand). */
  private def victim(name: String): Started =
    run.start(name, run.supervisorCommand(Program.Sbt, root, Seq("compile")))

  /**
   * The victim's own client record, bound to the victim directly. The supervisor starts the recorded leader, so the
   * leader's parent is the victim, and the recorded start must be the live process's. The supervisor's own scavenger
   * makes the same pid-plus-start check, so a stale record whose pid another child of the victim reused never passes.
   * None when the supervisor ends first.
   */
  private def clientRecord(victim: Started): Option[Path] =
    var found = Option.empty[Path]
    within(300, intervalMillis = 500):
      found = sessionDirectories.map(_ / "records" / "client").filter(Files.isRegularFile(_)).find: record =>
        Files.readString(record).trim.split(" ", 2) match
          case Array(pgid, start) =>
            run.psField(pgid.toLong, "ppid") == victim.pid.toString && run.psField(pgid.toLong, "lstart") == start.trim
          case _ => false
      found.nonEmpty || !victim.process.isAlive
    found

  private def sessionDirectories: Vector[Path] =
    try scala.util.Using.resource(Files.list(run.commandRoot))(_.iterator.asScala.filter(Files.isDirectory(_)).toVector)
    catch case _: java.io.IOException => Vector.empty

  private def lastLine(started: Started): String =
    started.output.linesIterator.filterNot(_.isBlank).toVector.lastOption.getOrElse("").take(80)

  /** SIGTERM mid-command: the supervisor's shutdown hook ends the groups and removes the command's directory before
    * the JVM exits (RunOnHostSession). A JVM's `finally` never runs on a signal. */
  private def sigterm(): Unit =
    val label = "SIGTERM: the supervisor cleans up behind itself"
    transcript.step(label)
    val started = victim("sigterm")
    clientRecord(started) match
      case None => run.fail(label, s"no client record appeared: ${lastLine(started)}")
      case Some(record) =>
        started.process.destroy()
        started.process.waitFor()
        val session = record.getParent.getParent
        // The victim's own directory, not a root-wide count: judging a concurrent legitimate command is not this
        // row's job.
        val cleaned = within(10)(
          !Files.exists(session) && !Files.exists(run.commandRoot / "condemned" / session.getFileName.toString) &&
            run.sbtServers(root).isEmpty && run.strayProxies.isEmpty)
        val left = Seq(
          Option.when(Files.exists(session))(session.toString),
          Option.when(run.sbtServers(root).nonEmpty)(s"sbt server ${run.sbtServers(root).mkString(" ")}"),
          Option.when(run.strayProxies.nonEmpty)(s"proxy ${run.strayProxies.mkString(" ")}"),
        ).flatten
        run.check(label, cleaned, if cleaned then "" else s"left: ${left.mkString(", ")}")

  /** SIGKILL mid-command: the leader survives the supervisor, so the next start ends the whole running group while its
    * leader is alive, instead of refusing a leaderless one. */
  private def sigkillMidCommand(): Unit =
    val label = "SIGKILL mid-command: the running group is ended while its leader is alive"
    transcript.step(label)
    val started = victim("killed-mid")
    clientRecord(started) match
      case None => run.fail(label, s"no client record appeared: ${lastLine(started)}")
      case Some(_) =>
        started.process.destroyForcibly()
        started.process.waitFor()
        // The recovery run's own command is beside the point, and --version is the cheap one.
        val recovered = run.supervisor("recover-mid", Program.Sbt, root, Seq("--version"))
        run.check(label, recovered.has("GroupEnded"), recovered.text.linesIterator.find(_.contains("scavenged"))
          .getOrElse(recovered.text.linesIterator.toVector.lastOption.getOrElse("")).take(90))

  /**
   * The leaderless server needs the leaders gone too:
   *
   *   1. SIGKILL the supervisor mid-command;
   *   2. let the client finish its command cleanly, so that the leader publishes its exit beside the record;
   *   3. SIGKILL the client's leader and the server's leader alone. The server survives with the portfile, its group's
   *      leader gone.
   *
   * The proxy is recorded and ended, the client and server groups are leaderless and skipped, and the server is ended
   * by attribution (RunOnHostSession.collectServers). Killing any of the client's processes instead stages the wrong
   * state: a server whose client dies mid-exec cancels the exec, and the supervisor's teardown would end the server's
   * group behind its live leader.
   */
  private def sigkillLeaderless(): Unit =
    val collected = "SIGKILL: next start condemns and collects"
    val attributed = "leaderless server ended by portfile attribution"
    transcript.step(collected)
    val started = victim("killed")
    clientRecord(started) match
      case None =>
        run.fail(collected, s"no client record appeared: ${lastLine(started)}")
        run.skip(attributed, "no orphan was staged")
      case Some(record) =>
        val clientGroup = Files.readString(record).trim.takeWhile(_ != ' ').toLong
        val serverRecord = scala.util.Using.resource(Files.list(record.getParent))(_.iterator.asScala
          .find(_.getFileName.toString.startsWith("server-sbt-")).toVector).headOption
        started.process.destroyForcibly()
        started.process.waitFor()
        val exit = record.resolveSibling("client.exit")
        if !within(300, intervalMillis = 500)(Files.exists(exit)) then
          run.fail(collected, "the client never finished")
          run.skip(attributed, "no orphan was staged")
          run.command("/usr/bin/pkill", "-9", "-g", clientGroup.toString)
        else
          // The leaders alone: the command is done, and the server stays.
          ProcessHandle.of(clientGroup).ifPresent(_.destroyForcibly())
          serverRecord.flatMap(file => Files.readString(file).trim.takeWhile(_ != ' ').toLongOption)
            .foreach(leader => ProcessHandle.of(leader).ifPresent(_.destroyForcibly()))
          Thread.sleep(1000)
          val staged = run.sbtServers(root)
          // The recovery run's stderr reports the cleanup of the victim's command directory.
          val recovered = run.supervisor("recover", Program.Sbt, root, Seq("--version"))
          val scavenged = recovered.text.linesIterator.find(_.contains("scavenged"))
          run.check(collected, scavenged.nonEmpty, scavenged.getOrElse(
            recovered.text.linesIterator.toVector.lastOption.getOrElse("")).take(90))
          run.check(attributed, staged.nonEmpty && recovered.has("ServerShutDown") && run.sbtServers(root).isEmpty,
            "ServerShutDown\\([^)]*\\)".r.findFirstIn(recovered.text)
              .getOrElse(s"staged: ${if staged.isEmpty then "none" else staged.mkString(" ")}; ${scavenged
                .getOrElse("")}").take(90))
