// The launch's Gradle daemons (run-on-host.md, "Gradle").
//
// - Gradle's own client starts each daemon under the command's profile, in the registry that every Gradle command
//   line names under the runner's `tmp/`.
// - The daemon detaches itself into a process group of its own (`DaemonMain`, `setsid`). The daemon's workers and
//   test executors are forked in that group.
// - The runner records each daemon by pid and start time as `records/daemon-gradle-<pid>`, after every command
//   and once more at the launch's end. The launch's end signals the group behind each record, as it signals every
//   recorded group.
//   - The daemon's pid is its group id, so a daemon's record is like a leader's record, written after the fact.
// - The daemon's initial environment identifies the daemon as the launch's:
//   - The client starts the daemon with the client's own environment
//     (`DefaultProcessForkOptions.getInheritableEnvironment`).
//   - That environment's `_JAVA_OPTIONS` names the runner's `tmp/` as `java.io.tmpdir`. No process outside this
//     launch's commands was started with that value.
// - No path identifies a daemon. The build writes across `tmp/` and the workspace. A file that one of the user's
//   other daemons holds open, once renamed into the registry under any name, is reported by the kernel at that
//   name.
// - Build code in the daemon can hide the daemon from its own launch, and from nothing else:
//   - `ps -E` reads the strings from the daemon's own memory (`KERN_PROCARGS2`, `sysctl_procargsx`), so build
//     code in the daemon can rewrite them.
//   - A daemon so hidden stays unrecorded. So does a daemon started under a runner that died during the command.
//   - Either daemon is confined, holds nothing, and exits on Gradle's idle timeout (SECURITY.md, "Run on host").
// - The daemons are observed on macOS only, like the supervisor, because the observations are pgrep and ps.
//   RunnerRuntimes therefore takes `gradleDaemons` as a parameter that tests replace, and the acceptance test
//   measures it.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{Files, Path}

import RunOnHostSession.{HostProcesses, Processes, Record}

object RunOnHostGradleDaemons:

  /** The daemon's main class. The class appears on the daemon's command line (`DefaultDaemonStarter`) and nowhere on
    * the client's. */
  val DaemonMain = "org.gradle.launcher.daemon.bootstrap.GradleDaemon"

  /** The value of `org.gradle.daemon.registry.base` on every Gradle command line (RunOnHostSandbox.gradleCommand).
    * The registry lies under the runner's `tmp/`, which every Gradle process of the launch is granted and which
    * ends with the launch. */
  def registryBase(tmp: Path): Path = tmp.resolve("gradle-daemon")

  private val RecordPrefix = "daemon-gradle-"

  def recordName(pid: Long): String = s"$RecordPrefix$pid"

  /** Whether a process's command line and initial environment carry the launch's temporary directory as the JVM
    * option that the command environment sets (RunOnHostSandbox.commandEnvironment). `ps -wwE -o command=` prints
    * the command line and the environment on one line.
    *
    *   - The option comes first in `_JAVA_OPTIONS`, so the variable's name prefixes the option.
    *   - The option's own closing quote ends it, so a directory whose name extends this one belongs to another
    *     launch. */
  def carriesTmp(commandAndEnvironment: String, tmp: Path): Boolean =
    val option = RunOnHostSandbox.jvmProperty("java.io.tmpdir", tmp.toString)
    s" $commandAndEnvironment ".contains(s" _JAVA_OPTIONS=$option ")

  /**
   * The daemons on the host that were started with the launch's environment, with their start times.
   *
   *   - The pid comes from the process table, never from a registry file.
   *   - The start time is read before the attribution and checked again after it, so a pid recycled between the two
   *     observations records no stranger.
   */
  def daemons(tmp: Path, processes: Processes): Vector[(Long, String)] =
    val real =
      try tmp.toRealPath()
      catch case _: IOException => tmp
    HostProcesses.lines(HostProcesses.Pgrep, "-f", "--", DaemonMain).flatMap(_.toLongOption).flatMap: pid =>
      processes.startOf(pid).filter: start =>
        val ours = HostProcesses.lines(HostProcesses.Ps, "-wwE", "-o", "command=", "-p", pid.toString)
          .exists(carriesTmp(_, real))
        ours && processes.startOf(pid).contains(start)
      .map(pid -> _)

  /**
   * Brings the session's daemon records in line with what `found` observed, and returns what changed, for the log.
   *
   *   - A record whose daemon is gone, or whose pid belongs to another process, is deleted.
   *   - A daemon without a record gets one.
   */
  def record(records: Path, found: Vector[(Long, String)], processes: Processes): Vector[String] =
    val existing = FileHelper.directoryEntriesIfAny(records).filter(_.getFileName.toString.startsWith(RecordPrefix))
    val (alive, stale) = existing.partition: file =>
      RunOnHostSession.leaderLives(file, processes)
    val deleted = stale.flatMap: file =>
      try
        Files.deleteIfExists(file)
        Some(s"forgot ${file.getFileName}: its daemon is gone")
      catch case _: IOException => None
    val recorded = alive.flatMap(RunOnHostSession.readRecord).map(record => record.pgid -> record.leaderStart).toSet
    val added = found.filterNot(recorded).flatMap: (pid, start) =>
      val file = records.resolve(recordName(pid))
      try
        RunOnHostSession.publishByRename(file, RunOnHostSession.renderRecord(Record(pid, start)))
        Some(s"recorded the gradle daemon $pid")
      catch case ex: IOException => Some(s"recording the gradle daemon $pid: ${ex.getMessage}")
    deleted ++ added
