// The launch's Gradle daemons (run-on-host.md "Gradle"): started by Gradle's own client under the
// command's profile, in the registry every Gradle command line names under the broker's `tmp/`,
// and detached by the daemon itself into a group of its own (`DaemonMain`, `setsid`), where its
// workers and test executors are forked. The broker records each after every command, and once
// more at the launch's end, by pid and start time, as `records/daemon-gradle-<pid>`, and the
// launch's end signals the group behind each record as it does every recorded group. What proves
// a daemon the launch's is its initial environment: the client starts it with its own
// (`DefaultProcessForkOptions.getInheritableEnvironment`), whose `_JAVA_OPTIONS` names the
// broker's `tmp/` as `java.io.tmpdir`, a value no process outside this launch's commands was
// started with. No path proves it: the build writes across `tmp/` and the project, and a file a
// daemon of yours holds open, renamed into the registry under any name, is reported by the kernel
// at that name. `ps -E` reads the strings from the daemon's own memory (`KERN_PROCARGS2`,
// `sysctl_procargsx`), so build code in the daemon can rewrite them and hide the daemon from its
// own launch, and nothing else: a daemon so hidden is unrecorded, as one started under a broker
// that died during the command is — the daemon's pid is its group id, so the record is one like
// any registered spawn's, written after the fact — and either is confined, holds nothing, and
// exits on Gradle's idle timeout (SECURITY.md "Run on host"). macOS only, like the wrapper: the
// observations are pgrep and ps, so BrokerRuntimes takes `gradleDaemons` as a parameter tests replace and the
// acceptance test measures it.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption}

import RunOnHostSession.{HostProcesses, Processes, Record}

object RunOnHostGradleDaemons:

  /** The daemon's main class, on its command line (`DefaultDaemonStarter`) and nowhere on the
    * client's. */
  val DaemonMain = "org.gradle.launcher.daemon.bootstrap.GradleDaemon"

  /** `org.gradle.daemon.registry.base` on every Gradle command line
    * (RunOnHostSandbox.gradleCommand): under the broker's `tmp/`, which every Gradle process of
    * the launch is granted and which ends with the launch. */
  def registryBase(tmp: Path): Path = tmp.resolve("gradle-daemon")

  private val RecordPrefix = "daemon-gradle-"

  def recordName(pid: Long): String = s"$RecordPrefix$pid"

  /** Whether a process's command line and initial environment, as `ps -wwE -o command=` prints
    * them on one line, carry the launch's temporary directory as the JVM option the command
    * environment sets (RunOnHostSandbox.commandEnvironment): first in `_JAVA_OPTIONS` and so
    * prefixed by the variable's name, and ended by the option's own closing quote, so a directory
    * whose name extends this one is another launch's. */
  def carriesTmp(commandAndEnvironment: String, tmp: Path): Boolean =
    val option = RunOnHostSandbox.jvmProperty("java.io.tmpdir", tmp.toString)
    s" $commandAndEnvironment ".contains(s" _JAVA_OPTIONS=$option ")

  /**
   * The daemons on the host started with the launch's environment, with their start times; the
   * pid is the process table's, never a registry file's. The start time is read before the
   * attribution and proved again after it, so a pid recycled between the two observations
   * records no stranger.
   */
  def daemons(tmp: Path, processes: Processes): Vector[(Long, String)] =
    val real =
      try tmp.toRealPath()
      catch case _: IOException => tmp
    HostProcesses.lines("pgrep", "-f", "--", DaemonMain).flatMap(_.toLongOption).flatMap: pid =>
      processes.startOf(pid).filter: start =>
        val ours = HostProcesses.lines("ps", "-wwE", "-o", "command=", "-p", pid.toString).exists(carriesTmp(_, real))
        ours && processes.startOf(pid).contains(start)
      .map(pid -> _)

  /**
   * Bring the session's daemon records to what `found` observed: a record whose daemon is gone,
   * or whose pid belongs to another process, is deleted, and a daemon without a record gets one.
   * What changed, for the log.
   */
  def record(records: Path, found: Vector[(Long, String)], processes: Processes): Vector[String] =
    val existing =
      try
        FileHelper.directoryEntries(records).filter(_.getFileName.toString.startsWith(RecordPrefix))
      catch case _: IOException => Vector.empty
    val (proved, stale) = existing.partition: file =>
      parsed(file).exists(record => processes.startOf(record.pgid).contains(record.leaderStart))
    val deleted = stale.flatMap: file =>
      try
        Files.deleteIfExists(file)
        Some(s"forgot ${file.getFileName}: its daemon is gone")
      catch case _: IOException => None
    val recorded = proved.flatMap(parsed).map(record => record.pgid -> record.leaderStart).toSet
    val added = found.filterNot(recorded).flatMap: (pid, start) =>
      val file = records.resolve(recordName(pid))
      try
        val pending = file.resolveSibling(s"${file.getFileName}.pending")
        Files.writeString(pending, RunOnHostSession.renderRecord(Record(pid, start)), UTF_8)
        Files.move(pending, file, StandardCopyOption.ATOMIC_MOVE)
        Some(s"recorded the gradle daemon $pid")
      catch case ex: IOException => Some(s"recording the gradle daemon $pid: ${ex.getMessage}")
    deleted ++ added

  private def parsed(file: Path): Option[Record] =
    try RunOnHostSession.parseRecord(Files.readString(file, UTF_8))
    catch case _: IOException => None
