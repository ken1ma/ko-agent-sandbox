package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import RunOnHostSession.{Processes, Record}

class RunOnHostGradleDaemonsTest extends munit.FunSuite:

  /** The process table as the test sets it: a map from pid to start time. */
  private class FakeProcesses(var alive: Map[Long, String]) extends Processes:
    val ended = scala.collection.mutable.ListBuffer[Long]()
    def startOf(pid: Long): Option[String] = alive.get(pid)
    def endGroup(pgid: Long): Boolean = { ended += pgid; true }
    def groupEmpty(pgid: Long): Boolean = !alive.contains(pgid)
    def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")

  private def recordOf(records: Path, pid: Long): Option[Record] =
    val file = records.resolve(RunOnHostGradleDaemons.recordName(pid))
    Option.when(Files.exists(file))(RunOnHostSession.parseRecord(Files.readString(file, UTF_8)).get)

  test("the registry base is under the runner's tmp, and its records name the daemon's pid"):
    assertEquals(RunOnHostGradleDaemons.registryBase(Path.of("/b/tmp")), Path.of("/b/tmp/gradle-daemon"))
    assertEquals(RunOnHostGradleDaemons.recordName(4242), "daemon-gradle-4242")

  test("a daemon observed is recorded once, a gone one forgotten, a recycled pid re-recorded; a record ends its group"):
    val records = Files.createTempDirectory("gradle-records")
    val processes = FakeProcesses(Map(100L -> "A", 200L -> "B"))
    // Two daemons run after the first command, and each gets a record of its pid and start time.
    val first = RunOnHostGradleDaemons.record(records, Vector(100L -> "A", 200L -> "B"), processes)
    assertEquals(first, Vector("recorded the gradle daemon 100", "recorded the gradle daemon 200"))
    assertEquals(recordOf(records, 100), Some(Record(100, "A")))
    assertEquals(recordOf(records, 200), Some(Record(200, "B")))
    // Nothing changed, so the registry writes and reports nothing.
    assertEquals(RunOnHostGradleDaemons.record(records, Vector(100L -> "A", 200L -> "B"), processes), Vector.empty)
    // The second daemon stopped itself, as a cancel past its grace period does. The registry forgets its record and
    // keeps the first daemon's record unchanged.
    processes.alive = Map(100L -> "A")
    assertEquals(
      RunOnHostGradleDaemons.record(records, Vector(100L -> "A"), processes),
      Vector("forgot daemon-gradle-200: its daemon is gone"),
    )
    assertEquals(recordOf(records, 200), None)
    assertEquals(recordOf(records, 100), Some(Record(100, "A")))
    // A fresh daemon of the launch recycles the second daemon's pid. The registry removes the stale record and records
    // the fresh daemon with its own start time.
    processes.alive = Map(100L -> "A", 200L -> "C")
    Files.writeString(
      records.resolve(RunOnHostGradleDaemons.recordName(200)), RunOnHostSession.renderRecord(Record(200, "B")), UTF_8,
    )
    assertEquals(
      RunOnHostGradleDaemons.record(records, Vector(100L -> "A", 200L -> "C"), processes),
      Vector("forgot daemon-gradle-200: its daemon is gone", "recorded the gradle daemon 200"),
    )
    assertEquals(recordOf(records, 200), Some(Record(200, "C")))
    // A file with another name in the records directory does not belong to the daemons.
    Files.writeString(records.resolve("proxy-gradle-0"), RunOnHostSession.renderRecord(Record(300, "D")))
    assertEquals(RunOnHostGradleDaemons.record(records, Vector(100L -> "A", 200L -> "C"), processes), Vector.empty)
    assert(Files.exists(records.resolve("proxy-gradle-0")))
    // The session's end reads a daemon record like any other record: it ends the group behind a pid with the recorded
    // start time, and it skips a group whose start time differs.
    processes.alive = Map(100L -> "A", 200L -> "E", 300L -> "D")
    val collected = RunOnHostSession.endRecordedGroups(records.getParent, records, processes)
    assertEquals(processes.ended.toSet, Set(100L, 300L))
    assert(collected.contains(RunOnHostSession.Collected.GroupSkipped(200, "pid recycled: start time differs")))

  test("a daemon is the launch's by the tmpdir option in its initial environment, the whole token"):
    val tmp = Path.of("/private/tmp/ko agent-501/bAb12/tmp")
    val line = "java -Xmx512m org.gradle.launcher.daemon.bootstrap.GradleDaemon 9.7.1 HOME=/Users/me " +
      s"_JAVA_OPTIONS=-Djava.io.tmpdir=\"$tmp\" -Djava.util.prefs.userRoot=\"$tmp\" GRADLE_USER_HOME=/g"
    assert(RunOnHostGradleDaemons.carriesTmp(line, tmp))
    // Another launch's tmp does not belong to this launch, and neither does a directory whose name extends this one.
    assert(!RunOnHostGradleDaemons.carriesTmp(line, Path.of("/private/tmp/ko agent-501/bAb13/tmp")))
    assert(!RunOnHostGradleDaemons.carriesTmp(line.replace(s"tmpdir=\"$tmp\" ", s"tmpdir=\"${tmp}2\" "), tmp))
    // A daemon the user started carries no such option.
    val yours = "java org.gradle.launcher.daemon.bootstrap.GradleDaemon 9.7.1 HOME=/Users/me"
    assert(!RunOnHostGradleDaemons.carriesTmp(yours, tmp))
