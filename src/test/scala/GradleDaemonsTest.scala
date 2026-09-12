package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import RunOnHostSession.{Processes, Record}

class GradleDaemonsTest extends munit.FunSuite:

  /** The process table as the test says it is: pid to start time. */
  private class FakeProcesses(var alive: Map[Long, String]) extends Processes:
    val ended = scala.collection.mutable.ListBuffer[Long]()
    def startOf(pid: Long): Option[String] = alive.get(pid)
    def endGroup(pgid: Long): Unit = ended += pgid

  private def recordOf(records: Path, pid: Long): Option[Record] =
    val file = records.resolve(GradleDaemons.recordName(pid))
    Option.when(Files.exists(file))(RunOnHostSession.parseRecord(Files.readString(file, UTF_8)).get)

  test("the registry base is under the broker's tmp, and its records name the daemon's pid"):
    assertEquals(GradleDaemons.registryBase(Path.of("/b/tmp")), Path.of("/b/tmp/gradle-daemon"))
    assertEquals(GradleDaemons.recordName(4242), "daemon-gradle-4242")

  test("a daemon observed is recorded once, a gone one forgotten, a recycled pid re-proved; a record ends its group"):
    val records = Files.createTempDirectory("gradle-records")
    val processes = FakeProcesses(Map(100L -> "A", 200L -> "B"))
    // Two daemons after the first command: a record each, pid and start time.
    val first = GradleDaemons.record(records, Vector(100L -> "A", 200L -> "B"), processes)
    assertEquals(first, Vector("recorded the gradle daemon 100", "recorded the gradle daemon 200"))
    assertEquals(recordOf(records, 100), Some(Record(100, "A")))
    assertEquals(recordOf(records, 200), Some(Record(200, "B")))
    // Nothing changed: nothing is written or said.
    assertEquals(GradleDaemons.record(records, Vector(100L -> "A", 200L -> "B"), processes), Vector.empty)
    // The second daemon stopped itself (a cancel past its grace): its record is forgotten, the
    // first's kept unchanged.
    processes.alive = Map(100L -> "A")
    assertEquals(
      GradleDaemons.record(records, Vector(100L -> "A"), processes),
      Vector("forgot daemon-gradle-200: its daemon is gone"),
    )
    assertEquals(recordOf(records, 200), None)
    assertEquals(recordOf(records, 100), Some(Record(100, "A")))
    // Its pid recycled by a fresh daemon of the launch: the stale record goes, and the fresh
    // daemon is recorded with the start time that proves it.
    processes.alive = Map(100L -> "A", 200L -> "C")
    Files.writeString(
      records.resolve(GradleDaemons.recordName(200)), RunOnHostSession.renderRecord(Record(200, "B")), UTF_8,
    )
    assertEquals(
      GradleDaemons.record(records, Vector(100L -> "A", 200L -> "C"), processes),
      Vector("forgot daemon-gradle-200: its daemon is gone", "recorded the gradle daemon 200"),
    )
    assertEquals(recordOf(records, 200), Some(Record(200, "C")))
    // A file of another name in the records directory is not the daemons'.
    Files.writeString(records.resolve("proxy-gradle-0"), RunOnHostSession.renderRecord(Record(300, "D")))
    assertEquals(GradleDaemons.record(records, Vector(100L -> "A", 200L -> "C"), processes), Vector.empty)
    assert(Files.exists(records.resolve("proxy-gradle-0")))
    // The record is one the session's end reads like any other: the group behind the proved pid
    // is ended; a mismatched one is skipped.
    processes.alive = Map(100L -> "A", 200L -> "E", 300L -> "D")
    val collected = RunOnHostSession.endRecordedGroups(records, processes)
    assertEquals(processes.ended.toSet, Set(100L, 300L))
    assert(collected.contains(RunOnHostSession.Collected.GroupSkipped(200, "pid recycled: start time differs")))

  test("a daemon is the launch's by the tmpdir option in its initial environment, the whole token"):
    val tmp = Path.of("/private/tmp/ko-agent-501/bAb12/tmp")
    val line = "java -Xmx512m org.gradle.launcher.daemon.bootstrap.GradleDaemon 9.7.1 HOME=/Users/me " +
      s"JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=$tmp -Djava.util.prefs.userRoot=$tmp GRADLE_USER_HOME=/g"
    assert(GradleDaemons.carriesTmp(line, tmp))
    // Another launch's tmp, or a directory whose name extends this one, is not this launch's.
    assert(!GradleDaemons.carriesTmp(line, Path.of("/private/tmp/ko-agent-501/bAb13/tmp")))
    assert(!GradleDaemons.carriesTmp(line.replace(s"tmpdir=$tmp ", s"tmpdir=${tmp}2 "), tmp))
    // Your own daemon carries no such option.
    val yours = "java org.gradle.launcher.daemon.bootstrap.GradleDaemon 9.7.1 HOME=/Users/me"
    assert(!GradleDaemons.carriesTmp(yours, tmp))
