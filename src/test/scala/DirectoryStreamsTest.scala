package agentsandbox.launcher

import com.sun.management.UnixOperatingSystemMXBean
import java.io.{IOException, UncheckedIOException}
import java.lang.management.ManagementFactory
import java.nio.file.{Files, Path}
import java.nio.file.attribute.PosixFilePermissions

import FileHelper.{deleteRecursively, directoryEntries}

class DirectoryStreamsTest extends munit.FunSuite:

  private def withDirectory(body: Path => Unit): Unit =
    val root = Files.createTempDirectory("directory-streams")
    try body(root)
    finally deleteRecursively(root)

  private def assertNoDescriptorGrowth(label: String)(body: => Unit): Unit =
    val operatingSystem = ManagementFactory.getOperatingSystemMXBean
    assume(operatingSystem.isInstanceOf[UnixOperatingSystemMXBean], "descriptor counts require a Unix JVM")
    val unix = operatingSystem.asInstanceOf[UnixOperatingSystemMXBean]
    // Warm class loading before counting; allow unrelated JVM activity, but not a descriptor per scan.
    body
    val before = unix.getOpenFileDescriptorCount
    for _ <- 0 until 32 do body
    val after = unix.getOpenFileDescriptorCount
    assert(after <= before + 4, s"$label: open descriptors grew from $before to $after")

  test("directory entries are usable after return, and listing errors reach the caller"):
    withDirectory: root =>
      assertEquals(directoryEntries(root), Vector.empty)
      val file = Files.writeString(root.resolve("file"), "content")
      val nested = Files.createDirectory(root.resolve("nested"))
      assertEquals(directoryEntries(root).toSet, Set(file, nested))
      intercept[IOException](directoryEntries(file))
      intercept[IOException](directoryEntries(root.resolve("absent")))

  for contents <- Vector("empty", "populated", "stray") do
    test(s"configuration, log and TLS directory scans close their streams: $contents"):
      withDirectory: root =>
        val boundary = Files.createDirectory(root.resolve("boundary"))
        val rules = Files.createDirectory(boundary.resolve("egress"))
        val logs = Files.createDirectory(root.resolve("logs"))
        val tls = Files.createDirectory(root.resolve("tls"))
        val session = Files.createDirectory(root.resolve("session"))
        val temporary = Files.createDirectory(session.resolve(RunOnHostSession.TmpDir))
        val channelLog = root.resolve("channel.log")
        if contents != "empty" then
          Files.writeString(rules.resolve("rule"), "deny defaults\n")
          Files.writeString(logs.resolve("proxy-run.log"), "proxy log\n")
          Files.writeString(logs.resolve("run-on-host-run.log"), "channel log\n")
          Files.createDirectory(tls.resolve("run"))
          Files.writeString(session.resolve("proxy.log"), "session proxy log\n")
          Files.writeString(temporary.resolve("sbt-server-err1.log"), "client log\n")
        if contents == "stray" then
          Vector(boundary, rules, logs, tls, session, temporary).foreach: directory =>
            Files.writeString(directory.resolve("unknown"), "stray entry\n")

        val scans: Vector[(String, () => Unit)] = Vector(
          "egress rules" -> (() => { EgressRules.readRuleFiles(rules); () }),
          "boundary entries" -> (() => { SandboxProject.boundaryDirError(boundary); () }),
          "proxy logs" -> (() => { EgressRules.retainedLogs(logs); () }),
          "channel logs" -> (() => { EgressRules.retainedLogs(logs, "run-on-host-"); () }),
          "TLS entries" -> (() => { directoryEntries(tls).map(_.getFileName.toString); () }),
          "session logs" -> (() => RunOnHostSandbox.appendSessionLogs(channelLog, session, "ended")),
        )
        scans.foreach: (label, scan) =>
          assertNoDescriptorGrowth(label)(scan())

  test("empty mount cleanup closes its listing and removes nested contents"):
    withDirectory: root =>
      assertNoDescriptorGrowth("empty mount cleanup"):
        val child = Files.createDirectories(root.resolve("empty/dir/nested/child"))
        Files.writeString(child.resolve("file"), "discarded")
        val (file, directory) = SandboxProject.emptyMountSources(root)
        assertEquals(Files.size(file), 0L)
        assertEquals(directoryEntries(directory), Vector.empty)

  test("source hashing closes its walk after success and after a file read fails"):
    withDirectory: root =>
      val source = Files.createDirectories(root.resolve("context/nested"))
      val file = Files.writeString(source.resolve("file"), "content")
      val expected = KoAgentFs.bundleSourceId(Vector("nested/file" -> Files.readAllBytes(file)))
      assertNoDescriptorGrowth("source hashing"):
        assertEquals(KoAgentFs.contextSourceId(root, "context"), expected)
      assume(Files.getFileStore(root).supportsFileAttributeView("posix"))
      val permissions = Files.getPosixFilePermissions(file)
      try
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("---------"))
        assume(!Files.isReadable(file), "the test user must not bypass read permissions")
        assertNoDescriptorGrowth("failed source read"):
          intercept[IOException](KoAgentFs.contextSourceId(root, "context"))
      finally Files.setPosixFilePermissions(file, permissions)

  test("recursive deletion and hashing close ancestor directories when traversal fails"):
    withDirectory: root =>
      assume(Files.getFileStore(root).supportsFileAttributeView("posix"))
      val blocked = Files.createDirectories(root.resolve("context/nested/blocked"))
      val permissions = Files.getPosixFilePermissions(blocked)
      try
        Files.setPosixFilePermissions(blocked, PosixFilePermissions.fromString("---------"))
        assume(!Files.isReadable(blocked), "the test user must not bypass directory permissions")
        assertNoDescriptorGrowth("failed recursive deletion"):
          intercept[IOException](deleteRecursively(root.resolve("context")))
        assertNoDescriptorGrowth("failed source traversal"):
          intercept[UncheckedIOException](KoAgentFs.contextSourceId(root, "context"))
      finally Files.setPosixFilePermissions(blocked, permissions)
