package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import RunOnHostSandbox.*
import RunOnHostPolicy.Tool

class RunOnHostSandboxTest extends munit.FunSuite:

  test("the measured runtime authority rides in the artifact, and parses"):
    val authority = RunOnHostSandbox.bundledRuntimeAuthority()
    assert(authority.executes.nonEmpty, "the bundled file grants no executable roots")

  // --------------------------------------------------------------------------
  // host-command/, the closed namespace inside the closed namespace
  // --------------------------------------------------------------------------

  def projectWith(paths: String*): Path =
    val project = Files.createTempDirectory("host-command")
    paths.foreach: path =>
      val full = project.resolve(path)
      Files.createDirectories(full.getParent)
      Files.writeString(full, "")
    project

  test("an absent host-command, or a complete one, is no stray"):
    assertEquals(hostCommandStray(Files.createTempDirectory("empty")), None)
    val project = projectWith(
      ".ko-agent-sandbox/host-command/sbt/egress/allowed",
      ".ko-agent-sandbox/host-command/mill/egress/allowed",
    )
    assertEquals(hostCommandStray(project), None)

  test("a stray name at any level refuses, naming itself; metadata does not"):
    for
      stray <- Seq(
        ".ko-agent-sandbox/host-command/gradle/egress/allowed",
        ".ko-agent-sandbox/host-command/sbt/egres/allowed",
        ".ko-agent-sandbox/host-command/sbt/egress/allowd",
      )
    do
      val refused = hostCommandStray(projectWith(stray))
      assert(refused.isDefined, stray)
      assert(refused.exists(_.contains("update the launcher")), refused.toString)
    val metadata = projectWith(
      ".ko-agent-sandbox/host-command/.DS_Store",
      ".ko-agent-sandbox/host-command/sbt/egress/allowed",
    )
    assertEquals(hostCommandStray(metadata), None)

  test("a symlinked component refuses by name"):
    val project = projectWith(".ko-agent-sandbox/host-command/sbt/egress/allowed")
    val dir = project.resolve(".ko-agent-sandbox/host-command/mill")
    Files.createSymbolicLink(dir, project.resolve(".ko-agent-sandbox/host-command/sbt"))
    val refused = hostCommandStray(project)
    assert(refused.exists(_.contains("symlink")), refused.toString)

  test("a file where a directory belongs refuses instead of reading as absent config"):
    val project = Files.createTempDirectory("host-command")
    val dir = project.resolve(".ko-agent-sandbox/host-command")
    Files.createDirectories(dir)
    Files.writeString(dir.resolve("sbt"), "")
    val refused = hostCommandStray(project)
    assert(refused.exists(r => r.contains("sbt") && r.contains("not a directory")), refused.toString)

  test("a non-regular file where allowed belongs refuses instead of being read"):
    val project = Files.createTempDirectory("host-command")
    val egress = project.resolve(".ko-agent-sandbox/host-command/sbt/egress")
    Files.createDirectories(egress.resolve("allowed")) // a directory; a FIFO would block a read
    val refused = hostCommandStray(project)
    assert(
      refused.exists(r => r.contains("allowed") && r.contains("not a regular file")),
      refused.toString,
    )

  test("readAllowlist reads the tool's file, refuses its strays, and defaults to nothing"):
    val project = projectWith(".ko-agent-sandbox/host-command/sbt/egress/allowed")
    Files.writeString(
      project.resolve(".ko-agent-sandbox/host-command/sbt/egress/allowed"),
      "+host repo.example.org\n",
      UTF_8,
    )
    assertEquals(readAllowlist(project, Tool.Sbt), Right(Vector("repo.example.org")))
    assertEquals(readAllowlist(project, Tool.Mill), Right(Vector.empty), "mill has no file here")

    Files.writeString(
      project.resolve(".ko-agent-sandbox/host-command/sbt/egress/allowed"),
      "+model-provider openai\n",
      UTF_8,
    )
    val refused = readAllowlist(project, Tool.Sbt)
    assert(refused.swap.exists(_.contains("+model-provider openai")), refused.toString)
    assert(refused.swap.exists(_.contains("+host <host>")), refused.toString)

  // --------------------------------------------------------------------------
  // The proxy handshake pieces
  // --------------------------------------------------------------------------

  test("awaitProxyPort reads the bound port from the ready line, stamped or not"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(log, "2026-08-31T01:08:25Z agent-egress-proxy listening on :51234\n", UTF_8)
    assertEquals(awaitProxyPort(log, deadlineMillis = 1_000), Right(51234))

  test("awaitProxyPort is a bounded Left with what the proxy said"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(log, "EGRESS_ALLOWED contains '+junk'\n", UTF_8)
    val refused = awaitProxyPort(log, deadlineMillis = 300)
    assert(refused.swap.exists(_.contains("+junk")), refused.toString)

  test("the relaunch classpath walked from the loaders carries these classes and their deps"):
    // What emit prints for the gate: inside sbt's layered loaders java.class.path is sbt's own,
    // so the walk is what has to find the test classes and munit.
    val classpath = EmitBuildProfile.classpathForRelaunch.split(java.io.File.pathSeparator).toVector
    assert(classpath.exists(_.contains("munit")), classpath.take(5).toString)
    def carries(entry: String): Boolean =
      val wanted = "agentsandbox/launcher/RunOnHost.class"
      val path = Path.of(entry)
      if Files.isDirectory(path) then Files.exists(path.resolve(wanted))
      else if Files.isRegularFile(path) then
        val zip = java.util.zip.ZipFile(path.toFile)
        try zip.getEntry(wanted) != null
        finally zip.close()
      else false
    assert(classpath.exists(carries), classpath.take(8).toString)

  test("selfInvocation on a JVM re-runs this classpath under the private verb"):
    val command = selfInvocation("--serve-proxy-on-host")
    assert(command.head.endsWith("/bin/java"), command.toString)
    assertEquals(command.last, "--serve-proxy-on-host")
    assert(command.contains("-cp"), command.toString)
    assert(command.contains("agentsandbox.launcher.AgentSandboxLauncher"), command.toString)
    assertEquals(
      selfInvocation("--run-build-on-host", "sbt", "/p", "/p/sub", "--").takeRight(5),
      Seq("--run-build-on-host", "sbt", "/p", "/p/sub", "--"),
    )

  test("deniedHosts reads the audit log's deny lines, once per host"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(
      log,
      """2026-08-31T01:08:25Z agent-egress-proxy listening on :51234
        |2026-08-31T01:08:25Z deny example.com CONNECT host not allowed
        |2026-08-31T01:08:26Z allow repo1.maven.org CONNECT -> 151.101.0.209
        |2026-08-31T01:08:27Z deny example.com CONNECT host not allowed
        |""".stripMargin,
      UTF_8,
    )
    assertEquals(deniedHosts(log), Vector("example.com"))
    assertEquals(deniedHosts(log.resolveSibling("absent")), Vector.empty)

  // --------------------------------------------------------------------------
  // The one-server-per-project refusal
  // --------------------------------------------------------------------------

  def projectWithPortfile(socket: Path): Path =
    val project = Files.createTempDirectory("portfile")
    Files.createDirectories(project.resolve("project/target"))
    Files.writeString(
      project.resolve("project/target/active.json"),
      s"""{"uri":"local://$socket"}""",
      UTF_8,
    )
    project

  test("a connectable portfile socket is a live server; a dead or absent one is not"):
    val socket = Files.createTempDirectory("srv").resolve("sock")
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    try
      assertEquals(livePortfileServer(projectWithPortfile(socket)), Some(socket))
    finally server.close()
    Files.delete(socket)
    assertEquals(livePortfileServer(projectWithPortfile(socket)), None, "gone is not live")
    assertEquals(livePortfileServer(Files.createTempDirectory("bare")), None, "no portfile")

  // --------------------------------------------------------------------------
  // The venue sweep
  // --------------------------------------------------------------------------

  test("foreign and dangling target links are swept; granted, intra-project and non-target stay"):
    val project = Files.createTempDirectory("sweep")
    val foreignStore = Files.createTempDirectory("foreign-store")
    val sbtGlobal = Files.createTempDirectory("sbt-global")
    val target = Files.createDirectories(project.resolve("sub/target/out"))
    val kept = Files.writeString(sbtGlobal.resolve("kept"), "")
    val foreign = Files.writeString(foreignStore.resolve("theirs"), "")
    val source = Files.writeString(project.resolve("source"), "")

    Files.createSymbolicLink(target.resolve("foreign.zip"), foreign)
    Files.createSymbolicLink(target.resolve("dangling.zip"), foreignStore.resolve("gone"))
    Files.createSymbolicLink(target.resolve("ours.zip"), kept)
    Files.createSymbolicLink(target.resolve("intra"), source)
    Files.createSymbolicLink(project.resolve("outside-target"), foreign)
    val git = Files.createDirectories(project.resolve(".git/target"))
    Files.createSymbolicLink(git.resolve("untouchable"), foreign)

    val removed = cleanForeignTargetLinks(project, Seq(project, sbtGlobal))
    assertEquals(
      removed.map(_.getFileName.toString).sorted,
      Vector("dangling.zip", "foreign.zip"),
    )
    assert(Files.isSymbolicLink(target.resolve("ours.zip")))
    assert(Files.isSymbolicLink(target.resolve("intra")))
    assert(Files.isSymbolicLink(project.resolve("outside-target")))
    assert(Files.isSymbolicLink(git.resolve("untouchable")))

  // --------------------------------------------------------------------------
  // The runtime-authority file
  // --------------------------------------------------------------------------

  test("readRuntimeAuthority splits reads from executables and drops what does not resolve"):
    val dir = Files.createTempDirectory("authority")
    val readable = Files.writeString(dir.resolve("readable"), "")
    val executable = Files.writeString(dir.resolve("executable"), "")
    val file = Files.writeString(
      dir.resolve("authority.txt"),
      s"""# measured grants
         |$readable
         |x $executable
         |/nowhere/at/all
         |""".stripMargin,
      UTF_8,
    )
    val authority = readRuntimeAuthority(Some(file))
    assertEquals(authority.reads.map(_.getFileName.toString), Seq("readable"))
    assertEquals(authority.executes.map(_.getFileName.toString), Seq("executable"))
    assertEquals(readRuntimeAuthority(None).reads, Seq.empty)
