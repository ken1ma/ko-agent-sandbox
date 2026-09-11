package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import RunOnHostSandbox.*
import scala.util.chaining.*
import RunOnHostPrereqs.Program

class RunOnHostSandboxTest extends munit.FunSuite:

  test("the measured runtime authority ships in the artifact, and parses"):
    val authority = RunOnHostSandbox.bundledRuntimeAuthority()
    assert(authority.executes.nonEmpty, "the bundled file grants no executable roots")

  test("the command's environment is a closed set: the wrapper's settings, three pass-throughs, and --env"):
    val jdk = Path.of("/Users/u/Library/Caches/Coursier/v1/jvm/temurin")
    val prereqs = RunOnHostPrereqs.CommandPrereqs(
      project = Path.of("/Users/u/project"), jdkHome = jdk, coursierV1 = Path.of("/cache/v1"),
      program = Program.Sbt, executable = Path.of("/Users/u/Library/Application Support/Coursier/bin/sbt"),
    )
    val host = Map(
      "HOME" -> "/Users/u", "LANG" -> "en_US.UTF-8", "PATH" -> "/usr/bin:/bin",
      "TERM" -> "xterm", "TMPDIR" -> "/var/folders/xy/T", "JAVA_HOME" -> "/Users/u/jdk-link",
      "HTTPS_PROXY" -> "http://alice:s3cret@proxy.example:3128", "AWS_SECRET_ACCESS_KEY" -> "hunter2",
      "SBT_OPTS" -> "-Xmx8g", "MILL_VERSION" -> "1.0.0", "MILL_OUTPUT_DIR" -> "elsewhere", "TOKEN" -> "t0ken",
      "USER" -> "shellname",
    )
    val environment = commandEnvironment(
      host.get,
      Vector(
        "TOKEN" -> "t0ken", "HTTPS_PROXY" -> "http://elsewhere.example:1", "MILL_VERSION" -> "1.0.0",
        "MILL_OUTPUT_DIR" -> "elsewhere", "JAVA_TOOL_OPTIONS" -> "-javaagent:/tmp/agent.jar",
      ),
      prereqs, sbtGlobal = Path.of("/cache/sbt"), ivyHome = Path.of("/cache/ivy"), m2Repository = Path.of("/cache/m2"),
      millDownloads = Some(Path.of("/Users/u/.cache/mill/download")), millVersion = Some("1.1.9-jvm"),
      sessionTmp = Path.of("/private/tmp/ko-agent-501/s"), socketDir = Path.of("/private/tmp/ko-agent-501/b/tmp"),
      proxyPort = 4711, userName = "u",
    )
    // Passed through as they are.
    assertEquals(environment("HOME"), "/Users/u")
    assertEquals(environment("LANG"), "en_US.UTF-8")
    // Set by the wrapper, from what it proved or made, never from the shell.
    assertEquals(environment("JAVA_HOME"), jdk.toString)
    assertEquals(environment("PATH"), s"$jdk/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    assertEquals(environment("TMPDIR"), "/private/tmp/ko-agent-501/s")
    assert(environment("JAVA_TOOL_OPTIONS").contains("-Djava.io.tmpdir=/private/tmp/ko-agent-501/s"))
    // The sockets are the runtime's: where the broker's server bound them.
    assertEquals(environment("XDG_RUNTIME_DIR"), "/private/tmp/ko-agent-501/b/tmp")
    assertEquals(environment("SBT_GLOBAL_SERVER_DIR"), "/private/tmp/ko-agent-501/b/tmp")
    assertEquals(environment("USER"), "u")
    assertEquals(environment("LOGNAME"), "u")
    assertEquals(environment("MILL_FINAL_DOWNLOAD_FOLDER"), "/Users/u/.cache/mill/download")
    // The wrapper's launcher version, never the forwarded one.
    assertEquals(environment("MILL_VERSION"), "1.1.9-jvm")
    assertEquals(environment("COURSIER_CACHE"), "/cache/v1")
    assert(environment("JAVA_TOOL_OPTIONS").contains("-Dsbt.global.base=/cache/sbt"))
    assert(environment("JAVA_TOOL_OPTIONS").contains("-Dsbt.ivy.home=/cache/ivy"))
    assert(environment("JAVA_TOOL_OPTIONS").contains("-Dmaven.repo.local=/cache/m2"))
    // A forward reaches the command; one naming a variable the wrapper sets loses to the wrapper.
    assertEquals(environment("TOKEN"), "t0ken")
    assertEquals(environment("HTTPS_PROXY"), "http://127.0.0.1:4711")
    assert(!environment("JAVA_TOOL_OPTIONS").contains("javaagent"))
    // And nothing else of the shell: not the secret, not the upstream proxy's credential, not the
    // programs' own overrides — mill's version and output-directory ones even when forwarded.
    Vector("AWS_SECRET_ACCESS_KEY", "SBT_OPTS", "DEFAULT_MILL_VERSION", "MILL_OUTPUT_DIR", "TERM", "ALL_PROXY")
      .foreach: name =>
      assert(!environment.contains(name), name)
    assert(!environment.values.exists(_.contains("s3cret")), environment.toString)
    assertEquals(
      environment.keySet,
      Set(
        "HOME", "LANG", "TOKEN", "PATH", "JAVA_HOME", "JAVA_TOOL_OPTIONS", "TMPDIR", "XDG_RUNTIME_DIR",
        "SBT_GLOBAL_SERVER_DIR", "COURSIER_CACHE", "USER", "LOGNAME", "MILL_FINAL_DOWNLOAD_FOLDER", "MILL_VERSION",
      ) ++ commandProxyVariables(4711).keySet,
    )
    // Without a derivable download folder the variable is simply absent, and so is the launcher
    // version for a program that is not mill — a forwarded one included.
    val noFolder =
      commandEnvironment(
        host.get, Vector("MILL_VERSION" -> "1.0.0"), prereqs, Path.of("/s"), Path.of("/i"), Path.of("/m"), None, None,
        Path.of("/t"), Path.of("/t"), 1, "u",
      )
    assert(!noFolder.contains("MILL_FINAL_DOWNLOAD_FOLDER"))
    assert(!noFolder.contains("MILL_VERSION"))

  test("a prerequisite file that cannot be read is a worded refusal at the assembly, not a stack trace"):
    import java.nio.file.attribute.PosixFilePermissions.fromString as permissions
    assume(System.getProperty("user.name") != "root", "root reads everything")
    // A Coursier layout the JVM rule accepts, so the assembly reaches the program's own files.
    val root = Files.createTempDirectory("unreadable")
    val cache = Files.createDirectories(root.resolve("coursier"))
    val jdk = Files.createDirectories(cache.resolve("arc/jdk.tar.gz/jdk"))
    Files.createDirectories(jdk.resolve("bin"))
    Files.setPosixFilePermissions(Files.createFile(jdk.resolve("bin/java")), permissions("rwxr-xr-x"))
    val project = Files.createDirectories(root.resolve("project"))
    val env = Map("HOME" -> root.toString, "COURSIER_CACHE" -> cache.toString, "JAVA_HOME" -> jdk.toString)
    val mvnw = project.resolve("mvnw")
    Files.write(mvnw, Array[Byte]('#', '!', 0xff.toByte, '\n'))
    Files.setPosixFilePermissions(mvnw, permissions("rwxr-xr-x"))
    val invalid = assemble(project, Program.Mvn, env.get, project)
    assert(clue(invalid).left.exists(text => text.contains(mvnw.toString) && text.contains("not valid UTF-8")))

    Files.writeString(mvnw, "#!/bin/sh\nhash_string() {\n}\n")
    val properties = Files.createDirectories(project.resolve(".mvn/wrapper")).resolve("maven-wrapper.properties")
    Files.writeString(properties, "distributionUrl=https://example.org/apache-maven-3.9.16-bin.zip\n")
    Files.setPosixFilePermissions(properties, permissions("---------"))
    val denied = assemble(project, Program.Mvn, env.get, project)
    assert(
      clue(denied).left.exists(text => text.contains(properties.toString) && text.contains("permission denied")),
    )

  test("the host-served proxy's variable is selected as the proxy selects it: an empty uppercase is unset"):
    val both = Map("HTTPS_PROXY" -> "", "https_proxy" -> "http://proxy.example:3128")
    assertEquals(upstreamProxyVariable(both.get), Some("https_proxy" -> "http://proxy.example:3128"))
    assertEquals(upstreamProxyVariable(Map("HTTPS_PROXY" -> "http://a.example:1").get), Some("HTTPS_PROXY" -> "http://a.example:1"))
    assertEquals(upstreamProxyVariable(Map.empty[String, String].get), None)
    assertEquals(carrierName("TOKEN"), "KO_AGENT_RUN_ON_HOST_ENV_TOKEN")

  test("--env names travel as options and come back as names; nothing else is an option"):
    assertEquals(
      forwardedNames(Seq("--env=TOKEN", ChannelLogOption + "/l", "--env=OTHER")),
      Vector("TOKEN", "OTHER"),
    )
    assertEquals(forwardedNames(Seq.empty), Vector.empty)

  test("the broker's runtime travels as three options, all or none, the daemon port with them"):
    val runtime = Runtime(Path.of("/b"), 4242, Path.of("/b/proxy-sbt-0.log"))
    assertEquals(runtimeOf(runtimeOptions(runtime) :+ "--env=TOKEN"), Right(Some(runtime)))
    assertEquals(runtime.tmp, Path.of("/b/tmp"))
    val withDaemon = runtime.copy(daemonPort = Some(51000))
    assertEquals(runtimeOf(runtimeOptions(withDaemon)), Right(Some(withDaemon)))
    assertEquals(runtimeOf(Seq("--env=TOKEN")), Right(None))
    assert(runtimeOf(Seq("--proxy-port=4242", "--proxy-log=/l")).isLeft)
    assert(runtimeOf(Seq("--runtime-session=/b", "--proxy-port=x", "--proxy-log=/l")).isLeft)
    assert(runtimeOf(runtimeOptions(runtime) :+ "--daemon-port=x").isLeft)
    assert(runtimeOf(Seq("--daemon-port=51000")).isLeft)

  test("a mill command's temporary directory is the broker's; sbt keeps its own with the broker's sockets"):
    val own = Path.of("/r/s1/tmp")
    val brokers = Path.of("/r/b1/tmp")
    assertEquals(temporaryDirectories(Program.Sbt, own, brokers), (own, brokers))
    assertEquals(temporaryDirectories(Program.Mill, own, brokers), (brokers, brokers))
    assertEquals(temporaryDirectories(Program.Mvn, own, brokers), (own, own))

  test("a redirected out/mill-daemon, or an entry of it with a second name, is refused; a plain one admitted"):
    val root = Files.createTempDirectory("rendezvous")
    val build = Files.createDirectory(root.resolve("build"))
    val other = Files.createDirectories(root.resolve("other/out/mill-daemon"))
    assertEquals(MillDaemons.rendezvousIsOwn(build), Right(()), "no out/ at all")
    val daemonDir = Files.createDirectories(build.resolve("out/mill-daemon"))
    Files.writeString(daemonDir.resolve("processId"), "1")
    assertEquals(MillDaemons.rendezvousIsOwn(build), Right(()), "a plain directory")
    // An entry linked elsewhere, then the directory, then out/ itself.
    Files.createSymbolicLink(daemonDir.resolve("daemonLock"), other.resolve("daemonLock"))
    assert(MillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("daemonLock is a symlink")))
    Files.delete(daemonDir.resolve("daemonLock"))
    Files.createLink(daemonDir.resolve("stdout"), other.resolve("stdout").pipe(Files.writeString(_, "")))
    assert(MillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("more than one name")))
    Files.delete(daemonDir.resolve("stdout"))
    assertEquals(MillDaemons.rendezvousIsOwn(build), Right(()))
    Files.move(daemonDir, root.resolve("aside"))
    Files.createSymbolicLink(daemonDir, other)
    assert(MillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("mill-daemon is a symlink")))
    Files.delete(daemonDir)
    Files.move(build.resolve("out"), root.resolve("out-aside"))
    Files.createSymbolicLink(build.resolve("out"), root.resolve("other/out"))
    assert(MillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("out is a symlink")))

  test("the server's command line is the thin client's, with the request's -D and -J and nothing else of it"):
    val sbt = Path.of("/Users/u/Library/Application Support/Coursier/bin/sbt")
    assertEquals(
      serverCommand(sbt, Seq("-Dprobe=1", "-J-Xmx2g", "-batch", "-mem", "512", "compile", "-v")),
      Seq(sbt.toString, s"-Dsbt.script=$sbt", "-Dprobe=1", "-J-Xmx2g", "--detach-stdio", "--server"),
    )

  // --------------------------------------------------------------------------
  // host-command/ and its parent both refuse unrecognized configuration entries
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
      ".ko-agent-sandbox/host-command/sbt/egress/rule",
      ".ko-agent-sandbox/host-command/mill/egress/rule",
    )
    assertEquals(hostCommandStray(project), None)

  test("a stray name at any level refuses, naming itself; metadata does not"):
    for
      stray <- Seq(
        ".ko-agent-sandbox/host-command/gradle/egress/rule",
        ".ko-agent-sandbox/host-command/sbt/egres/rule",
        ".ko-agent-sandbox/host-command/sbt/egress/rules",
      )
    do
      val refused = hostCommandStray(projectWith(stray))
      assert(refused.isDefined, stray)
      assert(refused.exists(_.contains("update the launcher")), refused.toString)
    val metadata = projectWith(
      ".ko-agent-sandbox/host-command/.DS_Store",
      ".ko-agent-sandbox/host-command/sbt/egress/rule",
    )
    assertEquals(hostCommandStray(metadata), None)
    // The retired grammar's file is named as such, with the pointer.
    val retired = hostCommandStray(projectWith(".ko-agent-sandbox/host-command/sbt/egress/allowed"))
    assert(retired.exists(r => r.contains("retired grammar") && r.contains("egress/rule")), retired.toString)

  test("a symlinked component refuses by name"):
    val project = projectWith(".ko-agent-sandbox/host-command/sbt/egress/rule")
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

  test("a non-regular file where rule belongs refuses instead of being read"):
    val project = Files.createTempDirectory("host-command")
    val egress = project.resolve(".ko-agent-sandbox/host-command/sbt/egress")
    Files.createDirectories(egress.resolve("rule")) // a directory; a FIFO would block a read
    val refused = hostCommandStray(project)
    assert(
      refused.exists(r => r.contains("rule") && r.contains("not a regular file")),
      refused.toString,
    )

  test("readProgramRules reads the program's file, refuses its strays, and defaults to nothing"):
    val project = projectWith(".ko-agent-sandbox/host-command/sbt/egress/rule")
    Files.writeString(
      project.resolve(".ko-agent-sandbox/host-command/sbt/egress/rule"),
      "allow https://repo.example.org/ read\n",
      UTF_8,
    )
    assertEquals(readProgramRules(project, Program.Sbt), Right(Vector("repo.example.org")))
    assertEquals(readProgramRules(project, Program.Mill), Right(Vector.empty), "mill has no file here")

    Files.writeString(
      project.resolve(".ko-agent-sandbox/host-command/sbt/egress/rule"),
      "allow model-provider openai\n",
      UTF_8,
    )
    val refused = readProgramRules(project, Program.Sbt)
    assert(refused.swap.exists(_.contains("allow model-provider openai")), refused.toString)
    assert(refused.swap.exists(_.contains(RunOnHostPrereqs.ProgramRuleForm)), refused.toString)

  // --------------------------------------------------------------------------
  // The proxy handshake pieces
  // --------------------------------------------------------------------------

  test("awaitProxyPort reads the bound port from the ready line, stamped or not"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(log, "2026-08-31T01:08:25Z agent-egress-proxy listening on :51234\n", UTF_8)
    assertEquals(awaitProxyPort(log, deadlineMillis = 1_000), Right(51234))

  test("awaitProxyPort is a bounded Left with what the proxy said"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(log, "rule: '+junk' is no line of the rule grammar\n", UTF_8)
    val refused = awaitProxyPort(log, deadlineMillis = 300)
    assert(refused.swap.exists(_.contains("+junk")), refused.toString)

  test("the relaunch classpath walked from the loaders includes these classes and their deps"):
    // What emit prints for the gate: inside sbt's layered loaders java.class.path is sbt's own,
    // so the walk is what has to find the test classes and munit.
    val classpath = EmitRunOnHostProfile.classpathForRelaunch.split(java.io.File.pathSeparator).toVector
    assert(classpath.exists(_.contains("munit")), classpath.take(5).toString)
    def includes(entry: String): Boolean =
      val wanted = "agentsandbox/launcher/RunOnHost.class"
      val path = Path.of(entry)
      if Files.isDirectory(path) then Files.exists(path.resolve(wanted))
      else if Files.isRegularFile(path) then
        val zip = java.util.zip.ZipFile(path.toFile)
        try zip.getEntry(wanted) != null
        finally zip.close()
      else false
    assert(classpath.exists(includes), classpath.take(8).toString)

  test("selfInvocation on a JVM re-runs this classpath under the private action"):
    val command = selfInvocation("--serve-proxy-on-host")
    assert(command.head.endsWith("/bin/java"), command.toString)
    assertEquals(command.last, "--serve-proxy-on-host")
    assert(command.contains("-cp"), command.toString)
    assert(command.contains("agentsandbox.launcher.AgentSandboxLauncher"), command.toString)
    assertEquals(
      selfInvocation("--run-command-on-host", "sbt", "/p", "/p/sub", "--").takeRight(5),
      Seq("--run-command-on-host", "sbt", "/p", "/p/sub", "--"),
    )

  test("a runtime is reused while proxy, server and portfile agree, replaced otherwise; a failed start is discarded"):
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the registration spawn never runs under the profile")
    val root = Files.createTempDirectory("brk")
    val project = Files.createDirectory(root.resolve("project"))
    val session = RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    val endedGroups = scala.collection.mutable.ListBuffer[Long]()
    // The server stand-in's listening sockets, by the group they belong to: a server's socket
    // closes with its group.
    val listeners = scala.collection.mutable.Map[Path, ServerSocketChannel]()
    val socketOfGroup = scala.collection.mutable.Map[Long, Path]()
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = RunOnHostSession.HostProcesses.startOf(pid)
      def endGroup(pgid: Long): Unit =
        endedGroups += pgid
        socketOfGroup.remove(pgid).foreach(socket => listeners.remove(socket).foreach(_.close()))
        ProcessHandle.of(pgid).ifPresent: leader =>
          leader.descendants().forEach(_.destroyForcibly())
          leader.destroyForcibly()
    def await(what: String)(condition: => Boolean): Unit =
      var waited = 0
      while !condition && waited < 200 do
        Thread.sleep(50)
        waited += 1
      assert(condition, what)
    // Where the proxy and the server would be: registered spawns of a sleep, so the records,
    // their exit files and the groups are real spawns'; the server stand-in also listens on a
    // socket under the session's tmp and writes the portfile naming it, as a server does.
    val spawns = scala.collection.mutable.ListBuffer[Process]()
    def standIn(record: Path): Unit =
      spawns += ProcessBuilder(RunOnHostSession.registeredSpawn(record, Seq("/bin/sleep", "30"))*).start()
      await(s"$record registered")(Files.exists(record))
    var neverReady = false
    var throwsAfterRegistering = false
    var lastPort = 0
    val proxy = (_: Program, _: Vector[String], record: Path, proxyLog: Path) =>
      standIn(record)
      Files.writeString(proxyLog, "listening\n", UTF_8)
      if throwsAfterRegistering then throw java.io.IOException("log unreadable")
      lastPort = spawns.size
      if neverReady then Left("never ready") else Right(lastPort)
    val serverStarts = scala.collection.mutable.ListBuffer[ServerStart]()
    var serverFails = false
    var serverThrows = false
    val server = (start: ServerStart) =>
      serverStarts += start
      standIn(start.record)
      if serverThrows then throw IllegalStateException("boom")
      if serverFails then Left("no portfile")
      else
        val socket = RunOnHostSandbox.expectedServerSocket(session.tmp, start.buildDirectory)
        Files.createDirectories(socket.getParent)
        listeners.remove(socket).foreach(_.close())
        Files.deleteIfExists(socket)
        val listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
        listener.bind(UnixDomainSocketAddress.of(socket))
        listeners(socket) = listener
        socketOfGroup(RunOnHostSession.parseRecord(Files.readString(start.record, UTF_8)).get.pgid) = socket
        writePortfile(start.buildDirectory, socket)
        Right(())
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(project, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/m"), None, None,
    )
    val logged = scala.collection.mutable.ListBuffer[String]()
    val authority = SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
    // The daemon stand-in: a registered spawn of a sleep, the sleep itself standing for the
    // daemon — the process a reuse proves by pid and start time — on a port of the seam's choosing.
    val daemonStarts = scala.collection.mutable.ListBuffer[DaemonStart]()
    var daemonFails = false
    val daemon = (start: DaemonStart) =>
      daemonStarts += start
      standIn(start.record)
      if daemonFails then Left("no daemon in the group")
      else
        val leader = ProcessHandle.of(RunOnHostSession.parseRecord(Files.readString(start.record, UTF_8)).get.pgid).get
        await("the sleep started")(leader.children().findFirst().isPresent)
        val sleeper = leader.children().findFirst().get.pid
        val started = RunOnHostSession.HostProcesses.startOf(sleeper).get
        Right(MillDaemons.Daemon(sleeper, started, 40_000 + daemonStarts.size))
    var assemblies = 0
    val runtimes = BrokerRuntimes(session, project, logged.append(_), authority, Vector.empty)(
      processes, (_, _, _) => { assemblies += 1; Right(assembled) }, proxy, server, daemon,
    )
    val dirA = Files.createDirectory(project.resolve("a"))
    val dirB = Files.createDirectory(project.resolve("b"))
    def hashOf(dir: Path) = RunOnHostSession.buildHash(dir)
    def recordOf(dir: Path, program: String = "sbt") = session.records.resolve(s"proxy-$program-${hashOf(dir)}")
    def serverOf(dir: Path) = session.records.resolve(s"server-sbt-${hashOf(dir)}")
    def buildOf(dir: Path) = RunOnHostSession.buildFile(session.directory, hashOf(dir))
    def logOf(dir: Path, program: String = "sbt") = session.directory.resolve(s"proxy-$program-${hashOf(dir)}.log")
    def portfileOf(dir: Path) = dir.resolve("project/target/active.json")
    def pgidOf(record: Path) = RunOnHostSession.parseRecord(Files.readString(record, UTF_8)).get.pgid
    // A server gone on its own: its socket closes with it, and its spawn publishes the exit.
    def serverExits(dir: Path): Unit =
      listeners.remove(RunOnHostSandbox.expectedServerSocket(session.tmp, dir)).foreach(_.close())
      ProcessHandle.of(pgidOf(serverOf(dir))).get.children().forEach(_.destroyForcibly())
      await("the exit published")(Files.exists(RunOnHostSession.exitRecord(serverOf(dir))))
    def current(dir: Path, program: String = "sbt") =
      Right(Some(Runtime(session.directory, lastPort, logOf(dir, program))))
    try
      val first = runtimes.prepare(Program.Sbt, dirA, Seq("-Dprobe=1", "compile"))
      assertEquals(first, current(dirA))
      assertEquals(Files.readString(buildOf(dirA), UTF_8).trim, dirA.toString, "the build file names the directory")
      assertEquals(serverStarts.map(_.arguments).toList, List(Seq("-Dprobe=1", "compile")))
      assertEquals(serverStarts.head.record, serverOf(dirA))
      assert(Files.exists(portfileOf(dirA)))
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("-Dprobe=2", "test")), first, "reused while all agree")
      assertEquals(spawns.size, 2)
      assertEquals(serverStarts.size, 1, "a later request's arguments reach no server")
      // The server exits — `shutdown`, its idle timeout — and the spawn publishes it: the next
      // command gets a server, the old group ended behind its leader.
      val firstServer = pgidOf(serverOf(dirA))
      serverExits(dirA)
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("test")), current(dirA))
      assertEquals(endedGroups.toList, List(firstServer))
      assertEquals(serverStarts.size, 2)
      assert(!Files.exists(RunOnHostSession.exitRecord(serverOf(dirA))), "the replacement's record has no exit")
      assert(logged.exists(_.contains("its server is gone")), logged.toString)
      // The portfile no longer names the running server: a client would attach elsewhere or
      // fork its own, so the server is replaced.
      Files.delete(portfileOf(dirA))
      val secondServer = pgidOf(serverOf(dirA))
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("test")), current(dirA))
      assertEquals(endedGroups.toList, List(firstServer, secondServer))
      assertEquals(serverStarts.size, 3)
      assert(logged.exists(_.contains("no longer names its server")), logged.toString)
      // A portfile naming a connectable socket that is not this directory's derived one does not
      // authorize reuse: the server record still lives, but prepare replaces the server rather
      // than send this directory's client to an alien server (a portfile copied from elsewhere).
      val thirdServer = pgidOf(serverOf(dirA))
      val alien = session.tmp.resolve("alien").resolve("sock")
      Files.createDirectories(alien.getParent)
      val alienListener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
      alienListener.bind(UnixDomainSocketAddress.of(alien))
      try
        writePortfile(dirA, alien)
        assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("test")), current(dirA))
        assertEquals(endedGroups.last, thirdServer, "the server whose portfile named an alien socket is replaced")
        assertEquals(serverStarts.size, 4)
      finally alienListener.close()
      // A replacement whose start throws after registering is discarded like a refused one,
      // and the next command retries.
      serverExits(dirA)
      serverThrows = true
      assertEquals(
        runtimes.prepare(Program.Sbt, dirA, Seq("test")),
        Left("starting the sbt server: IllegalStateException: boom"),
      )
      assert(!Files.exists(serverOf(dirA)), "the throwing start's record")
      serverThrows = false
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("test")), current(dirA))
      assertEquals(serverStarts.size, 6)
      // The proxy exits: the whole runtime is replaced, the server ended first.
      val firstProxy = pgidOf(recordOf(dirA))
      val sixthServer = pgidOf(serverOf(dirA))
      ProcessHandle.of(firstProxy).get.children().forEach(_.destroyForcibly())
      await("the exit published")(Files.exists(RunOnHostSession.exitRecord(recordOf(dirA))))
      val second = runtimes.prepare(Program.Sbt, dirA, Seq("test"))
      assertEquals(second, current(dirA))
      assert(second != first, "a new proxy")
      assertEquals(endedGroups.takeRight(2).toList, List(sixthServer, firstProxy))
      // The group killed whole: no exit is published, the leader is gone, and the record proves
      // nothing to end — replaced all the same.
      val leader = ProcessHandle.of(pgidOf(recordOf(dirA))).get
      val children = leader.children().toList
      leader.destroyForcibly()
      children.forEach(_.destroyForcibly())
      await("the leader gone")(!leader.isAlive)
      val before = endedGroups.size
      val aRuntime = runtimes.prepare(Program.Sbt, dirA, Seq("test"))
      assertEquals(aRuntime, current(dirA))
      assertEquals(endedGroups.size, before + 1, "the server's group is ended; the proxy's leader gone is skipped")

      // A second build directory leaves the first warm: each keeps its own proxy, server and
      // build file; visiting one does not retire the other.
      val serversAtA = serverStarts.size
      val bRuntime = runtimes.prepare(Program.Sbt, dirB, Seq("test"))
      assertEquals(bRuntime, current(dirB))
      assert(bRuntime != aRuntime, "dirB has its own runtime")
      assertEquals(serverStarts.size, serversAtA + 1, "dirB started its own server; dirA's stayed")
      assert(Files.exists(serverOf(dirA)) && Files.exists(buildOf(dirA)), "dirA stays warm")
      assert(Files.exists(serverOf(dirB)) && Files.exists(buildOf(dirB)))
      // Revisiting each reuses its warm runtime; no new server starts.
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("x")), aRuntime, "dirA reused")
      assertEquals(runtimes.prepare(Program.Sbt, dirB, Seq("x")), bRuntime, "dirB reused")
      assertEquals(serverStarts.size, serversAtA + 1, "reuse starts no server")

      // A fresh directory's failed starts leave no files, and touch neither warm runtime: a
      // proxy that never reports ready, a server that does not come up, and a start that throws.
      val dirC = Files.createDirectory(project.resolve("c"))
      neverReady = true
      assertEquals(runtimes.prepare(Program.Sbt, dirC, Seq("test")), Left("never ready"))
      assert(!Files.exists(recordOf(dirC)) && !Files.exists(logOf(dirC)) && !Files.exists(buildOf(dirC)))
      neverReady = false
      serverFails = true
      assertEquals(runtimes.prepare(Program.Sbt, dirC, Seq("test")), Left("no portfile"))
      assert(!Files.exists(recordOf(dirC)) && !Files.exists(serverOf(dirC)) && !Files.exists(buildOf(dirC)))
      serverFails = false
      throwsAfterRegistering = true
      assertEquals(
        runtimes.prepare(Program.Sbt, dirC, Seq("test")),
        Left("creating the runtime: IOException: log unreadable"),
      )
      assert(!Files.exists(recordOf(dirC)) && !Files.exists(logOf(dirC)) && !Files.exists(buildOf(dirC)))
      throwsAfterRegistering = false
      assert(Files.exists(serverOf(dirA)) && Files.exists(serverOf(dirB)), "the warm runtimes are untouched")

      // Mill's runtime is its proxy and its daemon, the client confined to the daemon's port;
      // sbt and mill share the directory's build file, so it outlives the retirement of one
      // program's runtime while the other's records name the hash.
      val serversBefore = serverStarts.size
      def daemonOf(dir: Path) = session.records.resolve(s"daemon-mill-${hashOf(dir)}")
      def millRuntime(dir: Path) =
        Runtime(session.directory, lastPort, logOf(dir, "mill"), Some(40_000 + daemonStarts.size))
      val millA = runtimes.prepare(Program.Mill, dirA, Seq("compile"))
      assertEquals(millA, Right(Some(millRuntime(dirA))))
      assertEquals(serverStarts.size, serversBefore, "mill starts no server")
      assertEquals(daemonStarts.map(_.record).toList, List(daemonOf(dirA)))
      assert(Files.exists(recordOf(dirA, "mill")) && Files.exists(serverOf(dirA)) && Files.exists(buildOf(dirA)))
      assertEquals(runtimes.prepare(Program.Mill, dirA, Seq("test")), millA, "reused while the daemon lives")
      assertEquals(daemonStarts.size, 1)
      // A link redirecting the rendezvous is refused before reuse, and the warm daemon is untouched.
      val daemonDirA = Files.createDirectories(dirA.resolve("out")).resolve("mill-daemon")
      Files.createSymbolicLink(daemonDirA, Files.createDirectories(dirB.resolve("out/mill-daemon")))
      val redirected = runtimes.prepare(Program.Mill, dirA, Seq("test"))
      assert(redirected.swap.exists(_.contains("redirected mill daemon directory")), redirected.toString)
      Files.delete(daemonDirA)
      assertEquals(runtimes.prepare(Program.Mill, dirA, Seq("test")), millA, "reused once the link is gone")
      assertEquals(daemonStarts.size, 1)
      // The daemon gone on its own — its idle exit, `shutdown`, the cancel that ends it — with its
      // starter's leader still alive: replaced, the old group ended.
      val firstDaemonLeader = pgidOf(daemonOf(dirA))
      val firstDaemon = ProcessHandle.of(firstDaemonLeader).get.children().findFirst().get
      firstDaemon.destroyForcibly()
      await("the daemon gone")(!firstDaemon.isAlive)
      val millA2 = runtimes.prepare(Program.Mill, dirA, Seq("test"))
      assertEquals(millA2, Right(Some(millRuntime(dirA))), "a new daemon")
      assertEquals(endedGroups.last, firstDaemonLeader)
      assertEquals(daemonStarts.size, 2)
      assert(logged.exists(_.contains("its daemon is gone")), logged.toString)
      // A change to what Mill's launcher restarts the daemon on replaces the daemon, the old
      // group ended and the assembly redone, before the client could meet the mismatch itself.
      val secondDaemonLeader = pgidOf(daemonOf(dirA))
      val assembliesBefore = assemblies
      Files.writeString(dirA.resolve(".mill-jvm-opts"), "-Xmx1g\n", UTF_8)
      val millA3 = runtimes.prepare(Program.Mill, dirA, Seq("test"))
      assertEquals(millA3, Right(Some(millRuntime(dirA))))
      assertEquals(endedGroups.last, secondDaemonLeader)
      assertEquals(assemblies, assembliesBefore + 1, "assembled afresh")
      assert(logged.exists(_.contains("its configuration changed")), logged.toString)
      assertEquals(runtimes.prepare(Program.Mill, dirA, Seq("test")), millA3, "reused under the new configuration")
      // A daemon start that fails leaves no record, and the next command retries.
      val thirdDaemonLeader = pgidOf(daemonOf(dirA))
      ProcessHandle.of(thirdDaemonLeader).get.children().forEach(_.destroyForcibly())
      await("the daemon gone")(ProcessHandle.of(thirdDaemonLeader).get.children().findFirst().isEmpty)
      daemonFails = true
      assertEquals(runtimes.prepare(Program.Mill, dirA, Seq("test")), Left("no daemon in the group"))
      assert(!Files.exists(daemonOf(dirA)), "the failed start's record")
      daemonFails = false
      assertEquals(
        runtimes.prepare(Program.Mill, dirA, Seq("test")).map(_.flatMap(_.daemonPort)),
        Right(Some(40_000 + daemonStarts.size)),
      )
      // Maven's proxy is the command's own.
      assertEquals(runtimes.prepare(Program.Mvn, dirA, Seq.empty), Right(None))
      // Last, since it discards dirA's server: a redirected socket directory is not reused as
      // this directory's own server. dirA's socket directory is replaced with a symlink to dirB's,
      // leaving dirA's portfile spelling unchanged but resolving to dirB. Reuse is refused — a
      // replacement start is attempted (and here fails by the seam) — so the client never reaches
      // dirB's server. The socket check compares spellings; the symlink guard catches the
      // redirection the spelling hides.
      val aSock = RunOnHostSandbox.expectedServerSocket(session.tmp, dirA)
      val bSock = RunOnHostSandbox.expectedServerSocket(session.tmp, dirB)
      listeners.remove(aSock).foreach(_.close())
      Files.deleteIfExists(aSock)
      Files.delete(aSock.getParent)
      Files.createSymbolicLink(aSock.getParent, bSock.getParent)
      serverFails = true
      assert(runtimes.prepare(Program.Sbt, dirA, Seq("test")).isLeft, "a redirected socket directory is not reused")
      serverFails = false
      Files.delete(aSock.getParent)
    finally
      listeners.values.foreach(_.close())
      spawns.foreach: spawn =>
        spawn.descendants().forEach(_.destroyForcibly())
        spawn.destroyForcibly()
      session.close()

  test("another live broker owning the build directory is refused, and its server is never signalled"):
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the registration spawn never runs under the profile")
    val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
    val root = Files.createTempDirectory("owned").toRealPath()
    RunOnHostSession.ensureRoot(root, uid).getOrElse(fail("root"))
    val project = Files.createDirectory(root.resolve("project"))
    val mine = RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    val peer = RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    val dir = Files.createDirectory(project.resolve("shared"))
    val hash = RunOnHostSession.buildHash(dir)
    // The peer owns dir: its build file names it, and it holds a live server for the hash.
    RunOnHostSession.publishBuildFile(peer.directory, hash, dir)
    val peerServerRecord = peer.records.resolve(s"server-sbt-$hash")
    val peerServer =
      ProcessBuilder(RunOnHostSession.registeredSpawn(peerServerRecord, Seq("/bin/sleep", "30"))*).start()
    var waited = 0
    while !Files.exists(peerServerRecord) && waited < 200 do { Thread.sleep(50); waited += 1 }
    val peerLeader = RunOnHostSession.parseRecord(Files.readString(peerServerRecord, UTF_8)).get.pgid
    val endedGroups = scala.collection.mutable.ListBuffer[Long]()
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = RunOnHostSession.HostProcesses.startOf(pid)
      def endGroup(pgid: Long): Unit = endedGroups += pgid
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(project, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/m"), None, None,
    )
    // A second directory the peer touched with Mill only: its build file names it, but there is
    // no server-sbt record, so the peer reserves no sbt server there.
    val millDir = Files.createDirectory(project.resolve("mill-only"))
    val millHash = RunOnHostSession.buildHash(millDir)
    RunOnHostSession.publishBuildFile(peer.directory, millHash, millDir)
    val started = scala.collection.mutable.ListBuffer[Path]()
    val server = (start: ServerStart) =>
      started += start.buildDirectory
      Right(())
    val emptyAuthority = SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
    val daemonStarts = scala.collection.mutable.ListBuffer[Path]()
    val daemon = (start: DaemonStart) =>
      daemonStarts += start.buildDirectory
      Right(MillDaemons.Daemon(1, "S", 40_001))
    val runtimes = BrokerRuntimes(mine, project, _ => (), emptyAuthority, Vector.empty)(
      processes,
      (_, _, _) => Right(assembled),
      (_, _, _, _) => Right(1), // a proxy port, no stand-in spawn
      server,
      daemon,
    )
    try
      // The peer owns the sbt server for `dir`: refused, and its server never signalled.
      val refused = runtimes.prepare(Program.Sbt, dir, Seq("compile"))
      assert(refused.swap.exists(_.contains("another launch's broker")), refused.toString)
      assert(!endedGroups.contains(peerLeader), "the peer's server was never signalled")
      assert(peerServer.isAlive, "the peer's server is untouched")
      assert(!started.contains(dir), "no server was started for the owned directory")
      // The peer's Mill-only directory reserves no sbt server: this launch starts sbt there.
      assertEquals(runtimes.prepare(Program.Sbt, millDir, Seq("compile")).map(_.isDefined), Right(true))
      assert(started.contains(millDir), "sbt started in the Mill-only directory")
      // The daemon record is the mill ownership: the peer's `daemon-mill-<hash>` refuses a mill
      // command for that directory, while its sbt-only `dir` admits one.
      Files.writeString(peer.records.resolve(s"daemon-mill-$millHash"), "1 S\n", UTF_8)
      val refusedMill = runtimes.prepare(Program.Mill, millDir, Seq("compile"))
      assert(refusedMill.swap.exists(_.contains("owns the mill daemon")), refusedMill.toString)
      assert(!daemonStarts.contains(millDir), "no daemon was started for the owned directory")
      assertEquals(
        runtimes.prepare(Program.Mill, dir, Seq("compile")).map(_.flatMap(_.daemonPort)), Right(Some(40_001)),
      )
      assert(daemonStarts.contains(dir), "mill started in the sbt-owned directory")
    finally
      peerServer.descendants().forEach(_.destroyForcibly())
      peerServer.destroyForcibly().waitFor()
      mine.close(); peer.close()

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
    // From an offset: what a command added to the broker's log, an earlier command's lines excluded.
    val before = Files.size(log)
    assertEquals(deniedHosts(log, before), Vector.empty)
    Files.writeString(log, "2026-08-31T01:08:28Z deny other.example CONNECT host not allowed\n", UTF_8,
      java.nio.file.StandardOpenOption.APPEND)
    assertEquals(deniedHosts(log, before), Vector("other.example"))
    assertEquals(deniedHosts(log, before + 1_000_000), Vector.empty)

  // --------------------------------------------------------------------------
  // The live server a portfile names
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
  // The target/ link sweep
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

  // --------------------------------------------------------------------------
  // The foreign server: derived socket, consented shutdown
  // --------------------------------------------------------------------------

  test("sbtServerSocket reproduces a live server's derivation, recorded from a real portfile"):
    // Recorded: sbt 2.0.7 served /Users/kenichi/ko-agent-sandbox from this hash directory.
    assertEquals(
      sbtServerSocket(Path.of("/Users/kenichi/ko-agent-sandbox"), _ => None, Path.of("/Users/kenichi")),
      Path.of("/Users/kenichi/.config/sbt/2/server/d5fe918c85e40c5548a2/sock"),
    )

  test("sbtServerSocket takes each serverDir source as sbt takes it, not as it reads better"):
    val project = Path.of("/Users/kenichi/ko-agent-sandbox")
    def serverDir(env: (String, String)*) =
      sbtServerSocket(project, env.toMap.get, Path.of("/u")).getParent.getParent
    assertEquals(serverDir("SBT_GLOBAL_SERVER_DIR" -> "/srv"), Path.of("/srv"))
    assertEquals(serverDir("SBT_CONFIG_HOME" -> "/cfg"), Path.of("/cfg/2/server"))
    assertEquals(serverDir("XDG_CONFIG_HOME" -> "/x"), Path.of("/x/sbt/2/server"))
    assertEquals(serverDir(), Path.of("/u/.config/sbt/2/server"))
    // SBT_GLOBAL_SERVER_DIR is sbt's `sys.env get … map file`: present-but-empty is a value, and
    // java.io.File resolves an empty parent against the root rather than staying relative.
    assertEquals(serverDir("SBT_GLOBAL_SERVER_DIR" -> ""), Path.of("/"))
    // The global base's own sources are sbt's `.filter(_.nonEmpty).map(p => file(p.trim))`.
    assertEquals(serverDir("SBT_CONFIG_HOME" -> ""), Path.of("/u/.config/sbt/2/server"))
    assertEquals(serverDir("SBT_CONFIG_HOME" -> " /cfg "), Path.of("/cfg/2/server"))
    // $HOME is not an input: sbt reads the user.home property, and the two can differ.
    assertEquals(serverDir("HOME" -> "/elsewhere"), Path.of("/u/.config/sbt/2/server"))

  private def writePortfile(project: Path, socket: Path): Unit =
    Files.createDirectories(project.resolve("project").resolve("target"))
    Files.writeString(
      project.resolve("project").resolve("target").resolve("active.json"),
      s"""{"uri":"local://$socket"}""",
      UTF_8,
    )

  test("shutdownForeignServer refuses a portfile socket that is not the derived one"):
    val project = Files.createTempDirectory("foreign")
    val result = shutdownForeignServer(
      project, project, Path.of("/somewhere/else/sock"), _ => None, _ => (), userHome = Path.of("/u"),
    )
    assert(result.swap.exists(_.contains("not the one sbt derives")), result)
    assert(result.swap.exists(_.contains("run `sbt shutdown` there and retry")), result)

  test("shutdownForeignServer refuses a derived socket the project itself could have planted"):
    // The whole defence of sending the shutdown only to the derived socket is that the project
    // cannot choose it. An environment that puts sbt's server directory inside the project takes
    // that away.
    val project = Files.createTempDirectory("foreign")
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> project.resolve("srv").toString).get
    val derived = sbtServerSocket(project, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    val log = collection.mutable.Buffer[String]()
    val result =
      shutdownForeignServer(project, project, derived, env, log.append(_), userHome = Path.of("/u"))
    assert(result.swap.exists(_.contains("reachable through what a command writes")), result)
    assertEquals(log.toList, Nil)

  test("shutdownForeignServer treats a server gone before the shutdown as ended, and says so"):
    val home = Files.createTempDirectory("home")
    val project = Files.createTempDirectory("foreign")
    val derived = sbtServerSocket(project, _ => None, home)
    writePortfile(project, derived)
    val log = collection.mutable.Buffer[String]()
    assertEquals(
      shutdownForeignServer(project, project, derived, _ => None, log.append(_), userHome = home),
      Right(()),
    )
    assert(log.exists(_.contains("shutting down the sbt server")), log)

  test("shutdownForeignServer refuses when the server never answers the shutdown"):
    // SBT_GLOBAL_SERVER_DIR, not the home fallback: a bound socket path must fit sun_path's 104.
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> Files.createTempDirectory("s").toString).get
    val project = Files.createTempDirectory("f")
    val derived = sbtServerSocket(project, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    val listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    listener.bind(UnixDomainSocketAddress.of(derived))
    try
      val result = shutdownForeignServer(
        project, project, derived, env, _ => (), shutdownDeadlineMillis = 300,
      )
      assert(result.swap.exists(_.contains("went unanswered")), result)
    finally listener.close()

  test("shutdownForeignServer refuses when the portfile outlives an answered shutdown"):
    // SBT_GLOBAL_SERVER_DIR, not the home fallback: a bound socket path must fit sun_path's 104.
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> Files.createTempDirectory("s").toString).get
    val project = Files.createTempDirectory("f")
    val derived = sbtServerSocket(project, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    writePortfile(project, derived)
    // A listener that answers initialize and closes — a shutdown that "succeeds" — but lives on,
    // so the portfile it holds keeps naming a connectable socket.
    val listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    listener.bind(UnixDomainSocketAddress.of(derived))
    @volatile var serving = true
    val server = Thread(() =>
      while serving do
        try
          val client = listener.accept()
          try
            val buffer = java.nio.ByteBuffer.allocate(4096)
            client.read(buffer) // initialize
            client.write(java.nio.ByteBuffer.wrap("ok".getBytes(UTF_8)))
            buffer.clear()
            client.read(buffer) // the shutdown exec; the close after it is the "completed" answer
          finally client.close()
        catch case _: Exception => (),
    )
    server.start()
    try
      val result = shutdownForeignServer(
        project, project, derived, env, _ => (),
        shutdownDeadlineMillis = 2_000, releaseDeadlineMillis = 300,
      )
      assert(result.swap.exists(_.contains("still holds the portfile")), result)
    finally
      serving = false
      listener.close()
      server.join(2_000)

  test("reachableThroughCommandWritable answers by what the walk enters, not by where it ends"):
    val project = Files.createTempDirectory("p")
    val outside = Files.createTempDirectory("o")
    def reachable(target: Path) = reachableThroughCommandWritable(target, project, Seq.empty)
    assert(reachable(project.resolve("srv/h/sock")))
    assert(!reachable(outside.resolve("srv/h/sock")))
    // The planting this exists to catch, in both forms a link can take: the endpoint tells
    // nothing, because the link inside the project is what chose it.
    val dangling = project.resolve("dangling.sock")
    Files.createSymbolicLink(dangling, outside.resolve("never-created"))
    assert(reachable(dangling))
    val existing = Files.writeString(outside.resolve("real.sock"), "")
    Files.createSymbolicLink(project.resolve("planted.sock"), existing)
    assert(reachable(project.resolve("planted.sock")))
    // The same escape one directory up: an ancestor link inside the project redirects the rest.
    Files.createSymbolicLink(project.resolve("srv"), outside)
    assert(reachable(project.resolve("srv/real.sock")))
    // Outside -> project -> outside: every hop but the middle one is outside the project, and only
    // the middle one is writable. Resolving the chain in one step would report the far end and clear it.
    val relay = project.resolve("relay")
    Files.createSymbolicLink(relay, existing)
    val entry = outside.resolve("entry")
    Files.createSymbolicLink(entry, relay)
    assert(reachable(entry))
    // A relative path resolves against a working directory this process does not control.
    assert(reachable(Path.of("srv/h/sock")))
    // An unanswerable question is reachable: a project that does not resolve cannot clear anything.
    assert(reachableThroughCommandWritable(outside.resolve("sock"), project.resolve("gone"), Seq.empty))

  test("reachableThroughCommandWritable covers the caches a command writes, not the project alone"):
    val project = Files.createTempDirectory("p")
    val cache = Files.createTempDirectory("c")
    val outside = Files.createTempDirectory("o")
    val planted = cache.resolve("h/sock")
    Files.createDirectories(planted.getParent)
    Files.writeString(planted, "")
    // A socket an earlier agent's command left in a persistent cache is as planted as one in the
    // project — and invisible while the project is the only root.
    assert(!reachableThroughCommandWritable(planted, project, Seq.empty))
    assert(reachableThroughCommandWritable(planted, project, Seq(cache)))
    assert(!reachableThroughCommandWritable(outside.resolve("sock"), project, Seq(cache)))
    // A cache that does not exist yet holds nothing, and must not refuse every shutdown.
    assert(!reachableThroughCommandWritable(outside.resolve("sock"), project, Seq(cache.resolve("gone"))))

  test("reachableThroughCommandWritable knows both firmlink spellings of every writable root"):
    // macOS serves the writable volume at / and at /System/Volumes/Data alike, and toRealPath
    // collapses neither, so the alternate spelling would otherwise walk past every root.
    val project = Files.createTempDirectory("p")
    val cache = Files.createTempDirectory("c")
    val outside = Files.createTempDirectory("o")
    def aliased(root: Path) = Path.of(s"/System/Volumes/Data${root.toRealPath()}/h/sock")
    assert(reachableThroughCommandWritable(aliased(project), project, Seq.empty))
    assert(reachableThroughCommandWritable(aliased(cache), project, Seq(cache)))
    assert(!reachableThroughCommandWritable(aliased(outside), project, Seq(cache)))

  test("appendSessionLogs reads each log as the file it found, inside the session, bounded, naming what it skipped"):
    val root = Files.createTempDirectory("session-logs")
    val condemned = Files.createDirectory(root.resolve("s1"))
    val tmp = Files.createDirectory(condemned.resolve(RunOnHostSession.TmpDir))
    val channelLog = root.resolve("channel.log")
    Files.writeString(channelLog, "before\n", UTF_8)
    val audit = ("audit line\n" * (SessionLogTailBytes / 8)).getBytes(UTF_8)
    Files.write(condemned.resolve("proxy.log"), audit)
    // A sparse file the command could have made as large as it liked: only the tail is read.
    val sparse = java.io.RandomAccessFile(tmp.resolve("sbt-server-err1.log").toFile, "rw")
    sparse.write("server said\n".getBytes(UTF_8))
    sparse.setLength(1L << 30)
    sparse.close()
    // A link out of the session: named, never followed.
    val secret = Files.writeString(root.resolve("secret"), "the user's own file\n", UTF_8)
    Files.createSymbolicLink(tmp.resolve("sbt-server-err2.log"), secret)
    // A FIFO: named, never opened, or this teardown would wait on a writer that never comes.
    assume(ProcessBuilder("mkfifo", tmp.resolve("sbt-server-err3.log").toString).start().waitFor() == 0, "needs mkfifo")
    Files.writeString(tmp.resolve("other.tmp"), "not a log\n", UTF_8)
    appendSessionLogs(channelLog, condemned, "command s1 ended by signal")
    val logged = Files.readString(channelLog, UTF_8)
    assert(logged.startsWith("before\n"), logged)
    assert(logged.contains("command s1 ended by signal; its logs follow"), logged)
    assert(logged.contains(s"==> proxy.log\n[last $SessionLogTailBytes bytes]\n"), logged)
    assert(logged.contains(s"==> sbt-server-err1.log\n[last $SessionLogTailBytes bytes]\n"), logged)
    assert(logged.contains("==> sbt-server-err2.log\n[skipped: not a regular file]\n"), logged)
    assert(logged.contains("==> sbt-server-err3.log\n[skipped: not a regular file]\n"), logged)
    assert(!logged.contains("the user's own file"), logged)
    assert(!logged.contains("not a log"), logged)
    // tmp itself replaced by a link to a directory holding a matching regular file: not listed.
    val planted = Files.createDirectory(root.resolve("planted"))
    Files.writeString(planted.resolve("sbt-server-err1.log"), "the user's other file\n", UTF_8)
    val linked = Files.createDirectory(root.resolve("s3"))
    Files.createSymbolicLink(linked.resolve(RunOnHostSession.TmpDir), planted)
    Files.writeString(linked.resolve("proxy.log"), "audit\n", UTF_8)
    Files.writeString(channelLog, "", UTF_8)
    appendSessionLogs(channelLog, linked, "command s3 ended by signal")
    val viaLink = Files.readString(channelLog, UTF_8)
    assert(viaLink.contains("==> tmp\n[skipped: not a directory]\n"), viaLink)
    assert(viaLink.contains("==> proxy.log\naudit\n"), viaLink)
    assert(!viaLink.contains("the user's other file"), viaLink)
    // Kept whole below the bound, and a session with a proxy log alone lists that alone.
    val alone = Files.createDirectory(root.resolve("s2"))
    Files.createDirectory(alone.resolve(RunOnHostSession.TmpDir))
    Files.writeString(alone.resolve("proxy.log"), "short\n", UTF_8)
    Files.writeString(channelLog, "", UTF_8)
    appendSessionLogs(channelLog, alone, "command s2 ended by signal")
    val again = Files.readString(channelLog, UTF_8)
    assert(again.contains("==> proxy.log\nshort\n"), again)
    assert(!again.contains("[last"), again)
    assert(!again.contains("sbt-server-err"), again)
    // The broker's session: one proxy log per runtime, and nothing else of the directory.
    val broker = Files.createDirectory(root.resolve("b1"))
    Files.createDirectory(broker.resolve(RunOnHostSession.TmpDir))
    Files.writeString(broker.resolve("proxy-sbt-0a.log"), "sbt audit\n", UTF_8)
    Files.writeString(broker.resolve("proxy-mill-0b.log"), "mill audit\n", UTF_8)
    Files.writeString(broker.resolve("server-sbt-0a.log"), "server said\n", UTF_8)
    Files.writeString(broker.resolve("project"), "/p\n", UTF_8)
    Files.writeString(channelLog, "", UTF_8)
    appendSessionLogs(channelLog, broker, "the broker's session b1 ended")
    val brokers = Files.readString(channelLog, UTF_8)
    assert(brokers.contains("the broker's session b1 ended; its logs follow"), brokers)
    assert(brokers.contains("==> proxy-mill-0b.log\nmill audit\n==> proxy-sbt-0a.log\nsbt audit\n"), brokers)
    assert(brokers.contains("==> server-sbt-0a.log\nserver said\n"), brokers)
    assert(!brokers.contains("==> project"), brokers)
