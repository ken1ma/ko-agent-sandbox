package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import RunOnHostSandbox.*
import RunOnHostPrereqs.Tool

class RunOnHostSandboxTest extends munit.FunSuite:

  test("the measured runtime authority ships in the artifact, and parses"):
    val authority = RunOnHostSandbox.bundledRuntimeAuthority()
    assert(authority.executes.nonEmpty, "the bundled file grants no executable roots")

  test("the build's environment is a closed set: the wrapper's settings, three pass-throughs, and --env"):
    val jdk = Path.of("/Users/u/Library/Caches/Coursier/v1/jvm/temurin")
    val prereqs = RunOnHostPrereqs.BuildPrereqs(
      project = Path.of("/Users/u/project"), jdkHome = jdk, coursierV1 = Path.of("/cache/v1"),
      tool = Tool.Sbt, executable = Path.of("/Users/u/Library/Application Support/Coursier/bin/sbt"),
    )
    val host = Map(
      "HOME" -> "/Users/u", "LANG" -> "en_US.UTF-8", "PATH" -> "/usr/bin:/bin",
      "TERM" -> "xterm", "TMPDIR" -> "/var/folders/xy/T", "JAVA_HOME" -> "/Users/u/jdk-link",
      "HTTPS_PROXY" -> "http://alice:s3cret@proxy.example:3128", "AWS_SECRET_ACCESS_KEY" -> "hunter2",
      "SBT_OPTS" -> "-Xmx8g", "MILL_VERSION" -> "1.0.0", "TOKEN" -> "t0ken", "USER" -> "shellname",
    )
    val environment = buildEnvironment(
      host.get,
      Vector(
        "TOKEN" -> "t0ken", "HTTPS_PROXY" -> "http://elsewhere.example:1", "MILL_VERSION" -> "1.0.0",
        "JAVA_TOOL_OPTIONS" -> "-javaagent:/tmp/agent.jar",
      ),
      prereqs, sbtGlobal = Path.of("/cache/sbt"), millDownloads = Some(Path.of("/Users/u/.cache/mill/download")),
      sessionTmp = Path.of("/private/tmp/ko-agent-501/s"), proxyPort = 4711, userName = "u",
    )
    // Passed through as they are.
    assertEquals(environment("HOME"), "/Users/u")
    assertEquals(environment("LANG"), "en_US.UTF-8")
    // Set by the wrapper, from what it proved or made, never from the shell.
    assertEquals(environment("JAVA_HOME"), jdk.toString)
    assertEquals(environment("PATH"), s"$jdk/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    assertEquals(environment("TMPDIR"), "/private/tmp/ko-agent-501/s")
    assertEquals(environment("USER"), "u")
    assertEquals(environment("LOGNAME"), "u")
    assertEquals(environment("MILL_FINAL_DOWNLOAD_FOLDER"), "/Users/u/.cache/mill/download")
    assertEquals(environment("COURSIER_CACHE"), "/cache/v1")
    assert(environment("JAVA_TOOL_OPTIONS").contains("-Dsbt.global.base=/cache/sbt"))
    // A forward reaches the build; one naming a variable the wrapper sets loses to the wrapper.
    assertEquals(environment("TOKEN"), "t0ken")
    assertEquals(environment("HTTPS_PROXY"), "http://127.0.0.1:4711")
    assert(!environment("JAVA_TOOL_OPTIONS").contains("javaagent"))
    // And nothing else of the shell: not the secret, not the upstream proxy's credential, not the
    // tools' own overrides — the mill version ones even when forwarded.
    Vector("AWS_SECRET_ACCESS_KEY", "SBT_OPTS", "MILL_VERSION", "TERM", "ALL_PROXY").foreach: name =>
      assert(!environment.contains(name), name)
    assert(!environment.values.exists(_.contains("s3cret")), environment.toString)
    assertEquals(
      environment.keySet,
      Set(
        "HOME", "LANG", "TOKEN", "PATH", "JAVA_HOME", "JAVA_TOOL_OPTIONS", "TMPDIR", "XDG_RUNTIME_DIR",
        "SBT_GLOBAL_SERVER_DIR", "COURSIER_CACHE", "USER", "LOGNAME", "MILL_FINAL_DOWNLOAD_FOLDER",
      ) ++ buildProxyVariables(4711).keySet,
    )
    // Without a derivable download folder the variable is simply absent.
    val noFolder = buildEnvironment(host.get, Vector.empty, prereqs, Path.of("/s"), None, Path.of("/t"), 1, "u")
    assert(!noFolder.contains("MILL_FINAL_DOWNLOAD_FOLDER"))

  test("the host-served proxy's variable is selected as the proxy selects it: an empty uppercase is unset"):
    val both = Map("HTTPS_PROXY" -> "", "https_proxy" -> "http://proxy.example:3128")
    assertEquals(upstreamProxyVariable(both.get), Some("https_proxy" -> "http://proxy.example:3128"))
    assertEquals(upstreamProxyVariable(Map("HTTPS_PROXY" -> "http://a.example:1").get), Some("HTTPS_PROXY" -> "http://a.example:1"))
    assertEquals(upstreamProxyVariable(Map.empty[String, String].get), None)
    assertEquals(carrierName("TOKEN"), "KO_AGENT_RUN_ON_HOST_ENV_TOKEN")

  test("--env names travel as options and come back as names; nothing else is an option"):
    assertEquals(
      forwardedNames(Seq("--env=TOKEN", AutoShutdownForeignSbtOption, "--env=OTHER")),
      Vector("TOKEN", "OTHER"),
    )
    assertEquals(forwardedNames(Seq.empty), Vector.empty)

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

  test("readBuildRules reads the tool's file, refuses its strays, and defaults to nothing"):
    val project = projectWith(".ko-agent-sandbox/host-command/sbt/egress/rule")
    Files.writeString(
      project.resolve(".ko-agent-sandbox/host-command/sbt/egress/rule"),
      "allow https://repo.example.org/ read\n",
      UTF_8,
    )
    assertEquals(readBuildRules(project, Tool.Sbt), Right(Vector("repo.example.org")))
    assertEquals(readBuildRules(project, Tool.Mill), Right(Vector.empty), "mill has no file here")

    Files.writeString(
      project.resolve(".ko-agent-sandbox/host-command/sbt/egress/rule"),
      "allow model-provider openai\n",
      UTF_8,
    )
    val refused = readBuildRules(project, Tool.Sbt)
    assert(refused.swap.exists(_.contains("allow model-provider openai")), refused.toString)
    assert(refused.swap.exists(_.contains(RunOnHostPrereqs.BuildRuleForm)), refused.toString)

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
    val classpath = EmitBuildProfile.classpathForRelaunch.split(java.io.File.pathSeparator).toVector
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

  test("autoShutdownForeignServer refuses a portfile socket that is not the derived one"):
    val project = Files.createTempDirectory("foreign")
    val result = autoShutdownForeignServer(
      project, Path.of("/somewhere/else/sock"), _ => None, _ => (), userHome = Path.of("/u"),
    )
    assert(result.swap.exists(_.contains("does not apply")), result)
    assert(result.swap.exists(_.contains("run `sbt shutdown` there and retry")), result)

  test("autoShutdownForeignServer refuses a derived socket the project itself could have planted"):
    // The whole defence of sending the shutdown only to the derived socket is that the project
    // cannot choose it. An environment that puts sbt's server directory inside the project takes
    // that away.
    val project = Files.createTempDirectory("foreign")
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> project.resolve("srv").toString).get
    val derived = sbtServerSocket(project, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    val log = collection.mutable.Buffer[String]()
    val result =
      autoShutdownForeignServer(project, derived, env, log.append(_), userHome = Path.of("/u"))
    assert(result.swap.exists(_.contains("reachable through what a build writes")), result)
    assertEquals(log.toList, Nil)

  test("autoShutdownForeignServer treats a server gone before the shutdown as ended, and says so"):
    val home = Files.createTempDirectory("home")
    val project = Files.createTempDirectory("foreign")
    val derived = sbtServerSocket(project, _ => None, home)
    writePortfile(project, derived)
    val log = collection.mutable.Buffer[String]()
    assertEquals(
      autoShutdownForeignServer(project, derived, _ => None, log.append(_), userHome = home),
      Right(()),
    )
    assert(log.exists(_.contains("shutting down the foreign sbt server")), log)

  test("autoShutdownForeignServer refuses when the server never answers the shutdown"):
    // SBT_GLOBAL_SERVER_DIR, not the home fallback: a bound socket path must fit sun_path's 104.
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> Files.createTempDirectory("s").toString).get
    val project = Files.createTempDirectory("f")
    val derived = sbtServerSocket(project, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    val listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    listener.bind(UnixDomainSocketAddress.of(derived))
    try
      val result = autoShutdownForeignServer(
        project, derived, env, _ => (), shutdownDeadlineMillis = 300,
      )
      assert(result.swap.exists(_.contains("went unanswered")), result)
    finally listener.close()

  test("autoShutdownForeignServer refuses when the portfile outlives an answered shutdown"):
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
      val result = autoShutdownForeignServer(
        project, derived, env, _ => (),
        shutdownDeadlineMillis = 2_000, releaseDeadlineMillis = 300,
      )
      assert(result.swap.exists(_.contains("still holds the portfile")), result)
    finally
      serving = false
      listener.close()
      server.join(2_000)

  test("reachableThroughBuildWritable answers by what the walk enters, not by where it ends"):
    val project = Files.createTempDirectory("p")
    val outside = Files.createTempDirectory("o")
    def reachable(target: Path) = reachableThroughBuildWritable(target, project, Seq.empty)
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
    // Outside -> project -> outside: every hop but the middle one looks innocent, and only the
    // middle one is writable. Resolving the chain in one step would report the far end and clear it.
    val relay = project.resolve("relay")
    Files.createSymbolicLink(relay, existing)
    val entry = outside.resolve("entry")
    Files.createSymbolicLink(entry, relay)
    assert(reachable(entry))
    // A relative path resolves against a working directory this process does not control.
    assert(reachable(Path.of("srv/h/sock")))
    // An unanswerable question is reachable: a project that does not resolve cannot clear anything.
    assert(reachableThroughBuildWritable(outside.resolve("sock"), project.resolve("gone"), Seq.empty))

  test("reachableThroughBuildWritable covers the caches a build writes, not the project alone"):
    val project = Files.createTempDirectory("p")
    val cache = Files.createTempDirectory("c")
    val outside = Files.createTempDirectory("o")
    val planted = cache.resolve("h/sock")
    Files.createDirectories(planted.getParent)
    Files.writeString(planted, "")
    // A socket an earlier agent's build left in a persistent cache is as planted as one in the
    // project — and invisible while the project is the only root.
    assert(!reachableThroughBuildWritable(planted, project, Seq.empty))
    assert(reachableThroughBuildWritable(planted, project, Seq(cache)))
    assert(!reachableThroughBuildWritable(outside.resolve("sock"), project, Seq(cache)))
    // A cache that does not exist yet holds nothing, and must not refuse every shutdown.
    assert(!reachableThroughBuildWritable(outside.resolve("sock"), project, Seq(cache.resolve("gone"))))

  test("reachableThroughBuildWritable knows both firmlink spellings of every writable root"):
    // macOS serves the writable volume at / and at /System/Volumes/Data alike, and toRealPath
    // collapses neither, so the alternate spelling would otherwise walk past every root.
    val project = Files.createTempDirectory("p")
    val cache = Files.createTempDirectory("c")
    val outside = Files.createTempDirectory("o")
    def aliased(root: Path) = Path.of(s"/System/Volumes/Data${root.toRealPath()}/h/sock")
    assert(reachableThroughBuildWritable(aliased(project), project, Seq.empty))
    assert(reachableThroughBuildWritable(aliased(cache), project, Seq(cache)))
    assert(!reachableThroughBuildWritable(aliased(outside), project, Seq(cache)))
