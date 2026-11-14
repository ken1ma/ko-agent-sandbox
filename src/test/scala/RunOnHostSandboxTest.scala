package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import RunOnHostProxy.*
import RunOnHostSandbox.*
import RunOnHostSbtServer.*
import scala.jdk.CollectionConverters.*
import scala.util.chaining.*
import RunOnHostPrereqs.Program

class RunOnHostSandboxTest extends munit.FunSuite:

  /** An assembly for an environment test, with paths that nothing reads and no mill derivation. */
  private def assembledFor(prereqs: RunOnHostPrereqs.CommandPrereqs): Assembled =
    Assembled(prereqs, None, Path.of("/s"), Path.of("/i"), Path.of("/g"), Path.of("/m"), None, None)

  test("the measured system paths ship in the artifact, and parse"):
    val systemPaths = RunOnHostSandbox.bundledSystemPaths()
    assert(systemPaths.executes.nonEmpty, "the bundled file grants no executable roots")

  test("a command's file rules are the launch's set when the runner hands one on, else the workspace's lines"):
    val workspace = Files.createTempDirectory("file-rules-of")
    try
      val resolved = FileRules.Resolved(FileRules.Defaults, Vector(".husky/_"), Vector.empty)
      val file = workspace.resolve("file-rules.resolved")
      Files.writeString(file, resolved.text)
      assertEquals(fileRulesOf(Seq(s"$FileRulesOption$file", "--other"), workspace), Right(resolved))
      assertEquals(fileRulesOf(Seq("--other"), workspace), FileRules.ofWorkspace(workspace))
    finally FileHelper.deleteRecursively(workspace)

  test("the command's environment is a closed set: the supervisor's settings, three pass-throughs, and --env"):
    val jdk = Path.of("/Users/u/Library/Caches/Coursier/v1/jvm/temurin")
    val prereqs = RunOnHostPrereqs.CommandPrereqs(
      workspaceRoot = Path.of("/Users/u/workspace"), jdkHome = jdk, coursierV1 = Path.of("/cache/v1"),
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
        "MILL_OUTPUT_DIR" -> "elsewhere", "_JAVA_OPTIONS" -> "-javaagent:/tmp/agent.jar",
        "JAVA_TOOL_OPTIONS" -> "-Duser.option=value", HostCommandVariable -> "0",
      ),
      Assembled(
        prereqs, None, sbtGlobal = Path.of("/cache/sbt"), ivyHome = Path.of("/cache/ivy"),
        gradleUserHome = Path.of("/cache/gradle"), m2Repository = Path.of("/cache/m2"),
        millDownloads = Some(Path.of("/Users/u/.cache/mill/download")), millLauncherVersion = Some("1.1.9-jvm"),
      ),
      sessionTmp = Path.of("/private/tmp/ko-agent-501/s"), socketDir = Path.of("/private/tmp/ko-agent-501/b/tmp"),
      proxyPort = 4711, trust = Path.of("/private/tmp/ko-agent-501/b/proxy-sbt-0.trust"), userName = "u",
    )
    // These variables pass through as they are.
    assertEquals(environment("HOME"), "/Users/u")
    assertEquals(environment("LANG"), "en_US.UTF-8")
    // The supervisor sets these variables from what it checked or made, never from the shell.
    assertEquals(environment("JAVA_HOME"), jdk.toString)
    assertEquals(environment("PATH"), s"$jdk/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    assertEquals(environment("TMPDIR"), "/private/tmp/ko-agent-501/s")
    assert(environment("_JAVA_OPTIONS").contains("-Djava.io.tmpdir=\"/private/tmp/ko-agent-501/s\""))
    // The sockets belong to the runtime, at the place where the runner's server bound them.
    assertEquals(environment("XDG_RUNTIME_DIR"), "/private/tmp/ko-agent-501/b/tmp")
    assertEquals(environment("SBT_GLOBAL_SERVER_DIR"), "/private/tmp/ko-agent-501/b/tmp")
    assertEquals(environment("USER"), "u")
    assertEquals(environment("LOGNAME"), "u")
    // A build reads the marker to tell a host command from a terminal's, so no forwarded value replaces it.
    assertEquals(environment(HostCommandVariable), "1")
    assertEquals(environment("MILL_FINAL_DOWNLOAD_FOLDER"), "/Users/u/.cache/mill/download")
    // MILL_VERSION is the supervisor's launcher version, never the forwarded one.
    assertEquals(environment("MILL_VERSION"), "1.1.9-jvm")
    assertEquals(environment("COURSIER_CACHE"), "/cache/v1")
    assertEquals(environment("GRADLE_USER_HOME"), "/cache/gradle")
    assert(environment("_JAVA_OPTIONS").contains("-Dsbt.global.base=\"/cache/sbt\""))
    assert(environment("_JAVA_OPTIONS").contains("-Dsbt.ivy.home=\"/cache/ivy\""))
    assert(environment("_JAVA_OPTIONS").contains("-Dmaven.repo.local=\"/cache/m2\""))
    // A forward reaches the command. A forward that names a variable the supervisor sets loses to the supervisor.
    assertEquals(environment("TOKEN"), "t0ken")
    assertEquals(environment("HTTPS_PROXY"), "http://127.0.0.1:4711")
    // The JVMs get the proxy's CA as a store, and the programs that HTTPS_PROXY serves get it as a PEM file.
    assert(environment("_JAVA_OPTIONS").contains(
      "-Djavax.net.ssl.trustStore=\"/private/tmp/ko-agent-501/b/proxy-sbt-0.trust/truststore.p12\"",
    ))
    assert(environment("_JAVA_OPTIONS").contains("-Djavax.net.ssl.trustStoreType=PKCS12"))
    assert(environment("_JAVA_OPTIONS").contains("-Djavax.net.ssl.trustStorePassword=changeit"))
    AgentSandboxLauncher.CaBundleVariables.foreach: name =>
      assertEquals(environment(name), "/private/tmp/ko-agent-501/b/proxy-sbt-0.trust/ca.crt")
    assert(!environment("_JAVA_OPTIONS").contains("javaagent"))
    assertEquals(environment("JAVA_TOOL_OPTIONS"), "-Duser.option=value")
    // Nothing else of the shell reaches the command: not the secret, not the upstream proxy's credential, and not the
    // programs' own overrides. Mill's version and output-directory overrides stay out even when forwarded.
    Vector("AWS_SECRET_ACCESS_KEY", "SBT_OPTS", "DEFAULT_MILL_VERSION", "MILL_OUTPUT_DIR",
      "TERM", "ALL_PROXY")
      .foreach: name =>
      assert(!environment.contains(name), name)
    assert(!environment.values.exists(_.contains("s3cret")), environment.toString)
    assertEquals(
      environment.keySet,
      Set(
        "HOME", "LANG", "TOKEN", "PATH", "JAVA_HOME", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "TMPDIR", "XDG_RUNTIME_DIR",
        "SBT_GLOBAL_SERVER_DIR", "COURSIER_CACHE", "GRADLE_USER_HOME", "USER", "LOGNAME", "MILL_FINAL_DOWNLOAD_FOLDER",
        "MILL_VERSION", HostCommandVariable,
      ) ++ commandProxyVariables(4711).keySet ++ AgentSandboxLauncher.CaBundleVariables,
    )
    // Without a derivable download folder, the variable is absent. The launcher version is absent too for a program
    // that is not mill, even when it is forwarded.
    val noFolder =
      commandEnvironment(
        host.get, Vector("MILL_VERSION" -> "1.0.0"), assembledFor(prereqs), Path.of("/t"), Path.of("/t"), 1,
        Path.of("/trust"), "u",
      )
    assert(!noFolder.contains("MILL_FINAL_DOWNLOAD_FOLDER"))
    assert(!noFolder.contains("MILL_VERSION"))

    val optIn = Vector(
      "TERM" -> "xterm", "SBT_OPTS" -> "-Xmx2g", "JAVA_OPTS" -> "-Xmx2g",
      "JAVA_TOOL_OPTIONS" -> "-Dbuild.option=value", "JDK_JAVA_OPTIONS" -> "-Dbuild.option=value",
      "ALL_PROXY" -> "http://example:3128",
      "FTP_PROXY" -> "http://example:3128", "SBT_CREDENTIALS" -> "/credentials",
    )
    for program <- Program.values do
      def withForwards(forwards: Vector[(String, String)]): Map[String, String] =
        commandEnvironment(
          optIn.toMap.get, forwards, assembledFor(prereqs.copy(program = program)), Path.of("/t"), Path.of("/t"), 1,
          Path.of("/trust"), "u",
        )
      val inherited = withForwards(Vector.empty)
      val explicit = withForwards(optIn)
      optIn.foreach: (name, value) =>
        assert(!inherited.contains(name), s"$program: $name must require forwarding")
        assertEquals(explicit(name), value, clue = program)

  test("each program's JVM paths survive sbt's parsing and inheritance by forked JVMs"):
    val jdk = Path.of(sys.props("java.home"))
    val jvm = jdk.resolve("bin/java").toString
    val settings = Seq("-XshowSettings:properties", "-version")
    val classpath = Seq(ForkJvmSettings.getClass, scala.runtime.LazyVals.getClass, classOf[Option[?]])
      .map(kind => Path.of(kind.getProtectionDomain.getCodeSource.getLocation.toURI).toString)
      .distinct.mkString(java.io.File.pathSeparator)
    // sbt 2.0.8's runner copies these variables into argv without interpreting their quotes.
    // Its getPreloaded lookup scans argv before splitting _JAVA_OPTIONS the same way.
    val sbtRunner = """java_tool_options=($JAVA_TOOL_OPTIONS)
                      |jdk_java_options=($JDK_JAVA_OPTIONS)
                      |read -a java_options <<< "$_JAVA_OPTIONS"
                      |for option in "$@" "${java_options[@]}"; do
                      |  case "$option" in
                      |    -Dsbt.global.base=*) echo "preloaded = ${option#*=}/preloaded" >&2; break ;;
                      |  esac
                      |done
                      |exec "$JAVA_HOME/bin/java" "$@" "${java_tool_options[@]}" "${jdk_java_options[@]}" \
                      |  -XshowSettings:properties -version
                      |""".stripMargin
    for
      program <- Program.values
      path <- Seq("/plain", "/with spaces", "/both'\"quotes", "/back\\slash and * ? [glob]")
    do
      val root = Path.of(path)
      val prereqs = RunOnHostPrereqs.CommandPrereqs(root, jdk, root, program, Path.of("/unused/sbt"))
      val environment = commandEnvironment(
        _ => None,
        Vector(
          "JAVA_TOOL_OPTIONS" -> "-Djava.io.tmpdir=/tool-option -Dforward.tool=value",
          "JDK_JAVA_OPTIONS" -> "-Djava.io.tmpdir=/jdk-option -Dforward.jdk=value",
          "_JAVA_OPTIONS" -> "-Djava.io.tmpdir=/forward",
        ),
        Assembled(
          prereqs, None, root.resolve("sbt"), root.resolve("ivy"), root.resolve("gradle"), root.resolve("m2"), None,
          None,
        ),
        root.resolve("tmp"), root.resolve("sockets"), 4711, root.resolve("trust"), "u",
      )
      val expected = Map(
        "java.io.tmpdir" -> root.resolve("tmp"), "java.util.prefs.userRoot" -> root.resolve("tmp"),
        "sbt.ipcsocket.tmpdir" -> root.resolve("tmp"), "sbt.global.base" -> root.resolve("sbt"),
        "sbt.ivy.home" -> root.resolve("ivy"), "maven.repo.local" -> root.resolve("m2"),
      )
      val launcher =
        if program == Program.Sbt then
          Seq("/bin/bash", "-c", sbtRunner, "sbt") ++ sbtCommand(prereqs.executable, root.resolve("sbt")).tail
        else Seq(jvm) ++ settings
      // A build supplies its own argv to a forked JVM, so only the environment carries these settings.
      for command <- Seq(launcher, Seq(jvm, "-cp", classpath, "agentsandbox.launcher.ForkJvmSettings")) do
        val builder = ProcessBuilder(command*)
        builder.environment().clear()
        builder.environment().putAll(environment.asJava)
        val process = builder.start()
        process.getOutputStream.close()
        val err = String(process.getErrorStream.readAllBytes(), UTF_8)
        assertEquals(process.waitFor(), 0, s"$program, $path: $err")
        expected.foreach: (name, value) =>
          assert(err.linesIterator.exists(_.trim == s"$name = $value"), s"$program, $name: $err")
        for name <- Seq("forward.tool", "forward.jdk") do
          assert(err.linesIterator.exists(_.trim == s"$name = value"), s"$program, $name: $err")
        if program == Program.Sbt && command == launcher then
          assert(err.linesIterator.contains(s"preloaded = ${root.resolve("sbt/preloaded")}"), err)

  test("a gradle command's registry is the launch's own, and its toolchain inventory the granted JDK"):
    val prereqs = RunOnHostPrereqs.CommandPrereqs(
      Path.of("/p"), Path.of("/jdk"), Path.of("/v1"), Program.Gradle, Path.of("/dists/gradle-9.7.1/bin/gradle"),
    )
    assertEquals(
      gradleCommand(prereqs, Path.of("/private/tmp/ko-agent-501/b/tmp")),
      Seq(
        "/dists/gradle-9.7.1/bin/gradle",
        "-Dorg.gradle.daemon.registry.base=/private/tmp/ko-agent-501/b/tmp/gradle-daemon",
        "-Dorg.gradle.java.installations.auto-detect=false",
        "-Dorg.gradle.java.installations.auto-download=false",
        "-Dorg.gradle.java.installations.paths=/jdk",
      ),
    )

  test("a gradle assembly grants the wrapper's one distribution and the workspace's own Gradle user home"):
    import java.nio.file.attribute.PosixFilePermissions.fromString as permissions
    val root = Files.createTempDirectory("gradle")
    val cache = Files.createDirectories(root.resolve("coursier"))
    val jdk = Files.createDirectories(cache.resolve("arc/jdk.tar.gz/jdk"))
    Files.createDirectories(jdk.resolve("bin"))
    Files.setPosixFilePermissions(Files.createFile(jdk.resolve("bin/java")), permissions("rwxr-xr-x"))
    val workspace = Files.createDirectories(root.resolve("workspace"))
    val env = Map("HOME" -> root.toString, "COURSIER_CACHE" -> cache.toString, "JAVA_HOME" -> jdk.toString)
    val absent = assemble(workspace, Program.Gradle, env.get, workspace)
    assert(clue(absent).left.exists(_.contains("no gradle/wrapper/gradle-wrapper.properties")))
    val properties = Files.createDirectories(workspace.resolve("gradle/wrapper")).resolve("gradle-wrapper.properties")
    Files.writeString(properties, "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.7.1-bin.zip\n")
    val unprovisioned = assemble(workspace, Program.Gradle, env.get, workspace)
    val distributionDir = root.resolve(".gradle/wrapper/dists/gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv")
    assert(clue(unprovisioned).left.exists(text => text.contains(distributionDir.toString)))
    assert(unprovisioned.left.exists(_.contains("./gradlew")))
    val gradleHome = Files.createDirectories(distributionDir.resolve("gradle-9.7.1"))
    Files.createDirectories(gradleHome.resolve("bin"))
    Files.setPosixFilePermissions(Files.createFile(gradleHome.resolve("bin/gradle")), permissions("rwxr-xr-x"))
    val assembled = assemble(workspace, Program.Gradle, env.get, workspace).fold(fail(_), identity)
    assertEquals(assembled.prereqs.executable, gradleHome.toRealPath().resolve("bin/gradle"))
    assertEquals(assembled.distribution, Some(gradleHome.toRealPath()))
    assertEquals(assembled.gradleUserHomeGranted, Some(assembled.gradleUserHome))
    assert(Files.isDirectory(assembled.gradleUserHome), "created for the program that reads it")

    // The tree is relinked elsewhere, and the state root is placed under the granted directory's target. The granted
    // directory would then resolve above the CA signing key, which its spelling never shows.
    val cacheRoot = root.resolve(".cache/ko-agent-sandbox")
    val tree = RunOnHostPrereqs.runOnHostCachesOf(cacheRoot)
    FileHelper.deleteRecursively(tree)
    Files.createSymbolicLink(tree, Files.createDirectories(root.resolve("elsewhere")))
    val granted =
      RunOnHostPrereqs.gradleUserHomeOf(cacheRoot, SandboxWorkspace.workspaceIdOf(workspace, HostCommands.Os.Mac))
    val relinked = assemble(workspace, Program.Gradle, (env + ("XDG_STATE_HOME" -> granted.toString)).get, workspace)
    assert(clue(relinked).left.exists(_.contains("overlaps the launcher's state root")))
    assert(assembled.gradleUserHome.startsWith(root.toRealPath().resolve(".cache/ko-agent-sandbox/run-on-host")))
    assertEquals(assembled.m2RepositoryGranted, None)
    assertEquals(assembled.sbtCachesGranted, Seq.empty)

  test("a prerequisite file that cannot be read is a worded refusal at the assembly, not a stack trace"):
    import java.nio.file.attribute.PosixFilePermissions.fromString as permissions
    assume(System.getProperty("user.name") != "root", "root reads everything")
    // The JVM rule accepts this Coursier layout, so the assembly reaches the program's own files.
    val root = Files.createTempDirectory("unreadable")
    val cache = Files.createDirectories(root.resolve("coursier"))
    val jdk = Files.createDirectories(cache.resolve("arc/jdk.tar.gz/jdk"))
    Files.createDirectories(jdk.resolve("bin"))
    Files.setPosixFilePermissions(Files.createFile(jdk.resolve("bin/java")), permissions("rwxr-xr-x"))
    val workspace = Files.createDirectories(root.resolve("workspace"))
    val env = Map("HOME" -> root.toString, "COURSIER_CACHE" -> cache.toString, "JAVA_HOME" -> jdk.toString)
    val mvnw = workspace.resolve("mvnw")
    Files.write(mvnw, Array[Byte]('#', '!', 0xff.toByte, '\n'))
    Files.setPosixFilePermissions(mvnw, permissions("rwxr-xr-x"))
    val invalid = assemble(workspace, Program.Mvn, env.get, workspace)
    assert(clue(invalid).left.exists(text => text.contains(mvnw.toString) && text.contains("not valid UTF-8")))

    Files.writeString(mvnw, "#!/bin/sh\nhash_string() {\n}\n")
    val properties = Files.createDirectories(workspace.resolve(".mvn/wrapper")).resolve("maven-wrapper.properties")
    Files.writeString(properties, "distributionUrl=https://example.org/apache-maven-3.9.16-bin.zip\n")
    Files.setPosixFilePermissions(properties, permissions("---------"))
    val denied = assemble(workspace, Program.Mvn, env.get, workspace)
    assert(
      clue(denied).left.exists(text => text.contains(properties.toString) && text.contains("permission denied")),
    )

  test("a forwarded value travels under a carrier name of its own"):
    assertEquals(carrierName("TOKEN"), "KO_AGENT_RUN_ON_HOST_ENV_TOKEN")

  test("--env names travel as options and come back as names; nothing else is an option"):
    assertEquals(
      forwardedNames(Seq("--env=TOKEN", ChannelLogOption + "/l", "--env=OTHER")),
      Vector("TOKEN", "OTHER"),
    )
    assertEquals(forwardedNames(Seq.empty), Vector.empty)

  test("the runner's runtime travels as three options, all or none, the daemon's port and pid with them"):
    val runtime = Runtime(Path.of("/b"), 4242, Path.of("/b/proxy-sbt-0.log"))
    assertEquals(runtimeOf(runtimeOptions(runtime) :+ "--env=TOKEN"), Right(Some(runtime)))
    assertEquals(runtime.tmp, Path.of("/b/tmp"))
    val withDaemon = runtime.copy(daemonPort = Some(51000), daemonPid = Some(4321))
    assertEquals(runtimeOf(runtimeOptions(withDaemon)), Right(Some(withDaemon)))
    assert(runtimeOf(runtimeOptions(runtime) :+ "--daemon-port=51000").isLeft)
    assert(runtimeOf(runtimeOptions(runtime) :+ "--daemon-pid=4321").isLeft)
    assert(runtimeOf(runtimeOptions(runtime) ++ Seq("--daemon-port=51000", "--daemon-pid=0")).isLeft)
    assertEquals(runtimeOf(Seq("--env=TOKEN")), Right(None))
    assert(runtimeOf(Seq("--proxy-port=4242", "--proxy-log=/l")).isLeft)
    assert(runtimeOf(Seq("--runtime-session=/b", "--proxy-port=x", "--proxy-log=/l")).isLeft)
    assert(runtimeOf(runtimeOptions(runtime) :+ "--daemon-port=x").isLeft)
    assert(runtimeOf(Seq("--daemon-port=51000")).isLeft)

  test("a mill command passes --no-daemon first under a launcher that runs without a daemon, nothing more otherwise"):
    def assembledFor(launcher: String) = Assembled(
      RunOnHostPrereqs.CommandPrereqs(Path.of("/w"), Path.of("/jdk"), Path.of("/v1"), Program.Mill, Path.of("/mill")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), Some(Path.of("/d")), Some(launcher),
    )
    val build = Path.of("/w/app")
    assertEquals(
      millCommand(build, assembledFor("1.3.0-jvm"), Seq("-k", "__.compile")),
      Seq("/w/app/mill", "--no-daemon", "-k", "__.compile"),
    )
    assertEquals(millCommand(build, assembledFor("1.1.10-jvm"), Seq("__.compile")), Seq("/w/app/mill", "__.compile"))

  test("a mill command's temporary directory is the runner's; sbt keeps its own with the runner's sockets"):
    val own = Path.of("/r/s1/tmp")
    val runners = Path.of("/r/b1/tmp")
    assertEquals(temporaryDirectories(Program.Sbt, own, runners), (own, runners))
    assertEquals(temporaryDirectories(Program.Mill, own, runners), (runners, runners))
    assertEquals(temporaryDirectories(Program.Gradle, own, runners), (runners, runners))
    assertEquals(temporaryDirectories(Program.Mvn, own, runners), (own, own))

  test("a redirected out/mill-daemon, or an entry of it with a second name, is refused; a plain one admitted"):
    val root = Files.createTempDirectory("rendezvous")
    val build = Files.createDirectory(root.resolve("build"))
    val other = Files.createDirectories(root.resolve("other/out/mill-daemon"))
    assertEquals(RunOnHostMillDaemons.rendezvousIsOwn(build), Right(()), "no out/ at all")
    val daemonDir = Files.createDirectories(build.resolve("out/mill-daemon"))
    Files.writeString(daemonDir.resolve("processId"), "1")
    assertEquals(RunOnHostMillDaemons.rendezvousIsOwn(build), Right(()), "a plain directory")
    // The checks cover an entry linked elsewhere, then the directory, then out/ itself.
    Files.createSymbolicLink(daemonDir.resolve("daemonLock"), other.resolve("daemonLock"))
    assert(RunOnHostMillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("daemonLock is a symlink")))
    Files.delete(daemonDir.resolve("daemonLock"))
    Files.createLink(daemonDir.resolve("stdout"), other.resolve("stdout").pipe(Files.writeString(_, "")))
    assert(RunOnHostMillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("more than one name")))
    Files.delete(daemonDir.resolve("stdout"))
    assertEquals(RunOnHostMillDaemons.rendezvousIsOwn(build), Right(()))
    Files.move(daemonDir, root.resolve("aside"))
    Files.createSymbolicLink(daemonDir, other)
    assert(RunOnHostMillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("mill-daemon is a symlink")))
    Files.delete(daemonDir)
    Files.move(build.resolve("out"), root.resolve("out-aside"))
    Files.createSymbolicLink(build.resolve("out"), root.resolve("other/out"))
    assert(RunOnHostMillDaemons.rendezvousIsOwn(build).swap.exists(_.contains("out is a symlink")))

  test("the starter to end is the daemon's parent in the group, other than the leader; any other topology is none"):
    import RunOnHostMillDaemons.{Member, starterOf}
    import RunOnHostSession.Record
    val leader = Record(500, "Sat Sep 12 15:42:15 2026")
    val daemonMain = "/usr/bin/java -Djava.io.tmpdir=/s/tmp mill.daemon.MillDaemonMain /p/out/mill-daemon"
    val rows = Vector(
      "  500   400 Sat Sep 12 15:42:15 2026 /usr/bin/perl -e setpgrp(0, 0) or exit 71; /s/records/daemon-mill-ab",
      "  501   500 Sat Sep 12 15:42:16 2026 /usr/bin/java -cp /dl/1.1.9 mill.launcher.MillLauncherMain version",
      s"  502   501 Sat Sep 12 15:42:19 2026 $daemonMain",
      "garbage",
    )
    val group = RunOnHostMillDaemons.parseMembers(rows, leader)
    assertEquals(group.map(_.pid), Vector(500L, 501L, 502L))
    assertEquals(group(2), Member(502, 501, "Sat Sep 12 15:42:19 2026", daemonMain))
    assertEquals(starterOf(group, leader.pgid), Some((group(2), group(1))))
    // The start time's width is the leader's, whatever ps spells. A padded day keeps the same width.
    val padded = RunOnHostMillDaemons.parseMembers(
      Vector("  500   400 Sat Sep  2 15:42:15 2026 perl", "  501   500 Sat Sep  2 15:42:16 2026 java"),
      Record(500, "Sat Sep  2 15:42:15 2026"),
    )
    assertEquals(padded.map(member => member.start -> member.command), Vector(
      "Sat Sep  2 15:42:15 2026" -> "perl", "Sat Sep  2 15:42:16 2026" -> "java",
    ))
    // A listing whose leader row does not carry the recorded start proves no width, so the result is empty.
    assertEquals(RunOnHostMillDaemons.parseMembers(rows, Record(500, "Sat Sep 12 15:42:14 2026")), Vector.empty)
    assertEquals(RunOnHostMillDaemons.parseMembers(rows.drop(1), leader), Vector.empty)
    val perl = group(0)
    val launcher = group(1)
    // The daemon's parent is the leader. The process whose start time is checked before the group is ended is never
    // signalled.
    assertEquals(starterOf(Vector(perl, Member(502, 500, "D", daemonMain)), leader.pgid), None)
    // The daemon's parent is outside the group, so the launcher attached to the daemon rather than spawning it.
    assertEquals(starterOf(Vector(perl, launcher, Member(502, 77, "D", daemonMain)), leader.pgid), None)
    // A java that does not exec leaves a daemon whose parent names DaemonMain too, whichever row comes first.
    val shim = Member(502, 501, "D", daemonMain)
    val underShim = Member(503, 502, "D2", daemonMain)
    assertEquals(starterOf(Vector(perl, launcher, underShim, shim), leader.pgid), None)
    assertEquals(starterOf(Vector(perl, launcher, shim, underShim), leader.pgid).map(_(0).pid), Some(502L))
    // No daemon runs yet.
    assertEquals(starterOf(Vector(perl, launcher), leader.pgid), None)

  test("the starter is TERMed behind the start time its group listing carries; one recycled meanwhile is not"):
    import RunOnHostMillDaemons.Member
    val root = Files.createTempDirectory("starter")
    val record = root.resolve("daemon-mill-ab")
    Files.writeString(record, "500 L\n")
    val group = Vector(
      Member(500, 1, "L", "/usr/bin/perl -e setpgrp(0, 0) or exit 71;"),
      Member(501, 500, "A", "java -cp /dl/1.1.9 mill.launcher.MillLauncherMain version"),
      Member(502, 501, "D", "java mill.daemon.MillDaemonMain /p/out/mill-daemon"),
    )
    class Fake(var alive: Map[Long, String]) extends RunOnHostSession.Processes:
      val signalled = scala.collection.mutable.ListBuffer[(Long, String)]()
      def startOf(pid: Long): Option[String] = alive.get(pid)
      def endGroup(pgid: Long): Boolean = fail(s"ended the group $pgid")
      def groupEmpty(pgid: Long): Boolean = !alive.contains(pgid)
      def signal(pid: Long, name: String): Unit = signalled += pid -> name
    val logged = scala.collection.mutable.ListBuffer[String]()
    val listens = (_: Path, pid: Long) => Option.when(pid == 502)(61210)
    def stillAlive = Fake(Map(500L -> "L", 501L -> "A", 502L -> "D"))
    // The daemon listens on the candidate port, and the launcher bears the listed start time, so one TERM goes out.
    val processes = stillAlive
    assert(RunOnHostMillDaemons.endStarter(record, root, processes, logged += _, _ => group, listens))
    assertEquals(processes.signalled.toList, List(501L -> "TERM"))
    assertEquals(logged.toList, List("TERM to the mill starter (pid 501): its daemon (pid 502) listens on port 61210"))
    logged.clear()
    // The launcher's pid is recycled after the listing was taken, during lsof or before the listing even returns. The
    // listed start time no longer holds, so endStarter signals nothing and logs nothing.
    val recycledDuringLsof = stillAlive
    val lsofRecycles = (_: Path, _: Long) => { recycledDuringLsof.alive += 501L -> "B"; Some(61210) }
    assert(!RunOnHostMillDaemons.endStarter(record, root, recycledDuringLsof, logged += _, _ => group, lsofRecycles))
    assertEquals(recycledDuringLsof.signalled.toList, Nil)
    val recycledAfterListing = stillAlive
    val listingThenRecycle = (_: RunOnHostSession.Record) => { recycledAfterListing.alive += 501L -> "B"; group }
    assert(
      !RunOnHostMillDaemons.endStarter(record, root, recycledAfterListing, logged += _, listingThenRecycle, listens),
    )
    assertEquals(recycledAfterListing.signalled.toList, Nil)
    // When the launcher is gone before the signal, or the daemon is not yet on its port, endStarter does nothing.
    val recycled = Fake(Map(500L -> "L", 502L -> "D"))
    assert(!RunOnHostMillDaemons.endStarter(record, root, recycled, logged += _, _ => group, listens))
    assert(!RunOnHostMillDaemons.endStarter(record, root, processes, logged += _, _ => group, (_, _) => None))
    assertEquals(processes.signalled.size, 1)
    assertEquals(logged.toList, Nil)

  test("mill's java-home file is read as the build's own: no link followed, the read bounded in size and time"):
    val root = Files.createTempDirectory("java-home").toRealPath()
    val build = Files.createDirectories(root.resolve("build"))
    val cache = Files.createDirectories(build.resolve("out/mill-daemon/cache"))
    val file = cache.resolve("java-home")
    val outside = Files.writeString(root.resolve("outside"), "outside")
    val elsewhere = Files.createDirectories(root.resolve("elsewhere"))
    Files.writeString(elsewhere.resolve("java-home"), "elsewhere")
    def fifo(): Boolean = ProcessBuilder("mkfifo", file.toString).start().waitFor() == 0

    assertEquals(millJavaHomeText(build), None)
    Files.writeString(file, "recorded")
    assertEquals(millJavaHomeText(build), Some("recorded"))
    // The read enforces its own bound and consults no size that the file reports.
    Files.writeString(file, "x" * (256 * 1024))
    assertEquals(millJavaHomeText(build).map(_.length), Some(256 * 1024))
    Files.writeString(file, "x" * (256 * 1024 + 1))
    assertEquals(millJavaHomeText(build), None)
    Files.write(file, Array(0xff.toByte))
    assertEquals(millJavaHomeText(build), None)

    // These are already in place when the read starts: a link for the file, a link for a directory, and a FIFO.
    Files.delete(file)
    Files.createSymbolicLink(file, outside)
    assertEquals(millJavaHomeText(build), None)
    Files.delete(file)
    Files.delete(cache)
    Files.createSymbolicLink(cache, elsewhere)
    assertEquals(millJavaHomeText(build), None)
    Files.delete(cache)
    Files.createDirectories(cache)
    assume(fifo(), "needs mkfifo")
    assertEquals(millJavaHomeText(build), None)
    Files.delete(file)

    // A command puts a link there between the type check and the open. The open refuses the link.
    Files.writeString(file, "recorded")
    val linked = millJavaHomeText(build, raced = () => { Files.delete(file); Files.createSymbolicLink(file, outside) })
    assertEquals(linked, None)
    Files.delete(file)
    // A command renames the directory away and replaces it with a link. The read stays in the directory it opened.
    Files.writeString(file, "recorded")
    val moved = root.resolve("moved")
    def redirect(): Unit =
      Files.move(cache, moved)
      Files.createSymbolicLink(cache, elsewhere)
    assertEquals(millJavaHomeText(build, raced = () => redirect()), Some("recorded"))
    Files.delete(cache)
    Files.move(moved, cache)
    // A FIFO's open does not return, so the read is abandoned, together with its thread and directories.
    // - Only a limited number of reads are abandoned at once.
    // - Past that limit, the file reads as absent, at once and without a thread, until a read returns. Here a read
    //   returns once a writer opens each FIFO.
    val readers = java.util.concurrent.Semaphore(2)
    def abandoned(index: Int): Path =
      var replaced = false
      val started = System.nanoTime
      val text = millJavaHomeText(
        build, millis = 300, raced = () => { Files.delete(file); replaced = fifo() }, readers = readers,
      )
      assert(replaced)
      assertEquals(text, None)
      assert((System.nanoTime - started) / 1_000_000 < 10_000)
      val kept = Files.move(file, root.resolve(s"fifo-$index"))
      Files.writeString(file, "recorded")
      kept
    val fifos = (1 to 2).map(abandoned)
    assertEquals(readers.availablePermits, 0)
    for _ <- 1 to 3 do
      var ran = false
      assertEquals(millJavaHomeText(build, millis = 300, raced = () => ran = true, readers = readers), None)
      assert(!ran)
    assertEquals(readers.availablePermits, 0)
    fifos.foreach: kept =>
      Thread.ofPlatform().daemon().start: () =>
        try Files.newOutputStream(kept).close()
        catch case _: java.io.IOException => ()
    val deadline = System.nanoTime + 10_000_000_000L
    while readers.availablePermits < 2 && System.nanoTime < deadline do Thread.sleep(20)
    assertEquals(readers.availablePermits, 2)
    assertEquals(millJavaHomeText(build, readers = readers), Some("recorded"))

  test("Mill's classpath file naming a path outside the granted cache is deleted; one inside, a link or none is left"):
    val build = Files.createTempDirectory("build")
    val cache = Files.createTempDirectory("cache").toRealPath()
    val classpathFile = build.resolve("out/mill-daemon/cache/mill-daemon-classpath")
    Files.createDirectories(classpathFile.getParent)
    def written(paths: String*): Unit =
      Files.writeString(classpathFile, paths.map(path => s"\"$path\"").mkString("[\"1.1.9 |\",[", ",", "]]"))
    // ChannelCheck measures the profile. Here the read and the delete are the plain ones.
    val direct = RunOnHostMillDaemons.Confined(
      read = file => Option.when(Files.isRegularFile(file))(Files.readString(file, UTF_8)),
      delete = file => Files.deleteIfExists(file),
    )
    written(s"$cache/https/repo1.maven.org/a.jar", s"$cache/https/repo1.maven.org/b.jar")
    assertEquals(RunOnHostMillDaemons.discardForeignClasspath(build, cache, direct), None)
    assert(Files.exists(classpathFile))
    written(s"$cache/https/repo1.maven.org/a.jar", "/Users/me/Library/Caches/Coursier/v1/https/repo1.maven.org/b.jar")
    val said = RunOnHostMillDaemons.discardForeignClasspath(build, cache, direct)
    assert(said.exists(_.contains("/Users/me/Library/Caches/Coursier/v1/https/repo1.maven.org/b.jar, outside")), said)
    assert(!Files.exists(classpathFile))
    // A file that is a link is not the build's own file. rendezvousIsOwn refuses the command first, and
    // discardForeignClasspath deletes nothing through the link.
    Files.createSymbolicLink(classpathFile, build.resolve("elsewhere"))
    assertEquals(RunOnHostMillDaemons.discardForeignClasspath(build, cache, direct), None)
    assert(Files.isSymbolicLink(classpathFile))
    Files.delete(classpathFile)
    assertEquals(RunOnHostMillDaemons.discardForeignClasspath(build, cache, direct), None)

  test("before each mill command without a daemon a foreign classpath file is discarded; with one, the start's"):
    val build = Files.createTempDirectory("build")
    val cache = Files.createTempDirectory("cache").toRealPath()
    val classpathFile = build.resolve("out/mill-daemon/cache/mill-daemon-classpath")
    Files.createDirectories(classpathFile.getParent)
    def foreign(): Unit =
      Files.writeString(classpathFile, "[\"1.3.0 |\",[\"/Users/me/Library/Caches/Coursier/v1/a.jar\"]]")
    val direct = RunOnHostMillDaemons.Confined(
      read = file => Option.when(Files.isRegularFile(file))(Files.readString(file, UTF_8)),
      delete = file => Files.deleteIfExists(file),
    )
    def assembledFor(launcher: String) = Assembled(
      RunOnHostPrereqs.CommandPrereqs(build, Path.of("/jdk"), cache, Program.Mill, Path.of("/mill")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), Some(Path.of("/d")), Some(launcher),
    )
    // A daemon's start discards the file (RunOnHostMillDaemons.start), so the command leaves it.
    foreign()
    assertEquals(discardForeignClasspathWithoutDaemon(assembledFor("1.1.10-jvm"), build, direct), None)
    assert(Files.exists(classpathFile))
    // Each command without a daemon checks the file again, because a host run may have rewritten it since the last
    // command.
    for _ <- 1 to 2 do
      foreign()
      val said = discardForeignClasspathWithoutDaemon(assembledFor("1.3.0-jvm"), build, direct)
      assert(said.exists(_.contains("outside")), said)
      assert(!Files.exists(classpathFile))

  test("out/'s lock is held only while another process locks it; absent, a link or no lock reads as not held"):
    val root = Files.createTempDirectory("out-lock").toRealPath()
    val build = Files.createDirectories(root.resolve("build"))
    val lock = Files.createDirectories(build.resolve("out")).resolve("mill-out-lock")
    assertEquals(millOutLockHeld(build), None)
    Files.createFile(lock)
    assertEquals(millOutLockHeld(build), Some(false))
    // Mill's own lock is an exclusive file lock that another process takes on the file.
    val holder = Files.writeString(root.resolve("HoldLock.java"),
      """import java.nio.channels.FileChannel;
        |import java.nio.file.*;
        |public class HoldLock {
        |  public static void main(String[] args) throws Exception {
        |    try (var channel = FileChannel.open(Path.of(args[0]), StandardOpenOption.WRITE);
        |         var held = channel.lock()) {
        |      System.out.println("locked");
        |      System.out.flush();
        |      System.in.read();
        |    }
        |  }
        |}
        |""".stripMargin)
    val javaExecutable = Path.of(System.getProperty("java.home"), "bin", "java").toString
    val process = ProcessBuilder(javaExecutable, holder.toString, lock.toString)
      .redirectError(ProcessBuilder.Redirect.DISCARD).start()
    try
      val said = java.io.BufferedReader(java.io.InputStreamReader(process.getInputStream, UTF_8)).readLine()
      assertEquals(said, "locked")
      assertEquals(millOutLockHeld(build), Some(true))
    finally
      process.getOutputStream.close()
      process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)
      process.destroyForcibly()
    assertEquals(millOutLockHeld(build), Some(false))
    Files.delete(lock)
    Files.createSymbolicLink(lock, Files.createFile(root.resolve("elsewhere")))
    assertEquals(millOutLockHeld(build), None)

  test("a command without a daemon waits while out/'s lock is held, then runs; past the bound it is refused"):
    val build = Path.of("/w/app")
    val logged = scala.collection.mutable.ListBuffer[String]()
    val answers = scala.collection.mutable.Queue(Some(true), Some(true), Some(false))
    assertEquals(awaitMillOutLock(build, logged.append(_), _ => answers.dequeue(), pollMillis = 1), Right(()))
    assert(answers.isEmpty)
    assertEquals(logged.size, 1, logged)
    assert(logged.head.contains("/w/app/out/mill-out-lock"), logged)
    // A lock that cannot be probed does not hold the command up, and Mill meets the lock as it is.
    assertEquals(awaitMillOutLock(build, _ => fail("no wait"), _ => None), Right(()))
    val refused = awaitMillOutLock(build, _ => (), _ => Some(true), deadlineMillis = 20, pollMillis = 1)
    assert(refused.swap.exists(_.contains("retry when its build is done")), refused)
    // The supervisor names a build that took the lock as the command started, after the command failed.
    val after = scala.collection.mutable.ListBuffer[String]()
    reportMillOutLockTaken(build, after.append(_), _ => Some(false))
    reportMillOutLockTaken(build, after.append(_), _ => None)
    assertEquals(after.toList, Nil)
    reportMillOutLockTaken(build, after.append(_), _ => Some(true))
    assert(after.exists(line => line.contains("/w/app/out/mill-out-lock") && line.contains("retry")), after)

  test("the server's command line is the thin client's: the request's launcher flags as the client forwards them"):
    val sbt = Path.of("/Users/u/Library/Application Support/Coursier/bin/sbt")
    val global = Path.of("/Users/a b/c\"d/sbt")
    def server(arguments: String*): Seq[String] =
      val line = serverCommand(sbt, global, arguments)
      assertEquals(line.take(3), sbtCommand(sbt, global) :+ s"-Dsbt.script=$sbt")
      assertEquals(line.takeRight(2), Seq("--detach-stdio", "--server"))
      line.drop(3).dropRight(2)
    // -D and a value flag reach the server. -J belongs to the client JVM, and -batch and -v belong to the client. A
    // command, with what follows it, goes over the socket.
    assertEquals(
      server("-Dprobe=1", "-J-Xmx2g", "-batch", "-mem", "512", "compile", "-v"), Seq("-Dprobe=1", "-mem", "512"),
    )
    // The empty-build flags are launcher flags even after the command, as the client treats them.
    assertEquals(server("new", "scala/scala3", "--allow-empty"), Seq("--allow-empty"))
    assertEquals(server("--sbt-create", "compile"), Seq("--sbt-create"))
    // The `=` form of a value flag splits as the client splits it, and the client's own `=` flags stay out.
    assertEquals(server("-sbt-version=2.0.8", "--color=never", "-Dx=y"), Seq("-sbt-version", "2.0.8", "-Dx=y"))
    // A flag that names a program to run never reaches the server, whatever its form.
    assertEquals(
      server("-java-home", "/x", "--sbt-jar=/y.jar", "--sbt-script", "/z", "-Dsbt.script=/w", "-v"), Seq.empty,
    )
    // The supervisor forwards a flag that the client does not know as the client forwards it.
    assertEquals(server("-sbt-launch-repo", "https://r", "-x"), Seq("-sbt-launch-repo"))

  // --------------------------------------------------------------------------
  // The proxy handshake pieces
  // --------------------------------------------------------------------------

  test("awaitProxyPort reads the bound port from the stamped ready line"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(log, "2026-08-31T01:08:25Z ko-agent-egress-proxy listening on :51234\n", UTF_8)
    assertEquals(awaitProxyPort(log, deadlineMillis = 1_000), Right(51234))

  test("awaitProxyPort is a bounded Left with what the proxy said"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(log, "rule: '+junk' is no line of the rule grammar\n", UTF_8)
    val refused = awaitProxyPort(log, deadlineMillis = 300)
    assert(refused.swap.exists(_.contains("+junk")), refused.toString)

  test("awaitProxyPort reports a proxy that ended at once, before or after its ready line"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(log, "rule: '+junk' is no line of the rule grammar\n", UTF_8)
    val started = System.nanoTime()
    val refused = awaitProxyPort(log, deadlineMillis = 10_000, ended = () => Some("exit 2"))
    assert((System.nanoTime() - started) / 1_000_000 < 5_000, "waited for the deadline")
    val reason = refused.swap.getOrElse(fail(s"a proxy that ended was ready: $refused"))
    assert(reason.startsWith("the proxy ended (exit 2) before reporting ready:\n"), reason)
    assert(reason.contains("+junk"), reason)
    Files.writeString(log, "2026-08-31T01:08:25Z ko-agent-egress-proxy listening on :51234\n", UTF_8)
    val gone = awaitProxyPort(log, deadlineMillis = 10_000, ended = () => Some("exit 2"))
    assert(gone.swap.exists(_.startsWith("the proxy ended (exit 2) after reporting ready:\n")), gone.toString)
    assertEquals(awaitProxyPort(log, deadlineMillis = 1_000, ended = () => None), Right(51234))

  test("the relaunch classpath walked from the loaders includes these classes and their deps"):
    // EmitRunOnHostProfile copies this classpath for the run-on-host checks. Inside sbt's layered loaders,
    // java.class.path is sbt's own, so the walk has to find the test classes and munit.
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

  test("selfInvocation on a JVM reruns this classpath under the private action"):
    val command = selfInvocation("--serve-proxy-on-host")
    assert(command.head.endsWith("/bin/java"), command.toString)
    assertEquals(command.last, "--serve-proxy-on-host")
    assert(command.contains("-cp"), command.toString)
    assert(command.contains("agentsandbox.launcher.AgentSandboxLauncher"), command.toString)
    // These are JVM options, so they go before the main class. The runner and the supervisor issue certificates.
    assert(command.containsSlice(CertificateBuilderExports), command.toString)
    assert(command.indexOfSlice(CertificateBuilderExports) < command.indexOf("-cp"), command.toString)
    assertEquals(
      selfInvocation("--run-command-on-host", "sbt", "/p", "/p/sub", "--").takeRight(5),
      Seq("--run-command-on-host", "sbt", "/p", "/p/sub", "--"),
    )

  test("the proxy profile's inputs on a JVM are the JDK to run and the class path to read"):
    val systemPaths = SeatbeltProfile.SystemPaths(Seq(Path.of("/usr/lib")), Seq(Path.of("/bin")))
    val inputs = proxyInputs(systemPaths).fold(fail(_), identity)
    assertEquals(inputs.executables, Seq(Path.of(System.getProperty("java.home")).toRealPath()))
    assert(inputs.reads.nonEmpty)
    assert(inputs.reads.forall(entry => Files.exists(entry) && entry.isAbsolute), inputs.reads.take(8).toString)
    assertEquals(inputs.systemPaths, systemPaths)
    // proxyInputs reads class-path entries as the JVM reads them:
    // - it skips an entry that does not exist;
    // - it resolves a relative entry against this JVM's working directory;
    // - an empty entry, including one after a trailing separator, is that working directory.
    // The proxy runs from / and needs the same entries there.
    val missing = proxyInputs(systemPaths, classPath = "/no/such/entry.jar").fold(fail(_), identity)
    assertEquals(missing.reads, Seq.empty)
    val cwd = Path.of("").toRealPath()
    val empty = proxyInputs(systemPaths, classPath = "/no/such/entry.jar:").fold(fail(_), identity)
    assertEquals(empty.reads, Seq(cwd))
    assertEquals(proxyInputs(systemPaths, classPath = "").fold(fail(_), identity).reads, Seq(cwd))
    assertEquals(proxyInputs(systemPaths, classPath = "build.sbt").fold(fail(_), identity).reads,
      Seq(cwd.resolve("build.sbt")))
    assertEquals(
      selfClassPath("target/dist/ko-agent-sandbox.jar:"),
      Seq(Path.of("").toAbsolutePath.resolve("target/dist/ko-agent-sandbox.jar").toString,
        Path.of("").toAbsolutePath.toString),
    )
    assert(proxyInputs(systemPaths, javaHome = "/no/such/jdk").isLeft)
    // launchEntry finds the launch entry by resolved path and keeps it as spelled; launchEntry records why.
    // - When the process was launched through a symlink, the entry is the link.
    // - Removing the link causes the refusal, which names the link even though its target stays.
    // - A retargeted link counts as its new target.
    val dir = Files.createTempDirectory("self")
    val real = Files.writeString(dir.resolve("real.jar"), "")
    val other = Files.writeString(dir.resolve("other.jar"), "")
    val link = Files.createSymbolicLink(dir.resolve("link.jar"), real)
    val classPath = s"${dir.resolve("unused.jar")}${java.io.File.pathSeparator}$link"
    val entry = launchEntry(classPath, Some(real))
    assertEquals(entry, Some(link))
    assertEquals(selfPresent(entry), Right(Some(real.toRealPath())))
    Files.delete(link)
    val refused = proxyInputs(systemPaths, self = entry)
    assert(refused.swap.exists(_.contains(link.toString)), refused.toString)
    Files.createSymbolicLink(link, other)
    assertEquals(selfPresent(entry), Right(Some(other.toRealPath())))
    // Code off the class path, such as this process's own code under sbt, has no entry and nothing to refuse.
    assertEquals(launchEntry(classPath, Some(dir.resolve("elsewhere.jar"))), None)
    assertEquals(selfPresent(None), Right(None))

  test("a command is refused before its supervisor runs when the launcher's executable is gone, Maven's included"):
    val root = Files.createTempDirectory("brk")
    val workspace = Files.createDirectory(root.resolve("workspace"))
    val session = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    var proxies = 0
    val systemPaths = SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty)
    val runtimes = RunnerRuntimes(session, workspace, _ => (), systemPaths, Vector.empty, FileRules.Resolved.Empty)(
      RunOnHostSession.HostProcesses,
      (_, _, _) => fail("assembled without an executable"),
      (_, _, _, _) => { proxies += 1; Right(1) },
      _ => fail("a server started without an executable"),
      _ => fail("a daemon started without an executable"),
      executable = () => Left("gone"),
    )
    for program <- Program.values do
      assertEquals(runtimes.prepare(program, workspace, Seq.empty), Left("gone"), clue = program)
    assertEquals(proxies, 0)

  test("a runtime is reused while proxy, server and portfile agree, replaced otherwise; a failed start is discarded"):
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the leader never runs under the profile")
    val root = RunOnHostSessionTest.socketSessionRoot("brk")
    val workspace = Files.createDirectory(root.resolve("workspace"))
    val session = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    val endedGroups = scala.collection.mutable.ListBuffer[Long]()
    // The server stand-in's listening sockets, keyed by the group that they belong to, since a server's socket closes
    // with its group.
    val listeners = scala.collection.mutable.Map[Path, ServerSocketChannel]()
    val socketOfGroup = scala.collection.mutable.Map[Long, Path]()
    var groupSurvives = false
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = RunOnHostSession.HostProcesses.startOf(pid)
      def endGroup(pgid: Long): Boolean =
        endedGroups += pgid
        if groupSurvives then false
        else
          socketOfGroup.remove(pgid).foreach(socket => listeners.remove(socket).foreach(_.close()))
          ProcessHandle.of(pgid).ifPresent: leader =>
            leader.descendants().forEach(_.destroyForcibly())
            leader.destroyForcibly()
          true
      def groupEmpty(pgid: Long): Boolean = ProcessHandle.of(pgid).isEmpty
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    def await(what: String)(condition: => Boolean): Unit =
      var waited = 0
      while !condition && waited < 200 do
        Thread.sleep(50)
        waited += 1
      assert(condition, what)
    // Leaders running a sleep stand where the proxy and the server would be, so the records, their exit files and the
    // groups are real leaders'. The server stand-in also listens on a socket under the session's tmp and writes the
    // portfile that names it, as a server does.
    val leaders = scala.collection.mutable.ListBuffer[Process]()
    def standIn(record: Path): Unit =
      leaders += ProcessBuilder(RunOnHostSession.registeredSpawn(record, Seq("/bin/sleep", "30"))*).start()
      await(s"$record registered")(Files.exists(record))
    var neverReady = false
    var throwsAfterRegistering = false
    var lastPort = 0
    val proxy = (_: Program, _: Vector[String], record: Path, proxyLog: Path) =>
      standIn(record)
      Files.writeString(proxyLog, "listening\n", UTF_8)
      if throwsAfterRegistering then throw java.io.IOException("log unreadable")
      lastPort = leaders.size
      if neverReady then Left("never ready") else Right(lastPort)
    val serverStarts = scala.collection.mutable.ListBuffer[RuntimeStart]()
    var serverFails = false
    var serverThrows = false
    val server = (start: RuntimeStart) =>
      serverStarts += start
      standIn(start.record)
      if serverThrows then throw IllegalStateException("boom")
      if serverFails then Left("no portfile")
      else
        val socket = RunOnHostSbtServer.expectedServerSocket(session.tmp, start.buildDirectory)
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
      RunOnHostPrereqs.CommandPrereqs(workspace, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
    )
    val logged = scala.collection.mutable.ListBuffer[String]()
    val systemPaths = SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty)
    // The daemon stand-in is a leader running a sleep. The sleep itself stands for the daemon, the process that a reuse
    // checks by pid and start time, on a port of the stand-in's choosing.
    val daemonStarts = scala.collection.mutable.ListBuffer[RuntimeStart]()
    var daemonFails = false
    var lastDaemonPid = 0L
    val daemon = (start: RuntimeStart) =>
      daemonStarts += start
      standIn(start.record)
      if daemonFails then Left("no daemon in the group")
      else
        val leader = ProcessHandle.of(RunOnHostSession.parseRecord(Files.readString(start.record, UTF_8)).get.pgid).get
        await("the sleep started")(leader.children().findFirst().isPresent)
        val sleeper = leader.children().findFirst().get.pid
        lastDaemonPid = sleeper
        val started = RunOnHostSession.HostProcesses.startOf(sleeper).get
        Right(RunOnHostMillDaemons.Daemon(sleeper, started, 40_000 + daemonStarts.size))
    var assemblies = 0
    val runtimes =
      RunnerRuntimes(session, workspace, logged.append(_), systemPaths, Vector.empty, FileRules.Resolved.Empty)(
        processes, (_, _, _) => { assemblies += 1; Right(assembled) }, proxy, server, daemon,
      )
    val dirA = Files.createDirectory(workspace.resolve("a"))
    val dirB = Files.createDirectory(workspace.resolve("b"))
    def hashOf(dir: Path) = RunOnHostSession.buildHash(dir)
    def recordOf(dir: Path, program: String = "sbt") = session.records.resolve(s"proxy-$program-${hashOf(dir)}")
    def serverOf(dir: Path) = session.records.resolve(s"server-sbt-${hashOf(dir)}")
    def buildOf(dir: Path) = RunOnHostSession.buildFile(session.directory, hashOf(dir))
    def logOf(dir: Path, program: String = "sbt") = session.directory.resolve(s"proxy-$program-${hashOf(dir)}.log")
    def portfileOf(dir: Path) = dir.resolve("project/target/active.json")
    def pgidOf(record: Path) = RunOnHostSession.parseRecord(Files.readString(record, UTF_8)).get.pgid
    // A server that exits on its own closes its socket, and its leader publishes the exit.
    def serverExits(dir: Path): Unit =
      listeners.remove(RunOnHostSbtServer.expectedServerSocket(session.tmp, dir)).foreach(_.close())
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
      assertEquals(leaders.size, 2)
      assertEquals(serverStarts.size, 1, "a later request's arguments reach no server")
      // The server exits through `shutdown` or its idle timeout, and the leader publishes the exit. The next command
      // gets a server, and the old group is ended behind its leader.
      val firstServer = pgidOf(serverOf(dirA))
      serverExits(dirA)
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("test")), current(dirA))
      assertEquals(endedGroups.toList, List(firstServer))
      assertEquals(serverStarts.size, 2)
      assert(!Files.exists(RunOnHostSession.exitRecord(serverOf(dirA))), "the replacement's record has no exit")
      assert(logged.exists(_.contains("its server is gone")), logged.toString)
      // The portfile no longer names the running server. A client would attach elsewhere or fork its own server, so
      // prepare replaces the server.
      Files.delete(portfileOf(dirA))
      val secondServer = pgidOf(serverOf(dirA))
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("test")), current(dirA))
      assertEquals(endedGroups.toList, List(firstServer, secondServer))
      assertEquals(serverStarts.size, 3)
      assert(logged.exists(_.contains("no longer names its server")), logged.toString)
      // A portfile that names a connectable socket other than this directory's derived socket does not authorize
      // reuse. Such a portfile was copied from elsewhere. The server record still lives, but prepare replaces the
      // server rather than sending this directory's client to an alien server.
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
      // A replacement whose start throws after registering is discarded like a refused replacement, and the next
      // command retries.
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
      // The proxy exits, so prepare replaces the whole runtime and ends the server first.
      val firstProxy = pgidOf(recordOf(dirA))
      val sixthServer = pgidOf(serverOf(dirA))
      ProcessHandle.of(firstProxy).get.children().forEach(_.destroyForcibly())
      await("the exit published")(Files.exists(RunOnHostSession.exitRecord(recordOf(dirA))))
      val second = runtimes.prepare(Program.Sbt, dirA, Seq("test"))
      assertEquals(second, current(dirA))
      assert(second != first, "a new proxy")
      assertEquals(endedGroups.takeRight(2).toList, List(sixthServer, firstProxy))
      // The whole group is killed. No exit is published, the leader is gone, and the record names nothing to end, but
      // prepare replaces the runtime all the same.
      val leader = ProcessHandle.of(pgidOf(recordOf(dirA))).get
      val children = leader.children().toList
      leader.destroyForcibly()
      children.forEach(_.destroyForcibly())
      await("the leader gone")(!leader.isAlive)
      val before = endedGroups.size
      val aRuntime = runtimes.prepare(Program.Sbt, dirA, Seq("test"))
      assertEquals(aRuntime, current(dirA))
      assertEquals(endedGroups.size, before + 1, "the server's group is ended; the proxy's leader gone is skipped")

      // A second build directory leaves the first warm. Each directory keeps its own proxy, server and build file, and
      // visiting one does not retire the other.
      val serversAtA = serverStarts.size
      val bRuntime = runtimes.prepare(Program.Sbt, dirB, Seq("test"))
      assertEquals(bRuntime, current(dirB))
      assert(bRuntime != aRuntime, "dirB has its own runtime")
      assertEquals(serverStarts.size, serversAtA + 1, "dirB started its own server; dirA's stayed")
      assert(Files.exists(serverOf(dirA)) && Files.exists(buildOf(dirA)), "dirA stays warm")
      assert(Files.exists(serverOf(dirB)) && Files.exists(buildOf(dirB)))
      // Revisiting each directory reuses its warm runtime, and no new server starts.
      assertEquals(runtimes.prepare(Program.Sbt, dirA, Seq("x")), aRuntime, "dirA reused")
      assertEquals(runtimes.prepare(Program.Sbt, dirB, Seq("x")), bRuntime, "dirB reused")
      assertEquals(serverStarts.size, serversAtA + 1, "reuse starts no server")

      // A fresh directory's failed starts leave no files and touch neither warm runtime. The failures are a proxy that
      // never reports ready, a server that does not come up, and a start that throws.
      val dirC = Files.createDirectory(workspace.resolve("c"))
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
      // A failed creation whose proxy group outlives its KILL keeps the record. While the group lives, prepare refuses
      // the next request before a leader could rename its record over the kept record.
      val dirD = Files.createDirectory(workspace.resolve("d"))
      neverReady = true
      groupSurvives = true
      val refused = runtimes.prepare(Program.Sbt, dirD, Seq("test"))
      assert(
        refused.swap.exists(reason => reason.startsWith("never ready; ") && reason.contains("kept for the next start")),
        refused.toString,
      )
      val keptProxy = pgidOf(recordOf(dirD))
      val leadersKept = leaders.size
      val again = runtimes.prepare(Program.Sbt, dirD, Seq("test"))
      assert(again.swap.exists(_.contains("kept for the next start")), again.toString)
      assertEquals(pgidOf(recordOf(dirD)), keptProxy, "the kept record is not renamed over")
      assertEquals(leaders.size, leadersKept, "no leader while the record is kept")
      // The group ends at last, so the record goes, and prepare retries the creation.
      groupSurvives = false
      neverReady = false
      assertEquals(runtimes.prepare(Program.Sbt, dirD, Seq("test")), current(dirD))
      assertEquals(endedGroups.takeRight(1).toList, List(keptProxy))

      // Mill's runtime is its proxy and its daemon, and the client is confined to the daemon's port. sbt and mill share
      // the directory's build file, so the build file outlives the retirement of one program's runtime while the other
      // program's records name the hash.
      val serversBefore = serverStarts.size
      def daemonOf(dir: Path) = session.records.resolve(s"daemon-mill-${hashOf(dir)}")
      def millRuntime(dir: Path) =
        Runtime(session.directory, lastPort, logOf(dir, "mill"), Some(40_000 + daemonStarts.size), Some(lastDaemonPid))
      val millA = runtimes.prepare(Program.Mill, dirA, Seq("compile"))
      assertEquals(millA, Right(Some(millRuntime(dirA))))
      assertEquals(serverStarts.size, serversBefore, "mill starts no server")
      assertEquals(daemonStarts.map(_.record).toList, List(daemonOf(dirA)))
      assert(Files.exists(recordOf(dirA, "mill")) && Files.exists(serverOf(dirA)) && Files.exists(buildOf(dirA)))
      assertEquals(runtimes.prepare(Program.Mill, dirA, Seq("test")), millA, "reused while the daemon lives")
      assertEquals(daemonStarts.size, 1)
      // prepare refuses a link that redirects the rendezvous before reuse, and the warm daemon stays untouched.
      val daemonDirA = Files.createDirectories(dirA.resolve("out")).resolve("mill-daemon")
      Files.createSymbolicLink(daemonDirA, Files.createDirectories(dirB.resolve("out/mill-daemon")))
      val redirected = runtimes.prepare(Program.Mill, dirA, Seq("test"))
      assert(redirected.swap.exists(_.contains("redirected mill daemon directory")), redirected.toString)
      Files.delete(daemonDirA)
      assertEquals(runtimes.prepare(Program.Mill, dirA, Seq("test")), millA, "reused once the link is gone")
      assertEquals(daemonStarts.size, 1)
      // The daemon exits on its own, through its idle exit, `shutdown` or the cancel that ends it, while its starter's
      // leader is still alive. prepare replaces the daemon and ends the old group.
      val firstDaemonLeader = pgidOf(daemonOf(dirA))
      val firstDaemon = ProcessHandle.of(firstDaemonLeader).get.children().findFirst().get
      firstDaemon.destroyForcibly()
      await("the daemon gone")(!firstDaemon.isAlive)
      val millA2 = runtimes.prepare(Program.Mill, dirA, Seq("test"))
      assertEquals(millA2, Right(Some(millRuntime(dirA))), "a new daemon")
      assertEquals(endedGroups.last, firstDaemonLeader)
      assertEquals(daemonStarts.size, 2)
      assert(logged.exists(_.contains("its daemon is gone")), logged.toString)
      // A change to a setting that makes Mill's launcher restart the daemon replaces the daemon. prepare ends the old
      // group and redoes the assembly before the client could meet the mismatch itself.
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
      // Gradle's runtime is its proxy, with no server and no daemon start. prepare reuses it while the proxy lives.
      val daemonsBefore = daemonStarts.size
      val gradleA = runtimes.prepare(Program.Gradle, dirA, Seq("build"))
      assertEquals(gradleA.map(_.map(_.daemonPort)), Right(Some(None)))
      assertEquals(gradleA.map(_.map(_.proxyLog)), Right(Some(logOf(dirA, "gradle"))))
      assertEquals(runtimes.prepare(Program.Gradle, dirA, Seq("test")), gradleA, "reused while the proxy lives")
      assertEquals(serverStarts.size, serversBefore, "gradle starts no server")
      assertEquals(daemonStarts.size, daemonsBefore, "gradle starts no daemon")
      // Maven's proxy belongs to the command itself.
      assertEquals(runtimes.prepare(Program.Mvn, dirA, Seq.empty), Right(None))
      // This check runs last, because it discards dirA's server. prepare does not reuse a redirected socket directory
      // as this directory's own server.
      // - The test replaces dirA's socket directory with a symlink to dirB's. dirA's portfile keeps its spelling but
      //   resolves to dirB.
      // - prepare refuses reuse and attempts a replacement start, which the stand-in fails here. The client therefore
      //   never reaches dirB's server.
      // - The socket check compares spellings, and the symlink guard catches the redirection that the spelling hides.
      val aSock = RunOnHostSbtServer.expectedServerSocket(session.tmp, dirA)
      val bSock = RunOnHostSbtServer.expectedServerSocket(session.tmp, dirB)
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
      leaders.foreach: leader =>
        leader.descendants().forEach(_.destroyForcibly())
        leader.destroyForcibly()
      session.close()
      FileHelper.deleteRecursively(root)

  test("another live runner's server is taken over by its record alone; a build file without one reserves nothing"):
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the leader never runs under the profile")
    val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
    val root = Files.createTempDirectory("owned").toRealPath()
    RunOnHostSession.ensureRoot(root, uid).getOrElse(fail("root"))
    val workspace = Files.createDirectory(root.resolve("workspace"))
    val mine = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    val peer = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    val dir = Files.createDirectory(workspace.resolve("shared"))
    val hash = RunOnHostSession.buildHash(dir)
    // The peer owns dir: the peer's build file names dir, and the peer holds a live server for the hash.
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
      def endGroup(pgid: Long): Boolean = { endedGroups += pgid; true }
      def groupEmpty(pgid: Long): Boolean = true
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(workspace, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
    )
    // The peer touched a second directory with Mill only. The peer's build file names that directory, but no
    // server-sbt record exists, so the peer reserves no sbt server there.
    val millDir = Files.createDirectory(workspace.resolve("mill-only"))
    val millHash = RunOnHostSession.buildHash(millDir)
    RunOnHostSession.publishBuildFile(peer.directory, millHash, millDir)
    // A record without a stand-in leader, like the proxy's record. The descriptor of a started runtime binds to it.
    def recordOnly(record: Path): Unit =
      Files.writeString(record, RunOnHostSession.renderRecord(RunOnHostSession.Record(1, "S")), UTF_8)
    val started = scala.collection.mutable.ListBuffer[Path]()
    val server = (start: RuntimeStart) =>
      started += start.buildDirectory
      recordOnly(start.record)
      Right(())
    val emptySystemPaths = SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty)
    val daemonStarts = scala.collection.mutable.ListBuffer[Path]()
    val daemon = (start: RuntimeStart) =>
      daemonStarts += start.buildDirectory
      recordOnly(start.record)
      Right(RunOnHostMillDaemons.Daemon(1, "S", 40_001))
    val runtimes = RunnerRuntimes(mine, workspace, _ => (), emptySystemPaths, Vector.empty, FileRules.Resolved.Empty)(
      processes,
      (_, _, _) => Right(assembled),
      (_, _, record, _) =>
        recordOnly(record)
        Right(1),
      server,
      daemon,
    )
    try
      // The peer owns the sbt server for `dir` and describes it by nothing that this launch can attach to. prepare ends
      // the group that the record names, by the recorded pgid, and this launch's server starts in its place.
      assertEquals(runtimes.prepare(Program.Sbt, dir, Seq("compile")).map(_.isDefined), Right(true))
      assertEquals(endedGroups.toList, List(peerLeader), "the recorded group, ended once")
      assert(started.contains(dir), "a server started for the taken-over directory")
      // The peer's Mill-only directory reserves no sbt server, so this launch starts sbt there and ends nothing.
      assertEquals(runtimes.prepare(Program.Sbt, millDir, Seq("compile")).map(_.isDefined), Right(true))
      assert(started.contains(millDir), "sbt started in the Mill-only directory")
      assertEquals(endedGroups.toList, List(peerLeader))
      // The daemon record carries the mill ownership. A mill command for that directory takes over the peer's
      // `daemon-mill-<hash>`, while the peer's sbt-only `dir` admits a mill command with nothing to end. The record
      // names a live group, with the peer's server's leader standing in, since a dead group's record owns nothing.
      Files.copy(peerServerRecord, peer.records.resolve(s"daemon-mill-$millHash"))
      assertEquals(
        runtimes.prepare(Program.Mill, millDir, Seq("compile")).map(_.flatMap(_.daemonPort)), Right(Some(40_001)),
      )
      assertEquals(endedGroups.toList, List(peerLeader, peerLeader))
      assert(daemonStarts.contains(millDir), "a daemon started for the taken-over directory")
      assertEquals(
        runtimes.prepare(Program.Mill, dir, Seq("compile")).map(_.flatMap(_.daemonPort)), Right(Some(40_001)),
      )
      assert(daemonStarts.contains(dir), "mill started in the sbt-owned directory")
      assertEquals(endedGroups.toList, List(peerLeader, peerLeader))
    finally
      peerServer.descendants().forEach(_.destroyForcibly())
      peerServer.destroyForcibly().waitFor()
      mine.close(); peer.close()

  test("the runner retires its own server under the retirement lock, below its monitor, and signals once"):
    // The process table that the runner and a taker share. An ended group leaves the table. While `pause` is set, the
    // end pauses between the leader's start-time check and the signal.
    class Table:
      @volatile var alive = Map.empty[Long, String]
      val ended = scala.collection.mutable.ListBuffer[Long]()
      @volatile var pause: Option[(java.util.concurrent.CountDownLatch, java.util.concurrent.CountDownLatch)] = None
    val table = Table()
    class Shared(pausing: Boolean) extends RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = table.alive.get(pid)
      def endGroup(pgid: Long): Boolean =
        if pausing then
          table.pause.foreach: (reached, proceed) =>
            reached.countDown()
            proceed.await()
        table.synchronized:
          table.ended += pgid
          table.alive -= pgid
        true
      def groupEmpty(pgid: Long): Boolean = !table.alive.contains(pgid)
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    def started[A](body: => A): java.util.concurrent.Future[A] =
      val task = java.util.concurrent.FutureTask[A](() => body)
      val thread = Thread(task)
      thread.setDaemon(true)
      thread.start()
      task
    def doneWithin(future: java.util.concurrent.Future[?], millis: Long): Boolean =
      try
        future.get(millis, java.util.concurrent.TimeUnit.MILLISECONDS)
        true
      catch case _: java.util.concurrent.TimeoutException => false
    val root = Files.createTempDirectory("brk")
    val workspace = Files.createDirectory(root.resolve("workspace"))
    val session = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(workspace, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
    )
    // The proxy and server stand-ins write their records themselves, and each record names a fresh live leader. No
    // stand-in writes a portfile, so every later sbt command replaces the server.
    var nextPid = 100L
    def register(record: Path): Long =
      nextPid += 1
      table.alive += nextPid -> s"START-$nextPid"
      val leader = RunOnHostSession.Record(nextPid, s"START-$nextPid")
      Files.writeString(record, RunOnHostSession.renderRecord(leader), UTF_8)
      nextPid
    val proxy = (_: Program, _: Vector[String], record: Path, proxyLog: Path) =>
      register(record)
      Files.writeString(proxyLog, "listening\n", UTF_8)
      Right(1)
    val server = (start: RuntimeStart) =>
      register(start.record)
      Right(())
    val systemPaths = SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty)
    val runtimes = RunnerRuntimes(session, workspace, _ => (), systemPaths, Vector.empty, FileRules.Resolved.Empty)(
      Shared(pausing = true), (_, _, _) => Right(assembled), proxy, server, _ => fail("no daemon here"),
    )
    val dirA = Files.createDirectory(workspace.resolve("a"))
    val dirB = Files.createDirectory(workspace.resolve("b"))
    val recordA = session.records.resolve(s"server-sbt-${RunOnHostSession.buildHash(dirA)}")
    def leaderA = RunOnHostSession.parseRecord(Files.readString(recordA, UTF_8)).get.pgid
    def latches() = (java.util.concurrent.CountDownLatch(1), java.util.concurrent.CountDownLatch(1))
    try
      assert(runtimes.prepare(Program.Sbt, dirA, Seq("compile")).isRight)
      val first = leaderA
      // Another holder has the retirement lock: a taker on a crashed launch's record of the same hash, paused between
      // its start-time check and its signal.
      // - The replacement waits for the lock under the monitor, and signals nothing until the lock is free.
      // - A second command, for a directory with nothing to retire, waits behind the replacement.
      // - The order is the monitor first and the retirement lock last.
      val crashed = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
      crashed.close()
      val crashedRecord = crashed.records.resolve(recordA.getFileName)
      val crashedLeader = register(crashedRecord)
      val (holderReached, holderProceed) = latches()
      table.pause = Some((holderReached, holderProceed))
      val holding = started(RunOnHostSession.endRecordedGroup(root, crashedRecord, Shared(pausing = true)))
      holderReached.await()
      table.pause = None
      val replacing = started(runtimes.prepare(Program.Sbt, dirA, Seq("test")))
      assert(!doneWithin(replacing, 300), "the replacement waits on the retirement lock")
      val other = started(runtimes.prepare(Program.Sbt, dirB, Seq("compile")))
      assert(!doneWithin(other, 300), "the monitor is held while the lock is waited for")
      assertEquals(table.ended.toList, Nil)
      holderProceed.countDown()
      assertEquals(holding.get, Some(RunOnHostSession.Collected.GroupEnded(crashedLeader)))
      assert(replacing.get.isRight && other.get.isRight)
      assertEquals(table.ended.toList, List(crashedLeader, first))
      val second = leaderA
      // The taker goes first and pauses between its start-time check and its signal. The runner's replacement waits,
      // then finds the leader gone and the group empty. The replacement skips the group without a signal and starts a
      // successor, so one signal goes out and one runtime results.
      val (takerReached, takerProceed) = latches()
      table.pause = Some((takerReached, takerProceed))
      val taking = started(RunOnHostSession.endRecordedGroup(root, recordA, Shared(pausing = true)))
      takerReached.await()
      table.pause = None
      val waiting = started(runtimes.prepare(Program.Sbt, dirA, Seq("test")))
      assert(!doneWithin(waiting, 300), "the replacement waits on the taker's lock")
      takerProceed.countDown()
      assertEquals(taking.get, Some(RunOnHostSession.Collected.GroupEnded(second)))
      assert(waiting.get.isRight)
      assertEquals(table.ended.toList, List(crashedLeader, first, second))
      val third = leaderA
      assert(table.alive.contains(third), "the successor lives behind its record")
      // The runner goes first and pauses. The taker waits, then reads what the runner left at the instant the taker
      // acquired the lock. The taker finds one of three states:
      // - the dead record, before the successor's record is published;
      // - no record;
      // - the successor's record, whose group the taker then ends as a taker would.
      // Whichever state the taker found, no group is signalled twice, and the runner's next command leaves one live
      // server. The command replaces a dead group without a signal, as an owner does after a takeover, or replaces a
      // live group under its own signal.
      val (runnerReached, runnerProceed) = latches()
      table.pause = Some((runnerReached, runnerProceed))
      val paused = started(runtimes.prepare(Program.Sbt, dirA, Seq("test")))
      runnerReached.await()
      table.pause = None
      val takingLater = started(RunOnHostSession.endRecordedGroup(root, recordA, Shared(pausing = false)))
      assert(!doneWithin(takingLater, 300), "the taker waits on the runner's lock")
      runnerProceed.countDown()
      assert(paused.get.isRight)
      val fourth = leaderA
      takingLater.get match
        case Some(RunOnHostSession.Collected.GroupEnded(g))     => assertEquals(g, fourth, "the successor, taken")
        case Some(RunOnHostSession.Collected.GroupSkipped(g, _)) => assertEquals(g, third, "the dead record")
        case None                                                => ()
        case other                                               => fail(s"the taker found $other")
      assertEquals(table.ended.toList.take(4), List(crashedLeader, first, second, third))
      assertEquals(table.ended.toList.distinct, table.ended.toList, "no group is signalled twice")
      val endedBefore = table.ended.toList
      val successorLives = table.alive.contains(fourth)
      assert(runtimes.prepare(Program.Sbt, dirA, Seq("test")).isRight)
      assertEquals(table.ended.toList, if successorLives then endedBefore :+ fourth else endedBefore)
      assert(table.alive.contains(leaderA), "one live server behind the record")
    finally session.close()

  test("the checks' entry: its teardown waits on the lock its own preparation holds, and keeps the record"):
    // One JVM runs two threads with no shared monitor: prepare on the main thread, and endSession from the shutdown
    // hook (ownRuntime). The teardown's bounded wait must neither signal nor release the holder's lock. The teardown
    // keeps the session for the next collection.
    class Table:
      @volatile var alive = Map.empty[Long, String]
      val ended = scala.collection.mutable.ListBuffer[Long]()
      @volatile var pause: Option[(java.util.concurrent.CountDownLatch, java.util.concurrent.CountDownLatch)] = None
    val table = Table()
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = table.alive.get(pid)
      def endGroup(pgid: Long): Boolean =
        table.pause.foreach: (reached, proceed) =>
          reached.countDown()
          proceed.await()
        table.synchronized:
          table.ended += pgid
          table.alive -= pgid
        true
      def groupEmpty(pgid: Long): Boolean = !table.alive.contains(pgid)
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    val root = Files.createTempDirectory("brk")
    val workspace = Files.createDirectory(root.resolve("workspace"))
    val session = RunOnHostSession.publish(root, workspace).toOption.get
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(workspace, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
    )
    var nextPid = 200L
    def register(record: Path): Unit =
      nextPid += 1
      table.alive += nextPid -> s"START-$nextPid"
      val leader = RunOnHostSession.Record(nextPid, s"START-$nextPid")
      Files.writeString(record, RunOnHostSession.renderRecord(leader), UTF_8)
    val proxy = (_: Program, _: Vector[String], record: Path, proxyLog: Path) =>
      register(record)
      Files.writeString(proxyLog, "listening\n", UTF_8)
      Right(1)
    val server = (start: RuntimeStart) =>
      register(start.record)
      Right(())
    val systemPaths = SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty)
    val runtimes = RunnerRuntimes(session, workspace, _ => (), systemPaths, Vector.empty, FileRules.Resolved.Empty)(
      processes, (_, _, _) => Right(assembled), proxy, server, _ => fail("no daemon here"),
    )
    val recordName = s"server-sbt-${RunOnHostSession.buildHash(workspace)}"
    assert(runtimes.prepare(Program.Sbt, workspace, Seq("compile")).isRight)
    val proxyName = s"proxy-sbt-${RunOnHostSession.buildHash(workspace)}"
    def leaderOf(record: Path) = RunOnHostSession.parseRecord(Files.readString(record, UTF_8)).get.pgid
    val serverLeader = leaderOf(session.records.resolve(recordName))
    val proxyLeader = leaderOf(session.records.resolve(proxyName))
    val (reached, proceed) = (java.util.concurrent.CountDownLatch(1), java.util.concurrent.CountDownLatch(1))
    table.pause = Some((reached, proceed))
    val task = java.util.concurrent.FutureTask[Either[String, Option[Runtime]]](() =>
      runtimes.prepare(Program.Sbt, workspace, Seq("test")))
    val preparing = Thread(task)
    preparing.setDaemon(true)
    preparing.start()
    reached.await()
    table.pause = None
    val teardown = RunOnHostSession.endSession(
      root, session, processes, _ => RunOnHostSession.ServerAnswer.ShutDown, retirementDeadlineMillis = 200,
    )
    val condemned = root.resolve(RunOnHostSession.CondemnedDir).resolve(session.directory.getFileName)
    // The proxy's record shares the server's lock, so both records wait and both are kept.
    assertEquals(
      teardown.collect { case RunOnHostSession.Collected.RetirementBusy(name, _) => name }.sorted,
      Vector(proxyName, recordName),
    )
    assert(Files.exists(condemned.resolve(RunOnHostSession.RecordsDir).resolve(recordName)), "the record is kept")
    assert(Files.exists(condemned.resolve(RunOnHostSession.RecordsDir).resolve(proxyName)))
    assertEquals(table.ended.toList, Nil, "the teardown signalled nothing")
    proceed.countDown()
    task.get(10, java.util.concurrent.TimeUnit.SECONDS)
    assertEquals(table.ended.toList, List(serverLeader), "the holder's signal, once")
    // The next start's scavenge collects what the teardown kept. The server's group is dead and skipped, and the
    // proxy's group lives and is ended.
    val collected =
      RunOnHostSession.scavenge(root, processes, _ => RunOnHostSession.ServerAnswer.ShutDown).flatMap(_(1))
    assertEquals(collected.collect { case RunOnHostSession.Collected.GroupSkipped(g, _) => g }, Vector(serverLeader))
    assertEquals(collected.collect { case RunOnHostSession.Collected.GroupEnded(g) => g }, Vector(proxyLeader))
    assertEquals(table.ended.toList, List(serverLeader, proxyLeader))
    assert(!Files.exists(condemned))

  /** Three launches' runners on one workspace in one JVM, over one shared process table and no real leader.
    * - `owner` starts the runtime for `dir`, `sharer` would start it alike, and `taker` forwards a value that the
    *   others do not.
    * - The proxy and the server or daemon are records with table pids. A stand-in's record names a fresh live leader.
    * - The server's socket is a listener under its session's `tmp/`, and the portfile names it.
    * - Ending a group takes its leader from the table and closes the server socket that the group held. `leaves` are
    *   the groups whose KILL leaves a member listed, together with the socket.
    * - `onEnd` runs between a group's start-time check and its signal, and `onAssemble` runs at each assembly. A test
    *   runs there what another process does meanwhile. */
  private class Runners(program: Program):
    val root: Path =
      if program == Program.Sbt then RunOnHostSessionTest.socketSessionRoot("share")
      else Files.createTempDirectory("share")
    val workspace: Path = Files.createDirectory(root.resolve("workspace"))
    val dir: Path = Files.createDirectory(workspace.resolve("app"))
    val hash: String = RunOnHostSession.buildHash(dir)
    val owner: RunOnHostSession.Session =
      RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    val sharer: RunOnHostSession.Session =
      RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    val taker: RunOnHostSession.Session =
      RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    @volatile var alive = Map.empty[Long, String]
    @volatile var leaves = Set.empty[Long]
    @volatile var members = Set.empty[Long]
    @volatile var onEnd: Long => Unit = _ => ()
    @volatile var onAssemble: () => Unit = () => ()
    val ended = scala.collection.mutable.ListBuffer[Long]()
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = alive.get(pid)
      def endGroup(pgid: Long): Boolean =
        onEnd(pgid)
        synchronized:
          ended += pgid
          alive -= pgid
          if leaves.contains(pgid) then members += pgid
          else groupSockets.get(pgid).flatMap(listeners.remove).foreach(_.close())
        !leaves.contains(pgid)
      def groupEmpty(pgid: Long): Boolean = !alive.contains(pgid) && !members.contains(pgid)
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    /** The member that a KILL left in the group exits, and the socket that it held closes with it. */
    def memberExits(pgid: Long): Unit = synchronized:
      members -= pgid
      groupSockets.get(pgid).flatMap(listeners.remove).foreach(_.close())
    private var nextPid = 300L
    def register(record: Path): Long = synchronized:
      nextPid += 1
      alive += nextPid -> s"START-$nextPid"
      val leader = RunOnHostSession.Record(nextPid, s"START-$nextPid")
      Files.writeString(record, RunOnHostSession.renderRecord(leader), UTF_8)
      nextPid
    val listeners = scala.collection.mutable.Map[Path, ServerSocketChannel]()
    @volatile var groupSockets = Map.empty[Long, Path]
    /** A server of `session`'s for `directory`: a listener at the socket that sbt derives under the session's `tmp/`,
      * which the directory's portfile names. */
    def listen(session: RunOnHostSession.Session, directory: Path = dir): Unit =
      val socket = RunOnHostSbtServer.expectedServerSocket(session.tmp, directory)
      Files.createDirectories(socket.getParent)
      listeners.remove(socket).foreach(_.close())
      Files.deleteIfExists(socket)
      val listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
      listener.bind(UnixDomainSocketAddress.of(socket))
      listeners(socket) = listener
      writePortfile(directory, socket)
    def listening(session: RunOnHostSession.Session, directory: Path = dir): Boolean =
      listeners.get(RunOnHostSbtServer.expectedServerSocket(session.tmp, directory)).exists(_.isOpen)
    /** The owner's server exits on its own: its socket closes with it, and its leader publishes the exit. */
    def serverExits(): Unit =
      listeners.remove(RunOnHostSbtServer.expectedServerSocket(owner.tmp, dir)).foreach(_.close())
      Files.writeString(RunOnHostSession.exitRecord(owner.records.resolve(s"server-sbt-$hash")), "0\n", UTF_8)
    def assembled(jdk: String = "/jdk"): Assembled =
      Assembled(
        RunOnHostPrereqs.CommandPrereqs(workspace, Path.of(jdk), Path.of("/v1"), program, Path.of("/exe")),
        None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
      )
    val systemPaths: SeatbeltProfile.SystemPaths = SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty)
    /** Every server and daemon start, identified by its record. */
    val started = scala.collection.mutable.ListBuffer[Path]()
    val serverArguments = scala.collection.mutable.ListBuffer[Seq[String]]()
    var daemonPid = 0L
    def port(session: RunOnHostSession.Session): Int =
      if session == owner then 7001 else if session == sharer then 7002 else 7003
    def runner(session: RunOnHostSession.Session, jdk: String = "/jdk"): RunnerRuntimes =
      val forwards = if session == taker then Vector("TOKEN" -> "t") else Vector.empty
      RunnerRuntimes(session, workspace, _ => (), systemPaths, forwards, FileRules.Resolved.Empty)(
        processes,
        (_, _, _) =>
          onAssemble()
          Right(assembled(jdk)),
        (_, _, record, proxyLog) =>
          register(record)
          Files.writeString(proxyLog, "listening\n", UTF_8)
          Right(port(session)),
        start =>
          started += start.record
          serverArguments += start.arguments
          val leader = register(start.record)
          listen(session, start.buildDirectory)
          groupSockets += leader -> RunOnHostSbtServer.expectedServerSocket(session.tmp, start.buildDirectory)
          Right(()),
        start =>
          started += start.record
          register(start.record)
          daemonPid = register(start.record.resolveSibling("daemon-pid-scratch"))
          Files.delete(start.record.resolveSibling("daemon-pid-scratch"))
          Right(RunOnHostMillDaemons.Daemon(daemonPid, s"START-$daemonPid", 40_001)),
      )
    def descriptor(session: RunOnHostSession.Session): Path =
      RunOnHostRuntimeDescriptor.file(session.directory, program, hash)
    def record(session: RunOnHostSession.Session, name: String): RunOnHostSession.Record =
      RunOnHostSession.parseRecord(Files.readString(session.records.resolve(name), UTF_8)).get
    def serverLeader(session: RunOnHostSession.Session): Long = record(session, s"server-sbt-$hash").pgid
    def daemonLeader(session: RunOnHostSession.Session): Long = record(session, s"daemon-mill-$hash").pgid
    def recordNames(session: RunOnHostSession.Session): List[String] =
      FileHelper.directoryEntries(session.records).map(_.getFileName.toString).toList.sorted
    /** The runtime that a prepare should give `session`'s commands, whether its own or one it attached to. With a
      * daemon, the runtime is the one that the stub started last. */
    def runtime(session: RunOnHostSession.Session, daemonPort: Option[Int] = None): Either[String, Option[Runtime]] =
      val proxyLog = session.directory.resolve(s"proxy-${program.name}-$hash.log")
      Right(Some(Runtime(session.directory, port(session), proxyLog, daemonPort, daemonPort.map(_ => daemonPid))))
    def refusal(prepared: Either[String, Option[Runtime]], why: String*): Unit =
      prepared match
        case Left(reason) => why.foreach(word => assert(reason.contains(word), s"'$word' in: $reason"))
        case other        => fail(s"attached, or started, instead of refusing for '${why.mkString(", ")}': $other")
    def close(): Unit =
      listeners.values.foreach(_.close())
      owner.close(); sharer.close(); taker.close()
      FileHelper.deleteRecursively(root)

  def inThread[A](body: => A): java.util.concurrent.Future[A] =
    val task = java.util.concurrent.FutureTask[A](() => body)
    val thread = Thread(task)
    thread.setDaemon(true)
    thread.start()
    task

  def doneWithin(future: java.util.concurrent.Future[?], millis: Long): Boolean =
    try
      future.get(millis, java.util.concurrent.TimeUnit.MILLISECONDS)
      true
    catch case _: java.util.concurrent.TimeoutException => false

  test("a second launch attaches to another launch's sbt server it would start alike, and takes over one it would not"):
    val two = Runners(Program.Sbt)
    import two.*
    val proxyName = s"proxy-sbt-$hash"
    val serverName = s"server-sbt-$hash"
    try
      val owning = runner(owner)
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("-Dmode=A", "compile")), runtime(owner))
      val published = RunOnHostRuntimeDescriptor.read(descriptor(owner)).getOrElse(fail("no descriptor"))
      assertEquals(published.proxy, record(owner, proxyName), "bound to the proxy's record")
      assertEquals(published.group, record(owner, serverName), "bound to the server's record")
      assertEquals(published.daemon, None)
      // The sharer attaches to the owner's session, port and log, and records nothing of its own. The comparison leaves
      // out the launcher flags of the sharer's request, because the server keeps the flags it was started with, as it
      // does for the owner's later commands (RunOnHostRuntimeDescriptor.fingerprint).
      val sharing = runner(sharer)
      assertEquals(sharing.prepare(Program.Sbt, dir, Seq("-Dmode=B", "test")), runtime(owner))
      assertEquals(sharing.prepare(Program.Sbt, dir, Seq("test")), runtime(owner), "asked again, attached again")
      assertEquals(serverArguments.toList, List(Seq("-Dmode=A", "compile")), "the server's flags are the owner's")
      assertEquals(recordNames(sharer), Nil, "the sharer recorded nothing")
      assert(!Files.exists(RunOnHostSession.buildFile(sharer.directory, hash)), "and published no build file")
      // A rule line appears that the owner did not start from, so the sharer would start another proxy.
      // - The sharer ends the owner's server by its record and starts its own server, which it records and describes.
      //   The sharer leaves the owner's record to the owner and leaves the owner's proxy untouched.
      // - With the line gone, the owner's would-be start differs from the sharer's, so the owner's next command takes
      //   the server back. The sharer, alike again, attaches to that server.
      val firstServer = serverLeader(owner)
      val rule = workspace.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
      Files.createDirectories(rule.getParent)
      Files.writeString(rule, "allow https://example.org/ read\n", UTF_8)
      assertEquals(sharing.prepare(Program.Sbt, dir, Seq("-Dmode=B", "test")), runtime(sharer))
      assertEquals(ended.toList, List(firstServer))
      assertEquals(recordNames(sharer), List(proxyName, serverName))
      assert(Files.exists(descriptor(sharer)) && listening(sharer) && !listening(owner))
      assert(Files.exists(owner.records.resolve(serverName)) && alive.contains(record(owner, proxyName).pgid))
      Files.delete(rule)
      val sharerServer = serverLeader(sharer)
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      assertEquals(ended.toList, List(firstServer, sharerServer))
      assertEquals(started.size, 3)
      assertEquals(sharing.prepare(Program.Sbt, dir, Seq("test")), runtime(owner), "alike again")
      assertEquals(started.size, 3)
      // A forwarded value makes the taker and the owner differ for good, so they alternate. Each command ends the other
      // launch's server and starts its own under its own proxy.
      val taking = runner(taker)
      val secondServer = serverLeader(owner)
      assertEquals(taking.prepare(Program.Sbt, dir, Seq("-Dmode=C", "compile")), runtime(taker))
      assertEquals(ended.toList, List(firstServer, sharerServer, secondServer))
      val takerServer = serverLeader(taker)
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      assertEquals(ended.toList, List(firstServer, sharerServer, secondServer, takerServer))
      assertEquals(taking.prepare(Program.Sbt, dir, Seq("test")), runtime(taker))
      val thirdServer = serverLeader(taker)
      assertEquals(ended.size, 5)
      // A KILL leaves a member listed.
      // - prepare refuses the owner's command, naming the record, after signalling it once.
      // - The taker's next command reuses the taker's server, whose group still lives.
      // - Once the taker's own replacement finds the leader gone with a member listed, prepare keeps the taker's record
      //   and refuses the start until the member is gone too.
      leaves += thirdServer
      refusal(owning.prepare(Program.Sbt, dir, Seq("test")), "another launch's runner", "not ended", "after the KILL")
      assertEquals(ended.size, 6)
      assert(Files.exists(taker.records.resolve(serverName)), "the taker's record survives the failed takeover")
      assert(!Files.exists(owner.records.resolve(serverName)), "the owner's dead record was discarded first")
      leaves -= thirdServer
      refusal(
        taking.prepare(Program.Sbt, dir, Seq("test")), "kept for the next start to retry", "a member still listed",
      )
      assertEquals(ended.size, 6)
      memberExits(thirdServer)
      assertEquals(taking.prepare(Program.Sbt, dir, Seq("test")), runtime(taker), "replaced once the group is empty")
      assertEquals(ended.size, 6)
      // The owner's server exits on its own. The sharer takes over what is left, the leader, and starts its own server.
      // A descriptor of a replaced server, restored over the successor's descriptor, names other records than the
      // present ones, and the sharer takes it over too.
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      val stale = Files.readString(descriptor(owner), UTF_8)
      serverExits()
      val exitedLeader = serverLeader(owner)
      assertEquals(sharing.prepare(Program.Sbt, dir, Nil), runtime(sharer))
      assertEquals(ended.takeRight(2).toList, List(serverLeader(taker), exitedLeader))
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      Files.writeString(descriptor(owner), stale, UTF_8)
      assertEquals(sharing.prepare(Program.Sbt, dir, Nil), runtime(sharer))
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      // The owner's session moves into condemned/ between its lookup and the takeover's read. The takeover looks the
      // record up once more where it is now and ends the group there.
      val condemned = Files.createDirectories(root.resolve(RunOnHostSession.CondemnedDir))
        .resolve(owner.directory.getFileName)
      val movingServer = serverLeader(owner)
      onAssemble = () =>
        if Files.exists(owner.directory) then
          Files.move(owner.directory, condemned, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
      assertEquals(sharing.prepare(Program.Sbt, dir, Nil), runtime(sharer))
      assertEquals(ended.last, movingServer)
      assertEquals(ended.toList.distinct, ended.toList, "no group is signalled twice")
    finally close()

  test("the owner's teardown against a taker: the taker waits on the lock, and the group is signalled once"):
    val two = Runners(Program.Sbt)
    import two.*
    try
      assertEquals(runner(owner).prepare(Program.Sbt, dir, Seq("compile")), runtime(owner))
      val ownerServer = serverLeader(owner)
      val reached = java.util.concurrent.CountDownLatch(1)
      val proceed = java.util.concurrent.CountDownLatch(1)
      onEnd = pgid =>
        if pgid == ownerServer then
          reached.countDown()
          proceed.await()
      val teardown = inThread(
        RunOnHostSession.endSession(root, owner, processes, _ => RunOnHostSession.ServerAnswer.ShutDown),
      )
      reached.await()
      // The teardown has checked the leader's start time and holds the lock. The taker finds the owner in condemned/
      // and waits rather than checking and signalling the same group.
      val taking = inThread(runner(taker).prepare(Program.Sbt, dir, Seq("compile")))
      assert(!doneWithin(taking, 300), "the taker waits on the lock")
      proceed.countDown()
      assert(teardown.get.contains(RunOnHostSession.Collected.GroupEnded(ownerServer)))
      assertEquals(taking.get, runtime(taker))
      assertEquals(ended.count(_ == ownerServer), 1, "one signal")
      val condemned = root.resolve(RunOnHostSession.CondemnedDir).resolve(owner.directory.getFileName)
      assert(!Files.exists(owner.directory) && !Files.exists(condemned), "the owner's session is collected")
    finally
      listeners.values.foreach(_.close())
      sharer.close(); taker.close()
      FileHelper.deleteRecursively(root)

  test("a takeover ends the recorded group, never what the portfile or a planted link leads to"):
    val two = Runners(Program.Sbt)
    import two.*
    val other = Files.createDirectory(workspace.resolve("lib"))
    try
      val owning = runner(owner)
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("compile")), runtime(owner))
      assert(owning.prepare(Program.Sbt, other, Seq("compile")).isRight)
      val otherServer = RunOnHostSession.parseRecord(
        Files.readString(owner.records.resolve(s"server-sbt-${RunOnHostSession.buildHash(other)}"), UTF_8),
      ).get.pgid
      val otherSocket = RunOnHostSbtServer.expectedServerSocket(owner.tmp, other)
      // `dir`'s portfile names the other directory's live socket. The takeover ends the group that `dir`'s record
      // names, and the start that follows refuses the live foreign socket that the portfile leads to (noForeignServer).
      // The other server is never signalled.
      val taking = runner(taker)
      writePortfile(dir, otherSocket)
      val first = serverLeader(owner)
      val foreignSocket = "a live sbt server holds this build directory's portfile"
      refusal(taking.prepare(Program.Sbt, dir, Seq("compile")), foreignSocket)
      assertEquals(ended.filter(_ == otherServer).toList, Nil)
      assertEquals(ended.filter(_ == first).toList, List(first))
      assert(listening(owner, other))
      // The owner's next command starts a fresh server under its proxy and rewrites the portfile.
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      // During the takeover's end of the group, a command plants a link at the owner's socket directory for `dir`, and
      // the link leads to the other server. The ended group is the record's, and the start that follows refuses the
      // link's live socket as any start does.
      val second = serverLeader(owner)
      val socketDir = RunOnHostSbtServer.expectedServerSocket(owner.tmp, dir).getParent
      onEnd = pgid =>
        if pgid == second then
          listeners.remove(RunOnHostSbtServer.expectedServerSocket(owner.tmp, dir)).foreach(_.close())
          FileHelper.directoryEntries(socketDir).foreach(Files.delete)
          Files.delete(socketDir)
          Files.createSymbolicLink(socketDir, otherSocket.getParent)
      refusal(taking.prepare(Program.Sbt, dir, Seq("compile")), foreignSocket)
      assertEquals(ended.filter(_ == otherServer).toList, Nil, "the other server is never signalled")
      assertEquals(ended.filter(_ == second).toList, List(second))
      assert(listening(owner, other))
      Files.delete(socketDir)
    finally close()

  test("a mill launcher that runs without a daemon gets its proxy alone; a version change starts or ends the daemon"):
    @volatile var alive = Map.empty[Long, String]
    val ended = scala.collection.mutable.ListBuffer[Long]()
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = alive.get(pid)
      def endGroup(pgid: Long): Boolean =
        ended += pgid
        alive -= pgid
        true
      def groupEmpty(pgid: Long): Boolean = !alive.contains(pgid)
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    var nextPid = 500L
    def register(record: Path): Long =
      nextPid += 1
      alive += nextPid -> s"START-$nextPid"
      val leader = RunOnHostSession.Record(nextPid, s"START-$nextPid")
      Files.writeString(record, RunOnHostSession.renderRecord(leader), UTF_8)
      nextPid
    val root = Files.createTempDirectory("nodaemon")
    val workspace = Files.createDirectory(root.resolve("workspace"))
    val dir = Files.createDirectory(workspace.resolve("app"))
    val session = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    try
      // The assembly follows the build directory's pin, as the real assembly does.
      def pinned = Files.readString(dir.resolve(".mill-version"), UTF_8).trim
      val assemble = (_: Path, _: Program, _: Path) =>
        Right(Assembled(
          RunOnHostPrereqs.CommandPrereqs(workspace, Path.of("/jdk"), Path.of("/v1"), Program.Mill, Path.of("/mill")),
          None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), Some(Path.of("/d")),
          Some(s"$pinned-jvm"),
        ))
      val proxy = (_: Program, _: Vector[String], record: Path, proxyLog: Path) =>
        register(record)
        Files.writeString(proxyLog, "listening\n", UTF_8)
        Right(7000)
      val daemonStarts = scala.collection.mutable.ListBuffer[Path]()
      val daemon = (start: RuntimeStart) =>
        daemonStarts += start.record
        val leader = register(start.record)
        val pid = register(Files.createTempFile(root, "daemon", ".record"))
        Right(RunOnHostMillDaemons.Daemon(pid, s"START-$pid", 40_000 + leader.toInt))
      val runtimes =
        RunnerRuntimes(session, workspace, _ => (), SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty), Vector.empty,
          FileRules.Resolved.Empty)(processes, assemble, proxy, _ => fail("no sbt server here"), daemon)
      val hash = RunOnHostSession.buildHash(dir)
      val proxyLog = session.directory.resolve(s"proxy-mill-$hash.log")
      val daemonRecord = session.records.resolve(s"daemon-mill-$hash")
      val proxyAlone = Right(Some(Runtime(session.directory, 7000, proxyLog)))

      Files.writeString(dir.resolve(".mill-version"), "1.3.0\n", UTF_8)
      assertEquals(runtimes.prepare(Program.Mill, dir, Seq("compile")), proxyAlone)
      assertEquals(runtimes.prepare(Program.Mill, dir, Seq("test")), proxyAlone, "reused")
      assertEquals(daemonStarts.toList, Nil)
      assert(!Files.exists(daemonRecord))

      // A pin of a launcher that keeps the daemon starts a daemon under the same proxy.
      Files.writeString(dir.resolve(".mill-version"), "1.1.10\n", UTF_8)
      val withDaemon = runtimes.prepare(Program.Mill, dir, Seq("compile"))
      assertEquals(daemonStarts.toList, List(daemonRecord))
      assert(withDaemon.exists(_.exists(_.daemonPort.isDefined)), withDaemon.toString)
      assertEquals(withDaemon.map(_.map(_.proxyPort)), Right(Some(7000)), "the same proxy")
      val daemonLeader = RunOnHostSession.parseRecord(Files.readString(daemonRecord, UTF_8)).get.pgid

      // Back on a launcher without a daemon, prepare ends the daemon's group and removes its record, and no daemon
      // starts.
      Files.writeString(dir.resolve(".mill-version"), "1.3.0\n", UTF_8)
      assertEquals(runtimes.prepare(Program.Mill, dir, Seq("compile")), proxyAlone)
      assertEquals(ended.toList, List(daemonLeader))
      assert(!Files.exists(daemonRecord))
      assertEquals(daemonStarts.size, 1)
    finally session.close()

  test("a second launch attaches to another launch's mill daemon under the directory's configuration, else takes over"):
    val two = Runners(Program.Mill)
    import two.*
    try
      val owning = runner(owner)
      assertEquals(owning.prepare(Program.Mill, dir, Seq("compile")), runtime(owner, Some(40_001)))
      val published = RunOnHostRuntimeDescriptor.read(descriptor(owner)).getOrElse(fail("no descriptor"))
      assertEquals(published.daemon, Some(RunOnHostMillDaemons.Daemon(daemonPid, s"START-$daemonPid", 40_001)))
      val sharing = runner(sharer)
      assertEquals(sharing.prepare(Program.Mill, dir, Seq("test")), runtime(owner, Some(40_001)))
      assertEquals(recordNames(sharer), Nil)
      // After a configuration edit, the daemon no longer matches the directory, so the sharer ends the daemon's starter
      // group and starts its own daemon under the new configuration. The owner's own daemon is gone, and its would-be
      // start is now the sharer's, so the owner's next command attaches.
      Files.writeString(dir.resolve(".mill-jvm-opts"), "-Xmx1g\n", UTF_8)
      val firstStarter = daemonLeader(owner)
      assertEquals(sharing.prepare(Program.Mill, dir, Nil), runtime(sharer, Some(40_001)))
      assertEquals(ended.toList, List(firstStarter))
      assertEquals(started.size, 2)
      assertEquals(owning.prepare(Program.Mill, dir, Seq("test")), runtime(sharer, Some(40_001)))
      assertEquals(started.size, 2)
      assertEquals(recordNames(owner), List(s"proxy-mill-$hash"), "the owner's dead record discarded, its proxy kept")
      // The daemon exits, through its idle exit or a cancel, while its starter's leader stays. The owner's command
      // takes over what is left and starts its own daemon.
      val sharerStarter = daemonLeader(sharer)
      alive -= daemonPid
      assertEquals(owning.prepare(Program.Mill, dir, Seq("test")), runtime(owner, Some(40_001)))
      assertEquals(ended.toList, List(firstStarter, sharerStarter))
      assertEquals(started.size, 3)
    finally close()

  test("after a gradle command the runner records the launch's daemons; after any other program nothing"):
    val root = Files.createTempDirectory("brk")
    val workspace = Files.createDirectory(root.resolve("workspace"))
    val session = RunOnHostSession.publish(root, workspace, RunOnHostSession.Kind.Runner).toOption.get
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = Option.when(pid == 4242)("S")
      def endGroup(pgid: Long): Boolean = true
      def groupEmpty(pgid: Long): Boolean = true
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    val observed = scala.collection.mutable.ListBuffer[Path]()
    val logged = scala.collection.mutable.ListBuffer[String]()
    val runtimes = RunnerRuntimes(
      session, workspace, logged.append(_), SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty), Vector.empty,
      FileRules.Resolved.Empty,
    )(
      processes = processes,
      gradleDaemons = base =>
        observed += base
        Vector(4242L -> "S"),
    )
    try
      val record = session.records.resolve(RunOnHostGradleDaemons.recordName(4242))
      runtimes.commandEnded(Program.Sbt)
      runtimes.commandEnded(Program.Mvn)
      assert(observed.isEmpty, "only a gradle command has daemons to observe")
      runtimes.commandEnded(Program.Gradle)
      // The observed registry is the launch's, under this session's tmp, and the record holds the pid's start time.
      assertEquals(observed.toList, List(session.tmp))
      assertEquals(Files.readString(record, UTF_8), "4242 S\n")
      assertEquals(logged.toList, List("recorded the gradle daemon 4242"))
    finally session.close()

  test("unwritableProxyLog is the proxy's own reason after a failed log write, and nothing from a proxy still logging"):
    import agentsandbox.egress.{AgentEgressProxy, RulesetHelper, TransportHelper}
    def asked(failure: Option[java.io.IOException]): Option[String] =
      val resolved = RulesetHelper.resolveRuleset(Some("deny-unless-allowed"), None, None)
      val run = AgentEgressProxy.Run(resolved, None, TransportHelper.Direct, () => failure)
      val listening =
        try Some(java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress))
        catch case _: java.net.SocketException => None
      assume(
        listening.nonEmpty, "needs a TCP listener, which sbt run on the host is not granted; the container's sbt is",
      )
      scala.util.Using.resource(listening.get): server =>
        val saved = System.err
        System.setErr(java.io.PrintStream(java.io.OutputStream.nullOutputStream()))
        val serving = Thread.startVirtualThread(() => AgentEgressProxy.handle(server.accept(), run))
        try unwritableProxyLog(server.getLocalPort)
        finally
          serving.join()
          System.setErr(saved)
    assertEquals(
      asked(Some(java.io.IOException("No space left on device"))),
      Some("audit log cannot be written: No space left on device"),
    )
    assertEquals(asked(None), None)

  test("deniedHosts reads the audit log's deny lines, once per host"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(
      log,
      """2026-08-31T01:08:25Z ko-agent-egress-proxy listening on :51234
        |2026-08-31T01:08:25Z deny example.com CONNECT host not allowed
        |2026-08-31T01:08:26Z allow repo1.maven.org CONNECT -> 151.101.0.209
        |2026-08-31T01:08:27Z deny example.com CONNECT host not allowed
        |""".stripMargin,
      UTF_8,
    )
    assertEquals(deniedHosts(log), Vector("example.com"))
    assertEquals(deniedHosts(log.resolveSibling("absent")), Vector.empty)
    // Read from an offset, the log yields what a command added to the runner's log, without an earlier command's lines.
    val before = Files.size(log)
    assertEquals(deniedHosts(log, before), Vector.empty)
    Files.writeString(log, "2026-08-31T01:08:28Z deny other.example CONNECT host not allowed\n", UTF_8,
      java.nio.file.StandardOpenOption.APPEND)
    assertEquals(deniedHosts(log, before), Vector("other.example"))
    assertEquals(deniedHosts(log, before + 1_000_000), Vector.empty)

  test("refusedRequests reads the requests denied inside a tunnel, once each"):
    val log = Files.createTempDirectory("proxy").resolve("proxy.log")
    Files.writeString(
      log,
      """2026-08-31T01:08:25Z deny example.com CONNECT host not allowed
        |2026-08-31T01:08:26Z allow repo1.maven.org GET /maven2/a.pom -> 151.101.0.209
        |2026-08-31T01:08:27Z deny repo1.maven.org PUT /maven2/a.pom PUT not granted
        |2026-08-31T01:08:28Z deny repo1.maven.org PUT /maven2/a.pom PUT not granted
        |2026-08-31T01:08:29Z deny repo1.maven.org - - malformed request line
        |2026-08-31T01:08:30Z deny repo1.maven.org GET /maven2/b.pom request body framing header
        |2026-08-31T01:08:31Z deny r.example GET https://r.example/x only origin-form request targets are allowed
        |2026-08-31T01:08:32Z deny repo1.maven.org POST /up id=3 invalid chunk size
        |2026-08-31T01:08:33Z deny repo1.maven.org POST /up id=4 invalid chunk size
        |""".stripMargin,
      UTF_8,
    )
    val put = RefusedRequest("PUT", "repo1.maven.org", "/maven2/a.pom", "PUT not granted")
    val framed = RefusedRequest("GET", "repo1.maven.org", "/maven2/b.pom", "request body framing header")
    val absolute =
      RefusedRequest("GET", "r.example", "https://r.example/x", "only origin-form request targets are allowed")
    val chunking = RefusedRequest("POST", "repo1.maven.org", "/up", "invalid chunk size")
    // A refused CONNECT has no target, and the first word of its reason is not a target.
    assertEquals(refusedRequests(log), Vector(put, framed, absolute, chunking))
    assertEquals(put.spelled, "PUT https://repo1.maven.org/maven2/a.pom")
    assertEquals(absolute.spelled, "GET https://r.example/x (r.example)")
    assertEquals(deniedHosts(log), Vector("example.com"))
    assertEquals(refusedRequests(log, Files.size(log)), Vector.empty)
    // The report has two kinds: the command corrects the framing refusal, and the user corrects the PUT.
    import agentsandbox.egress.RefusalAdvice
    assertEquals(RefusalAdvice.requestStep(framed.reason), Some(RefusalAdvice.bodyFramingHeader))
    assertEquals(RefusalAdvice.requestStep(absolute.reason), Some(RefusalAdvice.originForm))
    assertEquals(RefusalAdvice.requestStep(put.reason), None)
    assert(RefusalAdvice.grantRefused(put.reason) && !RefusalAdvice.grantRefused(framed.reason))
    // Each part of the report starts on a line of its own, whatever the command's last line ended with.
    val reported = Vector.newBuilder[String]
    reportDenied(log, 0, Program.Sbt, reported += _)
    val parts = reported.result()
    assertEquals(parts.size, 2)
    assert(parts.forall(_.startsWith("\nCommand ")), parts.toString)

  // --------------------------------------------------------------------------
  // The live server a portfile names
  // --------------------------------------------------------------------------

  def workspaceWithPortfile(socket: Path): Path =
    val workspace = Files.createTempDirectory("portfile")
    Files.createDirectories(workspace.resolve("project/target"))
    Files.writeString(
      workspace.resolve("project/target/active.json"),
      s"""{"uri":"local://$socket"}""",
      UTF_8,
    )
    workspace

  test("a connectable portfile socket is a live server; a dead or absent one is not"):
    val socket = Files.createTempDirectory("srv").resolve("sock")
    val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    server.bind(UnixDomainSocketAddress.of(socket))
    try
      assertEquals(livePortfileServer(workspaceWithPortfile(socket)), Some(socket))
    finally server.close()
    Files.delete(socket)
    assertEquals(livePortfileServer(workspaceWithPortfile(socket)), None, "gone is not live")
    assertEquals(livePortfileServer(Files.createTempDirectory("bare")), None, "no portfile")

  // --------------------------------------------------------------------------
  // The target/ link sweep
  // --------------------------------------------------------------------------

  test("foreign and dangling target links are swept with the store's links beside them; others stay"):
    val workspace = Files.createTempDirectory("sweep")
    val foreignStore = Files.createTempDirectory("foreign-store")
    val sbtGlobal = Files.createTempDirectory("sbt-global")
    val target = Files.createDirectories(workspace.resolve("sub/target/out"))
    val clean = Files.createDirectories(workspace.resolve("other/target/out"))
    val ours = Files.writeString(sbtGlobal.resolve("ours"), "")
    val foreign = Files.writeString(foreignStore.resolve("theirs"), "")
    val source = Files.writeString(workspace.resolve("source"), "")

    Files.createSymbolicLink(target.resolve("foreign.zip"), foreign)
    Files.createSymbolicLink(target.resolve("dangling.zip"), foreignStore.resolve("gone"))
    // A class file that sbt restored into the command's own store, beside the foreign links: a compile without the
    // swept analysis would write through it (sbt/sbt#9968).
    Files.createSymbolicLink(Files.createDirectories(target.resolve("classes")).resolve("A.class"), ours)
    Files.createSymbolicLink(target.resolve("intra"), source)
    // A tree with no foreign link keeps its store links: its analysis stays.
    Files.createSymbolicLink(clean.resolve("B.class"), ours)
    Files.createSymbolicLink(workspace.resolve("outside-target"), foreign)
    val git = Files.createDirectories(workspace.resolve(".git/target"))
    Files.createSymbolicLink(git.resolve("untouchable"), foreign)

    val removed = cleanForeignTargetLinks(workspace, Seq(workspace, sbtGlobal), Seq(sbtGlobal))
    assertEquals(
      removed.map(_.getFileName.toString).sorted,
      Vector("A.class", "dangling.zip", "foreign.zip"),
    )
    assert(Files.isSymbolicLink(target.resolve("intra")))
    assert(Files.isSymbolicLink(clean.resolve("B.class")))
    assert(Files.isSymbolicLink(workspace.resolve("outside-target")))
    assert(Files.isSymbolicLink(git.resolve("untouchable")))

  // --------------------------------------------------------------------------
  // SeatbeltProfile.SystemPaths.txt
  // --------------------------------------------------------------------------

  test("readSystemPaths splits reads from executables and drops what does not resolve"):
    val dir = Files.createTempDirectory("systemPaths")
    val readable = Files.writeString(dir.resolve("readable"), "")
    val executable = Files.writeString(dir.resolve("executable"), "")
    val file = Files.writeString(
      dir.resolve("systemPaths.txt"),
      s"""# measured grants
         |$readable
         |x $executable
         |/nowhere/at/all
         |""".stripMargin,
      UTF_8,
    )
    val systemPaths = readSystemPaths(Some(file))
    assertEquals(systemPaths.reads.map(_.getFileName.toString), Seq("readable"))
    assertEquals(systemPaths.executes.map(_.getFileName.toString), Seq("executable"))
    assertEquals(readSystemPaths(None).reads, Seq.empty)

  // --------------------------------------------------------------------------
  // The foreign server: derived socket, consented shutdown
  // --------------------------------------------------------------------------

  test("sbtServerSocket reproduces a live server's derivation, recorded from a real portfile"):
    // A recorded observation: sbt 2.0.7 served /Users/kenichi/ko-agent-sandbox from this hash directory.
    assertEquals(
      sbtServerSocket(Path.of("/Users/kenichi/ko-agent-sandbox"), _ => None, Path.of("/Users/kenichi")),
      Path.of("/Users/kenichi/.config/sbt/2/server/d5fe918c85e40c5548a2/sock"),
    )

  test("sbtServerSocket takes each serverDir source as sbt takes it, not as it reads better"):
    val workspace = Path.of("/Users/kenichi/ko-agent-sandbox")
    def serverDir(env: (String, String)*) =
      sbtServerSocket(workspace, env.toMap.get, Path.of("/u")).getParent.getParent
    assertEquals(serverDir("SBT_GLOBAL_SERVER_DIR" -> "/srv"), Path.of("/srv"))
    assertEquals(serverDir("SBT_CONFIG_HOME" -> "/cfg"), Path.of("/cfg/2/server"))
    assertEquals(serverDir("XDG_CONFIG_HOME" -> "/x"), Path.of("/x/sbt/2/server"))
    assertEquals(serverDir(), Path.of("/u/.config/sbt/2/server"))
    // sbt reads SBT_GLOBAL_SERVER_DIR as `sys.env get … map file`, so an empty value counts as a value. java.io.File
    // resolves an empty parent against the root rather than staying relative.
    assertEquals(serverDir("SBT_GLOBAL_SERVER_DIR" -> ""), Path.of("/"))
    // sbt reads the global base's own sources as `.filter(_.nonEmpty).map(p => file(p.trim))`.
    assertEquals(serverDir("SBT_CONFIG_HOME" -> ""), Path.of("/u/.config/sbt/2/server"))
    assertEquals(serverDir("SBT_CONFIG_HOME" -> " /cfg "), Path.of("/cfg/2/server"))
    // $HOME is not an input, because sbt reads the user.home property, and the two can differ.
    assertEquals(serverDir("HOME" -> "/elsewhere"), Path.of("/u/.config/sbt/2/server"))

  private def writePortfile(workspace: Path, socket: Path): Unit =
    Files.createDirectories(workspace.resolve("project").resolve("target"))
    Files.writeString(
      workspace.resolve("project").resolve("target").resolve("active.json"),
      s"""{"uri":"local://$socket"}""",
      UTF_8,
    )

  test("shutdownForeignServer refuses a portfile socket that is not the derived one"):
    val workspace = Files.createTempDirectory("foreign")
    val result = shutdownForeignServer(
      workspace, workspace, Path.of("/somewhere/else/sock"), _ => None, _ => (), userHome = Path.of("/u"),
    )
    assert(result.swap.exists(_.contains("not the one sbt derives")), result)
    assert(result.swap.exists(_.contains("run `sbt shutdown` there and retry")), result)

  test("shutdownForeignServer refuses a derived socket the workspace itself could have planted"):
    // Sending the shutdown only to the derived socket is a defence only because the workspace cannot choose that
    // socket. An environment that puts sbt's server directory inside the workspace takes that defence away.
    val workspace = Files.createTempDirectory("foreign")
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> workspace.resolve("srv").toString).get
    val derived = sbtServerSocket(workspace, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    val log = collection.mutable.Buffer[String]()
    val result =
      shutdownForeignServer(workspace, workspace, derived, env, log.append(_), userHome = Path.of("/u"))
    assert(result.swap.exists(_.contains("reachable through what a command writes")), result)
    assertEquals(log.toList, Nil)

  test("shutdownForeignServer treats a server gone before the shutdown as ended, and says so"):
    val home = Files.createTempDirectory("home")
    val workspace = Files.createTempDirectory("foreign")
    val derived = sbtServerSocket(workspace, _ => None, home)
    writePortfile(workspace, derived)
    val log = collection.mutable.Buffer[String]()
    assertEquals(
      shutdownForeignServer(workspace, workspace, derived, _ => None, log.append(_), userHome = home),
      Right(()),
    )
    assert(log.exists(_.contains("shutting down the sbt server")), log)

  test("shutdownForeignServer refuses when the server never answers the shutdown"):
    // The test sets SBT_GLOBAL_SERVER_DIR rather than using the home fallback, because a bound socket path must fit
    // sun_path's 104 bytes.
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> Files.createTempDirectory("s").toString).get
    val workspace = Files.createTempDirectory("f")
    val derived = sbtServerSocket(workspace, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    val listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    listener.bind(UnixDomainSocketAddress.of(derived))
    try
      val result = shutdownForeignServer(
        workspace, workspace, derived, env, _ => (), shutdownDeadlineMillis = 300,
      )
      assert(result.swap.exists(_.contains("went unanswered")), result)
    finally listener.close()

  test("shutdownForeignServer refuses when the portfile outlives an answered shutdown"):
    // The test sets SBT_GLOBAL_SERVER_DIR rather than using the home fallback, because a bound socket path must fit
    // sun_path's 104 bytes.
    val env = Map("SBT_GLOBAL_SERVER_DIR" -> Files.createTempDirectory("s").toString).get
    val workspace = Files.createTempDirectory("f")
    val derived = sbtServerSocket(workspace, env, Path.of("/u"))
    Files.createDirectories(derived.getParent)
    writePortfile(workspace, derived)
    // A listener answers initialize and closes, so the shutdown "succeeds", but the listener lives on. The portfile
    // that it holds therefore keeps naming a connectable socket.
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
        workspace, workspace, derived, env, _ => (),
        shutdownDeadlineMillis = 2_000, releaseDeadlineMillis = 300,
      )
      assert(result.swap.exists(_.contains("still holds the portfile")), result)
    finally
      serving = false
      listener.close()
      server.join(2_000)

  test("reachableThroughCommandWritable answers by what the walk enters, not by where it ends"):
    val workspace = Files.createTempDirectory("p")
    val outside = Files.createTempDirectory("o")
    def reachable(target: Path) = reachableThroughCommandWritable(target, workspace, Seq.empty)
    assert(reachable(workspace.resolve("srv/h/sock")))
    assert(!reachable(outside.resolve("srv/h/sock")))
    // The check exists to catch this planting, in both forms that a link can take. The endpoint tells nothing, because
    // the link inside the workspace chose it.
    val dangling = workspace.resolve("dangling.sock")
    Files.createSymbolicLink(dangling, outside.resolve("never-created"))
    assert(reachable(dangling))
    val existing = Files.writeString(outside.resolve("real.sock"), "")
    Files.createSymbolicLink(workspace.resolve("planted.sock"), existing)
    assert(reachable(workspace.resolve("planted.sock")))
    // The same escape works one directory up: an ancestor link inside the workspace redirects the rest of the path.
    Files.createSymbolicLink(workspace.resolve("srv"), outside)
    assert(reachable(workspace.resolve("srv/real.sock")))
    // In outside -> workspace -> outside, every hop but the middle one is outside the workspace, and only the middle
    // one is writable. Resolving the chain in one step would report the far end and clear it.
    val relay = workspace.resolve("relay")
    Files.createSymbolicLink(relay, existing)
    val entry = outside.resolve("entry")
    Files.createSymbolicLink(entry, relay)
    assert(reachable(entry))
    // A relative path resolves against a working directory this process does not control.
    assert(reachable(Path.of("srv/h/sock")))
    // An unanswerable question counts as reachable, because a workspace root that does not resolve cannot clear
    // anything.
    assert(reachableThroughCommandWritable(outside.resolve("sock"), workspace.resolve("gone"), Seq.empty))

  test("reachableThroughCommandWritable covers the caches a command writes, not the workspace alone"):
    val workspace = Files.createTempDirectory("p")
    val cache = Files.createTempDirectory("c")
    val outside = Files.createTempDirectory("o")
    val planted = cache.resolve("h/sock")
    Files.createDirectories(planted.getParent)
    Files.writeString(planted, "")
    // A socket that an earlier agent's command left in a persistent cache is as planted as a socket in the workspace.
    // That socket stays invisible while the workspace is the only root.
    assert(!reachableThroughCommandWritable(planted, workspace, Seq.empty))
    assert(reachableThroughCommandWritable(planted, workspace, Seq(cache)))
    assert(!reachableThroughCommandWritable(outside.resolve("sock"), workspace, Seq(cache)))
    // A cache that does not exist yet holds nothing, and it must not refuse every shutdown.
    assert(!reachableThroughCommandWritable(outside.resolve("sock"), workspace, Seq(cache.resolve("gone"))))

  test("reachableThroughCommandWritable knows both firmlink spellings of every writable root"):
    // macOS serves the writable volume at / and at /System/Volumes/Data alike, and toRealPath collapses neither.
    // Without this check, the alternate spelling would walk past every root.
    val workspace = Files.createTempDirectory("p")
    val cache = Files.createTempDirectory("c")
    val outside = Files.createTempDirectory("o")
    def aliased(root: Path) = Path.of(s"/System/Volumes/Data${root.toRealPath()}/h/sock")
    assert(reachableThroughCommandWritable(aliased(workspace), workspace, Seq.empty))
    assert(reachableThroughCommandWritable(aliased(cache), workspace, Seq(cache)))
    assert(!reachableThroughCommandWritable(aliased(outside), workspace, Seq(cache)))

  test("appendSessionLogs reads each log as the file it found, inside the session, bounded, naming what it skipped"):
    val root = Files.createTempDirectory("session-logs")
    val condemned = Files.createDirectory(root.resolve("s1"))
    val tmp = Files.createDirectory(condemned.resolve(RunOnHostSession.TmpDir))
    val channelLog = root.resolve("channel.log")
    Files.writeString(channelLog, "before\n", UTF_8)
    val audit = ("audit line\n" * (SessionLogTailBytes / 8)).getBytes(UTF_8)
    Files.write(condemned.resolve("proxy.log"), audit)
    // The command could have made this sparse file as large as it liked, so only the tail is read.
    val sparse = java.io.RandomAccessFile(tmp.resolve("sbt-server-err1.log").toFile, "rw")
    sparse.write("server said\n".getBytes(UTF_8))
    sparse.setLength(1L << 30)
    sparse.close()
    // A link out of the session is named and never followed.
    val secret = Files.writeString(root.resolve("secret"), "the user's own file\n", UTF_8)
    Files.createSymbolicLink(tmp.resolve("sbt-server-err2.log"), secret)
    // A FIFO is named and never opened, or this teardown would wait for a writer that never comes.
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
    // When tmp itself is replaced by a link to a directory that holds a matching regular file, that file is not listed.
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
    // A log below the bound is kept whole, and a session with only a proxy log lists only that log.
    val alone = Files.createDirectory(root.resolve("s2"))
    Files.createDirectory(alone.resolve(RunOnHostSession.TmpDir))
    Files.writeString(alone.resolve("proxy.log"), "short\n", UTF_8)
    Files.writeString(channelLog, "", UTF_8)
    appendSessionLogs(channelLog, alone, "command s2 ended by signal")
    val again = Files.readString(channelLog, UTF_8)
    assert(again.contains("==> proxy.log\nshort\n"), again)
    assert(!again.contains("[last"), again)
    assert(!again.contains("sbt-server-err"), again)
    // The runner's session lists one proxy log per runtime and nothing else of the directory.
    val runner = Files.createDirectory(root.resolve("r1"))
    Files.createDirectory(runner.resolve(RunOnHostSession.TmpDir))
    Files.writeString(runner.resolve("proxy-sbt-0a.log"), "sbt audit\n", UTF_8)
    Files.writeString(runner.resolve("proxy-mill-0b.log"), "mill audit\n", UTF_8)
    Files.writeString(runner.resolve("server-sbt-0a.log"), "server said\n", UTF_8)
    Files.writeString(runner.resolve(RunOnHostSession.WorkspaceFile), "/p\n", UTF_8)
    Files.writeString(channelLog, "", UTF_8)
    appendSessionLogs(channelLog, runner, "the runner's session r1 ended")
    val runners = Files.readString(channelLog, UTF_8)
    assert(runners.contains("the runner's session r1 ended; its logs follow"), runners)
    assert(runners.contains("==> proxy-mill-0b.log\nmill audit\n==> proxy-sbt-0a.log\nsbt audit\n"), runners)
    assert(runners.contains("==> server-sbt-0a.log\nserver said\n"), runners)
    assert(!runners.contains(s"==> ${RunOnHostSession.WorkspaceFile}"), runners)
  test("a host proxy's audit log is a file in the run's log directory, which the session's name links to"):
    def names(root: Path) =
      val logDirectory = Files.createDirectory(root.resolve("run-20261004T120000Z-abcd1234"))
      val session = Files.createDirectory(root.resolve("rXYZ"))
      Files.createDirectory(session.resolve(RunOnHostSession.TmpDir))
      (logDirectory.resolve("run-on-host.log"), session.resolve("proxy.log"), logDirectory.resolve("proxy-rXYZ.log"))
    // The test writes as the proxy's stderr is opened (startProxyUnder): by the session's name, appending.
    def proxyWrites(proxyLog: Path, line: String) =
      Files.writeString(proxyLog, line, UTF_8, java.nio.file.StandardOpenOption.APPEND)
    def permissions(file: Path) =
      java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(file))

    locally:
      val (channelLog, proxyLog, kept) = names(Files.createTempDirectory("audit-log"))
      keepAuditLog(channelLog, proxyLog)
      proxyWrites(proxyLog, "allow h.example CONNECT\n")
      assertEquals(Files.readSymbolicLink(proxyLog), kept)
      assertEquals(Files.readString(kept, UTF_8), "allow h.example CONNECT\n")
      assertEquals(Files.readString(proxyLog, UTF_8), "allow h.example CONNECT\n")
      assertEquals(permissions(kept), "rw-------")
      assert(!Files.exists(channelLog), "nothing to say in the channel log")
      // A report of an unwritable log names this file, not the session's link. Without a channel log, the report names
      // the session's link.
      assertEquals(proxyLogFile(Some(channelLog), proxyLog), kept)
      assertEquals(proxyLogFile(None, proxyLog), proxyLog)
      // The session's end reads the file the link names, as it reads a session's own file.
      appendSessionLogs(channelLog, proxyLog.getParent, "command rXYZ ended by signal")
      val logged = Files.readString(channelLog, UTF_8)
      assert(logged.contains("==> proxy.log\nallow h.example CONNECT\n"), logged)
      // The session's name goes away as a runtime's log does (RunnerRuntimes.discardRuntime), or with its directory.
      Files.delete(proxyLog)
      assertEquals(Files.readString(kept, UTF_8), "allow h.example CONNECT\n")

    // When a runtime's proxy starts again in the launch, the earlier proxy's log keeps its name and its lines.
    locally:
      val (channelLog, proxyLog, first) = names(Files.createTempDirectory("audit-log"))
      Files.writeString(first, "an earlier proxy's\n", UTF_8)
      val second = first.resolveSibling("proxy-rXYZ-2.log")
      Files.writeString(second, "another earlier proxy's\n", UTF_8)
      keepAuditLog(channelLog, proxyLog)
      proxyWrites(proxyLog, "ready\n")
      val third = first.resolveSibling("proxy-rXYZ-3.log")
      assertEquals(Files.readString(third, UTF_8), "ready\n")
      assertEquals(Files.readString(first, UTF_8), "an earlier proxy's\n")
      assertEquals(Files.readString(second, UTF_8), "another earlier proxy's\n")
      appendSessionLogs(channelLog, proxyLog.getParent, "the runner's session rXYZ ended")
      assert(Files.readString(channelLog, UTF_8).contains("==> proxy.log\nready\n"))

    // A link that the launcher did not make names something else, and it is never followed.
    locally:
      val root = Files.createTempDirectory("audit-log")
      val (channelLog, proxyLog, kept) = names(root)
      // The cases are the container proxy's log, the channel log, the right name in another directory, and a relative
      // link.
      val containerProxy = Files.writeString(kept.resolveSibling("proxy.log"), "a\n", UTF_8)
      val outside = Files.writeString(root.resolve(kept.getFileName), "b\n", UTF_8)
      for target <- Vector(containerProxy, channelLog, outside, Path.of(kept.getFileName.toString)) do
        Files.deleteIfExists(proxyLog)
        Files.createSymbolicLink(proxyLog, target)
        assertEquals(keptAuditLog(channelLog, proxyLog), None, target.toString)
        assertEquals(proxyLogFile(Some(channelLog), proxyLog), proxyLog, target.toString)
        Files.writeString(channelLog, "", UTF_8)
        appendSessionLogs(channelLog, proxyLog.getParent, "command rXYZ ended by signal")
        val logged = Files.readString(channelLog, UTF_8)
        assert(logged.contains("==> proxy.log\n[skipped: not a regular file]\n"), logged)

    // When the log directory takes no file, no proxy is started, and the refusal says what to do.
    locally:
      val (channelLog, proxyLog, kept) = names(Files.createTempDirectory("audit-log"))
      val logDirectory = channelLog.getParent
      val record = proxyLog.resolveSibling(RunOnHostSession.RecordsDir).resolve("proxy")
      Files.createDirectory(record.getParent)
      val systemPaths = SeatbeltProfile.SystemPaths(Seq(Path.of("/usr/lib")), Seq(Path.of("/bin")))
      val before = Files.getPosixFilePermissions(logDirectory)
      Files.setPosixFilePermissions(logDirectory, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"))
      val refused =
        try
          assert(keepAuditLog(channelLog, proxyLog).isLeft)
          // The test goes through the start, as a command's runtime is created (RunnerRuntimes.created, ownRuntime).
          createProxy(systemPaths, Vector.empty, Some(channelLog))(Program.Sbt, Vector.empty, record, proxyLog)
        finally Files.setPosixFilePermissions(logDirectory, before)
      val reason = refused.swap.getOrElse(fail(s"a proxy was started: $refused"))
      assert(
        reason.startsWith(
          s"The host command sandbox's proxy is not started: its audit log cannot be created in $logDirectory (",
        ),
        reason,
      )
      assert(reason.endsWith(s"Tell the user: make $logDirectory writable, then run the command again."), reason)
      // Nothing was started: no leader is registered, and no log exists by either name.
      assert(!Files.exists(record), "a proxy's record")
      assert(!Files.exists(proxyLog, java.nio.file.LinkOption.NOFOLLOW_LINKS) && !Files.exists(kept))

object ForkJvmSettings:
  def main(args: Array[String]): Unit =
    val command = ProcessBuilder(
      Path.of(sys.props("java.home"), "bin/java").toString,
      "-Djava.io.tmpdir=/build-option", "-XshowSettings:properties", "-version",
    )
    sys.exit(command.inheritIO().start().waitFor())
