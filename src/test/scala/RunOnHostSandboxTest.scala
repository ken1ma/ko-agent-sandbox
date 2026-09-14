package agentsandbox.launcher

import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import RunOnHostSandbox.*
import scala.jdk.CollectionConverters.*
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
        "MILL_OUTPUT_DIR" -> "elsewhere", "_JAVA_OPTIONS" -> "-javaagent:/tmp/agent.jar",
        "JAVA_TOOL_OPTIONS" -> "-Duser.option=value",
      ),
      prereqs, sbtGlobal = Path.of("/cache/sbt"), ivyHome = Path.of("/cache/ivy"),
      gradleUserHome = Path.of("/cache/gradle"), m2Repository = Path.of("/cache/m2"),
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
    assert(environment("_JAVA_OPTIONS").contains("-Djava.io.tmpdir=\"/private/tmp/ko-agent-501/s\""))
    // The sockets are the runtime's: where the broker's server bound them.
    assertEquals(environment("XDG_RUNTIME_DIR"), "/private/tmp/ko-agent-501/b/tmp")
    assertEquals(environment("SBT_GLOBAL_SERVER_DIR"), "/private/tmp/ko-agent-501/b/tmp")
    assertEquals(environment("USER"), "u")
    assertEquals(environment("LOGNAME"), "u")
    assertEquals(environment("MILL_FINAL_DOWNLOAD_FOLDER"), "/Users/u/.cache/mill/download")
    // The wrapper's launcher version, never the forwarded one.
    assertEquals(environment("MILL_VERSION"), "1.1.9-jvm")
    assertEquals(environment("COURSIER_CACHE"), "/cache/v1")
    assertEquals(environment("GRADLE_USER_HOME"), "/cache/gradle")
    assert(environment("_JAVA_OPTIONS").contains("-Dsbt.global.base=\"/cache/sbt\""))
    assert(environment("_JAVA_OPTIONS").contains("-Dsbt.ivy.home=\"/cache/ivy\""))
    assert(environment("_JAVA_OPTIONS").contains("-Dmaven.repo.local=\"/cache/m2\""))
    // A forward reaches the command; one naming a variable the wrapper sets loses to the wrapper.
    assertEquals(environment("TOKEN"), "t0ken")
    assertEquals(environment("HTTPS_PROXY"), "http://127.0.0.1:4711")
    assert(!environment("_JAVA_OPTIONS").contains("javaagent"))
    assertEquals(environment("JAVA_TOOL_OPTIONS"), "-Duser.option=value")
    // And nothing else of the shell: not the secret, not the upstream proxy's credential, not the
    // programs' own overrides — mill's version and output-directory ones even when forwarded.
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
        "MILL_VERSION",
      ) ++ commandProxyVariables(4711).keySet,
    )
    // Without a derivable download folder the variable is absent, and so is the launcher
    // version for a program that is not mill — a forwarded one included.
    val noFolder =
      commandEnvironment(
        host.get, Vector("MILL_VERSION" -> "1.0.0"), prereqs, Path.of("/s"), Path.of("/i"), Path.of("/g"),
        Path.of("/m"), None, None, Path.of("/t"), Path.of("/t"), 1, "u",
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
          optIn.toMap.get, forwards, prereqs.copy(program = program),
          Path.of("/s"), Path.of("/i"), Path.of("/g"), Path.of("/m"), None, None,
          Path.of("/t"), Path.of("/t"), 1, "u",
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
        prereqs, root.resolve("sbt"), root.resolve("ivy"), root.resolve("gradle"),
        root.resolve("m2"), None, None, root.resolve("tmp"), root.resolve("sockets"), 4711, "u",
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
      // A build supplies its own argv to a forked JVM; only the environment carries these settings.
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

  test("a gradle assembly grants the wrapper's one distribution and the project's own Gradle user home"):
    import java.nio.file.attribute.PosixFilePermissions.fromString as permissions
    val root = Files.createTempDirectory("gradle")
    val cache = Files.createDirectories(root.resolve("coursier"))
    val jdk = Files.createDirectories(cache.resolve("arc/jdk.tar.gz/jdk"))
    Files.createDirectories(jdk.resolve("bin"))
    Files.setPosixFilePermissions(Files.createFile(jdk.resolve("bin/java")), permissions("rwxr-xr-x"))
    val project = Files.createDirectories(root.resolve("project"))
    val env = Map("HOME" -> root.toString, "COURSIER_CACHE" -> cache.toString, "JAVA_HOME" -> jdk.toString)
    val absent = assemble(project, Program.Gradle, env.get, project)
    assert(clue(absent).left.exists(_.contains("no gradle/wrapper/gradle-wrapper.properties")))
    val properties = Files.createDirectories(project.resolve("gradle/wrapper")).resolve("gradle-wrapper.properties")
    Files.writeString(properties, "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.7.1-bin.zip\n")
    val unprovisioned = assemble(project, Program.Gradle, env.get, project)
    val distributionDir = root.resolve(".gradle/wrapper/dists/gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv")
    assert(clue(unprovisioned).left.exists(text => text.contains(distributionDir.toString)))
    assert(unprovisioned.left.exists(_.contains("./gradlew")))
    val gradleHome = Files.createDirectories(distributionDir.resolve("gradle-9.7.1"))
    Files.createDirectories(gradleHome.resolve("bin"))
    Files.setPosixFilePermissions(Files.createFile(gradleHome.resolve("bin/gradle")), permissions("rwxr-xr-x"))
    val assembled = assemble(project, Program.Gradle, env.get, project).fold(fail(_), identity)
    assertEquals(assembled.prereqs.executable, gradleHome.toRealPath().resolve("bin/gradle"))
    assertEquals(assembled.distribution, Some(gradleHome.toRealPath()))
    assertEquals(assembled.gradleUserHomeGranted, Some(assembled.gradleUserHome))
    assert(Files.isDirectory(assembled.gradleUserHome), "created for the program that reads it")

    // The tree relinked elsewhere, and the state root placed under the granted directory's
    // target: the directory would resolve above the CA signing key, which its spelling never shows.
    val cacheRoot = root.resolve(".cache/ko-agent-sandbox")
    val tree = RunOnHostPrereqs.runOnHostCachesOf(cacheRoot)
    FileHelper.deleteRecursively(tree)
    Files.createSymbolicLink(tree, Files.createDirectories(root.resolve("elsewhere")))
    val granted =
      RunOnHostPrereqs.gradleUserHomeOf(cacheRoot, SandboxProject.projectIdOf(project, HostCommands.Os.Mac))
    val relinked = assemble(project, Program.Gradle, (env + ("XDG_STATE_HOME" -> granted.toString)).get, project)
    assert(clue(relinked).left.exists(_.contains("overlaps the launcher's state root")))
    assert(assembled.gradleUserHome.startsWith(root.toRealPath().resolve(".cache/ko-agent-sandbox/run-on-host")))
    assertEquals(assembled.m2RepositoryGranted, None)
    assertEquals(assembled.sbtCachesGranted, Seq.empty)

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
    assertEquals(temporaryDirectories(Program.Gradle, own, brokers), (brokers, brokers))
    assertEquals(temporaryDirectories(Program.Mvn, own, brokers), (own, own))

  test("a redirected out/mill-daemon, or an entry of it with a second name, is refused; a plain one admitted"):
    val root = Files.createTempDirectory("rendezvous")
    val build = Files.createDirectory(root.resolve("build"))
    val other = Files.createDirectories(root.resolve("other/out/mill-daemon"))
    assertEquals(RunOnHostMillDaemons.rendezvousIsOwn(build), Right(()), "no out/ at all")
    val daemonDir = Files.createDirectories(build.resolve("out/mill-daemon"))
    Files.writeString(daemonDir.resolve("processId"), "1")
    assertEquals(RunOnHostMillDaemons.rendezvousIsOwn(build), Right(()), "a plain directory")
    // An entry linked elsewhere, then the directory, then out/ itself.
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
    // The start time's width is the leader's, whatever ps spells: a padded day, the same width.
    val padded = RunOnHostMillDaemons.parseMembers(
      Vector("  500   400 Sat Sep  2 15:42:15 2026 perl", "  501   500 Sat Sep  2 15:42:16 2026 java"),
      Record(500, "Sat Sep  2 15:42:15 2026"),
    )
    assertEquals(padded.map(member => member.start -> member.command), Vector(
      "Sat Sep  2 15:42:15 2026" -> "perl", "Sat Sep  2 15:42:16 2026" -> "java",
    ))
    // A listing whose leader row does not carry the recorded start proves no width: empty.
    assertEquals(RunOnHostMillDaemons.parseMembers(rows, Record(500, "Sat Sep 12 15:42:14 2026")), Vector.empty)
    assertEquals(RunOnHostMillDaemons.parseMembers(rows.drop(1), leader), Vector.empty)
    val perl = group(0)
    val launcher = group(1)
    // The daemon's parent is the leader: the group's proof is never signalled.
    assertEquals(starterOf(Vector(perl, Member(502, 500, "D", daemonMain)), leader.pgid), None)
    // The daemon's parent is outside the group: a daemon the launcher attached to, not spawned.
    assertEquals(starterOf(Vector(perl, launcher, Member(502, 77, "D", daemonMain)), leader.pgid), None)
    // A java that does not exec: the daemon's parent names DaemonMain too, whichever row comes first.
    val shim = Member(502, 501, "D", daemonMain)
    val underShim = Member(503, 502, "D2", daemonMain)
    assertEquals(starterOf(Vector(perl, launcher, underShim, shim), leader.pgid), None)
    assertEquals(starterOf(Vector(perl, launcher, shim, underShim), leader.pgid).map(_(0).pid), Some(502L))
    // No daemon yet.
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
    // The daemon listens on the candidate and the launcher bears the start time listed: one TERM.
    val processes = stillAlive
    assert(RunOnHostMillDaemons.endStarter(record, root, processes, logged += _, _ => group, listens))
    assertEquals(processes.signalled.toList, List(501L -> "TERM"))
    assertEquals(logged.toList, List("TERM to the mill starter (pid 501): its daemon (pid 502) listens on port 61210"))
    logged.clear()
    // The launcher's pid is recycled after the listing was taken — during lsof, or before the
    // listing even returns: the start time listed no longer holds, so nothing is signalled or said.
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
    // The launcher gone before the signal, or the daemon not yet on its port: nothing.
    val recycled = Fake(Map(500L -> "L", 502L -> "D"))
    assert(!RunOnHostMillDaemons.endStarter(record, root, recycled, logged += _, _ => group, listens))
    assert(!RunOnHostMillDaemons.endStarter(record, root, processes, logged += _, _ => group, (_, _) => None))
    assertEquals(processes.signalled.size, 1)
    assertEquals(logged.toList, Nil)

  test("a classpath memo naming a path outside the granted cache is deleted; one inside, a link or none is left"):
    val build = Files.createTempDirectory("build")
    val cache = Files.createTempDirectory("cache").toRealPath()
    val memo = build.resolve("out/mill-daemon/cache/mill-daemon-classpath")
    Files.createDirectories(memo.getParent)
    def written(paths: String*): Unit =
      Files.writeString(memo, paths.map(path => s"\"$path\"").mkString("[\"1.1.9 |\",[", ",", "]]"))
    // The profile is the gate's to measure; here the read and the delete are the plain ones.
    val direct = RunOnHostMillDaemons.Confined(
      read = file => Option.when(Files.isRegularFile(file))(Files.readString(file, UTF_8)),
      delete = file => Files.deleteIfExists(file),
    )
    written(s"$cache/https/repo1.maven.org/a.jar", s"$cache/https/repo1.maven.org/b.jar")
    assertEquals(RunOnHostMillDaemons.discardForeignMemo(build, cache, direct), None)
    assert(Files.exists(memo))
    written(s"$cache/https/repo1.maven.org/a.jar", "/Users/me/Library/Caches/Coursier/v1/https/repo1.maven.org/b.jar")
    val said = RunOnHostMillDaemons.discardForeignMemo(build, cache, direct)
    assert(said.exists(_.contains("/Users/me/Library/Caches/Coursier/v1/https/repo1.maven.org/b.jar, outside")), said)
    assert(!Files.exists(memo))
    // A memo that is a link is not the build's own file: rendezvousIsOwn refuses the command first,
    // and this deletes nothing through it.
    Files.createSymbolicLink(memo, build.resolve("elsewhere"))
    assertEquals(RunOnHostMillDaemons.discardForeignMemo(build, cache, direct), None)
    assert(Files.isSymbolicLink(memo))
    Files.delete(memo)
    assertEquals(RunOnHostMillDaemons.discardForeignMemo(build, cache, direct), None)

  test("the server's command line is the thin client's: the request's launcher flags as the client forwards them"):
    val sbt = Path.of("/Users/u/Library/Application Support/Coursier/bin/sbt")
    val global = Path.of("/Users/a b/c\"d/sbt")
    def server(arguments: String*): Seq[String] =
      val line = serverCommand(sbt, global, arguments)
      assertEquals(line.take(3), sbtCommand(sbt, global) :+ s"-Dsbt.script=$sbt")
      assertEquals(line.takeRight(2), Seq("--detach-stdio", "--server"))
      line.drop(3).dropRight(2)
    // -D and a value flag reach the server; -J is the client JVM's, -batch and -v the client's
    // own, and a command with what follows it goes over the socket.
    assertEquals(
      server("-Dprobe=1", "-J-Xmx2g", "-batch", "-mem", "512", "compile", "-v"), Seq("-Dprobe=1", "-mem", "512"),
    )
    // The empty-build flags are launcher flags even after the command, as the client has them.
    assertEquals(server("new", "scala/scala3", "--allow-empty"), Seq("--allow-empty"))
    assertEquals(server("--sbt-create", "compile"), Seq("--sbt-create"))
    // The `=` form of a value flag splits as the client splits it; the client's own `=` flags stay.
    assertEquals(server("-sbt-version=2.0.8", "--color=never", "-Dx=y"), Seq("-sbt-version", "2.0.8", "-Dx=y"))
    // A flag naming a program to run never reaches the server, whatever its form.
    assertEquals(
      server("-java-home", "/x", "--sbt-jar=/y.jar", "--sbt-script", "/z", "-Dsbt.script=/w", "-v"), Seq.empty,
    )
    // A flag the client does not know is forwarded as the client forwards it.
    assertEquals(server("-sbt-launch-repo", "https://r", "-x"), Seq("-sbt-launch-repo"))

  // --------------------------------------------------------------------------
  // run-on-host/ and its parent both refuse unrecognized configuration entries
  // --------------------------------------------------------------------------

  def projectWith(paths: String*): Path =
    val project = Files.createTempDirectory("run-on-host")
    paths.foreach: path =>
      val full = project.resolve(path)
      Files.createDirectories(full.getParent)
      Files.writeString(full, "")
    project

  test("an absent run-on-host, or a complete one, is no stray"):
    assertEquals(hostCommandStray(Files.createTempDirectory("empty")), None)
    val project = projectWith(
      ".ko-agent-sandbox/run-on-host/sbt/egress/rule",
      ".ko-agent-sandbox/run-on-host/mill/egress/rule",
    )
    assertEquals(hostCommandStray(project), None)

  test("a stray name at any level refuses, naming itself; metadata does not"):
    for
      stray <- Seq(
        ".ko-agent-sandbox/run-on-host/ant/egress/rule",
        ".ko-agent-sandbox/run-on-host/sbt/egres/rule",
        ".ko-agent-sandbox/run-on-host/sbt/egress/rules",
      )
    do
      val refused = hostCommandStray(projectWith(stray))
      assert(refused.isDefined, stray)
      assert(refused.exists(_.contains("update the launcher")), refused.toString)
    val metadata = projectWith(
      ".ko-agent-sandbox/run-on-host/.DS_Store",
      ".ko-agent-sandbox/run-on-host/sbt/egress/rule",
    )
    assertEquals(hostCommandStray(metadata), None)
    // The retired grammar's file is named as such, with the pointer.
    val retired = hostCommandStray(projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/allowed"))
    assert(retired.exists(r => r.contains("retired grammar") && r.contains("egress/rule")), retired.toString)

  test("a symlinked component refuses by name"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    val dir = project.resolve(".ko-agent-sandbox/run-on-host/mill")
    Files.createSymbolicLink(dir, project.resolve(".ko-agent-sandbox/run-on-host/sbt"))
    val refused = hostCommandStray(project)
    assert(refused.exists(_.contains("symlink")), refused.toString)

  test("a file where a directory belongs refuses instead of reading as absent config"):
    val project = Files.createTempDirectory("run-on-host")
    val dir = project.resolve(".ko-agent-sandbox/run-on-host")
    Files.createDirectories(dir)
    Files.writeString(dir.resolve("sbt"), "")
    val refused = hostCommandStray(project)
    assert(refused.exists(r => r.contains("sbt") && r.contains("not a directory")), refused.toString)

  test("a non-regular file where rule belongs refuses instead of being read"):
    val project = Files.createTempDirectory("run-on-host")
    val egress = project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress")
    Files.createDirectories(egress.resolve("rule")) // a directory; a FIFO would block a read
    val refused = hostCommandStray(project)
    assert(
      refused.exists(r => r.contains("rule") && r.contains("not a regular file")),
      refused.toString,
    )

  test("readProgramRules reads the program's file, refuses its strays, and defaults to nothing"):
    val project = projectWith(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
    Files.writeString(
      project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule"),
      "allow https://repo.example.org/ read\n",
      UTF_8,
    )
    assertEquals(readProgramRules(project, Program.Sbt), Right(Vector("repo.example.org")))
    assertEquals(readProgramRules(project, Program.Mill), Right(Vector.empty), "mill has no file here")

    Files.writeString(
      project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule"),
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

  test("the proxy profile's inputs on a JVM are the JDK to run and the class path to read"):
    val authority = SeatbeltProfile.RuntimeAuthority(Seq(Path.of("/usr/lib")), Seq(Path.of("/bin")))
    val inputs = proxyInputs(authority).fold(fail(_), identity)
    assertEquals(inputs.executables, Seq(Path.of(System.getProperty("java.home")).toRealPath()))
    assert(inputs.reads.nonEmpty)
    assert(inputs.reads.forall(entry => Files.exists(entry) && entry.isAbsolute), inputs.reads.take(8).toString)
    assertEquals(inputs.runtime, authority)
    // A class-path entry that does not exist is skipped; a relative one is absolute against this
    // JVM's working directory, and an empty one — a trailing separator included — is that
    // directory, as the JVM reads them; the proxy runs from / and needs the same entries there.
    val missing = proxyInputs(authority, classPath = "/no/such/entry.jar").fold(fail(_), identity)
    assertEquals(missing.reads, Seq.empty)
    val cwd = Path.of("").toRealPath()
    val empty = proxyInputs(authority, classPath = "/no/such/entry.jar:").fold(fail(_), identity)
    assertEquals(empty.reads, Seq(cwd))
    assertEquals(proxyInputs(authority, classPath = "").fold(fail(_), identity).reads, Seq(cwd))
    assertEquals(proxyInputs(authority, classPath = "build.sbt").fold(fail(_), identity).reads,
      Seq(cwd.resolve("build.sbt")))
    assertEquals(
      selfClassPath("target/dist/ko-agent-sandbox.jar:"),
      Seq(Path.of("").toAbsolutePath.resolve("target/dist/ko-agent-sandbox.jar").toString,
        Path.of("").toAbsolutePath.toString),
    )
    assert(proxyInputs(authority, javaHome = "/no/such/jdk").isLeft)
    // The launch entry is found by resolved path and kept as spelled (launchEntry has why):
    // launched through a symlink, the entry is the link; its removal is the refusal, naming
    // the link though its target stays, and a retargeted link is its new target.
    val dir = Files.createTempDirectory("self")
    val real = Files.writeString(dir.resolve("real.jar"), "")
    val other = Files.writeString(dir.resolve("other.jar"), "")
    val link = Files.createSymbolicLink(dir.resolve("link.jar"), real)
    val classPath = s"${dir.resolve("unused.jar")}${java.io.File.pathSeparator}$link"
    val entry = launchEntry(classPath, Some(real))
    assertEquals(entry, Some(link))
    assertEquals(selfPresent(entry), Right(Some(real.toRealPath())))
    Files.delete(link)
    val refused = proxyInputs(authority, self = entry)
    assert(refused.swap.exists(_.contains(link.toString)), refused.toString)
    Files.createSymbolicLink(link, other)
    assertEquals(selfPresent(entry), Right(Some(other.toRealPath())))
    // Code off the class path — this process's own under sbt — has no entry, and nothing to refuse.
    assertEquals(launchEntry(classPath, Some(dir.resolve("elsewhere.jar"))), None)
    assertEquals(selfPresent(None), Right(None))

  test("a command is refused before its wrapper runs when the launcher's executable is gone, Maven's included"):
    val root = Files.createTempDirectory("brk")
    val project = Files.createDirectory(root.resolve("project"))
    val session = RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    var proxies = 0
    val authority = SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
    val runtimes = BrokerRuntimes(session, project, _ => (), authority, Vector.empty)(
      RunOnHostSession.HostProcesses,
      (_, _, _) => fail("assembled without an executable"),
      (_, _, _, _) => { proxies += 1; Right(1) },
      _ => fail("a server started without an executable"),
      _ => fail("a daemon started without an executable"),
      executable = () => Left("gone"),
    )
    for program <- Program.values do
      assertEquals(runtimes.prepare(program, project, Seq.empty), Left("gone"), clue = program)
    assertEquals(proxies, 0)

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
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
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
        Right(RunOnHostMillDaemons.Daemon(sleeper, started, 40_000 + daemonStarts.size))
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
      // A failed creation whose proxy group outlives its KILL keeps the record; while it does,
      // the next request is refused before a spawn could rename its record over the kept one.
      val dirD = Files.createDirectory(project.resolve("d"))
      neverReady = true
      groupSurvives = true
      val refused = runtimes.prepare(Program.Sbt, dirD, Seq("test"))
      assert(
        refused.swap.exists(reason => reason.startsWith("never ready; ") && reason.contains("kept for the next start")),
        refused.toString,
      )
      val keptProxy = pgidOf(recordOf(dirD))
      val spawnsKept = spawns.size
      val again = runtimes.prepare(Program.Sbt, dirD, Seq("test"))
      assert(again.swap.exists(_.contains("kept for the next start")), again.toString)
      assertEquals(pgidOf(recordOf(dirD)), keptProxy, "the kept record is not renamed over")
      assertEquals(spawns.size, spawnsKept, "no spawn while the record is kept")
      // The group ends at last: the record goes, and the creation is retried.
      groupSurvives = false
      neverReady = false
      assertEquals(runtimes.prepare(Program.Sbt, dirD, Seq("test")), current(dirD))
      assertEquals(endedGroups.takeRight(1).toList, List(keptProxy))

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
      // Gradle's runtime is its proxy: no server, no daemon start, reused while the proxy lives.
      val daemonsBefore = daemonStarts.size
      val gradleA = runtimes.prepare(Program.Gradle, dirA, Seq("build"))
      assertEquals(gradleA.map(_.map(_.daemonPort)), Right(Some(None)))
      assertEquals(gradleA.map(_.map(_.proxyLog)), Right(Some(logOf(dirA, "gradle"))))
      assertEquals(runtimes.prepare(Program.Gradle, dirA, Seq("test")), gradleA, "reused while the proxy lives")
      assertEquals(serverStarts.size, serversBefore, "gradle starts no server")
      assertEquals(daemonStarts.size, daemonsBefore, "gradle starts no daemon")
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

  test("another live broker's server is taken over by its record alone; a build file without one reserves nothing"):
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
      def endGroup(pgid: Long): Boolean = { endedGroups += pgid; true }
      def groupEmpty(pgid: Long): Boolean = true
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(project, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
    )
    // A second directory the peer touched with Mill only: its build file names it, but there is
    // no server-sbt record, so the peer reserves no sbt server there.
    val millDir = Files.createDirectory(project.resolve("mill-only"))
    val millHash = RunOnHostSession.buildHash(millDir)
    RunOnHostSession.publishBuildFile(peer.directory, millHash, millDir)
    // A record without a stand-in spawn, as the proxy's: what the descriptor of a started
    // runtime binds to.
    def recordOnly(record: Path): Unit =
      Files.writeString(record, RunOnHostSession.renderRecord(RunOnHostSession.Record(1, "S")), UTF_8)
    val started = scala.collection.mutable.ListBuffer[Path]()
    val server = (start: ServerStart) =>
      started += start.buildDirectory
      recordOnly(start.record)
      Right(())
    val emptyAuthority = SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
    val daemonStarts = scala.collection.mutable.ListBuffer[Path]()
    val daemon = (start: DaemonStart) =>
      daemonStarts += start.buildDirectory
      recordOnly(start.record)
      Right(RunOnHostMillDaemons.Daemon(1, "S", 40_001))
    val runtimes = BrokerRuntimes(mine, project, _ => (), emptyAuthority, Vector.empty)(
      processes,
      (_, _, _) => Right(assembled),
      (_, _, record, _) =>
        recordOnly(record)
        Right(1),
      server,
      daemon,
    )
    try
      // The peer owns the sbt server for `dir`, and describes it by nothing this launch can
      // attach to: the group its record names is ended, by the recorded pgid, and this launch's
      // server starts in its place.
      assertEquals(runtimes.prepare(Program.Sbt, dir, Seq("compile")).map(_.isDefined), Right(true))
      assertEquals(endedGroups.toList, List(peerLeader), "the recorded group, ended once")
      assert(started.contains(dir), "a server started for the taken-over directory")
      // The peer's Mill-only directory reserves no sbt server: this launch starts sbt there,
      // ending nothing.
      assertEquals(runtimes.prepare(Program.Sbt, millDir, Seq("compile")).map(_.isDefined), Right(true))
      assert(started.contains(millDir), "sbt started in the Mill-only directory")
      assertEquals(endedGroups.toList, List(peerLeader))
      // The daemon record is the mill ownership: the peer's `daemon-mill-<hash>` is what a mill
      // command for that directory takes over, while its sbt-only `dir` admits one with nothing
      // to end. The record names a live group — the peer's server spawn stands in — since a dead
      // group's record owns nothing.
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

  test("the broker retires its own server under the retirement lock, below its monitor, and signals once"):
    // The process table the broker and a taker share; an ended group leaves it. The end pauses
    // between the proof and the signal while `pause` is set.
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
    val project = Files.createDirectory(root.resolve("project"))
    val session = RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(project, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
      None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
    )
    // The proxy and server stand-ins write their records themselves, each naming a fresh live
    // leader; no portfile is written, so every later sbt command replaces the server.
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
    val server = (start: ServerStart) =>
      register(start.record)
      Right(())
    val authority = SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
    val runtimes = BrokerRuntimes(session, project, _ => (), authority, Vector.empty)(
      Shared(pausing = true), (_, _, _) => Right(assembled), proxy, server, _ => fail("no daemon here"),
    )
    val dirA = Files.createDirectory(project.resolve("a"))
    val dirB = Files.createDirectory(project.resolve("b"))
    val recordA = session.records.resolve(s"server-sbt-${RunOnHostSession.buildHash(dirA)}")
    def leaderA = RunOnHostSession.parseRecord(Files.readString(recordA, UTF_8)).get.pgid
    def latches() = (java.util.concurrent.CountDownLatch(1), java.util.concurrent.CountDownLatch(1))
    try
      assert(runtimes.prepare(Program.Sbt, dirA, Seq("compile")).isRight)
      val first = leaderA
      // Another holder has the retirement lock — a taker on a crashed launch's record of the same
      // hash, paused between its proof and its signal: the replacement waits for it under the
      // monitor — a second command, for a directory with nothing to retire, waits behind it — and
      // signals nothing until it is free. Monitor first, retirement lock last.
      val crashed = RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
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
      // The taker first, paused between its proof and its signal: the broker's replacement waits,
      // then finds the leader gone and the group empty — skipped, not signalled — and starts a
      // successor. One signal, one runtime.
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
      // The broker first, paused: the taker waits, then reads what the broker left at the
      // instant it acquired — the dead record before the successor's is published, no record, or
      // the successor's, whose group it then ends as a taker would. Whichever it found, no group
      // is signalled twice, and the broker's next command leaves one live server: replacing a
      // dead group without a signal, as an owner does after a takeover, or a live one under its
      // own.
      val (brokerReached, brokerProceed) = latches()
      table.pause = Some((brokerReached, brokerProceed))
      val paused = started(runtimes.prepare(Program.Sbt, dirA, Seq("test")))
      brokerReached.await()
      table.pause = None
      val takingLater = started(RunOnHostSession.endRecordedGroup(root, recordA, Shared(pausing = false)))
      assert(!doneWithin(takingLater, 300), "the taker waits on the broker's lock")
      brokerProceed.countDown()
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

  test("the gate's entry: its teardown waits on the lock its own preparation holds, and keeps the record"):
    // One JVM, two threads and no shared monitor: prepare on the main thread, endSession from
    // the shutdown hook (ownRuntime). The teardown's bounded wait must neither signal nor
    // release the holder's lock; it keeps the session for the next collection.
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
    val project = Files.createDirectory(root.resolve("project"))
    val session = RunOnHostSession.publish(root, project).toOption.get
    val assembled = Assembled(
      RunOnHostPrereqs.CommandPrereqs(project, Path.of("/jdk"), Path.of("/v1"), Program.Sbt, Path.of("/sbt")),
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
    val server = (start: ServerStart) =>
      register(start.record)
      Right(())
    val authority = SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
    val runtimes = BrokerRuntimes(session, project, _ => (), authority, Vector.empty)(
      processes, (_, _, _) => Right(assembled), proxy, server, _ => fail("no daemon here"),
    )
    val recordName = s"server-sbt-${RunOnHostSession.buildHash(project)}"
    assert(runtimes.prepare(Program.Sbt, project, Seq("compile")).isRight)
    val proxyName = s"proxy-sbt-${RunOnHostSession.buildHash(project)}"
    def leaderOf(record: Path) = RunOnHostSession.parseRecord(Files.readString(record, UTF_8)).get.pgid
    val serverLeader = leaderOf(session.records.resolve(recordName))
    val proxyLeader = leaderOf(session.records.resolve(proxyName))
    val (reached, proceed) = (java.util.concurrent.CountDownLatch(1), java.util.concurrent.CountDownLatch(1))
    table.pause = Some((reached, proceed))
    val task = java.util.concurrent.FutureTask[Either[String, Option[Runtime]]](() =>
      runtimes.prepare(Program.Sbt, project, Seq("test")))
    val preparing = Thread(task)
    preparing.setDaemon(true)
    preparing.start()
    reached.await()
    table.pause = None
    val teardown = RunOnHostSession.endSession(
      root, session, processes, _ => RunOnHostSession.ServerAnswer.ShutDown, retirementDeadlineMillis = 200,
    )
    val condemned = root.resolve(RunOnHostSession.CondemnedDir).resolve(session.directory.getFileName)
    // The proxy's record shares the server's lock: both wait, both are kept.
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
    // The next start's scavenge collects what the teardown kept: the server's group is dead and
    // skipped; the proxy's lives and is ended.
    val collected =
      RunOnHostSession.scavenge(root, processes, _ => RunOnHostSession.ServerAnswer.ShutDown).flatMap(_(1))
    assertEquals(collected.collect { case RunOnHostSession.Collected.GroupSkipped(g, _) => g }, Vector(serverLeader))
    assertEquals(collected.collect { case RunOnHostSession.Collected.GroupEnded(g) => g }, Vector(proxyLeader))
    assertEquals(table.ended.toList, List(serverLeader, proxyLeader))
    assert(!Files.exists(condemned))

  /** Two brokers of one project in one JVM, over a shared process table and no real spawn: the
    * proxy and the server or daemon are records with table pids, the server's socket a listener
    * under its session's `tmp/` named by the portfile. The sharer's server and daemon seams must
    * never run. */
  /** Three launches' brokers on one project over one process table: `owner` starts the runtime
    * for `dir`, `sharer` would start it alike, `taker` forwards a value the others do not. A
    * stand-in's record names a fresh live leader; ending a group takes its leader from the table
    * and closes the server socket it held, and `leaves` are the groups whose KILL leaves a
    * member listed, the socket with it. `onEnd` runs between a group's proof and its signal,
    * `onAssemble` at each assembly — the tests' seams for what another process does meanwhile. */
  private class Brokers(program: Program):
    val root: Path = Files.createTempDirectory("share")
    val project: Path = Files.createDirectory(root.resolve("project"))
    val dir: Path = Files.createDirectory(project.resolve("app"))
    val hash: String = RunOnHostSession.buildHash(dir)
    val owner: RunOnHostSession.Session =
      RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    val sharer: RunOnHostSession.Session =
      RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    val taker: RunOnHostSession.Session =
      RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
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
    /** The member a KILL left in the group exits, the socket it held closing with it. */
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
    /** A server of `session`'s for `directory`: a listener at the socket sbt derives under its
      * `tmp/`, named by the directory's portfile. */
    def listen(session: RunOnHostSession.Session, directory: Path = dir): Unit =
      val socket = RunOnHostSandbox.expectedServerSocket(session.tmp, directory)
      Files.createDirectories(socket.getParent)
      listeners.remove(socket).foreach(_.close())
      Files.deleteIfExists(socket)
      val listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
      listener.bind(UnixDomainSocketAddress.of(socket))
      listeners(socket) = listener
      writePortfile(directory, socket)
    def listening(session: RunOnHostSession.Session, directory: Path = dir): Boolean =
      listeners.get(RunOnHostSandbox.expectedServerSocket(session.tmp, directory)).exists(_.isOpen)
    /** The owner's server gone on its own: its socket closes with it and its spawn publishes the exit. */
    def serverExits(): Unit =
      listeners.remove(RunOnHostSandbox.expectedServerSocket(owner.tmp, dir)).foreach(_.close())
      Files.writeString(RunOnHostSession.exitRecord(owner.records.resolve(s"server-sbt-$hash")), "0\n", UTF_8)
    def assembled(jdk: String = "/jdk"): Assembled =
      Assembled(
        RunOnHostPrereqs.CommandPrereqs(project, Path.of(jdk), Path.of("/v1"), program, Path.of("/exe")),
        None, Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
      )
    val authority: SeatbeltProfile.RuntimeAuthority = SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty)
    /** Every server and daemon start, by its record. */
    val started = scala.collection.mutable.ListBuffer[Path]()
    val serverArguments = scala.collection.mutable.ListBuffer[Seq[String]]()
    var daemonPid = 0L
    def port(session: RunOnHostSession.Session): Int =
      if session == owner then 7001 else if session == sharer then 7002 else 7003
    def broker(session: RunOnHostSession.Session, jdk: String = "/jdk"): BrokerRuntimes =
      val forwards = if session == taker then Vector("TOKEN" -> "t") else Vector.empty
      BrokerRuntimes(session, project, _ => (), authority, forwards)(
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
          groupSockets += leader -> RunOnHostSandbox.expectedServerSocket(session.tmp, start.buildDirectory)
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
    /** The runtime `session`'s commands run against, its own or attached to. */
    def runtime(session: RunOnHostSession.Session, daemonPort: Option[Int] = None): Either[String, Option[Runtime]] =
      val proxyLog = session.directory.resolve(s"proxy-${program.name}-$hash.log")
      Right(Some(Runtime(session.directory, port(session), proxyLog, daemonPort)))
    def refusal(prepared: Either[String, Option[Runtime]], why: String*): Unit =
      prepared match
        case Left(reason) => why.foreach(word => assert(reason.contains(word), s"'$word' in: $reason"))
        case other        => fail(s"attached, or started, instead of refusing for '${why.mkString(", ")}': $other")
    def close(): Unit =
      listeners.values.foreach(_.close())
      owner.close(); sharer.close(); taker.close()

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
    assume(
      !RunOnHostSessionTest.underRunOnHostProfile,
      "the socket derived under the host's temporary directory is longer than sun_path",
    )
    val two = Brokers(Program.Sbt)
    import two.*
    val proxyName = s"proxy-sbt-$hash"
    val serverName = s"server-sbt-$hash"
    try
      val owning = broker(owner)
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("-Dmode=A", "compile")), runtime(owner))
      val published = RunOnHostRuntimeDescriptor.read(descriptor(owner)).getOrElse(fail("no descriptor"))
      assertEquals(published.proxy, record(owner, proxyName), "bound to the proxy's record")
      assertEquals(published.group, record(owner, serverName), "bound to the server's record")
      assertEquals(published.daemon, None)
      // The sharer attaches: the owner's session, port and log, nothing of its own recorded. Its
      // request's own launcher flags are not compared: the server keeps the flags it was started
      // with, as it does for the owner's later commands (RunOnHostRuntimeDescriptor.fingerprint).
      val sharing = broker(sharer)
      assertEquals(sharing.prepare(Program.Sbt, dir, Seq("-Dmode=B", "test")), runtime(owner))
      assertEquals(sharing.prepare(Program.Sbt, dir, Seq("test")), runtime(owner), "asked again, attached again")
      assertEquals(serverArguments.toList, List(Seq("-Dmode=A", "compile")), "the server's flags are the owner's")
      assertEquals(recordNames(sharer), Nil, "the sharer recorded nothing")
      assert(!Files.exists(RunOnHostSession.buildFile(sharer.directory, hash)), "and published no build file")
      // A rule line the owner did not start from: the sharer would start another proxy, so it
      // ends the owner's server by its record and starts its own — recorded, described, the
      // owner's record left to the owner, its proxy untouched. With the line gone the owner's
      // would-be start differs from the sharer's, so its next command takes the server back,
      // and the sharer, alike again, attaches to it.
      val firstServer = serverLeader(owner)
      val rule = project.resolve(".ko-agent-sandbox/run-on-host/sbt/egress/rule")
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
      // A forwarded value: the taker and the owner differ for good, and alternate: each command
      // ends the other launch's server and starts its own under its own proxy.
      val taking = broker(taker)
      val secondServer = serverLeader(owner)
      assertEquals(taking.prepare(Program.Sbt, dir, Seq("-Dmode=C", "compile")), runtime(taker))
      assertEquals(ended.toList, List(firstServer, sharerServer, secondServer))
      val takerServer = serverLeader(taker)
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      assertEquals(ended.toList, List(firstServer, sharerServer, secondServer, takerServer))
      assertEquals(taking.prepare(Program.Sbt, dir, Seq("test")), runtime(taker))
      val thirdServer = serverLeader(taker)
      assertEquals(ended.size, 5)
      // A KILL that leaves a member listed: the owner's command is refused naming the record,
      // signalled once; the taker's next command reuses its server, whose group still lives,
      // and once the taker's own replacement finds the leader gone with a member listed, its
      // record is kept and the start refused, until the member is gone too.
      leaves += thirdServer
      refusal(owning.prepare(Program.Sbt, dir, Seq("test")), "another launch's broker", "not ended", "after the KILL")
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
      // The owner's server gone on its own: the sharer takes over what is left — the leader —
      // and starts its own; a descriptor of a replaced server, restored over the successor's,
      // names other records than the present ones, and is taken over too.
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
      // The owner's session moving into condemned/ between its lookup and the takeover's read:
      // the record is looked up once more where it is now, and the group ended there.
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
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the socket derived under the host's temporary directory")
    val two = Brokers(Program.Sbt)
    import two.*
    try
      assertEquals(broker(owner).prepare(Program.Sbt, dir, Seq("compile")), runtime(owner))
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
      // The teardown has proved the leader and holds the lock: the taker, finding the owner in
      // condemned/, waits rather than prove and signal the same group.
      val taking = inThread(broker(taker).prepare(Program.Sbt, dir, Seq("compile")))
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

  test("a takeover ends the recorded group, never what the portfile or a planted link leads to"):
    assume(!RunOnHostSessionTest.underRunOnHostProfile, "the socket derived under the host's temporary directory")
    val two = Brokers(Program.Sbt)
    import two.*
    val other = Files.createDirectory(project.resolve("lib"))
    try
      val owning = broker(owner)
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("compile")), runtime(owner))
      assert(owning.prepare(Program.Sbt, other, Seq("compile")).isRight)
      val otherServer = RunOnHostSession.parseRecord(
        Files.readString(owner.records.resolve(s"server-sbt-${RunOnHostSession.buildHash(other)}"), UTF_8),
      ).get.pgid
      val otherSocket = RunOnHostSandbox.expectedServerSocket(owner.tmp, other)
      // `dir`'s portfile naming the other directory's live socket: the takeover ends the group
      // `dir`'s record names, and the start that follows refuses the live foreign socket the
      // portfile leads to (noForeignServer), the other server never signalled.
      val taking = broker(taker)
      writePortfile(dir, otherSocket)
      val first = serverLeader(owner)
      val foreignSocket = "a live sbt server holds this build directory's portfile"
      refusal(taking.prepare(Program.Sbt, dir, Seq("compile")), foreignSocket)
      assertEquals(ended.filter(_ == otherServer).toList, Nil)
      assertEquals(ended.filter(_ == first).toList, List(first))
      assert(listening(owner, other))
      // The owner's next command starts a fresh server under its proxy and rewrites the portfile.
      assertEquals(owning.prepare(Program.Sbt, dir, Seq("test")), runtime(owner))
      // A link planted at the owner's socket directory for `dir` during the takeover's end of
      // the group, leading to the other server: the group ended is the record's, and the start
      // that follows refuses the link's live socket as any start does.
      val second = serverLeader(owner)
      val socketDir = RunOnHostSandbox.expectedServerSocket(owner.tmp, dir).getParent
      onEnd = pgid =>
        if pgid == second then
          listeners.remove(RunOnHostSandbox.expectedServerSocket(owner.tmp, dir)).foreach(_.close())
          FileHelper.directoryEntries(socketDir).foreach(Files.delete)
          Files.delete(socketDir)
          Files.createSymbolicLink(socketDir, otherSocket.getParent)
      refusal(taking.prepare(Program.Sbt, dir, Seq("compile")), foreignSocket)
      assertEquals(ended.filter(_ == otherServer).toList, Nil, "the other server is never signalled")
      assertEquals(ended.filter(_ == second).toList, List(second))
      assert(listening(owner, other))
      Files.delete(socketDir)
    finally close()

  test("a second launch attaches to another launch's mill daemon under the directory's configuration, else takes over"):
    val two = Brokers(Program.Mill)
    import two.*
    try
      val owning = broker(owner)
      assertEquals(owning.prepare(Program.Mill, dir, Seq("compile")), runtime(owner, Some(40_001)))
      val published = RunOnHostRuntimeDescriptor.read(descriptor(owner)).getOrElse(fail("no descriptor"))
      assertEquals(published.daemon, Some(RunOnHostMillDaemons.Daemon(daemonPid, s"START-$daemonPid", 40_001)))
      val sharing = broker(sharer)
      assertEquals(sharing.prepare(Program.Mill, dir, Seq("test")), runtime(owner, Some(40_001)))
      assertEquals(recordNames(sharer), Nil)
      // A configuration edit: the daemon is not the directory's, so the sharer ends its
      // starter's group and starts its own under the new configuration; the owner's next
      // command, whose own daemon is gone and whose would-be start is now the sharer's, attaches.
      Files.writeString(dir.resolve(".mill-jvm-opts"), "-Xmx1g\n", UTF_8)
      val firstStarter = daemonLeader(owner)
      assertEquals(sharing.prepare(Program.Mill, dir, Nil), runtime(sharer, Some(40_001)))
      assertEquals(ended.toList, List(firstStarter))
      assertEquals(started.size, 2)
      assertEquals(owning.prepare(Program.Mill, dir, Seq("test")), runtime(sharer, Some(40_001)))
      assertEquals(started.size, 2)
      assertEquals(recordNames(owner), List(s"proxy-mill-$hash"), "the owner's dead record discarded, its proxy kept")
      // The daemon gone — its idle exit, a cancel — while its starter's leader stays: the
      // owner's command takes over what is left and starts its own.
      val sharerStarter = daemonLeader(sharer)
      alive -= daemonPid
      assertEquals(owning.prepare(Program.Mill, dir, Seq("test")), runtime(owner, Some(40_001)))
      assertEquals(ended.toList, List(firstStarter, sharerStarter))
      assertEquals(started.size, 3)
    finally close()

  test("after a gradle command the broker records the launch's daemons; after any other program nothing"):
    val root = Files.createTempDirectory("brk")
    val project = Files.createDirectory(root.resolve("project"))
    val session = RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker).toOption.get
    val processes = new RunOnHostSession.Processes:
      def startOf(pid: Long): Option[String] = Option.when(pid == 4242)("S")
      def endGroup(pgid: Long): Boolean = true
      def groupEmpty(pgid: Long): Boolean = true
      def signal(pid: Long, name: String): Unit = fail(s"signalled $pid with $name")
    val observed = scala.collection.mutable.ListBuffer[Path]()
    val logged = scala.collection.mutable.ListBuffer[String]()
    val runtimes = BrokerRuntimes(
      session, project, logged.append(_), SeatbeltProfile.RuntimeAuthority(Seq.empty, Seq.empty), Vector.empty,
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
      // The registry observed is the launch's, under this session's tmp; the record proves the pid.
      assertEquals(observed.toList, List(session.tmp))
      assertEquals(Files.readString(record, UTF_8), "4242 S\n")
      assertEquals(logged.toList, List("recorded the gradle daemon 4242"))
    finally session.close()

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
object ForkJvmSettings:
  def main(args: Array[String]): Unit =
    val command = ProcessBuilder(
      Path.of(sys.props("java.home"), "bin/java").toString,
      "-Djava.io.tmpdir=/build-option", "-XshowSettings:properties", "-version",
    )
    sys.exit(command.inheritIO().start().waitFor())
