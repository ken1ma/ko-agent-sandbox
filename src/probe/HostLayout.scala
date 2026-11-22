#!/usr/bin/env -S scala shebang
//> using scala 3.10.1
//> using file ../test/scala/HostDriver.scala
//> using file ../test/scala/RunOnHostIdle.scala
//> using file ../test/scala/RunOnHostChecks.scala

/*
  Lists what is installed on this host and where: the layout that RunOnHostPrereqs encodes.

  Run the probe on the macOS HOST, from the workspace root, on a new machine and after upgrading Coursier or the JDK:

      src/probe/HostLayout.scala

  - Every "MISSING" line is a case that the prerequisite classifier has to name, not a gap to fill in silently.
  - A line that disagrees with RunOnHostPrereqsTest's fixtures is a finding, not a test to relax.
  - The probe only reads, except for one temporary directory that it creates in the workspace and removes.
*/

import agentsandbox.launcher.HostDriver
import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.*

import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*
import scala.util.Using

@main def layout(): Unit = HostLayout.run()

object HostLayout:
  private val env: String => Option[String] = sys.env.get

  def run(): Unit =
    // Inside a sandbox session, every answer would describe the container, and the output would read as a host that
    // misses its whole toolchain.
    orExit(Either.cond(sys.props("os.name") == "Mac OS X", (),
      s"This probe reports a macOS host's layout; this is ${sys.props("os.name")}. Run it on macOS."))
    val inSession =
      env("KO_AGENT_SANDBOX_EGRESS_RULESET").isDefined || Files.isDirectory(Path.of("/etc/ko-agent-sandbox"))
    orExit(Either.cond(!inSession, (), "This looks like a sandbox session. Run the probe on the host instead."))
    val home = orExit(env("HOME").filter(_.nonEmpty).map(Path.of(_)).toRight("HOME is not set"))
    val workspace = workingDir.toRealPath()
    val cacheHome = env("XDG_CACHE_HOME").filter(_.nonEmpty).map(Path.of(_)).getOrElse(home / ".cache")

    section("host")
    say("macOS", stdout("/usr/bin/sw_vers", "-productVersion").getOrElse("unknown"))
    say("arch", stdout("/usr/bin/uname", "-m").getOrElse("unknown"))
    say("sandbox-exec", present(Path.of("/usr/bin/sandbox-exec")))

    section("environment overrides")
    for variable <- Seq("XDG_CACHE_HOME", "XDG_STATE_HOME", "COURSIER_CACHE", "COURSIER_ARCHIVE_CACHE",
        "COURSIER_JVM_CACHE", "COURSIER_BIN_DIR", "MILL_FINAL_DOWNLOAD_FOLDER", "MILL_USER_CACHE_DIR", "JAVA_HOME",
        "SBT_OPTS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS")
    do say(variable, env(variable).filter(_.nonEmpty).getOrElse("(unset)"))

    section("workspace")
    say("canonical workspace root", workspace.toString)
    val probeDir = Files.createTempDirectory(workspace, ".layout-probe.")
    try
      Files.createFile(probeDir / "casetest")
      say("filesystem case", if Files.exists(probeDir / "CASETEST") then "insensitive" else "sensitive")
    finally removeTree(probeDir)
    val buildProperties = workspace / "project" / "build.properties"
    say("project/build.properties",
      if Files.isRegularFile(buildProperties) then Files.readString(buildProperties).trim else "MISSING")
    say("mill bootstrap", if Files.isRegularFile(workspace / "mill") then "./mill" else "MISSING")

    section("coursier")
    onPath("cs") match
      case Some(cs) =>
        val real = cs.toRealPath()
        say("cs on PATH", cs.toString)
        say("cs real path", real.toString)
        say("cs version", stdout(cs.toString, "version").getOrElse("unknown"))
        say("cs install dir", real.getParent.toString)
      case None => absent("cs on PATH", "cs install sbt is a prerequisite")

    val cacheRoot = home / "Library" / "Caches" / "Coursier"
    println("(measuring cache sizes; a large v1 has millions of inodes and this can take a minute)")
    say("cache root", if Files.isDirectory(cacheRoot) then cacheRoot.toString else s"MISSING $cacheRoot")
    for directory <- CoursierDirectory.values do
      val label = s"  ${directory.subdirectory}"
      userCoursierDirectory(env, home, directory) match
        case Left(reason) =>
          say(label, s"$reason; it lies under the current directory of each program that runs Coursier")
        case Right(dir) if Files.isDirectory(dir) =>
          val size = stdout("/usr/bin/du", "-sh", dir.toString).map(_.takeWhile(!_.isWhitespace)).getOrElse("?")
          say(label, s"present at $dir, $size ${listedNames(dir).size} entries")
        case Right(dir) => say(label, s"MISSING $dir")
    userCoursierDirectory(env, home, CoursierDirectory.Jvm).toOption.filter(Files.isDirectory(_)).foreach: jvm =>
      println("  managed JVMs:")
      listedNames(jvm).foreach(name => println(s"    $name"))

    section("sbt")
    onPath("sbt") match
      case Some(sbt) =>
        val real = sbt.toRealPath()
        say("sbt on PATH", sbt.toString)
        say("sbt real path", real.toString)
        say("first line", firstLine(real).take(70))
      case None => absent("sbt on PATH", "cs install sbt")

    section("mill")
    val millCache = cacheHome / "mill"
    say("user cache dir", if Files.isDirectory(millCache) then millCache.toString else s"MISSING $millCache")
    val downloads = millCache / "download"
    say("download folder", if Files.isDirectory(downloads) then listedNames(downloads).mkString(" ") else "MISSING")

    section("maven")
    val mavenDists = env("MAVEN_USER_HOME").filter(_.nonEmpty).map(Path.of(_)).getOrElse(home / ".m2") /
      "wrapper" / "dists"
    say("workspace wrapper", if Files.isExecutable(workspace / "mvnw") then "mvnw" else "MISSING")
    val wrapperProperties = workspace / ".mvn" / "wrapper" / "maven-wrapper.properties"
    say("distributionUrl",
      if Files.isRegularFile(wrapperProperties) then
        Files.readAllLines(wrapperProperties).asScala.collect:
          case line if line.startsWith("distributionUrl=") => line.stripPrefix("distributionUrl=")
        .mkString(" ")
      else "MISSING")
    say("wrapper dists",
      if Files.isDirectory(mavenDists) then listedNames(mavenDists).mkString(" ") else s"MISSING $mavenDists")

    section("what a Seatbelt profile would name")
    say("WORKSPACE", workspace.toString)
    say("COURSIER_JDK_HOME", env("JAVA_HOME").filter(_.nonEmpty).getOrElse("UNSET — a prerequisite failure"))
    say("MILL_DOWNLOAD", (cacheHome / "mill" / "download").toString)
    say("RUN_ON_HOST_COURSIER_V1",
      (cacheHome / "ko-agent-sandbox" / "run-on-host" / "<workspaceId>" / "coursier" / "v1").toString)
    println()
    println("The sbt distribution is the other half of PROGRAM; src/probe/SbtExecChain.scala finds it.")

  private def section(title: String): Unit =
    println()
    println(s"=== $title ===")

  private def say(label: String, value: String): Unit = println(f"$label%-34s $value")

  private def absent(label: String, remedy: String): Unit = say(label, s"MISSING ($remedy)")

  private def present(path: Path): String = if Files.isExecutable(path) then path.toString else "MISSING"

  /** The command's first line on stdout when it succeeds. */
  private def stdout(command: String*): Option[String] =
    val output = HostDriver.run(command, discardStderr = true)
    Option.when(output.ok)(output.text.linesIterator.nextOption().getOrElse("").trim)

  /** The first line of a file that can carry an appended jar, read as bytes up to the first newline. */
  private def firstLine(file: Path): String =
    Using.resource(Files.newInputStream(file)): in =>
      String(in.readNBytes(4096).takeWhile(_ != '\n'), java.nio.charset.StandardCharsets.ISO_8859_1)
