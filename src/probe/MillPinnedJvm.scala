#!/usr/bin/env -S scala shebang
//> using scala 3.10.1
//> using file ../test/scala/HostDriver.scala
//> using file ../test/scala/RunOnHostIdle.scala
//> using file ../test/scala/RunOnHostChecks.scala

/*
  Measures what Mill does under the command profile when a build pins its JVM with `mill-jvm-version: temurin:21`.
  RunOnHostPrereqs.millRecordedJdk rests on these measurements (doc/run-on-host-internals.md, "A pinned JVM"). Run the
  probe on each new Mill release.

  Mill's launcher writes the JDK home that it resolved for the pin to `out/mill-daemon/cache/java-home`, with a key
  that names the pin. The launcher uses that home while the key matches and the directory exists
  (`CoursierClient.resolveJavaHome`, Mill 1.1.10). The supervisor grants the JDK that the file names, and a command
  can write that file. So the rows measure whether Mill then runs that JDK without fetching, and what Mill does when
  the file is absent, has another key or names another JDK.

  Run the probe on the macOS HOST from the repository root, with no sandbox session on this workspace:

      src/probe/MillPinnedJvm.scala [PIN]     # a Coursier JVM id; temurin:21 when omitted

  - A pin that resolves to the JDK that JAVA_HOME names measures no second grant, so pass a pin that resolves to
    another JDK.
  - The provisioning run runs as you: Mill's launcher runs unconfined in your environment. The run downloads the
    pinned JDK into your Coursier cache, where the JDK stays.
  - Every row runs `mill --no-daemon --version`, which prints the `java.home` of the JVM that Mill started and
    evaluates no build. `--no-daemon` and a daemon start take the JVM from the same call
    (`MillProcessLauncher.javaExe`), so the rows need no runner. No proxy runs: a row that fetches fails at its first
    fetch, and the row's log names the host.
*/

import agentsandbox.launcher.HostDriver
import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.*
import agentsandbox.launcher.RunOnHostIdle

import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*
import scala.util.Using

@main def measure(args: String*): Unit = MillPinnedJvm.run(args)

object MillPinnedJvm:
  private val env: String => Option[String] = sys.env.get

  /** The pair that Mill writes (`CoursierClient.cached`), read as RunOnHostPrereqs.millRecordedJdk reads it: a file
    * that this pattern does not match is one the supervisor refuses as well. */
  private val RecordedJavaHome = raw"""\["([^"\\]*)","([^"\\]*)"\]""".r

  def run(args: Seq[String]): Unit =
    orExit(Either.cond(sys.props("os.name") == "Mac OS X", (), "Run this on macOS."))
    val pin = args.headOption.getOrElse("temurin:21")
    orExit(Either.cond(pin != "system" && pin.matches("[A-Za-z0-9.:+_-]+"), (),
      "usage: src/probe/MillPinnedJvm.scala [PIN]   a Coursier JVM id other than system, such as temurin:21"))
    val workspace = workingDir.toRealPath()
    val sourceFixture = workspace / "src" / "test" / "run-on-host" / "fixtures" / "mill"
    orExit(Either.cond(Files.isExecutable(sourceFixture / "mill"), (), "Run this from the repository root."))
    val home = orExit(env("HOME").filter(_.nonEmpty).map(Path.of(_)).toRight("HOME is not set"))
    val jdkHome = orExit(env("JAVA_HOME").map(Path.of(_)).filter(home => Files.isExecutable(home / "bin" / "java"))
      .map(_.toRealPath()).toRight("JAVA_HOME must name the granted JDK."))
    // The directories where Coursier unpacks JDKs, as RunOnHostPrereqs.coursierUnpacked locates them.
    val archiveCache = orExit(userCoursierDirectory(env, home, CoursierDirectory.Archive).flatMap: dir =>
      Option.when(Files.isDirectory(dir))(dir.toRealPath()).toRight(s"no Coursier archive cache at $dir"))
    val jvmCache = userCoursierDirectory(env, home, CoursierDirectory.Jvm).toOption.filter(Files.isDirectory(_))
      .map(_.toRealPath())
    // The probe interpolates paths into the emit's sbt command, which sbt's command parser reads, into the profile's
    // string literals and into the java-home file's JSON. In each place, a quote or backslash would end the quoting.
    def safePath(what: String, path: Path): Unit =
      orExit(Either.cond(!path.toString.exists("'\"\\".contains(_)), (),
        s"$what contains a quote or backslash and cannot be interpolated safely: $path"))
    safePath("the checkout path", workspace)
    safePath("JAVA_HOME", jdkHome)
    val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
    RunOnHostIdle.requireIdle(RunOnHostIdle.supervisorRoot(uid), Seq(workspace)).left.foreach: refusal =>
      System.err.println(refusal)
      sys.exit(1)

    // A fixed path: the run-on-host cache is kept per workspace path, so a new path in each run would leave a cache
    // behind each time.
    val work = workspace / "target" / "mill-pinned-jvm"
    val fixture = work / "pinned-jvm-fixture"
    val javaHomeFile = fixture / "out" / "mill-daemon" / "cache" / "java-home"
    removeTree(work)
    Files.createDirectories(fixture)
    for name <- Seq("mill", "build.mill.yaml") do
      Files.copy(sourceFixture / name, fixture / name, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES)
    val buildFile = Files.readString(sourceFixture / "build.mill.yaml")
    if !buildFile.linesIterator.contains("mill-jvm-version: system") then
      fail(s"$sourceFixture/build.mill.yaml has no 'mill-jvm-version: system' line to replace")

    println("machine")
    val macOS = firstLine(Seq("/usr/bin/sw_vers", "-productVersion"))
    println(s"  macOS $macOS, ${firstLine(Seq("/usr/bin/uname", "-m"))}")
    println(s"  JAVA_HOME: $jdkHome (${firstLine(Seq((jdkHome / "bin" / "java").toString, "-version"))})")
    val millVersion =
      "\"[0-9][^\"]*\"".r.findFirstIn(Files.readString(fixture / "mill")).getOrElse("?").replace("\"", "")
    println(s"  mill $millVersion, pin $pin")

    // The emit creates a temporary directory for this run alone (EmitRunOnHostProfile.newSessionTmp). The cleanup
    // removes it, and the fixture, which the next launch's provisioning would meet as a build directory.
    var sessionTmp: Option[Path] = None
    Runtime.getRuntime.addShutdownHook(Thread: () =>
      sessionTmp.filter(_.toString.matches("/private/tmp/ko-agent-[^/]*-accept/[^/]+/tmp"))
        .foreach(tmp => removeTree(tmp.getParent))
      removeTree(fixture))

    // The probe emits the profile before the pin replaces `system`, so the profile grants no pinned JDK. The rows add
    // that grant themselves.
    println(s"emitting the mill profile, for $fixture")
    val baseProfile = work / "base.sb"
    val emit = HostDriver.run(Seq("sbt", "-batch",
      s"Test/runMain agentsandbox.launcher.EmitRunOnHostProfile \"$baseProfile\" $SystemPathsFile mill \"$fixture\""))
    Files.writeString(work / "emit.log", emit.text)
    if !emit.ok then fail(s"emit failed:\n${emit.text.linesIterator.toSeq.takeRight(20).mkString("\n")}")
    HostDriver.run(Seq("sbt", "--jvm-client", "-batch", "shutdown"))
    def emitted(prefix: String): Option[String] =
      emit.text.linesIterator.collectFirst { case line if line.startsWith(prefix) => line.stripPrefix(prefix) }
    sessionTmp = Files.readAllLines(work / "base.sb.env").asScala
      .collectFirst { case line if line.startsWith("SESSION_TMP=") => Path.of(line.stripPrefix("SESSION_TMP=")) }
    val (tmp, cacheV1, millExecutable) = (sessionTmp, emitted("run-on-host cache: "), emitted("executable: ")) match
      case (Some(tmp), Some(cache), Some(executable)) if Files.isExecutable(Path.of(executable)) =>
        (tmp, Path.of(cache), Path.of(executable))
      case _ =>
        fail(s"emit named no command temporary directory, run-on-host cache or mill executable (${work / "emit.log"})")
    safePath("the command's temporary directory", tmp)

    // The supervisor's closed environment (RunOnHostSandbox.commandEnvironment), without its proxy settings.
    val account = sys.props("user.name")
    val closedEnvironment = Map(
      "PATH" -> s"$jdkHome/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      "JAVA_HOME" -> jdkHome.toString,
      "HOME" -> home.toString,
      "TMPDIR" -> tmp.toString,
      "COURSIER_CACHE" -> cacheV1.toString,
      "USER" -> account,
      "LOGNAME" -> account,
      "_JAVA_OPTIONS" ->
        s"-Djava.io.tmpdir=\"$tmp\" -Djava.util.prefs.userRoot=\"$tmp\" -Djava.net.preferIPv4Stack=true",
    ) ++ Seq("LANG", "LC_ALL").flatMap(name => env(name).map(name -> _))
    val versionCommand = Seq(millExecutable.toString, "--no-daemon", "--version")
    def logged(log: Path, output: Output): Output =
      Files.writeString(log, output.text)
      output
    // Runs the launcher file itself, as BuildsCheck's row "read and execute the mill launcher" runs it. A hang ends
    // the row, not the probe.
    def runMill(profile: Path, log: Path): Output =
      logged(log, HostDriver.run(Seq("/usr/bin/sandbox-exec", "-f", profile.toString) ++ versionCommand, cwd = fixture,
        timeoutSeconds = Some(300), environment = closedEnvironment, inheritEnvironment = false))
    def javaHomeOf(output: Output): Option[String] =
      output.text.linesIterator.collectFirst { case line if line.startsWith("java.home: ") => line.drop(11) }

    // This fetch runs unconfined, because no proxy runs here. A supervisor's first command fetches the same jars
    // through the supervisor's proxy.
    println(s"fetching Mill's own classpath into the run-on-host cache, unconfined ($cacheV1)")
    val warm = logged(work / "warm.log",
      HostDriver.run(versionCommand, cwd = fixture, environment = closedEnvironment, inheritEnvironment = false))
    if !warm.ok then fail(s"the fixture does not run unconfined:\n${said(warm)}")

    println("control: mill-jvm-version: system under the profile")
    val control = runMill(baseProfile, work / "control.log")
    javaHomeOf(control).filter(_ => control.ok) match
      case Some(ran) => println(s"  ran $ran")
      case None =>
        fail(s"  it does not run, so the rows would measure nothing (${work / "control.log"}):\n${said(control)}")

    Files.writeString(fixture / "build.mill.yaml", buildFile.linesIterator
      .map(line => if line == "mill-jvm-version: system" then s"mill-jvm-version: $pin" else line)
      .mkString("", "\n", "\n"))
    println(s"provisioning $pin: the launcher, unconfined, in your environment (${work / "provision.log"})")
    println("  the first run for a pin downloads its JDK")
    val provision = logged(work / "provision.log", HostDriver.run(versionCommand, cwd = fixture))
    if !provision.ok then fail(s"the provisioning run failed:\n${said(provision)}")
    if !Files.isRegularFile(javaHomeFile) then fail(s"the provisioning run left no $javaHomeFile")

    val (pinnedKey, recordedHome) = Files.readString(javaHomeFile) match
      case RecordedJavaHome(key, recorded) => (key, recorded)
      case text => fail(s"$javaHomeFile is not the pair Mill writes: $text")
    val pinnedHome = Some(Path.of(recordedHome)).filter(Files.isDirectory(_)).map(_.toRealPath())
      .getOrElse(fail(s"$javaHomeFile names no directory: $recordedHome"))
    safePath("the pinned home", pinnedHome)
    println()
    println("the java-home file the provisioning run wrote")
    println(s"  key:  $pinnedKey")
    println(s"  home: $recordedHome")
    if pinnedHome.toString != recordedHome then println(s"  canonical: $pinnedHome")
    println(s"  ${firstLine(Seq((pinnedHome / "bin" / "java").toString, "-version"))}")
    jdkHomeRefusal(pinnedHome, archiveCache, jvmCache) match
      case None => println("  the home passes the checks JAVA_HOME passes (RunOnHostPrereqs.resolveJdkHome)")
      case Some(refusal) =>
        println(s"  the home fails a check JAVA_HOME passes (RunOnHostPrereqs.resolveJdkHome): $refusal")
    println(s"  it is ${if pinnedHome.startsWith(archiveCache) then "inside" else "outside"} your Coursier archive " +
      s"cache, $archiveCache")
    val distinct = pinnedHome != jdkHome
    if !distinct then println("  it is the JDK JAVA_HOME names: the rows that withhold or swap the grant are skipped")

    // granted.sb is base.sb with the pinned home granted the way JAVA_HOME's home is: read and execute on the home,
    // and metadata on each ancestor. The grant goes right after JAVA_HOME's grant, so that the guard denies stay last.
    val ownGrant = s"""(allow process-exec* file-read* (subpath "$jdkHome"))"""
    val pinnedGrant =
      Iterator.iterate(pinnedHome.getParent)(_.getParent).takeWhile(dir => dir != null && dir.getParent != null)
        .map(dir => s"""(allow file-read-metadata file-test-existence (literal "$dir"))""").toSeq :+
        s"""(allow process-exec* file-read* (subpath "$pinnedHome"))"""
    val baseLines = Files.readAllLines(baseProfile).asScala.toSeq
    if !baseLines.contains(ownGrant) then
      fail(s"$baseProfile has no grant of $jdkHome to place the pinned home's after")
    val grantedProfile = work / "granted.sb"
    Files.write(grantedProfile, baseLines.flatMap(line => if line == ownGrant then line +: pinnedGrant else Seq(line))
      .asJava)

    var rows = 0
    // The java-home file that the row starts with: the key and home, or none for an empty key.
    def row(label: String, profile: Path, key: String, recorded: String): Unit =
      rows += 1
      Files.deleteIfExists(javaHomeFile)
      if key.nonEmpty then Files.writeString(javaHomeFile, s"""["$key","$recorded"]""")
      def fileText = if Files.isRegularFile(javaHomeFile) then Files.readString(javaHomeFile) else ""
      val before = fileText
      val stamp = Files.writeString(work / "stamp", "")
      val output = runMill(profile, work / s"row-$rows.log")
      val after = fileText
      val jvm = javaHomeOf(output) match
        case None => "no JVM"
        case Some(ran) if ran == pinnedHome.toString || ran == recordedHome => "the pinned JDK"
        case Some(ran) if ran == jdkHome.toString => "JAVA_HOME's JDK"
        case Some(ran) => s"another JDK, $ran"
      val fileAfter =
        if before.isEmpty && after.isEmpty then "not written"
        else if after == before then "unchanged"
        else if after.isEmpty then "removed"
        else s"written, $after"
      println(s"  $label")
      println(s"      exit ${output.status}, ran $jvm; ${writtenSince(cacheV1, stamp)} files written under the " +
        s"run-on-host cache; java-home file $fileAfter")
      if !output.ok then println(said(output))

    println()
    println("rows: mill --no-daemon --version under the command profile, no proxy running")
    row("java-home file present, its home granted", grantedProfile, pinnedKey, recordedHome)
    if distinct then row("java-home file present, its home not granted", baseProfile, pinnedKey, recordedHome)
    row("java-home file absent, the pinned home granted", grantedProfile, "", "")
    row("java-home file under another key, the pinned home granted", grantedProfile, s"stale $pinnedKey", recordedHome)
    if distinct then
      row("java-home file names JAVA_HOME's JDK under the pin's key", baseProfile, pinnedKey, jdkHome.toString)

    println()
    println(s"logs: $work")

  /** The first check of RunOnHostPrereqs.resolveJdkHome that a canonical home fails, or None. */
  private def jdkHomeRefusal(home: Path, archiveCache: Path, jvmCache: Option[Path]): Option[String] =
    val inArchive = home.startsWith(archiveCache) && home != archiveCache && home.getParent != archiveCache
    val inJvm = jvmCache.exists(jvm => home.startsWith(jvm) && home != jvm)
    val java = home / "bin" / "java"
    val realJava = Option.when(Files.exists(java))(java.toRealPath())
    if !inArchive && !inJvm then
      val jvm = jvmCache.fold("a JVM cache")(_.toString)
      Some(s"it is neither two or more levels inside $archiveCache nor inside $jvm")
    else
      realJava match
        case Some(binary) if binary.startsWith(home) =>
          Option.unless(Files.isRegularFile(binary) && Files.isExecutable(binary))("bin/java is not an executable file")
        case other => Some(s"bin/java resolves outside it, to ${other.fold("nothing")(_.toString)}")

  /** The regular files under the directory modified after the stamp, as `find -newer` counts them. */
  private def writtenSince(dir: Path, stamp: Path): Int =
    val since = Files.getLastModifiedTime(stamp)
    Using.resource(Files.walk(dir)):
      _.iterator.asScala.count: path =>
        Files.isRegularFile(path) && Files.getLastModifiedTime(path).compareTo(since) > 0

  /** What a log says, without the JVM's own notices, stack frames and Coursier's progress. */
  private def said(output: Output): String =
    output.text.linesIterator
      .filterNot(line => Seq("Picked up ", "WARNING: ", "Downloading ", "  not found: ").exists(line.startsWith))
      .filterNot(_.matches("\\s*at .*"))
      .take(4).map(line => "      " + line.take(150)).mkString("\n")

  private def firstLine(command: Seq[String]): String =
    HostDriver.run(command).text.linesIterator.nextOption().getOrElse("").trim

  private def fail(message: String): Nothing =
    println(message)
    sys.exit(1)
