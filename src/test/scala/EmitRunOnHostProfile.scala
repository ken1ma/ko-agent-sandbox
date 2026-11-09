// Writes the generated Seatbelt profile for the workspace that this driver runs in, so that a developer can drive a
// real build under the profile by hand.
//
// The driver lives in test scope on purpose. The run-on-host checks (src/test/run-on-host/) and probes are its only
// callers, and a profile emitter in the shipped jar would be a command that no document describes.
//
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> [system-paths-file] [<program>] [workspace]"
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> <system-paths-file> proxy <jdk> <classpath>"
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> <system-paths-file> proxy-image <binary>"
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile --checks <out-dir> <system-paths-file> \
//     <id>,<program>,<workspace>..."
//
// - The checks form is the run-on-host checks' setup, in one sbt run. It first checks every build directory for a
//   missing host run, prints every one it finds and exits 3. Otherwise it writes, into the output directory, each
//   profile as <id>.sb and the values its rows need as <id>.properties, the relaunch classpath as classpath.txt, and
//   the proxy's own profile, for JAVA_HOME and that classpath, as proxy.sb. The id tells apart two profiles of one
//   program, such as a fixture's and its copy on an older release.
// - The workspace defaults to the working directory. The mill rows name src/test/run-on-host/fixtures/mill.
// - RunOnHostSandbox.readSystemPaths defines the grammar of the system-paths file.
// - The proxy form renders the host proxy's own profile for the java and the class path that SeatbeltCheck runs its
//   proxy rows with.
// - The proxy-image form renders the host proxy's profile for a native image. RunOnHostProxy.proxyInputs builds the
//   inputs for a native image only when the proxy runs as one.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import RunOnHostPrereqs.*
import RunOnHostProvisioning.BuildDirectory

object EmitRunOnHostProfile:

  def main(args: Array[String]): Unit =
    if args.isEmpty then
      Console.err.println("usage: EmitRunOnHostProfile <out.sb> [system-paths-file] [sbt|mill|gradle|mvn] [workspace]")
      Console.err.println("       EmitRunOnHostProfile <out.sb> <system-paths-file> proxy <jdk> <classpath>")
      Console.err.println("       EmitRunOnHostProfile <out.sb> <system-paths-file> proxy-image <binary>")
      sys.exit(2)

    if args.head == "--checks" then checks(args.toList.tail)

    if args.lift(2).contains("proxy") then
      if args.length != 5 then fail("the proxy form takes <out.sb> <system-paths-file> proxy <jdk> <classpath>")
      val systemPaths = RunOnHostSandbox.readSystemPaths(args.lift(1).map(Paths.get(_)))
      val profile = RunOnHostProxy.proxyInputs(systemPaths, javaHome = args(3), classPath = args(4))
        .flatMap(SeatbeltProfile.renderProxy).fold(fail, identity)
      Files.writeString(Paths.get(args(0)), profile)
      Console.err.println(s"profile: ${args(0)}")
      sys.exit(0)

    if args.lift(2).contains("proxy-image") then
      if args.length != 4 then fail("the proxy-image form takes <out.sb> <system-paths-file> proxy-image <binary>")
      val systemPaths = RunOnHostSandbox.readSystemPaths(args.lift(1).map(Paths.get(_)))
      val binary = Paths.get(args(3)).toRealPath()
      val profile =
        SeatbeltProfile
          .renderProxy(SeatbeltProfile.ProxyInputs(Seq(binary), Seq.empty, systemPaths))
          .fold(fail, identity)
      Files.writeString(Paths.get(args(0)), profile)
      Console.err.println(s"profile: ${args(0)}")
      sys.exit(0)

    val workspace = Paths.get(args.lift(3).getOrElse("")).toAbsolutePath.toRealPath()

    val program = args.lift(2).map(_.toLowerCase) match
      case None        => Program.Sbt
      case Some(name)  => Program.named(name).getOrElse(fail(s"unknown program $name"))

    val systemPaths = RunOnHostSandbox.readSystemPaths(args.lift(1).map(Paths.get(_)))
    val (assembled, sessionTmp) = emit(Paths.get(args(0)), systemPaths, program, workspace)
    // The driver needs the command's temporary directory, because the profile grants that directory. Without it, the
    // JVM writes to the per-user temporary directory, which the profile does not grant.
    Files.writeString(Paths.get(args(0) + ".env"), s"SESSION_TMP=$sessionTmp\n")
    Console.err.println(s"profile: ${args(0)}")
    Console.err.println(s"env: ${args(0)}.env")
    Console.err.println(s"command temporary directory: $sessionTmp")
    Console.err.println(s"run-on-host cache: ${assembled.prereqs.coursierV1}")
    Console.err.println(s"program: $program")
    Console.err.println(s"executable: ${assembled.prereqs.executable}")
    Console.err.println(s"sbt global base: ${assembled.sbtGlobal}")
    Console.err.println(s"ivy home: ${assembled.ivyHome}")
    Console.err.println(s"gradle user home: ${assembled.gradleUserHome}")
    Console.err.println(s"m2 repository: ${assembled.m2Repository}")
    Console.err.println(s"classpath: ${relaunchClasspath(Paths.get(args(0) + ".cp"))}")

  private val env: String => Option[String] = name => Option(System.getenv(name))

  private def fail(reason: Any): Nothing =
    Console.err.println(s"refused: $reason")
    sys.exit(1)

  /** Writes the program's profile for the workspace to `out`, and gives the assembly and the command's temporary
    * directory that the profile grants. */
  private def emit(out: Path, systemPaths: SeatbeltProfile.SystemPaths, program: Program, workspace: Path)
      : (RunOnHostSandbox.Assembled, Path) =
    val assembled = RunOnHostSandbox.assemble(workspace, program, env, workspace).fold(fail, identity)
    val sessionTmp = sessionTmpFits(newSessionTmp()).fold(fail, identity)

    val inputs = assembled.profileInputs(
      sessionTmp = sessionTmp,
      proxyPort = 51234,
      // No proxy runs under the emitted profile, so this trust directory stays empty. The supervisor rows have the real
      // trust directory.
      trust = RunOnHostInspection.trustDirectory(sessionTmp.resolveSibling("proxy.log")),
      systemPaths = systemPaths,
      // A mill command without a daemon gets the grant that RunOnHostSandbox gives it. A mill client's port belongs to
      // the runner.
      network = program match
        case Program.Gradle                              => SeatbeltProfile.Network.Gradle
        case Program.Mill if assembled.millWithoutDaemon => SeatbeltProfile.Network.MillDaemon
        case _                                           => SeatbeltProfile.Network.ProxyOnly,
      // The workspace's file-rule lines, as a command gets them when the run-on-host checks start it without a launch.
      fileRules = FileRules.ofWorkspace(workspace).fold(fail, identity),
    )

    Files.writeString(out, SeatbeltProfile.render(inputs).fold(fail, identity))
    (assembled, sessionTmp)

  /** The checks form: the test for missing host runs, then every profile, the classpath and the proxy's profile. */
  private def checks(args: List[String]): Nothing = args match
    case outDir :: systemPathsFile :: specs if specs.nonEmpty =>
      val out = Files.createDirectories(Paths.get(outDir))
      val systemPaths = RunOnHostSandbox.readSystemPaths(Some(Paths.get(systemPathsFile)))
      val builds = specs.map: spec =>
        spec.split(",", 3) match
          case Array(id, name, dir) =>
            val program = Program.named(name).getOrElse(fail(s"unknown program $name"))
            id -> BuildDirectory(program, Paths.get(dir).toAbsolutePath.toRealPath())
          case _ => fail(s"$spec is not <id>,<program>,<workspace>")
      // The launch's own findings, so that the wording is the refusals' wording. sbt's executable is the user's, which
      // the workspace does not provision, so a launch takes no finding for sbt; `emit` refuses sbt's prerequisites.
      val findings = builds.collect:
        case (_, build) if build.program != Program.Sbt => RunOnHostProvisioning.finding(build, env)
      .flatten
      if findings.nonEmpty then
        findings.foreach(found => Console.err.println(s"missing: ${found.program.name} in ${found.buildDirectory}: ${
            found.wording}"))
        sys.exit(3)
      builds.foreach: (id, build) =>
        val (assembled, sessionTmp) = emit(out.resolve(s"$id.sb"), systemPaths, build.program, build.path)
        val values = java.util.Properties()
        values.setProperty("workspace", build.path.toString)
        values.setProperty("program", build.program.name)
        values.setProperty("session.tmp", sessionTmp.toString)
        values.setProperty("run-on-host.cache", assembled.prereqs.coursierV1.toString)
        values.setProperty("executable", assembled.prereqs.executable.toString)
        values.setProperty("sbt.global.base", assembled.sbtGlobal.toString)
        values.setProperty("ivy.home", assembled.ivyHome.toString)
        values.setProperty("gradle.user.home", assembled.gradleUserHome.toString)
        values.setProperty("m2.repository", assembled.m2Repository.toString)
        scala.util.Using.resource(Files.newBufferedWriter(out.resolve(s"$id.properties")))(
          values.store(_, null))
      val classpath = relaunchClasspath(out.resolve("classpath"))
      Files.writeString(out.resolve("classpath.txt"), classpath)
      val javaHome = env("JAVA_HOME").getOrElse(fail("JAVA_HOME is not set"))
      val proxy = RunOnHostProxy.proxyInputs(systemPaths, javaHome = javaHome, classPath = classpath)
        .flatMap(SeatbeltProfile.renderProxy).fold(fail, identity)
      Files.writeString(out.resolve("proxy.sb"), proxy)
      sys.exit(0)
    case _ => fail("the checks form takes --checks <out-dir> <system-paths-file> <id>,<program>,<workspace>...")

  private[launcher] def classpathForRelaunch: String =
    val urls = Iterator.iterate(getClass.getClassLoader)(_.getParent).takeWhile(_ != null)
      .collect { case loader: java.net.URLClassLoader => loader.getURLs.toSeq }
      .flatten.toVector
    if urls.isEmpty then System.getProperty("java.class.path")
    else urls.map(url => Paths.get(url.toURI).toString).distinct.mkString(java.io.File.pathSeparator)

  /**
   * The classpath that the checks rerun as RunOnHost and the runner in plain java, with no sbt in front. A supervisor
   * driven through `sbt Test/runMain` would find its own server holding the workspace's portfile and would end that
   * server, since a build directory has one server.
   *
   *   - The walk reads the class loaders, not java.class.path. runMain runs the driver inside the build JVM, whose own
   *     java.class.path is sbt's.
   *   - The jars are copied into `into`. The walk answers jars under `target/bg-jobs/`, and sbt removes them with its
   *     server. Measured: a java -cp of the walk's answer found none of those jars after the server ended.
   */
  private def relaunchClasspath(into: Path): String =
    Files.createDirectories(into)
    classpathForRelaunch.split(java.io.File.pathSeparator).toVector.zipWithIndex
      .map: (entry, index) =>
        val source = Paths.get(entry)
        if !Files.isRegularFile(source) then entry
        else
          val target = into.resolve(s"$index-${source.getFileName}")
          Files.copy(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
          target.toString
      .mkString(java.io.File.pathSeparator)

  /**
   * `/private/tmp/ko-agent-<uid>-accept/<session>/tmp`, which fits SessionTmpMaxLength where the per-user temporary
   * directory does not. The driver vets this root like the supervisor root.
   *
   * The directory has its own root on purpose. The run-on-host checks drive many builds against one emitted profile,
   * and nothing holds a session lock for them. Any scavenge would rightly collect such a directory inside the
   * supervisor root. This root lies outside every scan, and the checks' cleanup removes it.
   */
  private def newSessionTmp(): Path =
    import java.nio.file.attribute.PosixFilePermissions
    val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
    val root = RunOnHostSession.ensureRoot(Paths.get(s"/private/tmp/ko-agent-$uid-accept"), uid)
      .fold(reason => { Console.err.println(s"refused: $reason"); sys.exit(1) }, identity)
    val session = java.util.HexFormat.of().toHexDigits(java.security.SecureRandom().nextInt()).take(6)
    val tmp = root.resolve(session).resolve("tmp")
    Files.createDirectories(
      tmp,
      PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    )
    tmp.toRealPath()
