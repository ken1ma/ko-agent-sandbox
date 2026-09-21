// The generated Seatbelt profile for the project this runs in, so a real build can be driven
// under it by hand.
//
// Test scope on purpose: src/probe/run-on-host-acceptance-test.sh and src/probe/run-on-host-profile-iterate.sh are its
// only callers, and a profile emitter in the shipped jar would be a command nobody documented.
//
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> [system-paths-file] [<program>] [project]"
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> <system-paths-file> proxy <jdk> <classpath>"
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> <system-paths-file> proxy-image <binary>"
//
// The project defaults to the working directory; the acceptance test's mill rows name src/probe/mill-fixture.
// The system-paths-file grammar is RunOnHostSandbox.readSystemPaths's. The proxy form renders
// the host proxy's own profile for the java and class path the acceptance test runs its proxy rows with; the
// proxy-image form renders it for a native image, whose inputs RunOnHostSandbox.proxyInputs builds
// only when it runs as one.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import RunOnHostPrereqs.*

object EmitRunOnHostProfile:

  def main(args: Array[String]): Unit =
    if args.isEmpty then
      Console.err.println("usage: EmitRunOnHostProfile <out.sb> [system-paths-file] [sbt|mill|gradle|mvn] [project]")
      Console.err.println("       EmitRunOnHostProfile <out.sb> <system-paths-file> proxy <jdk> <classpath>")
      Console.err.println("       EmitRunOnHostProfile <out.sb> <system-paths-file> proxy-image <binary>")
      sys.exit(2)

    def fail(reason: Any): Nothing =
      Console.err.println(s"refused: $reason")
      sys.exit(1)

    if args.lift(2).contains("proxy") then
      if args.length != 5 then fail("the proxy form takes <out.sb> <system-paths-file> proxy <jdk> <classpath>")
      val systemPaths = RunOnHostSandbox.readSystemPaths(args.lift(1).map(Paths.get(_)))
      val profile = RunOnHostSandbox.proxyInputs(systemPaths, javaHome = args(3), classPath = args(4))
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

    val env: String => Option[String] = name => Option(System.getenv(name))
    val project = Paths.get(args.lift(3).getOrElse("")).toAbsolutePath.toRealPath()

    val program = args.lift(2).map(_.toLowerCase) match
      case None        => Program.Sbt
      case Some(name)  => Program.values.find(_.name == name).getOrElse(fail(s"unknown program $name"))

    val assembled = RunOnHostSandbox.assemble(project, program, env, project).fold(fail, identity)
    val sessionTmp = sessionTmpFits(newSessionTmp()).fold(fail, identity)
    val systemPaths = RunOnHostSandbox.readSystemPaths(args.lift(1).map(Paths.get(_)))

    val inputs = SeatbeltProfile.ProfileInputs(
      prereqs = assembled.prereqs,
      sessionTmp = sessionTmp,
      distribution = assembled.distribution,
      sbtGlobal = assembled.sbtGlobalGranted,
      ivyHome = assembled.ivyHomeGranted,
      gradleUserHome = assembled.gradleUserHomeGranted,
      m2Repository = assembled.m2RepositoryGranted,
      proxyPort = 51234,
      // No proxy runs under the emitted profile, so nothing is here: the wrapper rows have the real one.
      trust = RunOnHostInspection.trustDirectory(sessionTmp.resolveSibling("proxy.log")),
      systemPaths = systemPaths,
      network = program match
        case Program.Gradle => SeatbeltProfile.Network.Gradle
        case _              => SeatbeltProfile.Network.ProxyOnly,
    )

    val profile = SeatbeltProfile.render(inputs).fold(fail, identity)
    Files.writeString(Paths.get(args(0)), profile)
    // The driver needs the command's temporary directory: the profile grants it, and the JVM otherwise writes to the
    // per-user temporary directory, which it does not grant.
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
    // The acceptance test re-runs this classpath as RunOnHost, plain java with no sbt in front, because a
    // wrapper driven through `sbt Test/runMain` would find its own server holding the project's
    // portfile and end it (one server per build directory). Walked from the class loaders, not
    // java.class.path — runMain ran this inside the build JVM, whose own classpath is sbt's — and
    // copied beside the profile,
    // because the walk answers `target/bg-jobs/` jars sbt removes with its server (measured: the
    // acceptance test's java -cp found none of them).
    Console.err.println(s"classpath: ${relaunchClasspath(Paths.get(args(0) + ".cp"))}")

  private[launcher] def classpathForRelaunch: String =
    val urls = Iterator.iterate(getClass.getClassLoader)(_.getParent).takeWhile(_ != null)
      .collect { case loader: java.net.URLClassLoader => loader.getURLs.toSeq }
      .flatten.toVector
    if urls.isEmpty then System.getProperty("java.class.path")
    else urls.map(url => Paths.get(url.toURI).toString).distinct.mkString(java.io.File.pathSeparator)

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
   * `/private/tmp/ko-agent-<uid>-accept/<session>/tmp`: short enough for SessionTmpMaxLength where
   * the per-user temporary directory is not, vetted like the wrapper root. Its own root on
   * purpose: the acceptance test drives many builds against one emitted profile with nothing holding a
   * session lock, and inside the wrapper root any scavenge would rightly collect that; this root
   * is outside every scan and the acceptance test's to clean.
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
