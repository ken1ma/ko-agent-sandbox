// Writes the generated Seatbelt profile for the workspace that this driver runs in, so that a developer can drive a
// real build under the profile by hand.
//
// The driver lives in test scope on purpose. src/probe/run-on-host-acceptance-test.sh and
// src/probe/run-on-host-profile-iterate.sh are its only callers, and a profile emitter in the shipped jar would be a
// command that no document describes.
//
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> [system-paths-file] [<program>] [workspace]"
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> <system-paths-file> proxy <jdk> <classpath>"
//   sbt "Test/runMain agentsandbox.launcher.EmitRunOnHostProfile <out.sb> <system-paths-file> proxy-image <binary>"
//
// - The workspace defaults to the working directory. The acceptance test's mill rows name src/probe/mill-fixture.
// - RunOnHostSandbox.readSystemPaths defines the grammar of the system-paths file.
// - The proxy form renders the host proxy's own profile for the java and the class path that the acceptance test runs
//   its proxy rows with.
// - The proxy-image form renders the host proxy's profile for a native image. RunOnHostProxy.proxyInputs builds the
//   inputs for a native image only when the proxy runs as one.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import RunOnHostPrereqs.*

object EmitRunOnHostProfile:

  def main(args: Array[String]): Unit =
    if args.isEmpty then
      Console.err.println("usage: EmitRunOnHostProfile <out.sb> [system-paths-file] [sbt|mill|gradle|mvn] [workspace]")
      Console.err.println("       EmitRunOnHostProfile <out.sb> <system-paths-file> proxy <jdk> <classpath>")
      Console.err.println("       EmitRunOnHostProfile <out.sb> <system-paths-file> proxy-image <binary>")
      sys.exit(2)

    def fail(reason: Any): Nothing =
      Console.err.println(s"refused: $reason")
      sys.exit(1)

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

    val env: String => Option[String] = name => Option(System.getenv(name))
    val workspace = Paths.get(args.lift(3).getOrElse("")).toAbsolutePath.toRealPath()

    val program = args.lift(2).map(_.toLowerCase) match
      case None        => Program.Sbt
      case Some(name)  => Program.named(name).getOrElse(fail(s"unknown program $name"))

    val assembled = RunOnHostSandbox.assemble(workspace, program, env, workspace).fold(fail, identity)
    val sessionTmp = sessionTmpFits(newSessionTmp()).fold(fail, identity)
    val systemPaths = RunOnHostSandbox.readSystemPaths(args.lift(1).map(Paths.get(_)))

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
      // The workspace's file-rule lines, as a command gets them when the acceptance test starts it without a launch.
      fileRules = FileRules.ofWorkspace(workspace).fold(fail, identity),
    )

    val profile = SeatbeltProfile.render(inputs).fold(fail, identity)
    Files.writeString(Paths.get(args(0)), profile)
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
    // The acceptance test reruns this classpath as RunOnHost in plain java, with no sbt in front. A supervisor driven
    // through `sbt Test/runMain` would find its own server holding the workspace's portfile and would end that server,
    // since a build directory has one server.
    // - The driver walks the classpath from the class loaders, not from java.class.path. runMain runs the driver inside
    //   the build JVM, whose own java.class.path is sbt's.
    // - The driver copies the classpath beside the profile. The walk answers jars under `target/bg-jobs/`, and sbt
    //   removes them with its server. Measured: the acceptance test's java -cp found none of those jars.
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
   * `/private/tmp/ko-agent-<uid>-accept/<session>/tmp`, which fits SessionTmpMaxLength where the per-user temporary
   * directory does not. The driver vets this root like the supervisor root.
   *
   * The directory has its own root on purpose. The acceptance test drives many builds against one emitted profile,
   * and nothing holds a session lock for them. Any scavenge would rightly collect such a directory inside the
   * supervisor root. This root lies outside every scan, and the acceptance test cleans it.
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
