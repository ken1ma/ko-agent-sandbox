// The generated Seatbelt profile for the project this runs in, so a real build can be driven
// under it by hand.
//
// Test scope on purpose: src/probe/build-profile-gate.sh and src/probe/build-profile-iterate.sh are its
// only callers, and a profile emitter in the shipped jar would be a command nobody documented.
//
//   sbt "Test/runMain agentsandbox.launcher.EmitBuildProfile <out.sb> [authority-file] [sbt|mill] [project]"
//
// The project defaults to the working directory; the gate's mill rows name src/probe/mill-fixture.
// The authority-file grammar is RunOnHostSandbox.readRuntimeAuthority's.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}

import RunOnHostPolicy.*

object EmitBuildProfile:

  def main(args: Array[String]): Unit =
    if args.isEmpty then
      Console.err.println("usage: EmitBuildProfile <out.sb> [authority-file] [sbt|mill] [project]")
      sys.exit(2)

    val env: String => Option[String] = name => Option(System.getenv(name))
    val project = Paths.get(args.lift(3).getOrElse("")).toAbsolutePath.toRealPath()

    def fail(reason: Any): Nothing =
      Console.err.println(s"refused: $reason")
      sys.exit(1)

    val tool = args.lift(2).map(_.toLowerCase) match
      case None | Some("sbt") => Tool.Sbt
      case Some("mill")       => Tool.Mill
      case Some(other)        => fail(s"unknown tool $other")

    val assembled = RunOnHostSandbox.assemble(project, tool, env).fold(fail, identity)
    val sessionTmp = sessionTmpFits(newSessionTmp()).fold(fail, identity)
    val runtime = RunOnHostSandbox.readRuntimeAuthority(args.lift(1).map(Paths.get(_)))

    val inputs = SeatbeltProfile.ProfileInputs(
      policy = assembled.policy,
      sessionTmp = sessionTmp,
      sbtDistribution = assembled.sbtDistribution,
      sbtGlobal = assembled.sbtGlobal,
      proxyPort = 51234,
      runtime = runtime,
    )

    val profile = SeatbeltProfile.render(inputs).fold(fail, identity)
    Files.writeString(Paths.get(args(0)), profile)
    // The driver needs the session temp: the profile grants it, and the JVM otherwise writes to the
    // per-user temporary directory, which it does not grant.
    Files.writeString(Paths.get(args(0) + ".env"), s"SESSION_TMP=$sessionTmp\n")
    Console.err.println(s"profile: ${args(0)}")
    Console.err.println(s"env: ${args(0)}.env")
    Console.err.println(s"session temp: $sessionTmp")
    Console.err.println(s"agent cache: ${assembled.policy.coursierV1}")
    Console.err.println(s"tool: $tool")
    Console.err.println(s"launcher: ${assembled.policy.launcher}")
    assembled.sbtGlobal.foreach(base => Console.err.println(s"sbt global base: $base"))
    // The gate re-runs this classpath as RunOnHost, plain java with no sbt in front, because a
    // wrapper driven through `sbt Test/runMain` would find its own server holding the project's
    // portfile and refuse (one server per project). Walked from the class loaders, not java.class.path — runMain ran
    // this inside the build JVM, whose own classpath is sbt's — and copied beside the profile,
    // because the walk answers `target/bg-jobs/` jars sbt removes with its server (measured: the
    // gate's java -cp found none of them).
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
   * `/private/tmp/ko-agent-<uid>-gate/<session>/tmp`: short enough for SessionTmpMaxLength where
   * the per-user temporary directory is not, vetted like the wrapper root. Its own root on
   * purpose: the gate drives many builds against one emitted profile with nothing holding a
   * session lock, and inside the wrapper root any scavenge would rightly collect that; this root
   * is outside every scan and the gate's to clean.
   */
  private def newSessionTmp(): Path =
    import java.nio.file.attribute.PosixFilePermissions
    val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
    val root = RunOnHostSession.ensureRoot(Paths.get(s"/private/tmp/ko-agent-$uid-gate"), uid)
      .fold(reason => { Console.err.println(s"refused: $reason"); sys.exit(1) }, identity)
    val session = java.util.HexFormat.of().toHexDigits(java.security.SecureRandom().nextInt()).take(6)
    val tmp = root.resolve(session).resolve("tmp")
    Files.createDirectories(
      tmp,
      PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    )
    tmp.toRealPath()
