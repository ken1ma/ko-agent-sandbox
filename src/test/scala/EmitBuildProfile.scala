// Phase 2 scaffolding: the generated Seatbelt profile for the project this runs in, so a real
// build can be driven under it before any launcher verb exists to print one.
//
// Test scope on purpose. The durable answer is a management verb, which belongs with the rest of
// the launcher surface in Phase 5; until then a profile emitter in the shipped jar would be a
// command nobody documented. probe/build-profile-gate.sh and probe/build-profile-iterate.sh are its callers.
//
//   sbt "Test/runMain agentsandbox.launcher.EmitBuildProfile <out.sb> [authority-file] [sbt|mill] [project]"
//
// The project defaults to the working directory; the gate's Mill rows name probe/mill-fixture.
//
// The runtime-authority file is one absolute path per line, `#` comments allowed, `x ` prefix for
// a path that must also be executable. It starts empty: PLAN-SBT-ON-HOST.md §2.1 admits a runtime
// path only where testing proves the read is stable, and the driver discovers them.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.ISO_8859_1
import java.nio.file.{Files, Path, Paths}

import BuildSandboxPolicy.*
import HostCommands.Os
import SandboxProject.projectIdOf

object EmitBuildProfile:

  def main(args: Array[String]): Unit =
    if args.isEmpty then
      Console.err.println("usage: EmitBuildProfile <out.sb> [authority-file] [sbt|mill] [project]")
      sys.exit(2)

    val os = Os.Mac
    val env: String => Option[String] = name => Option(System.getenv(name))
    val project = Paths.get(args.lift(3).getOrElse("")).toAbsolutePath.toRealPath()

    def fail(reason: Any): Nothing =
      Console.err.println(s"refused: $reason")
      sys.exit(1)

    val tool = args.lift(2).map(_.toLowerCase) match
      case None | Some("sbt") => Tool.Sbt
      case Some("mill")       => Tool.Mill
      case Some(other)        => fail(s"unknown tool $other")

    def isExecutableFile(path: Path) = Files.isExecutable(path) && Files.isRegularFile(path)

    val coursierCache = coursierCacheRoot(os, env).getOrElse(fail("no Coursier cache root"))
    val jdk = resolveJdkHome(env, coursierCache, realPath, isExecutableFile).fold(fail, identity)

    // The launcher each tool is started through: §3.2's two-part launcher for sbt, §3.3's
    // provisioned native launcher for Mill. Both halves of sbt's are required — a profile without
    // the distribution starts a build that cannot find its launcher jar.
    val (launcher, distribution) = tool match
      case Tool.Sbt =>
        val installDir = coursierInstallDir(os, env).getOrElse(fail("no Coursier install directory"))
        val sbt = validateSbtLauncher(installDir.resolve("sbt"), installDir, realPath, isExecutableFile)
          .fold(fail, identity)
        val inner = SeatbeltProfile
          // ISO-8859-1, not UTF-8: cs appends a jar to its launchers, so the file is not text.
          // Every byte maps to a char, which leaves the ASCII path this searches for intact.
          .sbtDistribution(String(Files.readAllBytes(sbt), ISO_8859_1), coursierCache)
          .getOrElse(fail(s"$sbt names no distribution inside $coursierCache"))
        val home = validateSbtDistribution(inner, coursierCache, realPath, isExecutableFile).fold(fail, identity)
        (sbt, Some(home))
      case Tool.Mill =>
        validateMillBootstrap(project, isExecutableFile).fold(fail, identity)
        millJvmIsSystem(project, readLines).fold(fail, identity)
        val version = millVersion(project, env, readLines).fold(fail, identity)
        val downloads = millDownloadDir(env).getOrElse(fail("no Mill download folder"))
        val arch = System.getProperty("os.arch") match
          case "aarch64" => "arm64"
          case other     => other
        val provisioned = millLauncher(downloads, version, arch, isExecutableFile).fold(fail, identity)
        (realPath(provisioned).getOrElse(fail(s"$provisioned vanished")), None)

    val cacheRoot = cacheRootOutsideProject(cacheRootOf(os, env).fold(fail, identity), project, os,
      HostCommands.canonicalizedFuturePath).fold(fail, identity)
    val v1 = agentCoursierV1(cacheRoot, projectIdOf(project, os))
    Files.createDirectories(v1)

    val sessionTmp = sessionTmpFits(newSessionTmp()).fold(fail, identity)

    val (reads, executes) = args.lift(1).map(Paths.get(_)) match
      case None => (Seq.empty[Path], Seq.empty[Path])
      case Some(file) =>
        val lines = Files.readAllLines(file).toArray(Array.empty[String]).toSeq
          .map(_.trim).filter(line => line.nonEmpty && !line.startsWith("#"))
        val exec = lines.filter(_.startsWith("x ")).map(line => Paths.get(line.drop(2).trim))
        val read = lines.filterNot(_.startsWith("x ")).map(Paths.get(_))
        (read.flatMap(realPath), exec.flatMap(realPath))

    val inputs = SeatbeltProfile.ProfileInputs(
      policy = BuildPolicy(
        project = project,
        jdkHome = jdk,
        coursierV1 = v1.toRealPath(),
        tool = tool,
        launcher = launcher,
      ),
      sessionTmp = sessionTmp,
      sbtDistribution = distribution,
      proxyPort = 51234,
      runtime = SeatbeltProfile.RuntimeAuthority(reads, executes),
    )

    val profile = SeatbeltProfile.render(inputs).fold(fail, identity)
    Files.writeString(Paths.get(args(0)), profile)
    // The driver needs the session temp: the profile grants it, and the JVM otherwise writes to the
    // per-user temporary directory, which it does not grant.
    Files.writeString(Paths.get(args(0) + ".env"), s"SESSION_TMP=$sessionTmp\n")
    Console.err.println(s"profile: ${args(0)}")
    Console.err.println(s"env: ${args(0)}.env")
    Console.err.println(s"session temp: $sessionTmp")
    Console.err.println(s"agent cache: $v1")
    Console.err.println(s"tool: $tool")
    Console.err.println(s"launcher: $launcher")

  /**
   * `/private/tmp/ko-agent-<uid>/<session>/tmp`: short enough for SessionTmpMaxLength where the
   * per-user temporary directory is not, and checked the way an XDG runtime directory is — owned by
   * this user, mode 0700, no symlink — because /tmp is shared and sticky and anyone can pre-create
   * a name there.
   */
  private def newSessionTmp(): Path =
    import java.nio.file.attribute.PosixFilePermissions
    val uid = com.sun.security.auth.module.UnixSystem().getUid
    val root = Paths.get(s"/private/tmp/ko-agent-$uid")
    val ownerOnly = PosixFilePermissions.fromString("rwx------")
    if !Files.exists(root, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
      Files.createDirectory(root, PosixFilePermissions.asFileAttribute(ownerOnly))
    val me = root.getFileSystem.getUserPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name"))
    if Files.isSymbolicLink(root) || !Files.isDirectory(root) then
      Console.err.println(s"refused: $root is not a directory"); sys.exit(1)
    if Files.getOwner(root) != me || Files.getPosixFilePermissions(root) != ownerOnly then
      Console.err.println(s"refused: $root is not this user's, mode 0700"); sys.exit(1)
    val session = java.util.HexFormat.of().toHexDigits(java.security.SecureRandom().nextInt()).take(6)
    val tmp = root.resolve(session).resolve("tmp")
    Files.createDirectories(tmp, PosixFilePermissions.asFileAttribute(ownerOnly))
    tmp.toRealPath()

  /** Absent is None; existing-but-unreadable throws and fails the emit, never falls to the next
    * source — Mill would select the file and then fail reading it. */
  private def readLines(path: Path): Option[Seq[String]] =
    Option.when(Files.exists(path))(Files.readAllLines(path).toArray(Array.empty[String]).toSeq)
