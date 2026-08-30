// Phase 2 scaffolding: the generated Seatbelt profile for the project this runs in, so a real
// build can be driven under it before any launcher verb exists to print one.
//
// Test scope on purpose. The durable answer is a management verb, which belongs with the rest of
// the launcher surface in Phase 5; until then a profile emitter in the shipped jar would be a
// command nobody documented. probe/build-profile-iterate.sh is its caller.
//
//   sbt "Test/runMain agentsandbox.launcher.EmitBuildProfile <out.sb> [runtime-authority-file]"
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
      Console.err.println("usage: EmitBuildProfile <out.sb> [runtime-authority-file]")
      sys.exit(2)

    val os = Os.Mac
    val env: String => Option[String] = name => Option(System.getenv(name))
    val project = Paths.get("").toAbsolutePath.toRealPath()

    def fail(reason: Any): Nothing =
      Console.err.println(s"refused: $reason")
      sys.exit(1)

    val coursierCache = coursierCacheRoot(os, env).getOrElse(fail("no Coursier cache root"))
    val jdk = resolveJdkHome(env, coursierCache, realPath, os).fold(fail, identity)
    val installDir = coursierInstallDir(os, env).getOrElse(fail("no Coursier install directory"))
    val launcher = validateSbtLauncher(installDir.resolve("sbt"), installDir, realPath, os).fold(fail, identity)

    val distribution = SeatbeltProfile
      // ISO-8859-1, not UTF-8: cs appends a jar to its launchers, so the file is not text.
      // Every byte maps to a char, which leaves the ASCII path this searches for intact.
      .sbtDistribution(String(Files.readAllBytes(launcher), ISO_8859_1), coursierCache)
      .map(SeatbeltProfile.distributionHome)
      .flatMap(realPath)

    val cacheRoot = cacheRootOf(os, env).fold(fail, identity)
    cacheRootOutsideProject(cacheRoot, project, os).fold(fail, identity)
    val v1 = agentCoursierV1(cacheRoot, projectIdOf(project, os))
    Files.createDirectories(v1)

    val sessionTmp = Files.createTempDirectory("ko-agent-build-").toRealPath()

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
        tool = Tool.Sbt,
        launcher = launcher,
        sbtBoot = sbtBoot(env, Files.isDirectory(_)).toOption,
      ),
      sessionTmp = sessionTmp,
      sbtDistribution = distribution,
      proxyPort = 51234,
      runtime = SeatbeltProfile.RuntimeAuthority(reads, executes),
    )

    val profile = SeatbeltProfile.render(inputs).fold(fail, identity)
    Files.writeString(Paths.get(args(0)), profile)
    // The driver needs the session temp: the profile grants it, and without -Djava.io.tmpdir the
    // JVM writes to $TMPDIR instead, which it does not grant.
    Files.writeString(Paths.get(args(0) + ".env"), s"SESSION_TMP=$sessionTmp\n")
    Console.err.println(s"profile: ${args(0)}")
    Console.err.println(s"env: ${args(0)}.env")
    Console.err.println(s"session temp: $sessionTmp")
    Console.err.println(s"agent cache: $v1")
    if distribution.isEmpty then Console.err.println("warning: no sbt distribution found in the launcher")
