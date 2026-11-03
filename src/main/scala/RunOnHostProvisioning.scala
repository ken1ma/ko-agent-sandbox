// Provisioning at the launch under --run-on-host (run-on-host.md, "Program prerequisites").
//
// - What is provisioned: the mill launchers, the JDKs that mill's launcher resolves for the builds, and the Gradle
//   and Maven distributions the user provisions.
// - The launch checks every build directory of the workspace before the session starts. On the user's yes, the
//   stock script's own run provisions what is missing.
// - The launch misses a pin changed during the session and a build directory that a later edit creates. The first
//   command from such a directory refuses and names the same run.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{Files, LinkOption, Path}

import scala.jdk.CollectionConverters.*

import AgentSandboxLauncher.Reader
import FileHelper.{directoryEntries, isExecutableFile}
import HostCommands.{colorStderr, consented, displayPath, pathInline, renderArgument, shown, warn, weakened}
import RunOnHostPrereqs.{Program, Refusal}
import RunOnHostSandbox.StepRefusal

object RunOnHostProvisioning:

  /** A directory in which a command of the program would run as its own build (run-on-host-internals.md, "`mill`",
    * "Gradle", "Maven"):
    *
    *   - for mill, a directory holding a `mill` bootstrap;
    *   - for Gradle, a directory holding a Gradle wrapper's properties file. The supervisor keys a Gradle build
    *     directory on that file and reads the distribution from it;
    *   - for Maven, the workspace root alone, holding `mvnw`. */
  final case class BuildDirectory(program: Program, path: Path)

  /** What a command from one build directory would be refused for, before it runs. */
  enum Finding:
    def program: Program
    def buildDirectory: Path
    /** The refusal as the supervisor would word it, with the run it names. The refusal's paths are spelled for the
      * launcher's terminal. */
    def wording: String
    /** A missing executable or JDK that `command` provisions, run in the build directory with `environment` added to
      * the launcher's own. `command` is the run that the refusal names. */
    case Provisionable(
      program: Program, buildDirectory: Path, wording: String, command: Vector[String],
      environment: Map[String, String],
    )
    /** A refusal no host run fixes. */
    case Notice(program: Program, buildDirectory: Path, wording: String)

  /** Every build directory of the programs under the workspace root, the root first and the rest in path order.
    *
    *   - The walk follows no symlink and enters no FileRules.GuardedComponents name.
    *   - The walk passes over a directory it cannot list, and leaves that directory's build directories to the
    *     command. */
  def buildDirectories(workspaceRoot: Path, programs: Set[Program]): Vector[BuildDirectory] =
    val found = Vector.newBuilder[BuildDirectory]
    if programs(Program.Mvn) && isExecutableFile(workspaceRoot.resolve("mvnw")) then
      found += BuildDirectory(Program.Mvn, workspaceRoot)
    def visit(dir: Path): Unit =
      if programs(Program.Mill) && isExecutableFile(dir.resolve("mill")) then found += BuildDirectory(Program.Mill, dir)
      val properties = dir.resolve("gradle").resolve("wrapper").resolve("gradle-wrapper.properties")
      if programs(Program.Gradle) && Files.isRegularFile(properties) then found += BuildDirectory(Program.Gradle, dir)
      val entries =
        try directoryEntries(dir).sorted
        catch case _: IOException => Vector.empty
      entries
        .filter: entry =>
          Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)
            && !FileRules.GuardedComponents.contains(entry.getFileName.toString)
        .foreach(visit)
    visit(workspaceRoot)
    found.result()

  /** The build directory's finding, or none when the directory's command would be granted its executable. */
  def finding(build: BuildDirectory, env: String => Option[String]): Option[Finding] =
    def worded(refusal: StepRefusal): String = refusal.wordedShowing(displayPath(_, environment = env))
    RunOnHostSandbox.provisionedExecutable(build.program, env, build.path) match
      case Right(_) => None
      case Left(refusal @ StepRefusal(_, Refusal.PrereqMillExecutableMissing(launcherVersion, _))) =>
        Some(millVersionRun(build, worded(refusal), launcherVersion))
      case Left(refusal @ StepRefusal(_, Refusal.PrereqMillJdkMissing(_, launcherVersion))) =>
        Some(millVersionRun(build, worded(refusal), launcherVersion))
      case Left(refusal @ StepRefusal(_, Refusal.PrereqGradleDistributionMissing(_, _))) =>
        if isExecutableFile(build.path.resolve("gradlew")) then
          Some(Finding.Provisionable(
            build.program, build.path, worded(refusal), Vector("./gradlew", "--version"), Map.empty,
          ))
        else
          Some(Finding.Notice(
            build.program, build.path,
            s"${worded(refusal)}, and the build directory has no executable `gradlew` to run",
          ))
      case Left(refusal @ StepRefusal(_, Refusal.PrereqMvnDistributionMissing(_, _))) =>
        Some(Finding.Provisionable(
          build.program, build.path, worded(refusal), Vector("./mvnw", "--version"), Map.empty,
        ))
      case Left(refusal) => Some(Finding.Notice(build.program, build.path, worded(refusal)))

  /** `MILL_VERSION=<v>-jvm ./mill version`. The bootstrap downloads the launcher. The launcher then resolves a
    * pinned or unset `mill-jvm-version` and downloads that JDK. */
  private def millVersionRun(build: BuildDirectory, wording: String, launcherVersion: String): Finding =
    Finding.Provisionable(
      build.program, build.path, wording, Vector("./mill", "version"), Map("MILL_VERSION" -> launcherVersion),
    )

  /** The command as the reader agrees to it: `NAME=value` assignments first, and each word rendered as the start
    * prompt renders a word. */
  def rendered(provisionable: Finding.Provisionable): String =
    (provisionable.environment.toVector.sorted.map((name, value) => s"$name=${renderArgument(value)}")
      ++ provisionable.command.map(renderArgument)).mkString(" ")

  /**
   * Takes each build directory in turn and reports its finding as a warning.
   *
   *   - A directory's finding is taken only when the directory's turn comes, since one run can provision several
   *     directories that share a version.
   *   - The warning uses the supervisor's wording, so the run it names is the run the first command would name.
   *   - For a provisionable finding, given a reader, this method asks whether to run the command now.
   *   - The run is the user's own act on a workspace script, unconfined and in the launcher's environment, like the
   *     manual run the refusal asks for (SECURITY.md, "Run on host"). The prompt says so, tinted as a weakened
   *     boundary is tinted (HostCommands.weakened). Only an explicit yes starts the run.
   *   - Without a reader, the warning is the whole report. A launch has no reader when it has no terminal, or when
   *     its start mode holds nothing.
   *   - After a run, the finding is taken again, so a script that exits zero without provisioning is reported now
   *     rather than at the first command.
   */
  def provision(
    builds: Vector[BuildDirectory],
    finding: BuildDirectory => Option[Finding],
    reader: Option[Reader],
    run: Finding.Provisionable => Either[String, Int],
    report: String => Unit = warn,
    color: Boolean = colorStderr,
  ): Unit =
    def say(line: String): Unit = report(shown(line))
    builds.foreach: build =>
      finding(build).foreach: found =>
        say(s"run-on-host ${found.program.name} in ${pathInline(found.buildDirectory)}: ${found.wording}")
        (found, reader) match
          case (provisionable: Finding.Provisionable, Some(reader)) =>
            val command = rendered(provisionable)
            reader.prompt(
              weakened(
                shown(s"run `$command` in ${pathInline(provisionable.buildDirectory)} now, unconfined on the host?"),
                color,
              ) + " [y/N] ",
            )
            if consented(reader.readLine()) then
              run(provisionable) match
                case Left(reason) => say(s"`$command` could not start: $reason")
                case Right(0) =>
                  finding(build).foreach: still =>
                    say(
                      s"after the run, ${still.program.name} in ${pathInline(still.buildDirectory)}: ${still.wording}",
                    )
                case Right(code) => say(s"`$command` in ${pathInline(provisionable.buildDirectory)} exited $code")
          case _ => ()

  /** The run itself: the command runs in its build directory and prints its output on this terminal. */
  def runInBuildDirectory(provisionable: Finding.Provisionable): Either[String, Int] =
    try
      val builder = ProcessBuilder(provisionable.command*).directory(provisionable.buildDirectory.toFile).inheritIO()
      EgressCredentials.scrub(builder).environment().putAll(provisionable.environment.asJava)
      Right(builder.start().waitFor())
    catch case ex: IOException => Left(ex.getMessage)

  /** The whole of a launch's provisioning: `provision` takes every build directory of the programs. */
  def run(workspaceRoot: Path, programs: Set[Program], env: String => Option[String], reader: Option[Reader]): Unit =
    provision(buildDirectories(workspaceRoot, programs), finding(_, env), reader, runInBuildDirectory)
