// Provisioning at the launch under --run-on-host: the mill launchers, the JDKs mill's launcher
// resolves for the builds, and the Gradle and Maven distributions the user provisions
// (run-on-host.md "Program prerequisites"), checked for every build directory of the project
// before the session starts, and provisioned by the stock script's own run on the user's yes.
// What the launch misses — a pin changed during the session, a build directory a later edit
// creates — the first command from that directory refuses, naming the same run.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{Files, LinkOption, Path}

import scala.jdk.CollectionConverters.*

import AgentSandboxLauncher.Reader
import FileHelper.{directoryEntries, isExecutableFile}
import HostCommands.{colorStderr, consented, pathInline, renderArgument, shown, warn, weakened}
import RunOnHostPrereqs.{Program, Refusal}
import RunOnHostSandbox.StepRefusal

object RunOnHostProvisioning:

  /** A directory a command of the program would run in as its own build: one holding a `mill`
    * bootstrap, or a Gradle wrapper's properties file, the file the supervisor keys a Gradle
    * build directory on and reads the distribution from; for Maven the project alone, holding `mvnw`
    * (run-on-host.md "`mill`", "Gradle", "Maven"). */
  final case class BuildDirectory(program: Program, path: Path)

  /** What a command from one build directory would be refused for, before it runs. */
  enum Finding:
    def program: Program
    def buildDirectory: Path
    /** The refusal the supervisor would word, with the run it names. */
    def wording: String
    /** A missing executable or JDK that `command`, run in the build directory with
      * `environment` added to the launcher's own, provisions: the run the refusal names. */
    case Provisionable(
      program: Program, buildDirectory: Path, wording: String, command: Vector[String],
      environment: Map[String, String],
    )
    /** A refusal no host run fixes. */
    case Notice(program: Program, buildDirectory: Path, wording: String)

  /** Every build directory under the project for the programs, the project first and the rest in
    * path order. The walk follows no symlink and enters no FileRules.GuardedComponents name; a
    * directory it cannot list is passed over, its build directories left to the command. */
  def buildDirectories(project: Path, programs: Set[Program]): Vector[BuildDirectory] =
    val found = Vector.newBuilder[BuildDirectory]
    if programs(Program.Mvn) && isExecutableFile(project.resolve("mvnw")) then
      found += BuildDirectory(Program.Mvn, project)
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
    visit(project)
    found.result()

  /** The build directory's finding: none when its command would be granted its executable. */
  def finding(build: BuildDirectory, env: String => Option[String]): Option[Finding] =
    RunOnHostSandbox.provisionedExecutable(build.program, env, build.path) match
      case Right(_) => None
      case Left(refusal @ StepRefusal(_, Refusal.PrereqMillExecutableMissing(launcherVersion, _))) =>
        Some(millVersionRun(build, refusal, launcherVersion))
      case Left(refusal @ StepRefusal(_, Refusal.PrereqMillJdkMissing(_, launcherVersion))) =>
        Some(millVersionRun(build, refusal, launcherVersion))
      case Left(refusal @ StepRefusal(_, Refusal.PrereqGradleDistributionMissing(_, _))) =>
        if isExecutableFile(build.path.resolve("gradlew")) then
          Some(Finding.Provisionable(
            build.program, build.path, refusal.worded, Vector("./gradlew", "--version"), Map.empty,
          ))
        else
          Some(Finding.Notice(
            build.program, build.path,
            s"${refusal.worded}, and the build directory has no executable `gradlew` to run",
          ))
      case Left(refusal @ StepRefusal(_, Refusal.PrereqMvnDistributionMissing(_, _))) =>
        Some(Finding.Provisionable(build.program, build.path, refusal.worded, Vector("./mvnw", "--version"), Map.empty))
      case Left(refusal) => Some(Finding.Notice(build.program, build.path, refusal.worded))

  /** `MILL_VERSION=<v>-jvm ./mill version`: the bootstrap downloads the launcher, and the launcher
    * resolves a pinned or unset `mill-jvm-version` and downloads its JDK. */
  private def millVersionRun(build: BuildDirectory, refusal: StepRefusal, launcherVersion: String): Finding =
    Finding.Provisionable(
      build.program, build.path, refusal.worded, Vector("./mill", "version"), Map("MILL_VERSION" -> launcherVersion),
    )

  /** The command as the reader agrees to it, `NAME=value` assignments first, each word rendered
    * as the start prompt renders one. */
  def rendered(provisionable: Finding.Provisionable): String =
    (provisionable.environment.toVector.sorted.map((name, value) => s"$name=${renderArgument(value)}")
      ++ provisionable.command.map(renderArgument)).mkString(" ")

  /**
   * Takes each build directory in turn — its finding only when its turn comes, since one run can
   * provision several directories sharing a version — reports the finding as a warning in the
   * supervisor's wording, so the run it names is the one the first command would name, and for a
   * provisionable one, given a reader, asks whether to run it now. The run is the user's own act
   * on a project script, unconfined and in the launcher's environment, as the manual run the
   * refusal asks for is (SECURITY.md "Run on host"): the prompt says so, tinted as a weakened
   * boundary is (HostCommands.weakened), only an explicit yes
   * runs it, and no reader — no terminal, or a start mode that holds nothing — leaves the warning
   * as the whole report. After a run the finding is taken again, so a script that exits zero
   * without provisioning is reported now rather than at the first command.
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

  /** The run itself: the command in its build directory, its output on this terminal. */
  def runInBuildDirectory(provisionable: Finding.Provisionable): Either[String, Int] =
    try
      val builder = ProcessBuilder(provisionable.command*).directory(provisionable.buildDirectory.toFile).inheritIO()
      EgressCredentials.scrub(builder).environment().putAll(provisionable.environment.asJava)
      Right(builder.start().waitFor())
    catch case ex: IOException => Left(ex.getMessage)

  /** The whole of a launch's provisioning: every build directory of the programs through the
    * provisioning above. */
  def run(project: Path, programs: Set[Program], env: String => Option[String], reader: Option[Reader]): Unit =
    provision(buildDirectories(project, programs), finding(_, env), reader, runInBuildDirectory)
