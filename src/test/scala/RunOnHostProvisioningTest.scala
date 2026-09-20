package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.nio.file.attribute.PosixFilePermissions.fromString as permissions

import AgentSandboxLauncher.Reader
import RunOnHostProvisioning.*
import RunOnHostPrereqs.Program

class RunOnHostProvisioningTest extends munit.FunSuite:

  private def executable(path: Path): Path =
    Files.createDirectories(path.getParent)
    Files.setPosixFilePermissions(Files.createFile(path), permissions("rwxr-xr-x"))
    path

  /** A build directory whose bootstrap pins Mill `version` under a system JVM. */
  private def millBuild(dir: Path, version: String = "1.1.9"): Path =
    executable(dir.resolve("mill"))
    Files.writeString(dir.resolve("build.mill.yaml"), s"mill-version: $version\nmill-jvm-version: system\n")
    dir

  /** A build directory whose wrapper names Gradle 9.7.1, with or without the script beside it. */
  private def gradleBuild(dir: Path, withScript: Boolean = true): Path =
    val properties = Files.createDirectories(dir.resolve("gradle/wrapper")).resolve("gradle-wrapper.properties")
    Files.writeString(properties, "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.7.1-bin.zip\n")
    if withScript then executable(dir.resolve("gradlew"))
    dir

  private val GradleDistributionDir = ".gradle/wrapper/dists/gradle-9.7.1-bin/1w1c7tv4s851m17nbqdsro2tv"

  private val MvnDistributionUrl =
    "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.zip"

  /** A project whose only-script wrapper names Maven 3.9.16. */
  private def mvnProject(dir: Path): Path =
    Files.writeString(executable(dir.resolve("mvnw")), "#!/bin/sh\nhash_string() {\n}\n")
    val properties = Files.createDirectories(dir.resolve(".mvn/wrapper")).resolve("maven-wrapper.properties")
    Files.writeString(properties, s"distributionUrl=$MvnDistributionUrl\n")
    dir

  test("the scan finds every build directory of the programs, the project first, entering no link, .git or boundary"):
    val root = Files.createTempDirectory("provisioning").toRealPath()
    val project = millBuild(Files.createDirectories(root.resolve("project")))
    gradleBuild(project)
    mvnProject(project)
    gradleBuild(project.resolve("services/api"))
    mvnProject(Files.createDirectories(project.resolve("services/legacy")))
    millBuild(project.resolve("lib/b"))
    millBuild(project.resolve("lib/a"))
    millBuild(project.resolve(".git/hooks"))
    gradleBuild(project.resolve(".ko-agent-sandbox/run-on-host"))
    millBuild(project.resolve("out/nested/.git/tricky"))
    val elsewhere = millBuild(Files.createDirectories(root.resolve("elsewhere")))
    Files.createSymbolicLink(project.resolve("linked"), elsewhere)
    Files.createSymbolicLink(project.resolve("mill-link"), elsewhere.resolve("mill"))
    Files.createFile(Files.createDirectories(project.resolve("plain")).resolve("mill"))

    assertEquals(
      buildDirectories(project, Set(Program.Mill, Program.Gradle, Program.Mvn)),
      Vector(
        BuildDirectory(Program.Mvn, project),
        BuildDirectory(Program.Mill, project),
        BuildDirectory(Program.Gradle, project),
        BuildDirectory(Program.Mill, project.resolve("lib/a")),
        BuildDirectory(Program.Mill, project.resolve("lib/b")),
        BuildDirectory(Program.Gradle, project.resolve("services/api")),
      ),
    )
    assertEquals(
      buildDirectories(project, Set(Program.Gradle)),
      Vector(BuildDirectory(Program.Gradle, project), BuildDirectory(Program.Gradle, project.resolve("services/api"))),
    )
    assertEquals(buildDirectories(project, Set(Program.Sbt)), Vector.empty)

    assume(System.getProperty("user.name") != "root", "root lists everything")
    val unlistable = millBuild(Files.createDirectories(project.resolve("closed/inner"))).getParent
    Files.setPosixFilePermissions(unlistable, permissions("---------"))
    try
      val names = buildDirectories(project, Set(Program.Mill)).map(_.path.getFileName.toString)
      assertEquals(names, Vector("project", "a", "b"))
    finally Files.setPosixFilePermissions(unlistable, permissions("rwxr-xr-x"))
    assertEquals(buildDirectories(project.resolve("lib"), Set(Program.Mvn)), Vector.empty)

  test("a missing mill launcher is provisionable by the bootstrap under MILL_VERSION; other refusals are notices"):
    val root = Files.createTempDirectory("provisioning").toRealPath()
    val project = millBuild(Files.createDirectories(root.resolve("project")))
    val env = Map("HOME" -> root.toString)
    val build = BuildDirectory(Program.Mill, project)
    val downloads = root.resolve(".cache/mill/download")

    val missing = finding(build, env.get)
    assertEquals(
      missing,
      Some(Finding.Provisionable(
        Program.Mill, project,
        s"mill executable: mill's JVM launcher 1.1.9-jvm is not provisioned under $downloads; run " +
          "`MILL_VERSION=1.1.9-jvm ./mill version` once on the host",
        Vector("./mill", "version"), Map("MILL_VERSION" -> "1.1.9-jvm"),
      )),
    )
    assertEquals(
      missing.map(_.asInstanceOf[Finding.Provisionable]).map(rendered), Some("MILL_VERSION=1.1.9-jvm ./mill version"),
    )

    executable(downloads.resolve("1.1.9"))
    assertEquals(finding(build, env.get), None)

    val native = millBuild(Files.createDirectories(root.resolve("native")), version = "1.1.9-native")
    assertEquals(
      finding(BuildDirectory(Program.Mill, native), env.get).map(_.wording).exists(_.contains("native launcher")),
      true,
    )
    val unpinned = Files.createDirectories(root.resolve("unpinned"))
    executable(unpinned.resolve("mill"))
    val notice = finding(BuildDirectory(Program.Mill, unpinned), env.get)
    assert(clue(notice).exists(_.isInstanceOf[Finding.Notice]))

  test("a missing Gradle distribution is provisionable by gradlew, and a notice without one"):
    val root = Files.createTempDirectory("provisioning").toRealPath()
    val project = gradleBuild(Files.createDirectories(root.resolve("project")))
    val env = Map("HOME" -> root.toString)
    val build = BuildDirectory(Program.Gradle, project)

    val missing = finding(build, env.get)
    assertEquals(
      missing,
      Some(Finding.Provisionable(
        Program.Gradle, project,
        "gradle distribution: Gradle from https://services.gradle.org/distributions/gradle-9.7.1-bin.zip is not " +
          s"unpacked at ${root.resolve(GradleDistributionDir)}; run `./gradlew --version` once on the host",
        Vector("./gradlew", "--version"), Map.empty,
      )),
    )

    val scriptless = gradleBuild(Files.createDirectories(root.resolve("scriptless")), withScript = false)
    val notice = finding(BuildDirectory(Program.Gradle, scriptless), env.get)
    assert(clue(notice).exists(_.isInstanceOf[Finding.Notice]))
    assert(notice.exists(_.wording.endsWith("and the build directory has no executable `gradlew` to run")))

    executable(root.resolve(GradleDistributionDir).resolve("gradle-9.7.1/bin/gradle"))
    assertEquals(finding(build, env.get), None)

  test("a missing Maven distribution is provisionable by the project's mvnw"):
    val root = Files.createTempDirectory("provisioning").toRealPath()
    val project = mvnProject(Files.createDirectories(root.resolve("project")))
    val env = Map("HOME" -> root.toString)
    val build = BuildDirectory(Program.Mvn, project)
    val distribution = RunOnHostPrereqs.mvnDistributionDir(root.resolve(".m2"), MvnDistributionUrl)

    assertEquals(
      finding(build, env.get),
      Some(Finding.Provisionable(
        Program.Mvn, project,
        s"mvn distribution: Maven from $MvnDistributionUrl is not unpacked at $distribution; run " +
          "`./mvnw --version` once on the host",
        Vector("./mvnw", "--version"), Map.empty,
      )),
    )
    executable(distribution.resolve("bin/mvn"))
    assertEquals(finding(build, env.get), None)

    Files.writeString(project.resolve("mvnw"), "#!/bin/sh\nexec java -jar .mvn/wrapper/maven-wrapper.jar\n")
    val notice = finding(build, env.get)
    assert(clue(notice).exists(_.isInstanceOf[Finding.Notice]))
    assert(notice.exists(_.wording.contains("only-script")))

  test("provisioning reports every finding, runs only on an explicit yes, and rechecks after the run"):
    val project = Path.of("/Users/u/project")
    val provisionable: Finding.Provisionable = Finding.Provisionable(
      Program.Mill, project, "mill executable: not provisioned", Vector("./mill", "version"),
      Map("MILL_VERSION" -> "1.1.9-jvm"),
    )
    val notice = Finding.Notice(Program.Gradle, project.resolve("api"), "gradle wrapper: unreadable")
    val builds = Vector(BuildDirectory(Program.Gradle, project.resolve("api")), BuildDirectory(Program.Mill, project))
    def provisioned(
      reader: Option[Reader], exit: Either[String, Int], after: Option[Finding],
    ): (Vector[String], Vector[Finding.Provisionable]) =
      val reports = Vector.newBuilder[String]
      val runs = Vector.newBuilder[Finding.Provisionable]
      var ran = false
      val finding: BuildDirectory => Option[Finding] = build =>
        if build.program == Program.Gradle then Some(notice)
        else if ran then after
        else Some(provisionable)
      provision(
        builds, finding, reader,
        run = provisionable => { runs += provisionable; ran = true; exit }, report = reports += _,
      )
      (reports.result(), runs.result())

    def answering(answers: String*): (Reader, () => Vector[String]) =
      val prompts = Vector.newBuilder[String]
      val remaining = answers.iterator
      (Reader(prompts += _, () => if remaining.hasNext then Some(remaining.next()) else None), () => prompts.result())

    val expectedReports = Vector(
      "run-on-host gradle in /Users/u/project/api: gradle wrapper: unreadable",
      "run-on-host mill in /Users/u/project: mill executable: not provisioned",
    )
    assertEquals(provisioned(None, Right(0), None), (expectedReports, Vector.empty))

    val (declining, declinedPrompts) = answering("n")
    assertEquals(provisioned(Some(declining), Right(0), None), (expectedReports, Vector.empty))
    assertEquals(
      declinedPrompts(),
      Vector("run `MILL_VERSION=1.1.9-jvm ./mill version` in /Users/u/project now, unconfined on the host? [y/N] "),
    )
    val (silent, _) = answering()
    assertEquals(provisioned(Some(silent), Right(0), None)._2, Vector.empty)

    val (agreeing, _) = answering("y")
    assertEquals(provisioned(Some(agreeing), Right(0), None), (expectedReports, Vector(provisionable)))

    val (agreeingToFailure, _) = answering("yes")
    assertEquals(
      provisioned(Some(agreeingToFailure), Right(3), None)._1,
      expectedReports :+ "`MILL_VERSION=1.1.9-jvm ./mill version` in /Users/u/project exited 3",
    )
    val (agreeingToNoStart, _) = answering("y")
    assertEquals(
      provisioned(Some(agreeingToNoStart), Left("No such file"), None)._1,
      expectedReports :+ "`MILL_VERSION=1.1.9-jvm ./mill version` could not start: No such file",
    )
    val (agreeingInVain, _) = answering("y")
    assertEquals(
      provisioned(Some(agreeingInVain), Right(0), Some(provisionable))._1,
      expectedReports :+ "after the run, mill in /Users/u/project: mill executable: not provisioned",
    )

  test("a build directory is judged when its turn comes, so one run that provisions two is asked once"):
    val root = Files.createTempDirectory("provisioning").toRealPath()
    val project = millBuild(Files.createDirectories(root.resolve("project")))
    millBuild(project.resolve("lib"))
    val env = Map("HOME" -> root.toString)
    val prompts = Vector.newBuilder[String]
    val reports = Vector.newBuilder[String]
    val reader = Reader(prompts += _, () => Some("y"))
    provision(
      buildDirectories(project, Set(Program.Mill)), finding(_, env.get), Some(reader),
      run = _ =>
        executable(root.resolve(".cache/mill/download/1.1.9"))
        Right(0),
      report = reports += _,
    )
    assertEquals(prompts.result().size, 1)
    assertEquals(reports.result().size, 1)

  test("what the project wrote is shown spelled out, never acted on by the terminal"):
    val project = Path.of("/Users/u/project/a\u001b[2Kb\rc")
    val provisionable: Finding.Provisionable = Finding.Provisionable(
      Program.Mill, project, "mill executable: 1.1.9\u001b[2K-jvm is not provisioned", Vector("./mill", "version"),
      Map("MILL_VERSION" -> "1.1.9\u001b[2K-jvm"),
    )
    val prompts = Vector.newBuilder[String]
    val reports = Vector.newBuilder[String]
    provision(
      Vector(BuildDirectory(Program.Mill, project)), _ => Some(provisionable),
      Some(Reader(prompts += _, () => Some("n"))), run = _ => Right(0), report = reports += _,
    )
    assertEquals(
      reports.result(),
      Vector(
        "run-on-host mill in /Users/u/project/a\\x1b[2Kb\\rc: mill executable: 1.1.9\\x1b[2K-jvm is not provisioned",
      ),
    )
    assertEquals(
      prompts.result(),
      Vector(
        "run `MILL_VERSION=$'1.1.9\\x1b[2K-jvm' ./mill version` in /Users/u/project/a\\x1b[2Kb\\rc now, " +
          "unconfined on the host? [y/N] ",
      ),
    )

  test("the run happens in the build directory with the variables added to the launcher's environment"):
    val build = Files.createTempDirectory("provisioning").toRealPath()
    val script = build.resolve("mill")
    Files.writeString(script, "#!/bin/sh\nprintf '%s %s' \"$MILL_VERSION\" \"$PWD\" > witness\nexit 4\n")
    Files.setPosixFilePermissions(script, permissions("rwxr-xr-x"))
    val provisionable: Finding.Provisionable = Finding.Provisionable(
      Program.Mill, build, "", Vector("./mill", "version"), Map("MILL_VERSION" -> "1.1.9-jvm"),
    )
    assertEquals(runInBuildDirectory(provisionable), Right(4))
    assertEquals(Files.readString(build.resolve("witness")), s"1.1.9-jvm $build")
    assert(runInBuildDirectory(provisionable.copy(command = Vector("./absent"))).isLeft)
