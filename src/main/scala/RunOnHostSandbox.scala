// The supervisor: from a project and a program to a confined command's exit code, through the thirteen
// steps — validate, scavenge, publish, runtime, profile, run, end what was started, remove — and how
// the launcher's own executable is re-invoked as the runner, the supervisor and the proxy
// (selfInvocation). The runtimes the commands of one build directory share are RunnerRuntimes.scala,
// the sbt server RunOnHostSbtServer.scala, the proxy RunOnHostProxy.scala. macOS only, like everything it drives;
// the assembly and refusal logic are in RunOnHostPrereqs and are unit-tested there, so this file
// is the sequence of steps plus the host observations no Linux test can make.

package agentsandbox.launcher

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.{ISO_8859_1, UTF_8}
import java.nio.file.{Files, LinkOption, Path, SecureDirectoryStream, StandardOpenOption}
import java.nio.file.attribute.{BasicFileAttributeView, BasicFileAttributes}

import scala.jdk.CollectionConverters.*

import agentsandbox.egress.{BrokeredCredential, CredentialGrammar}

import RunOnHostPrereqs.*
import RunOnHostProxy.*
import RunOnHostSession.Session
import HostCommands.Os
import FileHelper.{directoryEntries, isExecutableFile, realPath}
import SandboxProject.projectIdOf

object RunOnHostSandbox:

  case class Assembled(
    prereqs: CommandPrereqs,
    /** The unpacked distribution the command also runs from: sbt's in the Coursier archive cache,
      * Gradle's and Maven's under their wrappers' `dists`; for mill, whose executable is one file,
      * the JDK a pinned `mill-jvm-version` runs the daemon on (RunOnHostPrereqs.millPinnedJdk),
      * none under `system`. */
    distribution: Option[Path],
    /** The per-project sbt global base and Ivy home, Gradle's user home and Maven's local
      * repository: created and granted for the program that reads each (`sbtCachesGranted`,
      * `gradleUserHomeGranted`, `m2RepositoryGranted`), and for the other programs paths nothing
      * reads, named all the same so the environment has the same variable names for every program
      * — as `millDownloads` is for sbt. */
    sbtGlobal: Path,
    ivyHome: Path,
    gradleUserHome: Path,
    m2Repository: Path,
    /** Where mill's bootstrap keeps launchers, as derived from this environment: what a mill
      * command is granted, and what its build script is pointed at (commandEnvironment). */
    millDownloads: Option[Path],
    /** The launcher version the bootstrap is told to run, `<v>-jvm`, for a mill command
      * (RunOnHostPrereqs.millLauncherVersion); None for the other programs. */
    millLauncherVersion: Option[String],
  ):
    def sbtGlobalGranted: Option[Path] = Option.when(prereqs.program == Program.Sbt)(sbtGlobal)
    def ivyHomeGranted: Option[Path] = Option.when(prereqs.program == Program.Sbt)(ivyHome)
    def gradleUserHomeGranted: Option[Path] = Option.when(prereqs.program == Program.Gradle)(gradleUserHome)
    def m2RepositoryGranted: Option[Path] = Option.when(prereqs.program == Program.Mvn)(m2Repository)
    /** The persistent caches an sbt command writes besides Coursier's. */
    def sbtCachesGranted: Seq[Path] = sbtGlobalGranted.toSeq ++ ivyHomeGranted

    /** The profile's inputs for a process of this command: what the assembly grants, and the rest
      * as the caller has it. */
    def profileInputs(
      sessionTmp: Path,
      proxyPort: Int,
      trust: Path,
      systemPaths: SeatbeltProfile.SystemPaths,
      network: SeatbeltProfile.Network,
      fileRules: FileRules.Resolved,
    ): SeatbeltProfile.ProfileInputs =
      SeatbeltProfile.ProfileInputs(
        prereqs = prereqs,
        sessionTmp = sessionTmp,
        distribution = distribution,
        sbtGlobal = sbtGlobalGranted,
        ivyHome = ivyHomeGranted,
        gradleUserHome = gradleUserHomeGranted,
        m2Repository = m2RepositoryGranted,
        proxyPort = proxyPort,
        trust = trust,
        systemPaths = systemPaths,
        network = network,
        fileRules = fileRules,
      )

  /** A file the prerequisites cannot read, carried out of the readers — whose callers are pure
    * and take a reader that answers absent or present — to the assembly's boundary, where it is
    * one worded refusal. Existing-but-unreadable never falls to the next source: mill would
    * select the file and then fail reading it. */
  private[launcher] final class Unreadable(val refusal: Refusal) extends RuntimeException(null, null, false, false)

  private def reading[A](path: Path)(read: => A): A =
    try read
    catch
      case ex: IOException =>
        val reason = ex match
          case _: java.nio.charset.CharacterCodingException => "not valid UTF-8"
          case _: java.nio.file.AccessDeniedException       => "permission denied"
          case _                                             => ex.getClass.getSimpleName
        throw Unreadable(Refusal.PrerequisiteFileUnreadable(path, reason))

  /** Absent is None. */
  private[launcher] def readLines(path: Path): Option[Seq[String]] =
    reading(path)(Option.when(Files.exists(path))(Files.readAllLines(path).toArray(Array.empty[String]).toSeq))

  private def readText(path: Path): Option[String] =
    reading(path)(Option.when(Files.exists(path))(Files.readString(path, UTF_8)))

  private def readBytes(path: Path): Array[Byte] = reading(path)(Files.readAllBytes(path))

  /** Absent is None. ISO-8859-1, as `java.util.Properties` reads a stream. */
  private def readLatin1(path: Path): Option[String] =
    reading(path)(Option.when(Files.exists(path))(String(Files.readAllBytes(path), ISO_8859_1)))

  /** Only so that the read is bounded: far above any key and path mill writes, the key's
    * `mill-repositories` included, and small beside the launcher's heap. */
  private val MillJavaHomeMaxBytes = 256 * 1024
  private val MillJavaHomeReadMillis = 2000L

  /** The reads of mill's `java-home` file running or abandoned at once (millJavaHomeText). */
  private val MillJavaHomeReaders = java.util.concurrent.Semaphore(4)

  /**
   * The text of mill's `java-home` file in `buildDirectory` (RunOnHostPrereqs.MillJavaHomeFile),
   * None when it is absent or cannot be read as the build's own file.
   *
   * The launcher reads it outside any profile, under the runner's monitor, while a command of the
   * project may be writing under `out/`. So each directory is opened relative to the one before
   * it and the file relative to the last, none through a symlink, whatever a command renames
   * meanwhile; the read stops at `MillJavaHomeMaxBytes`, whatever size the file reports; and the
   * whole is abandoned after `MillJavaHomeReadMillis`, since the open of a FIFO moved into the
   * file's place after the type check would not return. The text is never printed.
   *
   * An abandoned read keeps its thread and its directories until a writer opens that FIFO, so
   * `readers` bounds how many exist: with none free the file reads as absent, and the build is
   * refused as not provisioned until one returns.
   *
   * `raced` runs between the type check and the open: tests replace it to stand in for that command.
   */
  private[launcher] def millJavaHomeText(
    buildDirectory: Path,
    millis: Long = MillJavaHomeReadMillis,
    raced: () => Unit = () => (),
    readers: java.util.concurrent.Semaphore = MillJavaHomeReaders,
  ): Option[String] =
    if !readers.tryAcquire() then None
    else
      val read = java.util.concurrent.FutureTask[Option[String]]: () =>
        try millJavaHomeRead(buildDirectory, raced)
        finally readers.release()
      try Thread.ofPlatform().daemon().name("mill-java-home-read").start(read)
      catch
        case ex: Throwable =>
          readers.release()
          throw ex
      try read.get(millis, java.util.concurrent.TimeUnit.MILLISECONDS)
      catch case _: (java.util.concurrent.TimeoutException | java.util.concurrent.ExecutionException) => None

  private def millJavaHomeRead(buildDirectory: Path, raced: () => Unit): Option[String] =
    def opened(directory: SecureDirectoryStream[Path], names: List[Path]): Option[String] =
      try
        names match
          case file :: Nil =>
            val regular = directory
              .getFileAttributeView(file, classOf[BasicFileAttributeView], LinkOption.NOFOLLOW_LINKS)
              .readAttributes().isRegularFile
            raced()
            if !regular then None
            else
              val channel =
                directory.newByteChannel(file, java.util.Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))
              try
                val buffer = ByteBuffer.allocate(MillJavaHomeMaxBytes + 1)
                var open = true
                while open && buffer.hasRemaining do
                  if channel.read(buffer) < 0 then open = false
                Option.when(buffer.position() <= MillJavaHomeMaxBytes):
                  UTF_8.newDecoder().decode(buffer.flip()).toString
              finally channel.close()
          case next :: deeper => opened(directory.newDirectoryStream(next, LinkOption.NOFOLLOW_LINKS), deeper)
          case Nil            => None
      finally directory.close()
    try
      Files.newDirectoryStream(buildDirectory) match
        case secure: SecureDirectoryStream[Path] =>
          opened(secure, Path.of(MillJavaHomeFile).iterator().asScala.toList)
        // A JVM without openat has no way to hold a directory while a command renames it.
        case plain =>
          plain.close()
          None
    catch case _: IOException => None

  /** The directories directly inside `path`; none when it is absent. */
  private def directories(path: Path): Seq[Path] =
    reading(path):
      if !Files.isDirectory(path) then Seq.empty
      else directoryEntries(path).filter(Files.isDirectory(_))

  /** Steps 1–5: everything the profile derives authority from, decided before anything runs.
    * `buildDirectory` is where the command runs, the project or a directory beneath it: mill's
    * bootstrap, version pin and JVM pin are that directory's, as the bootstrap reads them from its
    * working directory, so a nested build is another build; the grants stay the project's. */
  def assemble(
    project: Path, program: Program, env: String => Option[String], buildDirectory: Path,
  ): Either[String, Assembled] =
    try assembled(project, program, env, buildDirectory).left.map(_.worded)
    catch case ex: Unreadable => Left(wording(ex.refusal))

  /** Why one step of the assembly refuses, kept typed to the assembly's boundary: the launch's
    * provisioning (RunOnHostProvisioning) runs a script for three of the cases and words the rest. */
  final case class StepRefusal(step: String, refusal: Refusal | String):
    def worded: String = refusal match
      case refusal: Refusal => s"$step: ${wording(refusal)}"
      case reason: String   => s"$step: $reason"

  private def context[A](step: String)(value: Either[Refusal | String, A]): Either[StepRefusal, A] =
    value.left.map(StepRefusal(step, _))

  /** The executable a `mill`, `gradle` or `mvn` command from `buildDirectory` — the project, for
    * Maven — would be granted, the one the user provisions (run-on-host.md "Program
    * prerequisites"), or the step refusing it. */
  def provisionedExecutable(
    program: Program, env: String => Option[String], buildDirectory: Path,
  ): Either[StepRefusal, Path] =
    try
      program match
        case Program.Mill   => millLauncher(env, buildDirectory).map(_.executable)
        case Program.Gradle => gradleDistribution(env, buildDirectory).map(_.resolve("bin").resolve("gradle"))
        case Program.Mvn    => mvnDistribution(env, buildDirectory).map(_.resolve("bin").resolve("mvn"))
        case Program.Sbt    => Left(StepRefusal("sbt executable", "sbt's executable is the user's, not the project's"))
    catch case ex: Unreadable => Left(StepRefusal(program.name, ex.refusal))

  /** Mill's provisioned JVM launcher, its version, `<v>-jvm`, and the JDK a pinned
    * `mill-jvm-version` runs the daemon on. */
  private case class MillLauncher(executable: Path, version: String, pinnedJdk: Option[Path])

  /** Resolved as the bootstrap and mill's launcher in `buildDirectory` resolve them. The
    * executable before the pinned JDK: the host run that provisions the one provisions the other. */
  private def millLauncher(env: String => Option[String], buildDirectory: Path): Either[StepRefusal, MillLauncher] =
    for
      _ <- context("mill bootstrap")(validateMillBootstrap(buildDirectory, isExecutableFile))
      jvm <- context("mill jvm")(millJvm(buildDirectory, readLines))
      pinned <- context("mill version")(millVersion(buildDirectory, readLines))
      launcher <- context("mill version")(millLauncherVersion(pinned))
      downloads <- context("mill executable")(millDownloadDir(env).toRight("no mill download folder"))
      provisioned <- context("mill executable")(millExecutable(downloads, launcher, isExecutableFile))
      real <- context("mill executable")(realPath(provisioned).toRight(s"$provisioned vanished"))
      jdk <- jvm match
        case MillJvm.System => Right(None)
        case MillJvm.Pinned(id) =>
          for
            cache <- context("mill jvm")(coursierCacheRoot(Os.Mac, env).toRight("no Coursier cache root"))
            home <- context("mill jvm"):
              millPinnedJdk(id, launcher, millJavaHomeText(buildDirectory), cache, realPath, isExecutableFile)
          yield Some(home)
    yield MillLauncher(real, launcher, jdk)

  /** Gradle's home as the wrapper in `buildDirectory` would run it: a nested build directory with
    * a wrapper of its own is another build, as under mill. */
  private def gradleDistribution(env: String => Option[String], buildDirectory: Path): Either[StepRefusal, Path] =
    val properties = buildDirectory.resolve("gradle").resolve("wrapper").resolve("gradle-wrapper.properties")
    for
      text <- context("gradle wrapper")(readLatin1(properties).toRight(Refusal.PrereqGradleWrapperMissing))
      url <- context("gradle wrapper")(
        gradleDistributionUrl(text, properties.getParent, readLatin1(buildDirectory.resolve("gradle.properties"))),
      )
      userHome <- context("gradle distribution")(gradleUserHome(env).toRight("no Gradle user home"))
      home <- context("gradle distribution")(
        gradleDistributionHome(gradleDistributionDir(userHome, url), url, directories, isExecutableFile),
      )
      real <- context("gradle distribution")(realPath(home).toRight(s"$home vanished"))
    yield real

  /** Maven's home as the project's wrapper would run it. */
  private def mvnDistribution(env: String => Option[String], project: Path): Either[StepRefusal, Path] =
    for
      wrapper <- context("mvn wrapper")(validateMvnWrapper(project, isExecutableFile))
      _ <- context("mvn wrapper")(validateMvnWrapperScript(readLines(wrapper).getOrElse(Seq.empty)))
      properties = project.resolve(".mvn").resolve("wrapper").resolve("maven-wrapper.properties")
      url <- context("mvn wrapper")(
        readText(properties).toRight(Refusal.PrereqMvnWrapperUnreadable(s"$properties is absent"))
          .flatMap(mvnDistributionUrl(_, env("MVNW_REPOURL"))),
      )
      userHome <- context("mvn distribution")(mvnUserHome(env).toRight("no Maven user home"))
      home <- context("mvn distribution")(mvnDistributionHome(mvnDistributionDir(userHome, url), url, isExecutableFile))
      real <- context("mvn distribution")(realPath(home).toRight(s"$home vanished"))
    yield real

  private def assembled(
    project: Path, program: Program, env: String => Option[String], buildDirectory: Path,
  ): Either[StepRefusal, Assembled] =
    val os = Os.Mac
    for
      coursierCache <- context("jvm")(coursierCacheRoot(os, env).toRight("no Coursier cache root"))
      jdk <- context("jvm")(resolveJdkHome(env, coursierCache, realPath, isExecutableFile))
      executableAndDistribution <- program match
        case Program.Sbt =>
          for
            installDir <- context("sbt executable")(
              coursierInstallDir(os, env).toRight("no Coursier install directory"),
            )
            sbt <- context("sbt executable")(
              validateSbtExecutable(installDir.resolve("sbt"), installDir, realPath, isExecutableFile),
            )
            // ISO-8859-1, not UTF-8: cs appends a jar to the scripts it installs, so the file is not text.
            // Every byte maps to a char, which leaves the ASCII path this searches for intact.
            inner <- context("sbt distribution")(
              sbtDistribution(String(readBytes(sbt), ISO_8859_1), coursierCache)
                .toRight(s"$sbt names no distribution inside $coursierCache"),
            )
            home <- context("sbt distribution")(
              validateSbtDistribution(inner, coursierCache, realPath, isExecutableFile),
            )
          yield (sbt, Some(home), None)
        case Program.Mill =>
          millLauncher(env, buildDirectory).map(mill => (mill.executable, mill.pinnedJdk, Some(mill.version)))
        case Program.Gradle =>
          gradleDistribution(env, buildDirectory).map(real => (real.resolve("bin").resolve("gradle"), Some(real), None))
        case Program.Mvn =>
          mvnDistribution(env, project).map(real => (real.resolve("bin").resolve("mvn"), Some(real), None))
      (executable, distribution, millLauncher) = executableAndDistribution
      configuredRoot <- context("cache root")(cacheRootOf(os, env))
      cacheRoot <- context("cache root")(
        cacheRootOutsideProject(configuredRoot, project, os, FileHelper.canonicalizedFuturePath),
      )
      // stateRootOf words its refusals for `fail`, which prints them whole.
      stateRoot <- context("state root")(
        LauncherState.stateRootOf(os, env).left.map(_.stripPrefix("error: ")),
      )
      projectId = projectIdOf(project, os)
      v1Dir = coursierV1Of(cacheRoot, projectId)
      sbtGlobalDir = sbtGlobalOf(cacheRoot, projectId)
      ivyHomeDir = ivyHomeOf(cacheRoot, projectId)
      gradleUserHomeDir = gradleUserHomeOf(cacheRoot, projectId)
      m2RepositoryDir = m2RepositoryOf(cacheRoot, projectId)
      // Each directory as it will be granted, before it is created: an existing symlink among its
      // ancestors — `run-on-host`, the project's directory — places it wherever the link points.
      _ <- Vector(v1Dir, sbtGlobalDir, ivyHomeDir, gradleUserHomeDir, m2RepositoryDir)
        .foldLeft(Right(()): Either[StepRefusal, Unit]): (checked, dir) =>
          checked.flatMap: _ =>
            context("cache directory"):
              FileHelper.canonicalizedFuturePath(dir).left.map(Refusal.CacheRootUnusable(_))
                .flatMap(cacheRootOutsideProject(_, project, os, Right(_)))
                .flatMap(cachePathClearOfStateRoot(_, stateRoot, os))
                .map(_ => ())
      v1 = Files.createDirectories(v1Dir)
      programCache = (owner: Program, dir: Path) =>
        if program == owner then Files.createDirectories(dir).toRealPath() else dir
      sbtGlobal = programCache(Program.Sbt, sbtGlobalDir)
      ivyHome = programCache(Program.Sbt, ivyHomeDir)
      gradleUserHome = programCache(Program.Gradle, gradleUserHomeDir)
      m2Repository = programCache(Program.Mvn, m2RepositoryDir)
    yield Assembled(
      CommandPrereqs(
        project = project,
        jdkHome = jdk,
        coursierV1 = v1.toRealPath(),
        program = program,
        executable = executable,
      ),
      distribution,
      sbtGlobal,
      ivyHome,
      gradleUserHome,
      m2Repository,
      millDownloadDir(env),
      millLauncher,
    )

  /**
   * The grammar of SeatbeltProfile.SystemPaths.txt: one absolute path per line, `#` comments,
   * `x ` prefix for a path that must also be executable. A system path is granted only where
   * testing proves the read is stable; the resource agentsandbox/SeatbeltProfile.SystemPaths.txt
   * is the measured set, and src/probe/run-on-host-profile-iterate.sh is how candidate entries are
   * measured.
   */
  def parseSystemPaths(all: Seq[String]): SeatbeltProfile.SystemPaths =
    val lines = all.map(_.trim).filter(line => line.nonEmpty && !line.startsWith("#"))
    val executes = lines.filter(_.startsWith("x ")).map(line => Path.of(line.drop(2).trim))
    val reads = lines.filterNot(_.startsWith("x ")).map(Path.of(_))
    SeatbeltProfile.SystemPaths(reads.flatMap(realPath), executes.flatMap(realPath))

  def readSystemPaths(file: Option[Path]): SeatbeltProfile.SystemPaths =
    file match
      case None => SeatbeltProfile.SystemPaths(Seq.empty, Seq.empty)
      case Some(path) =>
        parseSystemPaths(Files.readAllLines(path).toArray(Array.empty[String]).toSeq)

  def bundledSystemPaths(): SeatbeltProfile.SystemPaths =
    val stream = getClass.getResourceAsStream("/agentsandbox/SeatbeltProfile.SystemPaths.txt")
    if stream == null then
      throw IllegalStateException("this jar bundles no SeatbeltProfile.SystemPaths.txt; rebuild it")
    val text =
      try String(stream.readAllBytes(), UTF_8)
      finally stream.close()
    parseSystemPaths(text.linesIterator.toSeq)

  /** What opens the JDK's internal certificate builder to X509Helper, which has why. The jar's
    * manifest carries the same two for `java -jar` (build.sbt), and a manifest is read for `-jar`
    * alone: a re-invocation is `java -cp`, and the runner and the supervisor it starts issue each
    * proxy's certificates (RunOnHostInspection), which without these dies of IllegalAccessError. */
  val CertificateBuilderExports: Seq[String] = Seq(
    "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
    "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
  )

  /** How the supervisor re-invokes its own executable — the running JVM and classpath, or the native
    * image binary itself — under one of the launcher's private actions. */
  def selfInvocation(actionAndArguments: String*): Seq[String] =
    if isNativeImage then
      launchFile.getOrElse(throw IllegalStateException("the native image cannot name itself")).toString
        +: actionAndArguments
    else
      val javaExecutable = Path.of(System.getProperty("java.home")).resolve("bin").resolve("java").toString
      (javaExecutable +: CertificateBuilderExports) ++ Seq(
        "-cp", selfClassPath().mkString(java.io.File.pathSeparator),
        "agentsandbox.launcher.AgentSandboxLauncher",
      ) ++ actionAndArguments

  /** This JVM's class path with every element absolute against this JVM's working directory —
    * `java -jar target/dist/ko-agent-sandbox.jar` names it relative, and an empty element is
    * that directory itself — since the proxy runs from `/` (RunOnHostProxy.startProxy), where a relative
    * element names nothing. */
  def selfClassPath(classPath: String = System.getProperty("java.class.path")): Seq[String] =
    classPath.split(java.io.File.pathSeparator, -1).toSeq.map(entry => Path.of(entry).toAbsolutePath.toString)

  /** Whether this launcher runs as the GraalVM native image rather than as a JVM over the jar. */
  def isNativeImage: Boolean = System.getProperty("org.graalvm.nativeimage.imagecode") != null

  /** The class-path entry this process's code was loaded from, spelled as the class path spells
    * it, or none when that code is off the class path — under sbt, which loads the project's
    * classes through loaders of its own. Matched by resolved path, since the JDK canonicalizes an
    * entry as it loads it: the CodeSource has a launch symlink resolved away, while the
    * re-invocation (selfInvocation) spells the link, and it is the link that must remain. Any
    * other entry is the JVM's to skip when missing. */
  def launchEntry(classPath: String, codeSource: Option[Path]): Option[Path] =
    codeSource.flatMap(realPath).flatMap: source =>
      selfClassPath(classPath).map(Path.of(_)).find(entry => realPath(entry).contains(source))

  /** The file this launcher's own executable is re-invoked from (selfInvocation): the native
    * image binary, which is self-contained and reads no jar, or the jar form's launch entry
    * (launchEntry). Read once, when this object initializes — at each launcher process's start,
    * since every one calls in here before it serves or spawns — so it is the file the process was
    * loaded from. The JDK is left out: coursier's under the cache root, which no project clean
    * removes. */
  private[launcher] val launchFile: Option[Path] =
    if isNativeImage then
      val command = ProcessHandle.current().info().command()
      Option.when(command.isPresent)(Path.of(command.get))
    else
      launchEntry(
        System.getProperty("java.class.path"),
        Option(getClass.getProtectionDomain.getCodeSource).map(source => Path.of(source.getLocation.toURI)),
      )

  /** The launch file resolved, still present, or the reason to refuse the re-invocation with,
    * naming it as spelled; none to check passes, there being no file a re-invocation loads this
    * process's code from. Both forms alike: the jar and the native image are each one file, built
    * under `target/dist`, which `sbt clean` or `git clean` removes while a session runs. Checked
    * before a supervisor is exec'd (RunnerRuntimes.prepare, every program) and before a proxy is
    * started (RunOnHostProxy.proxyInputs): a JVM starts with a missing class-path entry and fails only at loading
    * the main class, so unchecked, the jar form's failure is the proxy's ready wait timing out over
    * a Java error in its log, and the native form's is a spawn that fails to exec. Not checked at
    * the launch's own runner spawn (RunOnHostChannel.spawnRunner), which follows the launcher's
    * own load from that file. A rebuild at the same path is not a removal, nor is a symlink's
    * retargeting: the running processes keep their inode, and the next re-invocation runs the new
    * file. */
  def selfPresent(file: Option[Path] = launchFile): Either[String, Option[Path]] =
    file match
      case None => Right(None)
      case Some(path) =>
        realPath(path).map(Some(_)).toRight(
          s"the launcher's executable $path no longer exists; rebuild it at that path, " +
            "or relaunch the session from an executable outside the project",
        )

  /** `--run-command-on-host <program> <project> <cwd> [--env=<name>...] [--channel-log=<file>]
    * [--runtime-session=<dir> --proxy-port=<port> --proxy-log=<file> [--daemon-port=<port> --daemon-pid=<pid>]]
    * [--credentials-on-stdin] --
    * <args...>`: one channel request as a process of its own, so the runner's cancel is a SIGTERM
    * whose answer is this supervisor's shutdown hook. The runtime options name the runner's runtime
    * (Runtime). */
  def runCommandMain(args: Seq[String]): Unit =
    def start(
      programName: String,
      project: String,
      workingDirectory: String,
      options: List[String],
      commandArgs: List[String],
    ): Unit =
      val program = Program.named(programName).getOrElse:
        Console.err.println(s"--run-command-on-host: unknown program $programName")
        sys.exit(2)
      val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
      val stray = options.filterNot(option =>
        option.startsWith(EnvOption) || option.startsWith(ChannelLogOption)
          || option.startsWith(RuntimeSessionOption) || option.startsWith(ProxyPortOption)
          || option.startsWith(ProxyLogOption) || option.startsWith(DaemonPortOption)
          || option.startsWith(DaemonPidOption)
          || option.startsWith(FileRulesOption) || option == CredentialsOption,
      )
      if stray.nonEmpty then
        Console.err.println(s"--run-command-on-host: unexpected arguments: ${stray.mkString(" ")}")
        sys.exit(2)
      val runtime = runtimeOf(options).fold(
        reason => { Console.err.println(s"--run-command-on-host: $reason"); sys.exit(2) },
        identity,
      )
      val fileRules = fileRulesOf(options, Path.of(project)).fold(
        reason => { Console.err.println(s"--run-command-on-host: $reason"); sys.exit(2) },
        identity,
      )
      // The frame the runner wrote after its word, before anything else reads this pipe.
      val credentials =
        if !options.contains(CredentialsOption) then Vector.empty
        else
          readStdinCredentials().fold(
            reason => { Console.err.println(s"--run-command-on-host: the brokered credentials: $reason"); sys.exit(2) },
            identity,
          )
      // The runner's pipe (RunOnHostChannel.dispatch): its EOF is the runner gone, and the command
      // ends with it through the shutdown hook, as it ends with the requester's ctl. The status is
      // nobody's to read. A def, not the thread's own lambda: a lambda ending in sys.exit types
      // as Nothing, which the JVM's lambda factory refuses for Runnable's void at link time.
      def endWithRunner(): Unit =
        try while System.in.read() != -1 do ()
        catch case _: IOException => ()
        sys.exit(143)
      val runnerGone = Thread(() => endWithRunner())
      runnerGone.setDaemon(true)
      runnerGone.start()
      sys.exit(
        run(
          Path.of(project), program, commandArgs, bundledSystemPaths(), uid,
          Console.err.println, workingDirectory = Some(Path.of(workingDirectory)),
          forwarded = forwardedNames(options),
          channelLog = options.find(_.startsWith(ChannelLogOption))
            .map(option => Path.of(option.stripPrefix(ChannelLogOption))),
          runtime = runtime,
          fileRules = fileRules,
          credentials = credentials,
        ),
      )
    args.toList match
      case programName :: project :: workingDirectory :: rest if rest.contains("--") =>
        val (options, commandArgs) = rest.span(_ != "--")
        start(programName, project, workingDirectory, options, commandArgs.drop(1))
      case other =>
        Console.err.println(s"--run-command-on-host: unexpected arguments: ${other.mkString(" ")}")
        sys.exit(2)

  /** `--env=<name>` as the runner and the command receive it: the name alone, the value read from
    * the receiving process's own environment under `carrierName` (RunOnHostChannel.spawnRunner).
    * A forward is thus never an argument with a secret in it below the launcher. */
  val EnvOption = "--env="

  def forwardedNames(options: Seq[String]): Vector[String] =
    options.filter(_.startsWith(EnvOption)).map(_.stripPrefix(EnvOption)).toVector

  /** `--credentials-on-stdin`: the process's brokered credentials follow on its standard input
    * (CredentialGrammar.bindingInput), the runner's from the launcher and a supervisor's after the
    * runner's word (RunOnHostChannel.dispatch). The option carries no value; values never appear in arguments. */
  val CredentialsOption = "--credentials-on-stdin"

  /** Reads one byte at a time, consuming nothing after the bindings; call it before anything else reads
    * standard input. */
  def readStdinCredentials(): Either[String, Vector[BrokeredCredential]] =
    CredentialGrammar.readBindings(java.io.FileInputStream(java.io.FileDescriptor.in))

  /**
   * The hosts a program's proxy substitutes credentials for: every host its rules allow, all of which it
   * inspects (egressRuleText), as the proxy's own resolution names them (RunOnHostInspection.leafNames).
   * A binding's host has that form (CredentialGrammar), and the proxy's start refuses a binding to any
   * other host. Empty for rules the proxy refuses, which readProgramRules does not return.
   */
  def credentialHosts(program: Program, fileHosts: Vector[String]): Set[String] =
    RunOnHostInspection.leafNames(egressRuleText(program, fileHosts)).fold(_ => Set.empty, _.toSet)

  /** What a program's proxy is given: the credentials for its credentialHosts, and no other. */
  def credentialsFor(
    program: Program,
    fileHosts: Vector[String],
    credentials: Seq[BrokeredCredential],
  ): Vector[BrokeredCredential] =
    EgressCredentials.bindingsFor(credentials, credentialHosts(program, fileHosts))

  /** `--channel-log=<file>`: the runner's own log, where the supervisor appends a signal-ended
    * command's logs (appendSessionLogs). */
  val ChannelLogOption = "--channel-log="

  /** `--file-rules=<file>`: the resolved file rules the launch wrote for its runner, which hands the
    * option on to each command (RunOnHostChannel.spawnRunner). */
  val FileRulesOption = "--file-rules="

  /** The file rules a command's or runtime's profile denies writes to: the launch's resolved set
    * when the runner handed one on, else the project's lines alone (FileRules.ofProject). */
  def fileRulesOf(options: Seq[String], project: Path): Either[String, FileRules.Resolved] =
    options.find(_.startsWith(FileRulesOption)) match
      case Some(option) => FileRules.readResolved(Path.of(option.stripPrefix(FileRulesOption)))
      case None         => FileRules.ofProject(project)

  /** The runner's runtime as the supervisor's options: the first three together or none, the
    * daemon's port and pid with them for a mill runtime. */
  val RuntimeSessionOption = "--runtime-session="
  val ProxyPortOption = "--proxy-port="
  val ProxyLogOption = "--proxy-log="
  val DaemonPortOption = "--daemon-port="
  val DaemonPidOption = "--daemon-pid="

  def runtimeOptions(runtime: Runtime): Seq[String] =
    Seq(
      s"$RuntimeSessionOption${runtime.session}", s"$ProxyPortOption${runtime.proxyPort}",
      s"$ProxyLogOption${runtime.proxyLog}",
    ) ++ runtime.daemonPort.map(port => s"$DaemonPortOption$port")
      ++ runtime.daemonPid.map(pid => s"$DaemonPidOption$pid")

  def runtimeOf(options: Seq[String]): Either[String, Option[Runtime]] =
    def value(prefix: String) = options.find(_.startsWith(prefix)).map(_.stripPrefix(prefix))
    def port(prefix: String, text: String) = text.toIntOption.toRight(s"$prefix$text is no port")
    def pid(text: String) = text.toLongOption.filter(_ > 0).toRight(s"$DaemonPidOption$text is no pid")
    (value(RuntimeSessionOption), value(ProxyPortOption), value(ProxyLogOption), value(DaemonPortOption),
      value(DaemonPidOption)) match
      case (None, None, None, None, None) => Right(None)
      case (Some(_), Some(_), Some(_), Some(_), None) | (Some(_), Some(_), Some(_), None, Some(_)) =>
        Left(s"$DaemonPortOption and $DaemonPidOption come together")
      case (Some(session), Some(proxy), Some(log), daemonPortText, daemonPidText) =>
        for
          proxyPort <- port(ProxyPortOption, proxy)
          daemonPort <- daemonPortText.map(port(DaemonPortOption, _).map(Some(_))).getOrElse(Right(None))
          daemonPid <- daemonPidText.map(pid(_).map(Some(_))).getOrElse(Right(None))
        yield Some(Runtime(Path.of(session), proxyPort, Path.of(log), daemonPort, daemonPid))
      case _ => Left(s"$RuntimeSessionOption, $ProxyPortOption and $ProxyLogOption come together")

  /** The last bytes of each command log appended to the channel log: a stalled command's last
    * lines are the finding, and a build's audit log can run long. */
  val SessionLogTailBytes = 64 << 10

  /** Logs retained before a session's directory is removed: the proxy audit logs — a command's
    * `proxy.log`, the runner's one per runtime — the sbt servers' logs (RunOnHostSbtServer.serverLog),
    * the mill starters' output (RunOnHostMillDaemons.starterLog), and the stderr file a thin client
    * leaves under `tmp/` when it forked a server of its own.
    * run-on-host.md "The channel and the command" has why every signal keeps them and what a
    * server's file holds. `condemned` is the session directory at its condemned pathname with
    * its groups ended (RunOnHostSession.endSession), so no process the session started can
    * change what is read; the tmp check below and sessionLogTail keep each read inside the
    * directory, except a proxy's audit log, which is read where the launcher keeps it
    * (RunOnHostProxy.keptAuditLog). `ended` is the block's first line, naming the session and how it ended. */
  def appendSessionLogs(channelLog: Path, condemned: Path, ended: String): Unit =
    val block = StringBuilder()
    block.append(s"${java.time.Instant.now()} $ended; its logs follow\n")
    val proxyLogs =
      try
        directoryEntries(condemned)
          .filter(file => file.getFileName.toString.matches("(proxy|server|daemon).*\\.log")).sorted
      catch case _: IOException => Vector.empty
    // The command's write grant includes tmp itself, so the command can replace it with a symlink
    // that survives the session directory's rename.
    val tmp = condemned.resolve(RunOnHostSession.TmpDir)
    val clientForkedStderr =
      if !Files.isDirectory(tmp, LinkOption.NOFOLLOW_LINKS) then
        block.append(s"==> ${RunOnHostSession.TmpDir}\n[skipped: not a directory]\n")
        Vector.empty
      else
        try
          directoryEntries(tmp)
            .filter(_.getFileName.toString.startsWith("sbt-server-err")).sorted
        catch case _: IOException => Vector.empty
    (proxyLogs ++ clientForkedStderr).foreach: file =>
      sessionLogTail(RunOnHostProxy.keptAuditLog(channelLog, file).getOrElse(file)).foreach: tail =>
        block.append(s"==> ${file.getFileName}\n").append(tail)
        if !tail.endsWith("\n") then block.append('\n')
    try Files.writeString(channelLog, block.toString, UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND)
    catch case _: IOException => ()

  /** The tail of one session log, as the file the listing named and nothing it could point to:
    * the attributes are read without following a link, the open refuses one, and the read is
    * positioned at the tail rather than sized by the file — a sparse file's size is the command's
    * to choose. Absent is None; anything but a regular file is named and not opened, since an
    * open FIFO would hold this teardown. */
  private[launcher] def sessionLogTail(file: Path, bytes: Int = SessionLogTailBytes): Option[String] =
    try
      val attributes = Files.readAttributes(file, classOf[BasicFileAttributes], LinkOption.NOFOLLOW_LINKS)
      if !attributes.isRegularFile then Some("[skipped: not a regular file]\n")
      else
        val channel = Files.newByteChannel(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)
        try
          val start = math.max(0L, channel.size() - bytes)
          channel.position(start)
          val buffer = ByteBuffer.allocate(bytes)
          var open = true
          while open && buffer.hasRemaining do
            if channel.read(buffer) < 0 then open = false
          val text = String(buffer.array, 0, buffer.position(), UTF_8)
          Some(if start > 0 then s"[last $bytes bytes]\n$text" else text)
        finally channel.close()
    catch
      case _: java.nio.file.NoSuchFileException => None
      case ex: IOException => Some(s"[unreadable: ${ex.getMessage}]\n")

  /** The name a forwarded value is carried under from the launcher to the confined command: one nothing
    * reads by accident. The runner and the supervisor are unconfined JVMs of the launcher's own code, and an
    * explicit `--env=NAME=VALUE` installed under its own name — a loader variable, say — would be
    * read by them first; the requested name is restored inside the command's environment alone,
    * where the supervisor's own settings still win over it. */
  def carrierName(name: String): String = s"KO_AGENT_RUN_ON_HOST_ENV_$name"

  // ---------------------------------------------------------------------------
  // The thirteen steps
  // ---------------------------------------------------------------------------

  def run(
    projectArg: Path,
    program: Program,
    commandArgs: Seq[String],
    systemPaths: SeatbeltProfile.SystemPaths,
    uid: Int,
    log: String => Unit,
    // The channel's validated WORKING_DIRECTORY: only the child's cwd, never a grant.
    workingDirectory: Option[Path] = None,
    // What `--env` named at launch, the same authority; the values are in this process's
    // environment under carrierName.
    forwarded: Vector[String] = Vector.empty,
    // Where a command ended by signal leaves its session's logs (appendSessionLogs).
    channelLog: Option[Path] = None,
    // The runner's runtime for this command (Runtime).
    runtime: Option[Runtime] = None,
    // The launch's resolved file rules (fileRulesOf).
    fileRules: FileRules.Resolved = FileRules.Resolved.Empty,
    // The brokered credentials, for the proxy this command starts when the runner holds none for it.
    credentials: Vector[BrokeredCredential] = Vector.empty,
  ): Int =
    val env: String => Option[String] = name => Option(System.getenv(name))
    val root = RunOnHostSession.root(uid)

    val prepared: Either[String, Assembled] =
      for
        project <-
          try Right(projectArg.toAbsolutePath.toRealPath())
          catch case ex: IOException => Left(s"$projectArg: ${ex.getMessage}")
        assembled <- assemble(project, program, env, workingDirectory.getOrElse(project))
        _ <- RunOnHostSession.ensureRoot(root, uid)
        // Scavenge before anything runs — an orphan a kill left is ours to end here — but only
        // when not dispatched by a runner: the runner owns scavenging (at its startup and before
        // each runtime it prepares), and a dispatched command scavenging the root could condemn
        // the live runner's own session. channelLog is set exactly when the runner dispatched
        // this command; the acceptance test's own entry, with none, still scavenges.
        _ =
          if channelLog.isEmpty then
            RunOnHostSession
              .scavenge(root, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_))
              .foreach: (entry, actions) =>
                log(s"scavenged ${entry.getFileName}: ${actions.mkString(", ")}")
      yield assembled

    prepared match
      case Left(reason) =>
        log(s"refused: $reason")
        2
      case Right(assembled) =>
        RunOnHostSession.publish(root, assembled.prereqs.project) match
          case Left(reason) =>
            log(s"refused: $reason")
            2
          case Right(session) =>
            // Also on a shutdown hook (RunOnHostSession.Teardown): the registered groups are
            // outside the terminal's own, so nothing but this would end them on a Ctrl-C.
            val teardown = RunOnHostSession.Teardown: bySignal =>
              RunOnHostSession
                .endSession(root, session, RunOnHostSession.HostProcesses,
                  RunOnHostSbtServerShutdown.shutdown(_),
                  beforeRemoval =
                    if bySignal then
                      condemned =>
                        channelLog.foreach(
                          appendSessionLogs(_, condemned, s"command ${condemned.getFileName} ended by signal"),
                        )
                    else _ => ())
                .filter(_.keeps)
                .foreach(kept => log(s"kept for the next start to retry: $kept"))
            val hook = Thread(() => teardown(bySignal = true))
            java.lang.Runtime.getRuntime.addShutdownHook(hook)
            val outcome =
              try
                sessionTmpFits(session.tmp) match
                  case Left(refusal) => Left(wording(refusal))
                  case Right(_) =>
                    runInSession(
                      session, assembled, commandArgs, systemPaths, workingDirectory, log,
                      forwarded.flatMap(name => env(carrierName(name)).map(name -> _)), runtime, fileRules,
                      credentials, channelLog,
                    )
              finally
                teardown(bySignal = false)
                try java.lang.Runtime.getRuntime.removeShutdownHook(hook)
                catch case _: IllegalStateException => () // already shutting down; the hook ran
            outcome match
              case Left(reason) =>
                log(s"refused: $reason")
                2
              case Right(exit) => exit

  /** One program's runtime, as a command runs against it: the session holding its records —
    * whose `tmp/` an sbt client reaches its server's socket under — the port of its proxy, which
    * the profile and the environment name, the proxy's log, which the denied-host report
    * reads and whose name the proxy's trust directory has (RunOnHostInspection), and for mill the
    * one port of its daemon, the port a client's profile admits, and its pid, whose arguments the
    * client's profile lets it read (SeatbeltProfile.Network.MillClient).
    * Created with the program's rule file as read then, in the session whose records
    * name its groups — the runner's for its launch's sbt, mill and gradle commands, or another launch's
    * runner's when this launch attaches to its runtime (RunnerRuntimes), the command's own for
    * Maven and for the acceptance test's entry — and ended with that session. */
  case class Runtime(
    session: Path,
    proxyPort: Int,
    proxyLog: Path,
    daemonPort: Option[Int] = None,
    daemonPid: Option[Long] = None,
  ):
    def tmp: Path = session.resolve(RunOnHostSession.TmpDir)
    def trust: Path = RunOnHostInspection.trustDirectory(proxyLog)

  /** What a runtime's server or daemon is started with: its profile's inputs and its
    * environment, derived from the assembly, the runtime's `tmp/` and proxy port, and the
    * launch's forwards. One derivation for the starters (RunOnHostSbtServer.startSbtServer,
    * RunOnHostMillDaemons.start) and for the fingerprint another launch compares before attaching
    * (RunOnHostRuntimeDescriptor), so that equal fingerprints mean a start under the same confinement and
    * environment. */
  case class RuntimeInputs(profile: SeatbeltProfile.ProfileInputs, environment: Map[String, String])

  def runtimeInputs(
    assembled: Assembled,
    tmp: Path,
    proxyPort: Int,
    trust: Path,
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
    network: SeatbeltProfile.Network,
    fileRules: FileRules.Resolved,
    host: String => Option[String] = name => Option(System.getenv(name)),
    userName: String = System.getProperty("user.name"),
  ): RuntimeInputs =
    val prereqs = assembled.prereqs
    RuntimeInputs(
      assembled.profileInputs(tmp, proxyPort, trust, systemPaths, network, fileRules),
      commandEnvironment(
        host, forwards, prereqs, assembled.sbtGlobal, assembled.ivyHome, assembled.gradleUserHome,
        assembled.m2Repository, assembled.millDownloads, assembled.millLauncherVersion, tmp, tmp, proxyPort, trust,
        userName,
      ),
    )

  /** What one sbt server is started from: the runtime whose proxy it uses, the request whose
    * launcher flags it takes (RunOnHostSbtServer.serverCommand), and the record its group is registered at. */
  case class ServerStart(
    assembled: Assembled, buildDirectory: Path, hash: String, arguments: Seq[String], record: Path, runtime: Runtime,
  )

  /** What one mill daemon is started from: the runtime whose proxy it uses, and the record its
    * starter's group — the daemon's — is registered at (RunOnHostMillDaemons.start). */
  case class DaemonStart(assembled: Assembled, buildDirectory: Path, hash: String, record: Path, runtime: Runtime)

  /** How long a starting server may make no progress — neither its log nor the proxy
    * log growing, and no portfile — before the start fails. Progress rather than time, because
    * a first start resolves sbt's own dependencies through the proxy; sbt's own client waits
    * with no bound at all (doc/TODO.md, "a bound on a silent host command"). */
  val ServerStartSilenceMillis = 120_000L

  def sandboxExec(profileFile: Path, command: Seq[String]): Seq[String] =
    Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString) ++ command

  /** Where the profile of the server or daemon a record names is written: beside the session's
    * logs, named after the record. */
  def runtimeProfileFile(session: Session, recordName: String): Path = session.directory.resolve(s"$recordName.sb")

  /** The sbt server or mill's starter (`mill version`), registered under `record`
    * (registeredSpawn). Both streams go to `output`: sbt asks on stdout whether to create a build
    * where it finds none, and a refused start quotes what it said. */
  def startRuntimeStarter(
    record: Path, profileFile: Path, command: Seq[String], buildDirectory: Path, environment: Map[String, String],
    output: Path,
  ): Process =
    val builder = ProcessBuilder(RunOnHostSession.registeredSpawn(record, sandboxExec(profileFile, command))*)
    builder.directory(buildDirectory.toFile)
    builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
    builder.redirectOutput(ProcessBuilder.Redirect.appendTo(output.toFile))
    builder.redirectError(ProcessBuilder.Redirect.appendTo(output.toFile))
    builder.environment.clear()
    builder.environment.putAll(environment.asJava)
    builder.start()

  /** The end of a starter's output, for the refusal that quotes it. */
  def starterOutputTail(output: Path): String = sessionLogTail(output, 4096).getOrElse("(nothing was written)\n")

  enum StartProgress:
    case Grew, Waiting, Silent

  /** Polled while a server or daemon starts: Grew when its output or the proxy log grew since the
    * last poll, Silent once neither has for ServerStartSilenceMillis. */
  final class StartWatch(output: Path, proxyLog: Path):
    private def sizes = (logLength(output), logLength(proxyLog))
    private var last = sizes
    private var since = System.nanoTime

    def poll(): StartProgress =
      val now = sizes
      if now != last then
        last = now
        since = System.nanoTime
        StartProgress.Grew
      else if System.nanoTime - since > ServerStartSilenceMillis * 1_000_000 then StartProgress.Silent
      else StartProgress.Waiting

  private def runInSession(
    session: Session,
    assembled: Assembled,
    commandArgs: Seq[String],
    systemPaths: SeatbeltProfile.SystemPaths,
    workingDirectory: Option[Path],
    log: String => Unit,
    forwards: Vector[(String, String)],
    runnerRuntime: Option[Runtime],
    fileRules: FileRules.Resolved,
    credentials: Vector[BrokeredCredential],
    channelLog: Option[Path],
  ): Either[String, Int] =
    val program = assembled.prereqs.program
    val buildDirectory = workingDirectory.getOrElse(assembled.prereqs.project)
    for
      runtime <- runnerRuntime.map(Right(_)).getOrElse(
        ownRuntime(
          session, assembled, buildDirectory, commandArgs, systemPaths, forwards, fileRules, credentials, channelLog,
          log,
        ),
      )
      // The runner's log has served earlier commands: the report reads what this one adds.
      reportFrom = logLength(runtime.proxyLog)
      (tmp, socketDir) = temporaryDirectories(program, session.tmp, runtime.tmp)
      network <- program match
        case Program.Sbt => Right(SeatbeltProfile.Network.SbtClient(runtime.tmp))
        case Program.Mill =>
          runtime.daemonPort.zip(runtime.daemonPid).map(SeatbeltProfile.Network.MillClient(_, _))
            .toRight("the mill runtime names no daemon port and pid")
        case Program.Gradle => Right(SeatbeltProfile.Network.Gradle)
        case Program.Mvn    => Right(SeatbeltProfile.Network.ProxyOnly)
      profile <- SeatbeltProfile.render(
        assembled.profileInputs(tmp, runtime.proxyPort, runtime.trust, systemPaths, network, fileRules),
      )
      exit <- runCommand(session, assembled, profile, runtime, commandArgs, workingDirectory, forwards, tmp, socketDir)
    yield
      // Under the runner the daemons are the runner's to record (RunnerRuntimes.commandEnded).
      if program == Program.Gradle && runnerRuntime.isEmpty then
        val processes = RunOnHostSession.HostProcesses
        val found = RunOnHostGradleDaemons.daemons(runtime.tmp, processes)
        RunOnHostGradleDaemons.record(session.records, found, processes).foreach(log)
      reportDenied(runtime.proxyLog, reportFrom, program, log)
      if exit != 0 then reportUnwritableProxyLog(runtime, log)
      exit

  /** The runtime a command without the runner's runs against: the acceptance test's entry, and Maven under
    * the runner. Created in the command's own session — by the runner's functions for the
    * programs whose runtime the runner holds, and as the command's proxy alone for Maven — and
    * ended with the session. */
  private def ownRuntime(
    session: Session,
    assembled: Assembled,
    buildDirectory: Path,
    commandArgs: Seq[String],
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
    fileRules: FileRules.Resolved,
    credentials: Vector[BrokeredCredential],
    channelLog: Option[Path],
    log: String => Unit,
  ): Either[String, Runtime] =
    val program = assembled.prereqs.program
    RunnerRuntimes(session, assembled.prereqs.project, log, systemPaths, forwards, fileRules, credentials, channelLog)(
      assemble = (_, _, _) => Right(assembled),
    )
      .prepare(program, buildDirectory, commandArgs)
      .flatMap:
        case Some(runtime) => Right(runtime)
        case None =>
          val proxyLog = session.directory.resolve("proxy.log")
          readProgramRules(assembled.prereqs.project, program)
            .flatMap(
              createProxy(systemPaths, credentials, channelLog)(program, _, session.records.resolve("proxy"), proxyLog),
            )
            .map(Runtime(session.directory, _, proxyLog))

  private[launcher] def logLength(file: Path): Long =
    try Files.size(file)
    catch case _: IOException => 0L

  /**
   * Where a command's processes keep temporary files, and where sbt's sockets are: `(tmp,
   * socketDir)`. Under sbt the command's own `tmp/`, and the runner's for the sockets its server
   * listens under. Under mill the runner's `tmp/` for both: the daemon's forked JVMs — a `run`,
   * a test — inherit the daemon's profile, which grants the runner's `tmp/`, but get the client's
   * environment (`RunModule.scala`, `ctx.env`), so a `TMPDIR` or `java.io.tmpdir` naming the
   * command's own `tmp/` would be denied there; and with one directory the starter's environment
   * and every client's are one map, so an option file Mill interpolates from the environment
   * (`MillProcessLauncher.loadMillConfig`) yields the same value in both, and a client never meets
   * a fingerprint mismatch of the supervisor's own making. Under Gradle the runner's too, for the
   * first reason: the daemon the first command's client starts serves the commands that follow
   * with the profile and environment it was started with, so what it writes must be a directory
   * every later command's profile grants and no command's end removes. Under Maven the command's
   * own.
   */
  def temporaryDirectories(program: Program, sessionTmp: Path, runtimeTmp: Path): (Path, Path) =
    program match
      case Program.Sbt                   => (sessionTmp, runtimeTmp)
      case Program.Mill | Program.Gradle => (runtimeTmp, runtimeTmp)
      case Program.Mvn                   => (sessionTmp, sessionTmp)

  private def runCommand(
    session: Session,
    assembled: Assembled,
    profile: String,
    runtime: Runtime,
    commandArgs: Seq[String],
    workingDirectory: Option[Path],
    forwards: Vector[(String, String)],
    tmp: Path,
    socketDir: Path,
  ): Either[String, Int] =
    val prereqs = assembled.prereqs
    val profileFile = session.directory.resolve("profile.sb")
    Files.writeString(profileFile, profile, UTF_8)

    val buildDirectory = workingDirectory.getOrElse(prereqs.project)
    val programCommand = prereqs.program match
      // With the portfile live the client connects and forks nothing
      // (NetworkClient.connectOrStartServerAndConnect, v1.13.0 and v2.0.9).
      case Program.Sbt =>
        sbtCommand(prereqs.executable, assembled.sbtGlobal) ++
          Seq("--jvm-client", "-batch", "-java-home", prereqs.jdkHome.toString) ++ commandArgs
      // The build directory's own bootstrap, which runs the JVM launcher the environment's
      // MILL_VERSION names; the launcher attaches to the daemon on the one port the profile admits.
      case Program.Mill =>
        buildDirectory.resolve("mill").toString +: commandArgs
      case Program.Gradle => gradleCommand(prereqs, tmp) ++ commandArgs
      // The distribution's own `mvn`, not the project's `mvnw` (run-on-host.md "Maven");
      // --batch-mode as sbt's -batch.
      case Program.Mvn =>
        Seq(prereqs.executable.toString, "--batch-mode") ++ commandArgs

    val record = session.records.resolve("client")
    val command = RunOnHostSession.registeredSpawn(
      record,
      sandboxExec(profileFile, programCommand),
    )
    val builder = ProcessBuilder(command*)
    builder.directory(buildDirectory.toFile)
    // Not the supervisor's own stdin, which under the runner is its liveness pipe (runCommandMain).
    builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
    builder.redirectOutput(ProcessBuilder.Redirect.INHERIT)
    builder.redirectError(ProcessBuilder.Redirect.INHERIT)
    builder.environment.clear()
    builder.environment.putAll(
      commandEnvironment(
        name => Option(System.getenv(name)), forwards, prereqs, assembled.sbtGlobal, assembled.ivyHome,
        assembled.gradleUserHome, assembled.m2Repository, assembled.millDownloads, assembled.millLauncherVersion,
        tmp, socketDir, runtime.proxyPort, runtime.trust, System.getProperty("user.name"),
      ).asJava,
    )

    // The leader publishes the command's exit status and then stays alive, for teardown to check its
    // start time (RunOnHostSession): the answer is the exit file, never the leader's own end.
    try RunOnHostSession.awaitExit(RunOnHostSession.exitRecord(record), builder.start())
    catch case ex: IOException => Left(s"starting the command: ${ex.getMessage}")

  /**
   * The distribution's own `gradle`, not the project's `gradlew` (run-on-host.md "Gradle"), with
   * its settings on the command line, where a `-D` overrides every gradle.properties. The daemon
   * registry is the launch's own, under the runner's `tmp/`, which every Gradle process of the
   * launch is granted and which ends with the launch: `gradle --stop` stops every daemon in the
   * registry, whatever its JVM (`DaemonStopClient`), so a registry under the per-project user
   * home would let one launch's `--stop` end another launch's builds on the project. Attaching
   * is already the launch's own: the client's `java.io.tmpdir`, the runner's `tmp/`, is among the
   * immutable properties Gradle's daemon compatibility compares (`InitialPropertiesConverter`,
   * `DaemonCompatibilitySpec`). The daemons the registry holds are recorded after each command
   * and ended with the launch (RunOnHostGradleDaemons). The toolchain inventory is closed to the JDK the
   * profile grants, so a project asking for another toolchain fails naming it, not by a denial.
   */
  def gradleCommand(prereqs: CommandPrereqs, tmp: Path): Seq[String] =
    Seq(
      prereqs.executable.toString,
      s"-Dorg.gradle.daemon.registry.base=${RunOnHostGradleDaemons.registryBase(tmp)}",
      "-Dorg.gradle.java.installations.auto-detect=false",
      "-Dorg.gradle.java.installations.auto-download=false",
      s"-Dorg.gradle.java.installations.paths=${prereqs.jdkHome}",
    )

  val PassedThrough = Vector("HOME", "LANG", "LC_ALL")

  /** Never the forwarded value. The version overrides: the supervisor resolved the version from the
    * build directory alone and granted that launcher (RunOnHostPrereqs.millVersion,
    * millLauncherVersion), and either would make the bootstrap select another; `MILL_VERSION` is
    * the supervisor's own setting for a mill command, naming that launcher. The output-directory
    * overrides (`OutFiles.java`): the daemon's rendezvous, its port candidate and the foreign
    * daemons are all looked for under `out/`, and Mill sent elsewhere would be checked nowhere. */
  val MillOverrides = Set("MILL_VERSION", "DEFAULT_MILL_VERSION", "MILL_OUTPUT_DIR", "MILL_BSP_OUTPUT_DIR")

  // sbt's getPreloaded also splits JVM environment options without unquoting them. Its first
  // lookup is argv: give it the global base as one argument, before any user options.
  def sbtCommand(executable: Path, sbtGlobal: Path): Seq[String] =
    Seq(executable.toString, s"-Dsbt.global.base=$sbtGlobal")

  /**
   * HotSpot splits _JAVA_OPTIONS on whitespace; an unquoted path with a space can produce
   * an extra option that prevents JVM startup.
   * HotSpot's _JAVA_OPTIONS parser (`Arguments::parse_options_buffer`) joins adjacent quoted
   * runs and drops their delimiters. Unlike a shell, it does not interpret backslash escapes;
   * a literal double quote therefore needs a single-quoted run between double-quoted runs.
   */
  def jvmProperty(name: String, value: String): String =
    "-D" + name + "=\"" + value.replace("\"", "\"'\"'\"") + "\""

  /**
   * The command's whole environment, a closed set: `PassedThrough`, then what `--env` named, then
   * the supervisor's own settings, which win. doc/run-on-host.md, "The command's lifetime and environment",
   * has the table of what is in it; SECURITY.md, "Run on host", has why it is closed.
   */
  def commandEnvironment(
    host: String => Option[String],
    forwards: Vector[(String, String)],
    prereqs: CommandPrereqs,
    sbtGlobal: Path,
    ivyHome: Path,
    gradleUserHome: Path,
    m2Repository: Path,
    millDownloads: Option[Path],
    // The launcher version a mill command's bootstrap runs, `<v>-jvm`; None for the other programs.
    millVersion: Option[String],
    sessionTmp: Path,
    // Where sbt's server binds its sockets and its clients find them: the runtime's `tmp/` for
    // sbt, mill and gradle, the command's own for Maven.
    socketDir: Path,
    proxyPort: Int,
    // The runtime's proxy's CA certificate, in both formats (RunOnHostInspection).
    trust: Path,
    userName: String,
  ): Map[String, String] =
    val passed = PassedThrough.flatMap(name => host(name).map(name -> _)).toMap
    // The settings must reach the JVMs the command forks — a forked test or `run` — and such a JVM
    // inherits the environment and nothing else: its options come from the build definition, so
    // SBT_OPTS and JAVA_OPTS, which the sbt script and the mill executable do read, would reach
    // only the program's own JVMs. sbt 2.0.9 also copies JAVA_TOOL_OPTIONS and JDK_JAVA_OPTIONS
    // into argv without unquoting them; _JAVA_OPTIONS reaches HotSpot unchanged. HotSpot applies
    // it after argv, so the supervisor's properties also win over command-line properties.
    // The shim handles the resulting startup banner.
    val javaOptions = (Seq(
      jvmProperty("java.io.tmpdir", sessionTmp.toString),
      jvmProperty("java.util.prefs.userRoot", sessionTmp.toString),
      // ipcsocket extracts its native socket library to sbt.ipcsocket.tmpdir, else
      // $XDG_RUNTIME_DIR, else java.io.tmpdir (org.scalasbt.ipcsocket.NativeLoader). An sbt
      // client's XDG_RUNTIME_DIR is the runner's tmp/, which its profile grants no write or
      // exec, so the load fails there; this points it at the command's own tmp/, always
      // read-write-exec. The rendezvous sockets still go under XDG_RUNTIME_DIR.
      jvmProperty("sbt.ipcsocket.tmpdir", sessionTmp.toString),
      jvmProperty("sbt.global.base", sbtGlobal.toString),
      jvmProperty("sbt.ivy.home", ivyHome.toString),
      jvmProperty("maven.repo.local", m2Repository.toString),
      // Maven's resolver ignores the JVM proxy properties unless told (run-on-host.md "Maven").
      "-Daether.connector.http.useSystemProperties=true",
    ) ++ JdkTrust.proxyProperties("127.0.0.1", proxyPort).map((name, value) => s"-D$name=$value") ++ Vector(
      // The proxy answers for every host it allows under a leaf of its own CA, so that CA is the
      // whole store: the JDK's own roots would verify nothing the command can reach.
      jvmProperty("javax.net.ssl.trustStore", RunOnHostInspection.trustStore(trust).toString),
      "-Djavax.net.ssl.trustStoreType=PKCS12",
      s"-Djavax.net.ssl.trustStorePassword=${RunOnHostInspection.TrustStorePassword}",
      // Without this a JVM reaches 127.0.0.1 through a dual-stack AF_INET6 socket as v4-mapped
      // ::ffff:127.0.0.1, which the profile's "localhost" class does not cover: the connect to
      // the proxy dies with EPERM (measured, src/probe/jvm-proxy-rule.sh).
      "-Djava.net.preferIPv4Stack=true",
    )).mkString(" ")
    val own = Map(
      // The JDK, then the system directories a command may execute from
      // (SeatbeltProfile.SystemPaths.txt) — never the host's PATH: an entry of it the confinement refuses,
      // a version manager's shim or a Homebrew program ahead of the system one, fails the lookup
      // with EPERM at that entry, and the shell tries no further, so a command the system PATH
      // serves would break on the shell's.
      "PATH" -> s"${prereqs.jdkHome.resolve("bin")}:/usr/bin:/bin:/usr/sbin:/sbin",
      "JAVA_HOME" -> prereqs.jdkHome.toString,
      "_JAVA_OPTIONS" -> javaOptions,
      "TMPDIR" -> sessionTmp.toString,
      "XDG_RUNTIME_DIR" -> socketDir.toString,
      "SBT_GLOBAL_SERVER_DIR" -> socketDir.toString,
      "COURSIER_CACHE" -> prereqs.coursierV1.toString,
      "GRADLE_USER_HOME" -> gradleUserHome.toString,
      "USER" -> userName,
      "LOGNAME" -> userName,
    ) ++
      // Set for every program, not mill alone: sbt ignores it, and one unconditional setting is
      // simpler than a conditional. Mill's bootstrap otherwise derives the folder from HOME and
      // XDG_CACHE_HOME, and this sets it to the folder holding the executable the command is
      // granted.
      millDownloads.map(dir => "MILL_FINAL_DOWNLOAD_FOLDER" -> dir.toString) ++
      // The bootstrap's own override, set to the JVM launcher of the pinned version: the
      // bootstrap would run the native image for a bare pin (RunOnHostPrereqs.millLauncherVersion).
      millVersion.map("MILL_VERSION" -> _) ++
      commandProxyVariables(proxyPort) ++
      // For the programs HTTPS_PROXY serves, which read no JVM property.
      AgentSandboxLauncher.CaBundleVariables.map(_ -> RunOnHostInspection.caBundle(trust).toString)
    passed ++ (forwards.toMap -- MillOverrides) ++ own

  /**
   * The proxy variables the command's environment gets (AgentSandboxLauncher.proxyVariables), for
   * the programs that read the environment rather than the JVM properties; the loopback exemption
   * lets a test server on it be reached directly. The rest of the family — ALL_PROXY, FTP_PROXY —
   * requires explicit forwarding. The launcher's own HTTPS_PROXY is absent: that one names an
   * upstream proxy the confinement refuses, with a credential the command has no business reading.
   */
  def commandProxyVariables(proxyPort: Int): Map[String, String] =
    AgentSandboxLauncher.proxyVariables(s"http://127.0.0.1:$proxyPort").toMap

  /**
   * The cost of switching where a build runs, paid before each sbt server starts
   * (RunnerRuntimes.sweepTargetLinks). sbt 2 leaves `target/` outputs as
   * symlinks into its global base's content-addressed store, so a tree the user's own sbt built
   * links into a store this profile cannot reach — and zinc treats the unreadable state as an
   * error, not a cold start (measured: `previousCompile` fails on `inc_compile_3.zip`). Every
   * symlink under a `target/` directory that does not resolve inside a granted root — the
   * dangling included — is removed then; the artifacts it named still exist in the
   * store of the sbt that made them, which relinks on its own next run. The roots are compared
   * resolved, as the links are: a root reached through a symlink, macOS's `/var`, would
   * otherwise match nothing and the sweep would take every link.
   */
  def cleanForeignTargetLinks(project: Path, granted: Seq[Path]): Vector[Path] =
    val roots = granted.flatMap(realPath)
    val removed = Vector.newBuilder[Path]
    def walk(dir: Path, inTarget: Boolean): Unit =
      val entries =
        try directoryEntries(dir)
        catch case _: IOException => return
      entries.foreach: entry =>
        val name = entry.getFileName.toString
        if Files.isSymbolicLink(entry) then
          if inTarget then
            val resolvesInside =
              try roots.exists(entry.toRealPath().startsWith)
              catch case _: IOException => false
            if !resolvesInside then
              try
                Files.delete(entry)
                removed += entry
              catch case _: IOException => ()
        else if Files.isDirectory(entry) && !FileRules.GuardedComponents.contains(name) then
          walk(entry, inTarget || name == "target")
    walk(project, inTarget = false)
    removed.result()
