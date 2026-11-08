// The supervisor: it takes a workspace and a program to a confined command's exit code.
//
// - The supervisor's steps are: validate, scavenge, publish, runtime, profile, run, end what was started, remove.
// - This file also holds how the launcher's own executable is re-invoked as the runner, the supervisor and the proxy
//   (selfInvocation).
// - RunnerRuntimes.scala holds the runtimes that the commands of one build directory share,
//   RunOnHostSbtServer.scala the sbt server, and RunOnHostProxy.scala the proxy.
// - The supervisor runs on macOS only, like everything it drives. The assembly and refusal logic are in
//   RunOnHostPrereqs and are unit-tested there. This file is therefore the sequence of steps, plus the host
//   observations that no Linux test can make.

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
import FileHelper.{directoryEntries, directoryEntriesIfAny, isExecutableFile, realPath}
import SandboxWorkspace.workspaceIdOf

object RunOnHostSandbox:

  case class Assembled(
    prereqs: CommandPrereqs,
    /** The unpacked distribution that the command also runs from.
      *
      *   - For sbt, the distribution in the Coursier archive cache.
      *   - For Gradle and Maven, the distribution under the wrapper's `dists`.
      *   - For mill, whose executable is one file, the JDK on which a pinned or unset `mill-jvm-version` runs the
      *     daemon (RunOnHostPrereqs.millRecordedJdk). Under `system`, none. */
    distribution: Option[Path],
    /** The per-workspace sbt global base and Ivy home, Gradle's user home and Maven's local repository.
      *
      *   - Each path is created and granted for the program that reads it (`sbtCachesGranted`,
      *     `gradleUserHomeGranted`, `m2RepositoryGranted`).
      *   - For the other programs, nothing reads the path. The path is named all the same, so that the environment has
      *     the same variable names for every program, as `millDownloads` is for every program but mill. */
    sbtGlobal: Path,
    ivyHome: Path,
    gradleUserHome: Path,
    m2Repository: Path,
    /** Where mill's bootstrap keeps launchers, as derived from this environment. A mill command is granted this
      * directory, and its build script is pointed at it (commandEnvironment). */
    millDownloads: Option[Path],
    /** The launcher version that the bootstrap is told to run, `<v>-jvm`, for a mill command
      * (RunOnHostPrereqs.millLauncherVersion). None for the other programs. */
    millLauncherVersion: Option[String],
  ):
    def sbtGlobalGranted: Option[Path] = Option.when(prereqs.program == Program.Sbt)(sbtGlobal)
    def ivyHomeGranted: Option[Path] = Option.when(prereqs.program == Program.Sbt)(ivyHome)
    def gradleUserHomeGranted: Option[Path] = Option.when(prereqs.program == Program.Gradle)(gradleUserHome)
    def m2RepositoryGranted: Option[Path] = Option.when(prereqs.program == Program.Mvn)(m2Repository)
    /** The persistent caches an sbt command writes besides Coursier's. */
    def sbtCachesGranted: Seq[Path] = sbtGlobalGranted.toSeq ++ ivyHomeGranted
    /** A mill command whose build runs without the runner's daemon (RunOnHostPrereqs.millRunsWithoutDaemon). */
    def millWithoutDaemon: Boolean = millLauncherVersion.exists(millRunsWithoutDaemon)

    /** The profile's inputs for a process of this command: what the assembly grants, and the rest as the caller has
      * it. */
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

  /** A file that the prerequisites cannot read.
    *
    *   - The exception carries the file out of the readers to the assembly's boundary, where it becomes one worded
    *     refusal. The readers' callers are pure, and take a reader that answers absent or present.
    *   - A file that exists but cannot be read never falls through to the next source: mill would select the file
    *     and then fail reading it. */
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

  /** Absent is None. The text is read as ISO-8859-1, as `java.util.Properties` reads a stream. */
  private def readLatin1(path: Path): Option[String] =
    reading(path)(Option.when(Files.exists(path))(String(Files.readAllBytes(path), ISO_8859_1)))

  /** A bound for the read, and nothing else. The bound lies far above any key and path that mill writes, the key's
    * `mill-repositories` included, and it is small beside the launcher's heap. */
  private val MillJavaHomeMaxBytes = 256 * 1024
  private val MillJavaHomeReadMillis = 2000L

  /** How many reads of mill's `java-home` file may be running or abandoned at once (millJavaHomeText). */
  private val MillJavaHomeReaders = java.util.concurrent.Semaphore(4)

  /**
   * The text of mill's `java-home` file in `buildDirectory` (RunOnHostPrereqs.MillJavaHomeFile), or None when the
   * file is absent or cannot be read as the build's own file.
   *
   * The launcher reads the file outside any profile, under the runner's monitor, while a command in the workspace
   * may be writing under `out/`. The read therefore works as follows:
   *
   *   - Each directory is opened relative to the one before it, and the file relative to the last, none through a
   *     symlink, whatever a command renames meanwhile.
   *   - The read stops at `MillJavaHomeMaxBytes`, whatever size the file reports.
   *   - The whole read is abandoned after `MillJavaHomeReadMillis`. A FIFO moved into the file's place after the type
   *     check would make the open never return.
   *   - The text is never printed.
   *
   * An abandoned read keeps its thread and its directories until a writer opens that FIFO, so `readers` bounds how
   * many such reads exist. With no reader free, the file reads as absent, and the build is refused as not
   * provisioned until a reader returns.
   *
   * `raced` runs between the type check and the open. Tests replace it to stand in for that command.
   */
  private[launcher] def millJavaHomeText(
    buildDirectory: Path,
    millis: Long = MillJavaHomeReadMillis,
    raced: () => Unit = () => (),
    readers: java.util.concurrent.Semaphore = MillJavaHomeReaders,
  ): Option[String] =
    buildFileOpened(buildDirectory, MillJavaHomeFile, "mill-java-home-read", millis, raced, readers): channel =>
      val buffer = ByteBuffer.allocate(MillJavaHomeMaxBytes + 1)
      var open = true
      while open && buffer.hasRemaining do
        if channel.read(buffer) < 0 then open = false
      Option.when(buffer.position() <= MillJavaHomeMaxBytes):
        UTF_8.newDecoder().decode(buffer.flip()).toString

  /** How many probes of `out/mill-out-lock` may be running or abandoned at once (millOutLockHeld). */
  private val MillOutLockProbes = java.util.concurrent.Semaphore(4)

  /**
   * Whether a process holds Mill's lock on the build directory's `out/` (`MillOutLockFile`).
   *
   *   - The file is opened as millJavaHomeText opens the `java-home` file, and the probe is abandoned after as long.
   *   - The result is None when the file is absent or cannot be opened as the build's own file.
   *   - A shared lock, taken and released at once, conflicts with the exclusive lock that Mill takes. This JVM holds
   *     no lock on the file.
   */
  private[launcher] def millOutLockHeld(
    buildDirectory: Path,
    raced: () => Unit = () => (),
    readers: java.util.concurrent.Semaphore = MillOutLockProbes,
  ): Option[Boolean] =
    buildFileOpened(buildDirectory, MillOutLockFile, "mill-out-lock-probe", MillJavaHomeReadMillis, raced, readers):
      case file: java.nio.channels.FileChannel =>
        Option(file.tryLock(0, Long.MaxValue, true)) match
          case None => Some(true)
          case Some(lock) =>
            lock.release()
            Some(false)
      case _ => None

  /** Applies `use` to the file at `relative` under `buildDirectory`, opened for reading as millJavaHomeText describes.
    *
    *   - The read runs on a thread of its own, abandoned after `millis`.
    *   - The result is None when the file is absent, is not the build's own regular file, or `use` gave no result in
    *     time. */
  private def buildFileOpened[A](
    buildDirectory: Path, relative: String, threadName: String, millis: Long, raced: () => Unit,
    readers: java.util.concurrent.Semaphore,
  )(use: java.nio.channels.SeekableByteChannel => Option[A]): Option[A] =
    if !readers.tryAcquire() then None
    else
      val read = java.util.concurrent.FutureTask[Option[A]]: () =>
        try buildFileRead(buildDirectory, relative, raced)(use)
        finally readers.release()
      try Thread.ofPlatform().daemon().name(threadName).start(read)
      catch
        case ex: Throwable =>
          readers.release()
          throw ex
      try read.get(millis, java.util.concurrent.TimeUnit.MILLISECONDS)
      catch case _: (java.util.concurrent.TimeoutException | java.util.concurrent.ExecutionException) => None

  private def buildFileRead[A](buildDirectory: Path, relative: String, raced: () => Unit)(
    use: java.nio.channels.SeekableByteChannel => Option[A],
  ): Option[A] =
    def opened(directory: SecureDirectoryStream[Path], names: List[Path]): Option[A] =
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
              try use(channel)
              finally channel.close()
          case next :: deeper => opened(directory.newDirectoryStream(next, LinkOption.NOFOLLOW_LINKS), deeper)
          case Nil            => None
      finally directory.close()
    try
      Files.newDirectoryStream(buildDirectory) match
        case secure: SecureDirectoryStream[Path] =>
          opened(secure, Path.of(relative).iterator().asScala.toList)
        // A JVM without openat has no way to hold a directory while a command renames the directory.
        case plain =>
          plain.close()
          None
    catch case _: IOException => None

  /** The directories directly inside `path`, or none when `path` is absent. */
  private def directories(path: Path): Seq[Path] =
    reading(path):
      if !Files.isDirectory(path) then Seq.empty
      else directoryEntries(path).filter(Files.isDirectory(_))

  /** The assembly: everything the profile derives authority from, decided before anything runs.
    *
    *   - `buildDirectory` is where the command runs: the workspace root or a directory beneath it.
    *   - mill's bootstrap, version pin and `mill-jvm-version` are that directory's, as the bootstrap reads them from
    *     its working directory. A nested build is therefore another build.
    *   - The grants stay the workspace's. */
  def assemble(
    workspaceRoot: Path, program: Program, env: String => Option[String], buildDirectory: Path,
  ): Either[String, Assembled] =
    try assembled(workspaceRoot, program, env, buildDirectory).left.map(_.worded)
    catch case ex: Unreadable => Left(wording(ex.refusal))

  /** Why one step of the assembly refuses, kept typed up to the assembly's boundary. The launch's provisioning
    * (RunOnHostProvisioning) runs one of three scripts for four of the cases, and words the rest. */
  final case class StepRefusal(step: String, refusal: Refusal | String):
    def worded: String = wordedShowing(_.toString)
    /** As [[RunOnHostPrereqs.wording]] words it with `shown`. */
    def wordedShowing(shown: Path => String): String = refusal match
      case refusal: Refusal => s"$step: ${wording(refusal, shown)}"
      case reason: String   => s"$step: $reason"

  private def context[A](step: String)(value: Either[Refusal | String, A]): Either[StepRefusal, A] =
    value.left.map(StepRefusal(step, _))

  /** The executable that a `mill`, `gradle` or `mvn` command from `buildDirectory` would be granted, or the step that
    * refuses it.
    *
    *   - For Maven, `buildDirectory` is the workspace root.
    *   - The executable is the one the user provisions (run-on-host.md, "Program prerequisites"). */
  def provisionedExecutable(
    program: Program, env: String => Option[String], buildDirectory: Path,
  ): Either[StepRefusal, Path] =
    try
      program match
        case Program.Mill   => millLauncher(env, buildDirectory).map(_.executable)
        case Program.Gradle => gradleDistribution(env, buildDirectory).map(_.resolve("bin").resolve("gradle"))
        case Program.Mvn    => mvnDistribution(env, buildDirectory).map(_.resolve("bin").resolve("mvn"))
        case Program.Sbt    =>
          Left(StepRefusal("sbt executable", "sbt's executable is the user's, not the workspace's"))
    catch case ex: Unreadable => Left(StepRefusal(program.name, ex.refusal))

  /** Mill's provisioned JVM launcher, its version `<v>-jvm`, and the JDK on which a pinned or unset
    * `mill-jvm-version` runs the daemon. */
  private case class MillLauncher(executable: Path, version: String, recordedJdk: Option[Path])

  /** Resolves the launcher as the bootstrap and mill's launcher in `buildDirectory` resolve it. The executable is
    * resolved before the recorded JDK, because the host run that provisions the executable also provisions the
    * JDK. */
  private def millLauncher(env: String => Option[String], buildDirectory: Path): Either[StepRefusal, MillLauncher] =
    def recordedJdk(id: Option[String], launcher: String): Either[StepRefusal, Option[Path]] =
      for
        cache <- context("mill jvm")(coursierCacheRoot(Os.Mac, env).toRight("no Coursier cache root"))
        home <- context("mill jvm"):
          millRecordedJdk(id, launcher, millJavaHomeText(buildDirectory), cache, realPath, isExecutableFile)
      yield Some(home)
    for
      _ <- context("mill bootstrap")(validateMillBootstrap(buildDirectory, isExecutableFile))
      jvm <- context("mill jvm")(millJvm(buildDirectory, readLines))
      pinned <- context("mill version")(millVersion(buildDirectory, readLines))
      launcher <- context("mill version")(millLauncherVersion(pinned))
      _ <- context("mill jvm")(millUnsetJvmAccepted(jvm, launcher))
      downloads <- context("mill executable")(millDownloadDir(env).toRight("no mill download folder"))
      provisioned <- context("mill executable")(millExecutable(downloads, launcher, isExecutableFile))
      real <- context("mill executable")(realPath(provisioned).toRight(s"$provisioned vanished"))
      jdk <- jvm match
        case MillJvm.System     => Right(None)
        case MillJvm.Pinned(id) => recordedJdk(Some(id), launcher)
        case MillJvm.Unset      => recordedJdk(None, launcher)
    yield MillLauncher(real, launcher, jdk)

  /** Gradle's home as the wrapper in `buildDirectory` would run it. A nested build directory with a wrapper of its own
    * is another build, as under mill. */
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

  /** Maven's home as the workspace's wrapper would run it. */
  private def mvnDistribution(env: String => Option[String], workspaceRoot: Path): Either[StepRefusal, Path] =
    for
      wrapper <- context("mvn wrapper")(validateMvnWrapper(workspaceRoot, isExecutableFile))
      _ <- context("mvn wrapper")(validateMvnWrapperScript(readLines(wrapper).getOrElse(Seq.empty)))
      properties = workspaceRoot.resolve(".mvn").resolve("wrapper").resolve("maven-wrapper.properties")
      url <- context("mvn wrapper")(
        readText(properties).toRight(Refusal.PrereqMvnWrapperUnreadable(s"$properties is absent"))
          .flatMap(mvnDistributionUrl(_, env("MVNW_REPOURL"))),
      )
      userHome <- context("mvn distribution")(mvnUserHome(env).toRight("no Maven user home"))
      home <- context("mvn distribution")(mvnDistributionHome(mvnDistributionDir(userHome, url), url, isExecutableFile))
      real <- context("mvn distribution")(realPath(home).toRight(s"$home vanished"))
    yield real

  private def assembled(
    workspaceRoot: Path, program: Program, env: String => Option[String], buildDirectory: Path,
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
            // ISO-8859-1, not UTF-8: cs appends a jar to the scripts it installs, so the file is not text. Every
            // byte maps to a char, which leaves intact the ASCII path that this step searches for.
            inner <- context("sbt distribution")(
              sbtDistribution(String(readBytes(sbt), ISO_8859_1), coursierCache)
                .toRight(s"$sbt names no distribution inside $coursierCache"),
            )
            home <- context("sbt distribution")(
              validateSbtDistribution(inner, coursierCache, realPath, isExecutableFile),
            )
          yield (sbt, Some(home), None)
        case Program.Mill =>
          millLauncher(env, buildDirectory).map(mill => (mill.executable, mill.recordedJdk, Some(mill.version)))
        case Program.Gradle =>
          gradleDistribution(env, buildDirectory).map(real => (real.resolve("bin").resolve("gradle"), Some(real), None))
        case Program.Mvn =>
          mvnDistribution(env, workspaceRoot).map(real => (real.resolve("bin").resolve("mvn"), Some(real), None))
      (executable, distribution, millLauncher) = executableAndDistribution
      configuredRoot <- context("cache root")(cacheRootOf(os, env))
      cacheRoot <- context("cache root")(
        cacheRootOutsideWorkspace(configuredRoot, workspaceRoot, os, FileHelper.canonicalizedFuturePath),
      )
      // stateRootOf words its refusals for `fail`, which prints them whole, so the prefix is stripped here.
      stateRoot <- context("state root")(
        LauncherState.stateRootOf(os, env).left.map(_.stripPrefix("error: ")),
      )
      workspaceId = workspaceIdOf(workspaceRoot, os)
      v1Dir = coursierV1Of(cacheRoot, workspaceId)
      sbtGlobalDir = sbtGlobalOf(cacheRoot, workspaceId)
      ivyHomeDir = ivyHomeOf(cacheRoot, workspaceId)
      gradleUserHomeDir = gradleUserHomeOf(cacheRoot, workspaceId)
      m2RepositoryDir = m2RepositoryOf(cacheRoot, workspaceId)
      // Each directory is checked as it will be granted, before it is created. An existing symlink among its
      // ancestors, such as `run-on-host` or the workspace's directory, places it wherever the link points.
      _ <- Vector(v1Dir, sbtGlobalDir, ivyHomeDir, gradleUserHomeDir, m2RepositoryDir)
        .foldLeft(Right(()): Either[StepRefusal, Unit]): (checked, dir) =>
          checked.flatMap: _ =>
            context("cache directory"):
              FileHelper.canonicalizedFuturePath(dir).left.map(Refusal.CacheRootUnusable(_))
                .flatMap(cacheRootOutsideWorkspace(_, workspaceRoot, os, Right(_)))
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
        workspaceRoot = workspaceRoot,
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
   * The grammar of SeatbeltProfile.SystemPaths.txt: one absolute path per line, `#` comments, and an `x ` prefix for
   * a path that must also be executable.
   *
   *   - A system path is granted only where testing proves the read is stable.
   *   - The resource agentsandbox/SeatbeltProfile.SystemPaths.txt is the measured set.
   *   - src/probe/run-on-host-profile-iterate.sh measures candidate entries.
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

  /** The options that open the JDK's internal certificate builder to X509Helper, which explains why.
    *
    *   - The jar's manifest carries the same two options for `java -jar` (build.sbt).
    *   - The JVM reads a manifest for `-jar` alone, and a re-invocation is `java -cp`.
    *   - The runner and the supervisor it starts issue each proxy's certificates (RunOnHostInspection). Without these
    *     options, the issuing dies of IllegalAccessError. */
  val CertificateBuilderExports: Seq[String] = Seq(
    "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
    "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
  )

  /** How the supervisor re-invokes its own executable under one of the launcher's private actions. The executable is
    * the running JVM and classpath, or the native image binary itself. */
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

  /** This JVM's class path, with every element made absolute against this JVM's working directory.
    *
    *   - `java -jar target/dist/ko-agent-sandbox.jar` names the element relative, and an empty element is the working
    *     directory itself.
    *   - The proxy runs from `/` (RunOnHostProxy.startProxy), where a relative element names nothing. */
  def selfClassPath(classPath: String = System.getProperty("java.class.path")): Seq[String] =
    classPath.split(java.io.File.pathSeparator, -1).toSeq.map(entry => Path.of(entry).toAbsolutePath.toString)

  /** Whether this launcher runs as the GraalVM native image rather than as a JVM over the jar. */
  def isNativeImage: Boolean = System.getProperty("org.graalvm.nativeimage.imagecode") != null

  /** The class-path entry that this process's code was loaded from, spelled as the class path spells it.
    *
    *   - The result is none when that code is off the class path. That happens under sbt, which loads the project's
    *     classes through loaders of its own.
    *   - The entry is matched by resolved path, since the JDK canonicalizes an entry as it loads it. The CodeSource has
    *     a launch symlink resolved away, while the re-invocation (selfInvocation) spells the link. The link is what
    *     must remain.
    *   - The JVM skips any other entry when it is missing. */
  def launchEntry(classPath: String, codeSource: Option[Path]): Option[Path] =
    codeSource.flatMap(realPath).flatMap: source =>
      selfClassPath(classPath).map(Path.of(_)).find(entry => realPath(entry).contains(source))

  /** The file from which this launcher's own executable is re-invoked (selfInvocation).
    *
    *   - The file is the native image binary, which is self-contained and reads no jar, or the jar form's launch entry
    *     (launchEntry).
    *   - The value is read once, when this object initializes. Every launcher process calls in here before it serves
    *     or spawns, so the read happens at the process's start, and the value is the file the process was loaded
    *     from.
    *   - The JDK is left out: it is coursier's JDK under the cache root, which no clean in the workspace removes. */
  private[launcher] val launchFile: Option[Path] =
    if isNativeImage then
      val command = ProcessHandle.current().info().command()
      Option.when(command.isPresent)(Path.of(command.get))
    else
      launchEntry(
        System.getProperty("java.class.path"),
        Option(getClass.getProtectionDomain.getCodeSource).map(source => Path.of(source.getLocation.toURI)),
      )

  /** The launch file resolved and still present, or the reason to refuse the re-invocation, naming the file as
    * spelled.
    *
    *   - No file to check passes, since then no file exists from which a re-invocation loads this process's code.
    *   - Both forms are checked alike. The jar and the native image are each one file, built under `target/dist`,
    *     which `sbt clean` or `git clean` removes while a session runs.
    *   - The check runs before a supervisor is exec'd (RunnerRuntimes.prepare, every program) and before a proxy is
    *     started (RunOnHostProxy.proxyInputs). A JVM starts with a missing class-path entry and fails only at loading
    *     the main class. Unchecked, the jar form's failure would be the proxy's ready wait timing out over a Java
    *     error in its log, and the native form's failure would be a spawn that fails to exec.
    *   - The check does not run at the launch's own runner spawn (RunOnHostChannel.spawnRunner), which follows the
    *     launcher's own load from that file.
    *   - A rebuild at the same path is not a removal, and neither is a symlink's retargeting. The running processes
    *     keep their inode, and the next re-invocation runs the new file. */
  def selfPresent(file: Option[Path] = launchFile): Either[String, Option[Path]] =
    file match
      case None => Right(None)
      case Some(path) =>
        realPath(path).map(Some(_)).toRight(
          s"the launcher's executable $path no longer exists; rebuild it at that path, " +
            "or relaunch the session from an executable outside the workspace",
        )

  /** `--run-command-on-host <program> <workspace-root> <cwd> [--env=<name>...] [--channel-log=<file>]
    * [--runtime-session=<dir> --proxy-port=<port> --proxy-log=<file> [--daemon-port=<port> --daemon-pid=<pid>]]
    * [--credentials-on-stdin] --
    * <args...>`.
    *
    *   - Each channel request runs as a process of its own. The runner's cancel is therefore a SIGTERM, which this
    *     supervisor's shutdown hook answers.
    *   - The runtime options name the runner's runtime (Runtime). */
  def runCommandMain(args: Seq[String]): Unit =
    def start(
      programName: String,
      workspaceArg: String,
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
      val fileRules = fileRulesOf(options, Path.of(workspaceArg)).fold(
        reason => { Console.err.println(s"--run-command-on-host: $reason"); sys.exit(2) },
        identity,
      )
      // The frame that the runner wrote after its word, read before anything else reads this pipe.
      val credentials =
        if !options.contains(CredentialsOption) then Vector.empty
        else
          readStdinCredentials().fold(
            reason => { Console.err.println(s"--run-command-on-host: the brokered credentials: $reason"); sys.exit(2) },
            identity,
          )
      // The runner's pipe (RunOnHostChannel.dispatch). The pipe's EOF means that the runner is gone. The command then
      // ends through the shutdown hook, as it ends with the requester's ctl. Nobody reads the status. endWithRunner is
      // a def, not the thread's own lambda: a lambda ending in sys.exit types as Nothing, which the JVM's lambda
      // factory refuses for Runnable's void at link time.
      def endWithRunner(): Unit =
        try while System.in.read() != -1 do ()
        catch case _: IOException => ()
        sys.exit(143)
      val runnerGone = Thread(() => endWithRunner())
      runnerGone.setDaemon(true)
      runnerGone.start()
      sys.exit(
        run(
          Path.of(workspaceArg), program, commandArgs, bundledSystemPaths(), uid,
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
      case programName :: workspaceArg :: workingDirectory :: rest if rest.contains("--") =>
        val (options, commandArgs) = rest.span(_ != "--")
        start(programName, workspaceArg, workingDirectory, options, commandArgs.drop(1))
      case other =>
        Console.err.println(s"--run-command-on-host: unexpected arguments: ${other.mkString(" ")}")
        sys.exit(2)

  /** `--env=<name>` as the runner and the command receive it: the name alone. The receiving process reads the value
    * from its own environment under `carrierName` (RunOnHostChannel.spawnRunner). Below the launcher, a forward is
    * thus never an argument with a secret in it. */
  val EnvOption = "--env="

  def forwardedNames(options: Seq[String]): Vector[String] =
    options.filter(_.startsWith(EnvOption)).map(_.stripPrefix(EnvOption)).toVector

  /** `--credentials-on-stdin`: the process's brokered credentials follow on its standard input
    * (CredentialGrammar.bindingInput).
    *
    *   - The launcher writes the runner's credentials, and the runner writes a supervisor's credentials after its word
    *     (RunOnHostChannel.dispatch).
    *   - The option carries no value. Values never appear in arguments. */
  val CredentialsOption = "--credentials-on-stdin"

  /** Reads one byte at a time, and consumes nothing after the bindings. Call it before anything else reads standard
    * input. */
  def readStdinCredentials(): Either[String, Vector[BrokeredCredential]] =
    CredentialGrammar.readBindings(java.io.FileInputStream(java.io.FileDescriptor.in))

  /**
   * The hosts for which a program's proxy substitutes credentials.
   *
   *   - The hosts are every host the program's rules allow, all of which the proxy inspects (egressRuleText). The hosts
   *     are named as the proxy's own resolution names them (RunOnHostInspection.leafNames).
   *   - A binding's host has that form (CredentialGrammar), and the proxy's start refuses a binding to any other host.
   *   - The set is empty for rules the proxy refuses, which readProgramRules does not return.
   */
  def credentialHosts(program: Program, fileHosts: Vector[String]): Set[String] =
    RunOnHostInspection.leafNames(egressRuleText(program, fileHosts)).fold(_ => Set.empty, _.toSet)

  /** What a program's proxy is given: the credentials for its credentialHosts, and no others. */
  def credentialsFor(
    program: Program,
    fileHosts: Vector[String],
    credentials: Seq[BrokeredCredential],
  ): Vector[BrokeredCredential] =
    EgressCredentials.bindingsFor(credentials, credentialHosts(program, fileHosts))

  /** `--channel-log=<file>`: the runner's own log. The supervisor appends a signal-ended command's logs there
    * (appendSessionLogs). */
  val ChannelLogOption = "--channel-log="

  /** `--file-rules=<file>`: the resolved file rules that the launch wrote for its runner. The runner hands the option
    * on to each command (RunOnHostChannel.spawnRunner). */
  val FileRulesOption = "--file-rules="

  /** The file rules whose files a command's or runtime's profile denies writes to. The rules are the launch's
    * resolved set when the runner handed one on, or else the workspace's lines alone (FileRules.ofWorkspace). */
  def fileRulesOf(options: Seq[String], workspaceRoot: Path): Either[String, FileRules.Resolved] =
    options.find(_.startsWith(FileRulesOption)) match
      case Some(option) => FileRules.readResolved(Path.of(option.stripPrefix(FileRulesOption)))
      case None         => FileRules.ofWorkspace(workspaceRoot)

  /** The runner's runtime as the supervisor's options. The first three come together or not at all. For a mill
    * runtime, the daemon's port and pid come with them. */
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

  /** How many of the last bytes of each command log are appended to the channel log. A stalled command's last lines
    * are the finding, and a build's audit log can run long. */
  val SessionLogTailBytes = 64 << 10

  /** Retains a session's logs before the session's directory is removed.
    *
    *   - The logs are the proxy audit logs, the sbt servers' logs (RunOnHostSbtServer.serverLog), the mill starters'
    *     output (RunOnHostMillDaemons.starterLog), and the stderr file that a thin client leaves under `tmp/` when it
    *     forked a server of its own. A command has one `proxy.log`, and the runner has one audit log per runtime.
    *   - run-on-host-internals.md, "The channel and the command", explains why every signal keeps these logs and what a
    *     server's file holds.
    *   - `condemned` is the session directory at its condemned pathname, with its groups ended
    *     (RunOnHostSession.endSession). No process that the session started can therefore change what is read.
    *   - The tmp check below and sessionLogTail keep each read inside the directory. The exception is a proxy's audit
    *     log, which is read where the launcher keeps it (RunOnHostProxy.keptAuditLog).
    *   - `ended` is the block's first line, which names the session and how it ended. */
  def appendSessionLogs(channelLog: Path, condemned: Path, ended: String): Unit =
    val block = StringBuilder()
    block.append(s"${java.time.Instant.now()} $ended; its logs follow\n")
    val proxyLogs =
      directoryEntriesIfAny(condemned)
        .filter(file => file.getFileName.toString.matches("(proxy|server|daemon).*\\.log")).sorted
    // The command's write grant includes tmp itself, so the command can replace tmp with a symlink that survives the
    // session directory's rename.
    val tmp = condemned.resolve(RunOnHostSession.TmpDir)
    val clientForkedStderr =
      if !Files.isDirectory(tmp, LinkOption.NOFOLLOW_LINKS) then
        block.append(s"==> ${RunOnHostSession.TmpDir}\n[skipped: not a directory]\n")
        Vector.empty
      else directoryEntriesIfAny(tmp).filter(_.getFileName.toString.startsWith("sbt-server-err")).sorted
    (proxyLogs ++ clientForkedStderr).foreach: file =>
      sessionLogTail(RunOnHostProxy.keptAuditLog(channelLog, file).getOrElse(file)).foreach: tail =>
        block.append(s"==> ${file.getFileName}\n").append(tail)
        if !tail.endsWith("\n") then block.append('\n')
    try Files.writeString(channelLog, block.toString, UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND)
    catch case _: IOException => ()

  /** The tail of one session log, read from the file that the listing named and from nothing that file could point to.
    *
    *   - The attributes are read without following a link, and the open refuses a link.
    *   - The read is positioned at the tail rather than sized by the file, because the command chooses a sparse file's
    *     size.
    *   - Absent is None.
    *   - Anything but a regular file is named and not opened, since an open FIFO would hold this teardown. */
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

  /** The name under which a forwarded value is carried from the launcher to the confined command. Nothing reads this
    * name by accident.
    *
    *   - The runner and the supervisor are unconfined JVMs of the launcher's own code. An explicit `--env=NAME=VALUE`
    *     installed under its own name, such as a loader variable, would be read by them first.
    *   - The requested name is restored inside the command's environment alone, where the supervisor's own settings
    *     still win over it. */
  def carrierName(name: String): String = s"KO_AGENT_RUN_ON_HOST_ENV_$name"

  // ---------------------------------------------------------------------------
  // The supervisor's steps
  // ---------------------------------------------------------------------------

  def run(
    workspaceArg: Path,
    program: Program,
    commandArgs: Seq[String],
    systemPaths: SeatbeltProfile.SystemPaths,
    uid: Int,
    log: String => Unit,
    // The channel's validated WORKING_DIRECTORY: only the child's cwd, never a grant.
    workingDirectory: Option[Path] = None,
    // What `--env` named at launch, with the same authority. The values are in this process's environment under
    // carrierName.
    forwarded: Vector[String] = Vector.empty,
    // Where a command ended by signal leaves its session's logs (appendSessionLogs).
    channelLog: Option[Path] = None,
    // The runner's runtime for this command (Runtime).
    runtime: Option[Runtime] = None,
    // The launch's resolved file rules (fileRulesOf).
    fileRules: FileRules.Resolved = FileRules.Resolved.Empty,
    // The brokered credentials, for the proxy that this command starts when the runner holds no runtime for it.
    credentials: Vector[BrokeredCredential] = Vector.empty,
  ): Int =
    val env: String => Option[String] = name => Option(System.getenv(name))
    val root = RunOnHostSession.root(uid)

    val prepared: Either[String, Assembled] =
      for
        workspaceRoot <-
          try Right(workspaceArg.toAbsolutePath.toRealPath())
          catch case ex: IOException => Left(s"$workspaceArg: ${ex.getMessage}")
        assembled <- assemble(workspaceRoot, program, env, workingDirectory.getOrElse(workspaceRoot))
        _ <- RunOnHostSession.ensureRoot(root, uid)
        // Scavenge before anything runs, since an orphan that a kill left is ours to end here. Scavenge only when no
        // runner dispatched this command:
        //
        // - The runner owns scavenging, at its startup and before each runtime it prepares.
        // - A dispatched command that scavenges the root could condemn the live runner's own session.
        // - channelLog is set exactly when the runner dispatched this command. The acceptance test's own entry has
        //   no channelLog and still scavenges.
        _ =
          if channelLog.isEmpty then
            RunOnHostSession
              .scavenge(root, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_))
              .foreach: (entry, actions) =>
                log(s"scavenged ${entry.getFileName}: ${actions.mkString(", ")}")
      yield assembled

    def refused(reason: String): Int =
      log(s"refused: $reason")
      2

    prepared match
      case Left(reason) => refused(reason)
      case Right(assembled) =>
        RunOnHostSession.publish(root, assembled.prereqs.workspaceRoot) match
          case Left(reason) => refused(reason)
          case Right(session) =>
            // The teardown also runs on a shutdown hook (RunOnHostSession.Teardown). The registered groups are outside
            // the terminal's own group, so nothing but this hook would end them on a Ctrl-C.
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
              case Left(reason) => refused(reason)
              case Right(exit)  => exit

  /** One program's runtime, as a command runs against it.
    *
    *   - `session` holds the runtime's records. An sbt client reaches its server's socket under the session's `tmp/`.
    *   - `proxyPort` is the port of the runtime's proxy, which the profile and the environment name.
    *   - `proxyLog` is the proxy's log. The denied-host report reads it, and the proxy's trust directory takes its
    *     name from it (RunOnHostInspection).
    *   - For mill, `daemonPort` is the one port of the daemon, which a client's profile admits. `daemonPid` is the
    *     daemon's pid, whose arguments the client's profile lets the client read (SeatbeltProfile.Network.MillClient).
    *
    * The runtime is created with the program's rule file as read then, in the session whose records name its groups,
    * and it ends with that session. That session is:
    *
    *   - the runner's session, for the launch's sbt, mill and gradle commands;
    *   - another launch's runner's session, when this launch attaches to that runtime (RunnerRuntimes);
    *   - the command's own session, for Maven and for the acceptance test's entry. */
  case class Runtime(
    session: Path,
    proxyPort: Int,
    proxyLog: Path,
    daemonPort: Option[Int] = None,
    daemonPid: Option[Long] = None,
  ):
    def tmp: Path = session.resolve(RunOnHostSession.TmpDir)
    def trust: Path = RunOnHostInspection.trustDirectory(proxyLog)

  /** What a runtime's server or daemon is started with: its profile's inputs and its environment.
    *
    *   - Both are derived from the assembly, the runtime's `tmp/` and proxy port, and the launch's forwards.
    *   - They are derived once per start (RunnerRuntimes), and carried in the RuntimeStart to the starter and to the
    *     descriptor's fingerprint.
    *   - A launch deciding whether to attach derives them again (RunOnHostRuntimeDescriptor). Equal fingerprints thus
    *     mean a start under the same confinement and environment. */
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
    RuntimeInputs(
      assembled.profileInputs(tmp, proxyPort, trust, systemPaths, network, fileRules),
      commandEnvironment(host, forwards, assembled, tmp, tmp, proxyPort, trust, userName),
    )

  /** What one sbt server or mill daemon is started from:
    *
    *   - the runtime whose proxy it uses;
    *   - the record at which its group is registered, the daemon's group for mill (RunOnHostSbtServer.startSbtServer,
    *     RunOnHostMillDaemons.start);
    *   - its inputs;
    *   - for sbt, the request's launcher flags (RunOnHostSbtServer.serverCommand). */
  case class RuntimeStart(
    assembled: Assembled, buildDirectory: Path, hash: String, record: Path, runtime: Runtime, inputs: RuntimeInputs,
    arguments: Seq[String] = Seq.empty,
  )

  /** How long a starting server may make no progress before the start fails. No progress means that neither its log
    * nor the proxy log grows, and that no portfile appears.
    *
    *   - The bound is on progress rather than time, because a first start resolves sbt's own dependencies through the
    *     proxy.
    *   - sbt's own client waits with no bound at all (doc/TODO.md, "a bound on a silent host command"). */
  val ServerStartSilenceMillis = 120_000L

  def sandboxExec(profileFile: Path, command: Seq[String]): Seq[String] =
    Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString) ++ command

  /** Where the profile of the server or daemon that a record names is written: beside the session's logs, named
    * after the record. */
  def runtimeProfileFile(session: Session, recordName: String): Path = session.directory.resolve(s"$recordName.sb")

  /** That profile, rendered from the start's inputs and written. */
  def writeRuntimeProfile(session: Session, recordName: String, inputs: RuntimeInputs): Either[String, Path] =
    SeatbeltProfile.render(inputs.profile).flatMap: profile =>
      val file = runtimeProfileFile(session, recordName)
      try Right(Files.writeString(file, profile, UTF_8))
      catch case ex: IOException => Left(s"writing $file: ${ex.getMessage}")

  /** Starts the sbt server or mill's starter (`mill version`), registered under `record` (registeredSpawn). Both
    * streams go to `output`: sbt asks on stdout whether to create a build where it finds none, and a refused start
    * quotes what it said. */
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

  /** Polled while a server or daemon starts. Grew when its output or the proxy log grew since the last poll, and
    * Silent once neither has grown for ServerStartSilenceMillis. */
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
    val buildDirectory = workingDirectory.getOrElse(assembled.prereqs.workspaceRoot)
    for
      runtime <- runnerRuntime.map(Right(_)).getOrElse(
        ownRuntime(
          session, assembled, buildDirectory, commandArgs, systemPaths, forwards, fileRules, credentials, channelLog,
          log,
        ),
      )
      // The runner's log has served earlier commands, so the report reads only what this command adds.
      reportFrom = logLength(runtime.proxyLog)
      (tmp, socketDir) = temporaryDirectories(program, session.tmp, runtime.tmp)
      network <- program match
        case Program.Sbt => Right(SeatbeltProfile.Network.SbtClient(runtime.tmp))
        // The build runs in the command's own profile, so the profile gets the grant the daemon's profile would get.
        case Program.Mill if assembled.millWithoutDaemon => Right(SeatbeltProfile.Network.MillDaemon)
        case Program.Mill =>
          runtime.daemonPort.zip(runtime.daemonPid).map(SeatbeltProfile.Network.MillClient(_, _))
            .toRight("the mill runtime names no daemon port and pid")
        case Program.Gradle => Right(SeatbeltProfile.Network.Gradle)
        case Program.Mvn    => Right(SeatbeltProfile.Network.ProxyOnly)
      profile <- SeatbeltProfile.render(
        assembled.profileInputs(tmp, runtime.proxyPort, runtime.trust, systemPaths, network, fileRules),
      )
      _ = assembled.millLauncherVersion.filter(_ => assembled.millWithoutDaemon).foreach: version =>
        log(
          s"mill $version runs the build without a daemon (--no-daemon): the JDK fails its daemon's " +
            "read of each launcher under the sandbox, so each command starts its own JVM",
        )
      _ <- if assembled.millWithoutDaemon then awaitMillOutLock(buildDirectory, log) else Right(())
      exit <- runCommand(
        session, assembled, profile, runtime, commandArgs, workingDirectory, forwards, tmp, socketDir, log,
      )
    yield
      // Under the runner, the runner records the daemons (RunnerRuntimes.commandEnded).
      if program == Program.Gradle && runnerRuntime.isEmpty then
        val processes = RunOnHostSession.HostProcesses
        val found = RunOnHostGradleDaemons.daemons(runtime.tmp, processes)
        RunOnHostGradleDaemons.record(session.records, found, processes).foreach(log)
      reportDenied(runtime.proxyLog, reportFrom, program, log)
      if exit != 0 then reportUnwritableProxyLog(runtime, channelLog, log)
      if exit != 0 && assembled.millWithoutDaemon then reportMillOutLockTaken(buildDirectory, log)
      exit

  /** The runtime for a command without the runner's runtime: the acceptance test's entry, and Maven under the runner.
    *
    *   - The runtime is created in the command's own session, and ends with the session.
    *   - For the programs whose runtime the runner holds, the runner's functions create it.
    *   - For Maven, the runtime is the command's proxy alone. */
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
    RunnerRuntimes(
      session, assembled.prereqs.workspaceRoot, log, systemPaths, forwards, fileRules, credentials, channelLog,
    )(
      assemble = (_, _, _) => Right(assembled),
    )
      .prepare(program, buildDirectory, commandArgs)
      .flatMap:
        case Some(runtime) => Right(runtime)
        case None =>
          val proxyLog = session.directory.resolve("proxy.log")
          readProgramRules(assembled.prereqs.workspaceRoot, program)
            .flatMap(
              createProxy(systemPaths, credentials, channelLog)(program, _, session.records.resolve("proxy"), proxyLog),
            )
            .map(Runtime(session.directory, _, proxyLog))

  private[launcher] def logLength(file: Path): Long =
    try Files.size(file)
    catch case _: IOException => 0L

  /**
   * Where a command's processes keep temporary files, and where sbt's sockets are: `(tmp, socketDir)`.
   *
   *   - Under sbt, temporary files go to the command's own `tmp/`, and the sockets the server listens under go to the
   *     runner's.
   *   - Under mill, both go to the runner's `tmp/`, for two reasons:
   *     - The daemon's forked JVMs, such as a `run` or a test, inherit the daemon's profile, which grants the runner's
   *       `tmp/`. The forked JVMs get the client's environment, though (`RunModule.scala`, `ctx.env`). A `TMPDIR` or
   *       `java.io.tmpdir` naming the command's own `tmp/` would therefore be denied there.
   *     - With one directory, the starter's environment and every client's environment are one map. An option file
   *       that Mill interpolates from the environment (`MillProcessLauncher.loadMillConfig`) then yields the same
   *       value in both, and a client never meets a fingerprint mismatch of the supervisor's own making.
   *   - Under Gradle, both also go to the runner's `tmp/`, for the first reason. The daemon that the first command's
   *     client starts serves the commands that follow, with the profile and environment it was started with. What it
   *     writes must therefore go to a directory that every later command's profile grants and no command's end
   *     removes.
   *   - Under Maven, both go to the command's own `tmp/`.
   */
  def temporaryDirectories(program: Program, sessionTmp: Path, runtimeTmp: Path): (Path, Path) =
    program match
      case Program.Sbt                   => (sessionTmp, runtimeTmp)
      case Program.Mill | Program.Gradle => (runtimeTmp, runtimeTmp)
      case Program.Mvn                   => (sessionTmp, sessionTmp)

  /** The build directory's own bootstrap, which runs the JVM launcher that the environment's MILL_VERSION names. The
    * launcher attaches to the daemon on the one port the profile admits. Otherwise it runs the build itself, with
    * `--no-daemon` first among Mill's options (millWithoutDaemon). */
  def millCommand(buildDirectory: Path, assembled: Assembled, commandArgs: Seq[String]): Seq[String] =
    buildDirectory.resolve("mill").toString +: (Option.when(assembled.millWithoutDaemon)("--no-daemon").toSeq ++
      commandArgs)

  /**
   * Runs before a mill command that runs its build without a daemon.
   *
   *   - While a process holds `out/`'s lock (millOutLockHeld), this method waits for it. Such a process is one of the
   *     user's Mill builds, outside any profile.
   *   - The wait lasts up to the bound that a busy daemon of the user's gets
   *     (RunOnHostMillDaemons.ForeignIdleDeadlineMillis). This method then refuses.
   *   - Mill words its own wait from the start time of the launcher that the newest record names
   *     (`SharedOutLockManager.activeOtherProcessPrefix`, `LauncherOutFilesRecordStore.mostRecentActive`, 1.3.0).
   *     That read throws under the profile (upstream-issues.md, openjdk/jdk).
   *   - A daemon's build writes such a record, and a build without a daemon writes none
   *     (`MillMain0.createLauncherResources`).
   *   - A build that takes the lock after the last probe fails the command that way, and no probe before the command
   *     closes that window. reportMillOutLockTaken names the case afterwards.
   */
  def awaitMillOutLock(
    buildDirectory: Path,
    log: String => Unit,
    held: Path => Option[Boolean] = millOutLockHeld(_),
    deadlineMillis: Long = RunOnHostMillDaemons.ForeignIdleDeadlineMillis,
    pollMillis: Long = 500,
  ): Either[String, Unit] =
    val lock = buildDirectory.resolve(MillOutLockFile)
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    var waiting = false
    var result: Option[Either[String, Unit]] = None
    while result.isEmpty do
      if !held(buildDirectory).contains(true) then result = Some(Right(()))
      else if System.nanoTime > deadline then
        result = Some(Left(
          s"a Mill process not this launch's holds $lock and held it for the ${deadlineMillis / 1000}s this " +
            "command waited; retry when its build is done",
        ))
      else
        if !waiting then log(s"waiting up to ${deadlineMillis / 1000}s for the Mill process that holds $lock")
        waiting = true
        Thread.sleep(pollMillis)
    result.get

  /** Runs after a mill command without a daemon failed. A process that holds `out/`'s lock now may have taken the lock
    * after awaitMillOutLock's last probe, which fails the command as awaitMillOutLock describes. */
  def reportMillOutLockTaken(
    buildDirectory: Path, log: String => Unit, held: Path => Option[Boolean] = millOutLockHeld(_),
  ): Unit =
    if held(buildDirectory).contains(true) then
      log(
        s"a Mill process not this launch's holds ${buildDirectory.resolve(MillOutLockFile)}; if the command " +
          "failed with \"Operation not permitted\" in ProcessHandle, it met that build as it started: retry when " +
          "that build is done",
      )

  /** Checks the daemon's classpath file before a mill command that runs its build without a daemon.
    *
    *   - Such a command reads the daemon's classpath file too (`CoursierClient.resolveMillDaemon`, 1.3.0).
    *   - A host run can rewrite the file between commands. The file is therefore checked before each such command,
    *     under the command's profile, as a daemon start checks it (RunOnHostMillDaemons.discardForeignClasspath).
    *   - The result is None for any other command. */
  def discardForeignClasspathWithoutDaemon(
    assembled: Assembled, buildDirectory: Path, confined: RunOnHostMillDaemons.Confined,
  ): Option[String] =
    if !assembled.millWithoutDaemon then None
    else RunOnHostMillDaemons.discardForeignClasspath(buildDirectory, assembled.prereqs.coursierV1, confined)

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
    log: String => Unit,
  ): Either[String, Int] =
    val prereqs = assembled.prereqs
    val profileFile = session.directory.resolve("profile.sb")
    Files.writeString(profileFile, profile, UTF_8)

    val buildDirectory = workingDirectory.getOrElse(prereqs.workspaceRoot)
    discardForeignClasspathWithoutDaemon(assembled, buildDirectory, RunOnHostMillDaemons.confined(profileFile))
      .foreach(log)
    val programCommand = prereqs.program match
      // With the portfile live, the client connects and forks nothing
      // (NetworkClient.connectOrStartServerAndConnect, v1.13.0 and v2.0.9).
      case Program.Sbt =>
        sbtCommand(prereqs.executable, assembled.sbtGlobal) ++
          Seq("--jvm-client", "-batch", "-java-home", prereqs.jdkHome.toString) ++ commandArgs
      case Program.Mill => millCommand(buildDirectory, assembled, commandArgs)
      case Program.Gradle => gradleCommand(prereqs, tmp) ++ commandArgs
      // The distribution's own `mvn`, not the workspace's `mvnw` (run-on-host-internals.md, "Maven"). --batch-mode
      // serves as sbt's -batch does.
      case Program.Mvn =>
        Seq(prereqs.executable.toString, "--batch-mode") ++ commandArgs

    val record = session.records.resolve("client")
    val command = RunOnHostSession.registeredSpawn(
      record,
      sandboxExec(profileFile, programCommand),
    )
    val builder = ProcessBuilder(command*)
    builder.directory(buildDirectory.toFile)
    // Not the supervisor's own stdin, which is the supervisor's liveness pipe under the runner (runCommandMain).
    builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
    builder.redirectOutput(ProcessBuilder.Redirect.INHERIT)
    builder.redirectError(ProcessBuilder.Redirect.INHERIT)
    builder.environment.clear()
    builder.environment.putAll(
      commandEnvironment(
        name => Option(System.getenv(name)), forwards, assembled, tmp, socketDir, runtime.proxyPort, runtime.trust,
        System.getProperty("user.name"),
      ).asJava,
    )

    // The leader publishes the command's exit status and then stays alive, so that teardown can check its start time
    // (RunOnHostSession). The answer is therefore the exit file, never the leader's own end.
    try RunOnHostSession.awaitExit(RunOnHostSession.exitRecord(record), builder.start())
    catch case ex: IOException => Left(s"starting the command: ${ex.getMessage}")

  /**
   * The distribution's own `gradle`, not the workspace's `gradlew` (run-on-host-internals.md, "Gradle").
   *
   *   - The settings go on the command line, where a `-D` overrides every gradle.properties.
   *   - The daemon registry is the launch's own, under the runner's `tmp/`, which every Gradle process of the launch
   *     is granted and which ends with the launch. `gradle --stop` stops every daemon in the registry, whatever its
   *     JVM (`DaemonStopClient`). A registry under the per-workspace user home would therefore let one launch's
   *     `--stop` end another launch's builds in the same workspace.
   *   - Attaching is already the launch's own. The client's `java.io.tmpdir`, the runner's `tmp/`, is among the
   *     immutable properties that Gradle's daemon compatibility compares (`InitialPropertiesConverter`,
   *     `DaemonCompatibilitySpec`).
   *   - The daemons that the registry holds are recorded after each command and ended with the launch
   *     (RunOnHostGradleDaemons).
   *   - The toolchain inventory is closed to the JDK the profile grants. A project asking for another toolchain
   *     therefore fails with an error naming the toolchain, not with a denial.
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

  /** Variables whose forwarded value the command never gets.
    *
    *   - The version overrides: the supervisor resolved the version from the build directory alone and granted that
    *     launcher (RunOnHostPrereqs.millVersion, millLauncherVersion). Either override would make the bootstrap select
    *     another launcher. `MILL_VERSION` is the supervisor's own setting for a mill command, and names that launcher.
    *   - The output-directory overrides (`OutFiles.java`): the daemon's rendezvous, its port candidate and the foreign
    *     daemons are all looked for under `out/`. A Mill sent elsewhere would be checked nowhere. */
  val MillOverrides = Set("MILL_VERSION", "DEFAULT_MILL_VERSION", "MILL_OUTPUT_DIR", "MILL_BSP_OUTPUT_DIR")

  // sbt's getPreloaded also splits JVM environment options without unquoting them. getPreloaded's first lookup is argv,
  // so the global base goes there as one argument, before any user options.
  def sbtCommand(executable: Path, sbtGlobal: Path): Seq[String] =
    Seq(executable.toString, s"-Dsbt.global.base=$sbtGlobal")

  /**
   * A JVM property as one `_JAVA_OPTIONS` word.
   *
   *   - HotSpot splits _JAVA_OPTIONS on whitespace. An unquoted path with a space can produce an extra option that
   *     prevents JVM startup.
   *   - HotSpot's _JAVA_OPTIONS parser (`Arguments::parse_options_buffer`) joins adjacent quoted runs and drops their
   *     delimiters.
   *   - Unlike a shell, the parser does not interpret backslash escapes. A literal double quote therefore needs a
   *     single-quoted run between double-quoted runs.
   */
  def jvmProperty(name: String, value: String): String =
    "-D" + name + "=\"" + value.replace("\"", "\"'\"'\"") + "\""

  /**
   * The command's whole environment, a closed set: `PassedThrough`, then what `--env` named, then the supervisor's
   * own settings, which win.
   *
   *   - doc/run-on-host-internals.md, "The command's lifetime and environment", has the table of what the environment
   *     holds.
   *   - SECURITY.md, "Run on host", explains why the environment is closed.
   */
  def commandEnvironment(
    host: String => Option[String],
    forwards: Vector[(String, String)],
    assembled: Assembled,
    sessionTmp: Path,
    // Where sbt's server binds its sockets and its clients find them: the runtime's `tmp/` for sbt, mill and gradle,
    // and the command's own for Maven.
    socketDir: Path,
    proxyPort: Int,
    // The runtime's proxy's CA certificate, in both formats (RunOnHostInspection).
    trust: Path,
    userName: String,
  ): Map[String, String] =
    import assembled.{gradleUserHome, ivyHome, m2Repository, millDownloads, millLauncherVersion, prereqs, sbtGlobal}
    val passed = PassedThrough.flatMap(name => host(name).map(name -> _)).toMap
    // Why _JAVA_OPTIONS carries the settings:
    //
    // - The settings must reach the JVMs the command forks, such as a forked test or `run`. Such a JVM inherits the
    //   environment and nothing else, because its options come from the build definition.
    // - SBT_OPTS and JAVA_OPTS, which the sbt script and the mill executable do read, would therefore reach only the
    //   program's own JVMs.
    // - sbt 2.0.9 copies JAVA_TOOL_OPTIONS and JDK_JAVA_OPTIONS into argv without unquoting them. _JAVA_OPTIONS
    //   reaches HotSpot unchanged.
    // - HotSpot applies _JAVA_OPTIONS after argv, so the supervisor's properties also win over command-line
    //   properties.
    // - The shim handles the resulting startup banner.
    val javaOptions = (Seq(
      jvmProperty("java.io.tmpdir", sessionTmp.toString),
      jvmProperty("java.util.prefs.userRoot", sessionTmp.toString),
      // ipcsocket extracts its native socket library to sbt.ipcsocket.tmpdir, else $XDG_RUNTIME_DIR, else
      // java.io.tmpdir (org.scalasbt.ipcsocket.NativeLoader). An sbt client's XDG_RUNTIME_DIR is the runner's tmp/,
      // where the client's profile grants no write or exec, so the load fails there. This property points the
      // library at the command's own tmp/, which is always read-write-exec. The rendezvous sockets still go under
      // XDG_RUNTIME_DIR.
      jvmProperty("sbt.ipcsocket.tmpdir", sessionTmp.toString),
      jvmProperty("sbt.global.base", sbtGlobal.toString),
      jvmProperty("sbt.ivy.home", ivyHome.toString),
      jvmProperty("maven.repo.local", m2Repository.toString),
      // Maven's resolver ignores the JVM proxy properties unless told to use them (run-on-host-internals.md, "Maven").
      "-Daether.connector.http.useSystemProperties=true",
    ) ++ JdkTrust.proxyProperties("127.0.0.1", proxyPort).map((name, value) => s"-D$name=$value") ++ Vector(
      // The proxy answers for every host it allows under a leaf of its own CA, so that CA is the whole store. The
      // JDK's own roots would verify nothing the command can reach.
      jvmProperty("javax.net.ssl.trustStore", RunOnHostInspection.trustStore(trust).toString),
      "-Djavax.net.ssl.trustStoreType=PKCS12",
      s"-Djavax.net.ssl.trustStorePassword=${RunOnHostInspection.TrustStorePassword}",
      // Without this property, a JVM reaches 127.0.0.1 through a dual-stack AF_INET6 socket as v4-mapped
      // ::ffff:127.0.0.1, which the profile's "localhost" class does not cover. The connect to the proxy then dies
      // with EPERM (measured, src/probe/jvm-proxy-rule.sh).
      "-Djava.net.preferIPv4Stack=true",
    )).mkString(" ")
    val own = Map(
      // The JDK, then the system directories a command may execute from (SeatbeltProfile.SystemPaths.txt), and
      // never the host's PATH. The confinement may refuse an entry of the host's PATH, such as a version manager's
      // shim or a Homebrew program ahead of the system one. The lookup then fails with EPERM at that entry, and the
      // shell tries no further. A command that the system PATH serves would therefore break on the host's PATH.
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
      // Set for every program, not mill alone: the other programs ignore it, and one unconditional setting is
      // simpler than a conditional one. Mill's bootstrap otherwise derives the folder from HOME and XDG_CACHE_HOME.
      // This variable sets it to the folder that holds the executable the command is granted.
      millDownloads.map(dir => "MILL_FINAL_DOWNLOAD_FOLDER" -> dir.toString) ++
      // The bootstrap's own override, set to the JVM launcher of the pinned version. For a bare pin, the bootstrap
      // would run the native image (RunOnHostPrereqs.millLauncherVersion).
      millLauncherVersion.map("MILL_VERSION" -> _) ++
      commandProxyVariables(proxyPort) ++
      // For the programs that HTTPS_PROXY serves, which read no JVM property.
      AgentSandboxLauncher.CaBundleVariables.map(_ -> RunOnHostInspection.caBundle(trust).toString)
    passed ++ (forwards.toMap -- MillOverrides) ++ own

  /**
   * The proxy variables that the command's environment gets (AgentSandboxLauncher.proxyVariables), for the programs
   * that read the environment rather than the JVM properties.
   *
   *   - The loopback exemption lets the command reach a test server on loopback directly.
   *   - The rest of the variable family, such as ALL_PROXY and FTP_PROXY, requires explicit forwarding.
   *   - The launcher's own HTTPS_PROXY is absent. That variable names an upstream proxy that the confinement refuses,
   *     with a credential the command has no business reading.
   */
  def commandProxyVariables(proxyPort: Int): Map[String, String] =
    AgentSandboxLauncher.proxyVariables(s"http://127.0.0.1:$proxyPort").toMap

  /**
   * The cost of switching where a build runs, paid before each sbt server starts (RunnerRuntimes.sweepTargetLinks).
   *
   *   - sbt 2 leaves `target/` outputs as symlinks into its content-addressed store, which lies under the global base
   *     only when `sbt.global.base` is set (run-on-host-internals.md, "sbt"). A tree that the user's own sbt built
   *     therefore links into a store this profile cannot reach.
   *   - zinc treats the unreadable state as an error, not as a cold start (measured: `previousCompile` fails on
   *     `inc_compile_3.zip`).
   *   - This method removes every symlink under a `target/` directory that does not resolve inside a granted root,
   *     dangling links included. The artifacts a link named still exist in the store of the sbt that made them,
   *     which relinks them on its own next run.
   *   - The roots are compared resolved, as the links are. A root reached through a symlink, such as macOS's `/var`,
   *     would otherwise match nothing, and the sweep would take every link.
   */
  def cleanForeignTargetLinks(workspaceRoot: Path, granted: Seq[Path]): Vector[Path] =
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
    walk(workspaceRoot, inTarget = false)
    removed.result()
