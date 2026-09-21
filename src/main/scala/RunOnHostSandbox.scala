// The wrapper: from a project and a program to a confined command's exit code, through the thirteen
// steps — validate, scavenge, publish, runtime, profile, run, end what was started, remove — and
// the broker's runtimes, the proxy and the sbt server or mill daemon the commands of one build
// directory share (BrokerRuntimes). macOS only, like everything it drives; the assembly and
// refusal logic are in RunOnHostPrereqs and are unit-tested there, so this file is the sequence
// of steps plus the host observations no Linux test can make.

package agentsandbox.launcher

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.{ISO_8859_1, UTF_8}
import java.nio.file.{Files, LinkOption, Path, StandardOpenOption}
import java.nio.file.attribute.BasicFileAttributes

import scala.jdk.CollectionConverters.*
import scala.util.control.NonFatal

import RunOnHostPrereqs.*
import RunOnHostSession.{ServerAnswer, Session}
import HostCommands.Os
import FileHelper.directoryEntries
import SandboxProject.{isMetadataEntry, projectIdOf}

object RunOnHostSandbox:

  case class Assembled(
    prereqs: CommandPrereqs,
    /** The unpacked distribution the executable runs from: sbt's in the Coursier archive cache,
      * Gradle's and Maven's under their wrappers' `dists`; mill's executable is one file and has
      * none. */
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

  private def isExecutableFile(path: Path) = Files.isExecutable(path) && Files.isRegularFile(path)

  /** A file the prerequisites cannot read, carried out of the readers — whose callers are pure
    * and take a reader that answers absent or present — to the assembly's boundary, where it is
    * one worded refusal. Existing-but-unreadable never falls to the next source: mill would
    * select the file and then fail reading it. */
  private final class Unreadable(val refusal: Refusal) extends RuntimeException(null, null, false, false)

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
  private def readLines(path: Path): Option[Seq[String]] =
    reading(path)(Option.when(Files.exists(path))(Files.readAllLines(path).toArray(Array.empty[String]).toSeq))

  private def readText(path: Path): Option[String] =
    reading(path)(Option.when(Files.exists(path))(Files.readString(path, UTF_8)))

  private def readBytes(path: Path): Array[Byte] = reading(path)(Files.readAllBytes(path))

  /** Absent is None. ISO-8859-1, as `java.util.Properties` reads a stream. */
  private def readLatin1(path: Path): Option[String] =
    reading(path)(Option.when(Files.exists(path))(String(Files.readAllBytes(path), ISO_8859_1)))

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
        case Program.Mill   => millLauncher(env, buildDirectory).map(_._1)
        case Program.Gradle => gradleDistribution(env, buildDirectory).map(_.resolve("bin").resolve("gradle"))
        case Program.Mvn    => mvnDistribution(env, buildDirectory).map(_.resolve("bin").resolve("mvn"))
        case Program.Sbt    => Left(StepRefusal("sbt executable", "sbt's executable is the user's, not the project's"))
    catch case ex: Unreadable => Left(StepRefusal(program.name, ex.refusal))

  /** Mill's provisioned JVM launcher and its version, `<v>-jvm`, resolved as the bootstrap in
    * `buildDirectory` resolves them. */
  private def millLauncher(env: String => Option[String], buildDirectory: Path): Either[StepRefusal, (Path, String)] =
    for
      _ <- context("mill bootstrap")(validateMillBootstrap(buildDirectory, isExecutableFile))
      _ <- context("mill jvm")(millJvmIsSystem(buildDirectory, readLines))
      pinned <- context("mill version")(millVersion(buildDirectory, readLines))
      launcher <- context("mill version")(millLauncherVersion(pinned))
      downloads <- context("mill executable")(millDownloadDir(env).toRight("no mill download folder"))
      provisioned <- context("mill executable")(millExecutable(downloads, launcher, isExecutableFile))
      real <- context("mill executable")(realPath(provisioned).toRight(s"$provisioned vanished"))
    yield (real, launcher)

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
              SeatbeltProfile
                .sbtDistribution(String(readBytes(sbt), ISO_8859_1), coursierCache)
                .toRight(s"$sbt names no distribution inside $coursierCache"),
            )
            home <- context("sbt distribution")(
              validateSbtDistribution(inner, coursierCache, realPath, isExecutableFile),
            )
          yield (sbt, Some(home), None)
        case Program.Mill =>
          millLauncher(env, buildDirectory).map((real, launcher) => (real, None, Some(launcher)))
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
        AgentSandboxLauncher.stateRootOf(os, env).left.map(_.stripPrefix("error: ")),
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
   * run-on-host/ accepts only recognized configuration entries, as does its parent directory
   * (SandboxProject.boundaryDirError): the programs this wrapper serves, egress/ inside each, rule
   * inside that — a stray name, a symlinked component, or a component of the wrong type refuses the
   * command, never remains as ignored config. The type rule prevents real failures: a file where a
   * directory belongs would read as absent configuration, and a FIFO where the file belongs would
   * block the read forever.
   */
  def hostCommandStray(project: Path): Option[String] =
    val dir = project.resolve(".ko-agent-sandbox").resolve("run-on-host")
    val programs = Program.values.toVector.map(_.name)
    def strays(path: Path, allowed: Set[String]): Vector[String] =
      if !Files.isDirectory(path) then Vector.empty
      else
        directoryEntries(path).map(_.getFileName.toString).filterNot(isMetadataEntry).filterNot(allowed).sorted
          .map(name => s"$path/$name")

    if !Files.exists(dir, java.nio.file.LinkOption.NOFOLLOW_LINKS) then None
    else
      val directories = dir +: programs.flatMap: name =>
        Vector(dir.resolve(name), dir.resolve(name).resolve("egress"))
      val ruleFiles = programs.map(name => dir.resolve(name).resolve("egress").resolve("rule"))
      def wrongType(path: Path, directory: Boolean): Boolean =
        Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) &&
          (if directory then !Files.isDirectory(path) else !Files.isRegularFile(path))
      (directories ++ ruleFiles).find(Files.isSymbolicLink)
        .map(link => s"$link is a symlink; boundary configuration is read plainly or not at all")
        .orElse(directories.find(wrongType(_, directory = true))
          .map(p => s"$p is not a directory; boundary configuration is read plainly or not at all"))
        .orElse(ruleFiles.find(wrongType(_, directory = false))
          .map(p => s"$p is not a regular file; boundary configuration is read plainly or not at all"))
        .orElse:
          val stray = strays(dir, programs.toSet) ++ programs.flatMap: name =>
            strays(dir.resolve(name), Set("egress")) ++
              strays(dir.resolve(name).resolve("egress"), Set("rule"))
          Option.when(stray.nonEmpty):
            s"${stray.mkString(", ")}: not configuration this launcher reads — " +
              "a typo, or a newer launcher's file; check the spelling or update the launcher"

  /** The project file's hosts, validated to the program's rule grammar (run-on-host.md
    * "Configuration"); an absent file contributes nothing. */
  def readProgramRules(project: Path, program: Program): Either[String, Vector[String]] =
    hostCommandStray(project).toLeft(()).flatMap: _ =>
      val file = programRulePath(project, program)
      if !Files.exists(file) then Right(Vector.empty)
      else
        try
          programRuleHosts(Files.readString(file, UTF_8)).left.map(refusal => s"$file: ${wording(refusal)}")
        catch case ex: IOException => Left(s"$file: ${ex.getMessage}")

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

  /** How the wrapper re-invokes its own executable — the running JVM and classpath, or the native
    * image binary itself — under one of the launcher's private actions. */
  def selfInvocation(actionAndArguments: String*): Seq[String] =
    if isNativeImage then
      launchFile.getOrElse(throw IllegalStateException("the native image cannot name itself")).toString
        +: actionAndArguments
    else
      Seq(
        Path.of(System.getProperty("java.home")).resolve("bin").resolve("java").toString,
        "-cp", selfClassPath().mkString(java.io.File.pathSeparator),
        "agentsandbox.launcher.AgentSandboxLauncher",
      ) ++ actionAndArguments

  /** This JVM's class path with every element absolute against this JVM's working directory —
    * `java -jar target/dist/ko-agent-sandbox.jar` names it relative, and an empty element is
    * that directory itself — since the proxy runs from `/` (startProxy), where a relative
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
  private val launchFile: Option[Path] =
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
    * before a wrapper is exec'd (BrokerRuntimes.prepare, every program) and before a proxy is
    * started (proxyInputs): a JVM starts with a missing class-path entry and fails only at loading
    * the main class, so unchecked, the jar form's failure is the proxy's ready wait timing out over
    * a Java error in its log, and the native form's is a spawn that fails to exec. Not checked at
    * the launch's own broker spawn (RunOnHostChannel.spawnBroker), which follows the launcher's
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
    * [--runtime-session=<dir> --proxy-port=<port> --proxy-log=<file> [--daemon-port=<port>]] --
    * <args...>`: one channel request as a process of its own, so the broker's cancel is a SIGTERM
    * whose answer is this wrapper's shutdown hook. The runtime options name the broker's runtime
    * (Runtime). */
  def runCommandMain(args: Seq[String]): Unit =
    def start(
      programName: String,
      project: String,
      workingDirectory: String,
      options: List[String],
      commandArgs: List[String],
    ): Unit =
      val program = Program.values.find(_.name == programName).getOrElse:
        Console.err.println(s"--run-command-on-host: unknown program $programName")
        sys.exit(2)
      val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
      val stray = options.filterNot(option =>
        option.startsWith(EnvOption) || option.startsWith(ChannelLogOption)
          || option.startsWith(RuntimeSessionOption) || option.startsWith(ProxyPortOption)
          || option.startsWith(ProxyLogOption) || option.startsWith(DaemonPortOption),
      )
      if stray.nonEmpty then
        Console.err.println(s"--run-command-on-host: unexpected arguments: ${stray.mkString(" ")}")
        sys.exit(2)
      val runtime = runtimeOf(options).fold(
        reason => { Console.err.println(s"--run-command-on-host: $reason"); sys.exit(2) },
        identity,
      )
      // The broker's pipe (RunOnHostChannel.dispatch): its EOF is the broker gone, and the command
      // ends with it through the shutdown hook, as it ends with the requester's ctl. The status is
      // nobody's to read. A def, not the thread's own lambda: a lambda ending in sys.exit types
      // as Nothing, which the JVM's lambda factory refuses for Runnable's void at link time.
      def endWithBroker(): Unit =
        try while System.in.read() != -1 do ()
        catch case _: IOException => ()
        sys.exit(143)
      val brokerGone = Thread(() => endWithBroker())
      brokerGone.setDaemon(true)
      brokerGone.start()
      sys.exit(
        run(
          Path.of(project), program, commandArgs, bundledSystemPaths(), uid,
          Console.err.println, workingDirectory = Some(Path.of(workingDirectory)),
          forwarded = forwardedNames(options),
          channelLog = options.find(_.startsWith(ChannelLogOption))
            .map(option => Path.of(option.stripPrefix(ChannelLogOption))),
          runtime = runtime,
        ),
      )
    args.toList match
      case programName :: project :: workingDirectory :: rest if rest.contains("--") =>
        val (options, commandArgs) = rest.span(_ != "--")
        start(programName, project, workingDirectory, options, commandArgs.drop(1))
      case other =>
        Console.err.println(s"--run-command-on-host: unexpected arguments: ${other.mkString(" ")}")
        sys.exit(2)

  /** `--env=<name>` as the broker and the command receive it: the name alone, the value read from
    * the receiving process's own environment under `carrierName` (RunOnHostChannel.spawnBroker).
    * A forward is thus never an argument with a secret in it below the launcher. */
  val EnvOption = "--env="

  def forwardedNames(options: Seq[String]): Vector[String] =
    options.filter(_.startsWith(EnvOption)).map(_.stripPrefix(EnvOption)).toVector

  /** `--channel-log=<file>`: the broker's own log, where the wrapper appends a signal-ended
    * command's logs (appendSessionLogs). */
  val ChannelLogOption = "--channel-log="

  /** The broker's runtime as the wrapper's options: the first three together or none, the
    * daemon port with them for a mill runtime. */
  val RuntimeSessionOption = "--runtime-session="
  val ProxyPortOption = "--proxy-port="
  val ProxyLogOption = "--proxy-log="
  val DaemonPortOption = "--daemon-port="

  def runtimeOptions(runtime: Runtime): Seq[String] =
    Seq(
      s"$RuntimeSessionOption${runtime.session}", s"$ProxyPortOption${runtime.proxyPort}",
      s"$ProxyLogOption${runtime.proxyLog}",
    ) ++ runtime.daemonPort.map(port => s"$DaemonPortOption$port")

  def runtimeOf(options: Seq[String]): Either[String, Option[Runtime]] =
    def value(prefix: String) = options.find(_.startsWith(prefix)).map(_.stripPrefix(prefix))
    def port(prefix: String, text: String) = text.toIntOption.toRight(s"$prefix$text is no port")
    (value(RuntimeSessionOption), value(ProxyPortOption), value(ProxyLogOption), value(DaemonPortOption)) match
      case (None, None, None, None) => Right(None)
      case (Some(session), Some(proxy), Some(log), daemon) =>
        for
          proxyPort <- port(ProxyPortOption, proxy)
          daemonPort <- daemon.map(port(DaemonPortOption, _).map(Some(_))).getOrElse(Right(None))
        yield Some(Runtime(Path.of(session), proxyPort, Path.of(log), daemonPort))
      case _ => Left(s"$RuntimeSessionOption, $ProxyPortOption and $ProxyLogOption come together")

  /** The last bytes of each command log appended to the channel log: a stalled command's last
    * lines are the finding, and a build's audit log can run long. */
  val SessionLogTailBytes = 64 << 10

  /** Logs retained before a session's directory is removed: the proxy audit logs — a command's
    * `proxy.log`, the broker's one per runtime — the sbt servers' logs (serverLog),
    * the mill starters' output (RunOnHostMillDaemons.starterLog), and the stderr file a thin client
    * leaves under `tmp/` when it forked a server of its own.
    * run-on-host.md "The channel and the command" has why every signal keeps them and what a
    * server's file holds. `condemned` is the session directory at its condemned pathname with
    * its groups ended (RunOnHostSession.endSession), so no process the session started can
    * change what is read; the tmp check below and sessionLogTail keep each read inside the
    * directory. `ended` is the block's first line, naming the session and how it ended. */
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
      sessionLogTail(file).foreach: tail =>
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
    * reads by accident. The broker and the wrapper are unconfined JVMs of the launcher's own code, and an
    * explicit `--env=NAME=VALUE` installed under its own name — a loader variable, say — would be
    * read by them first; the requested name is restored inside the command's environment alone,
    * where the wrapper's own settings still win over it. */
  def carrierName(name: String): String = s"KO_AGENT_RUN_ON_HOST_ENV_$name"

  /** The bound port, from the ready line the proxy prints after `bind`; its log file is its
    * stderr, so the line is written where this polls. */
  def awaitProxyPort(log: Path, deadlineMillis: Long): Either[String, Int] =
    val Ready = raw""".*ko-agent-egress-proxy listening on :(\d+).*""".r
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    // Decoded leniently: the log carries what the proxy's clients asked for.
    def text = if Files.exists(log) then String(Files.readAllBytes(log), UTF_8) else ""
    var found: Option[Int] = None
    while found.isEmpty && System.nanoTime < deadline do
      text.linesIterator.collectFirst { case Ready(port) => port.toInt } match
        case Some(port) => found = Some(port)
        case None       => Thread.sleep(50)
    found.toRight:
      val said =
        if Files.exists(log) then text.linesIterator.take(5).mkString("\n")
        else "(no log was written)"
      s"the proxy did not report ready within ${deadlineMillis / 1000}s:\n$said"

  /**
   * The live server a build directory's portfile names, if any: SECURITY.md "Run on host"
   * records the one-server rule it serves. A thin client attaches to whatever server the
   * portfile names and then runs with that server's environment and confinement, so before the
   * broker starts its own server, a live one here is ended (BrokerRuntimes.noForeignServer), and
   * while the broker's runs, a live socket inside the broker's `tmp/` is that server. Live means
   * connectable; a stale portfile is left for sbt, which replaces it. The socket here is wherever
   * the portfile points, uncontained on purpose — the user's own server runs outside any
   * sandbox — and the probe only connects and closes, writing nothing to what it reaches.
   */
  def livePortfileServer(buildDirectory: Path): Option[Path] =
    val portfile = buildDirectory.resolve("project").resolve("target").resolve("active.json")
    if !Files.isRegularFile(portfile) then None
    else
      try
        RunOnHostSession.portfileSocket(Files.readString(portfile, UTF_8)).filter: socket =>
          Files.exists(socket) && connectable(socket)
      catch case _: IOException => None

  private def connectable(socket: Path): Boolean =
    try
      val channel = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.UNIX)
      try
        channel.connect(java.net.UnixDomainSocketAddress.of(socket))
        true
      finally channel.close()
    catch case _: IOException => false

  def foreignServerRefusal(socket: Path): String =
    s"a live sbt server holds this build directory's portfile (socket $socket); " +
      "run `sbt shutdown` there and retry"

  /**
   * Where the user's own sbt 2 keeps this project's server socket:
   * `<serverDir>/<half SHA-1 hex of the portfile path's Path.toUri spelling>/sock`, with
   * serverDir `$SBT_GLOBAL_SERVER_DIR`, else the global base versioned `/2`, then `/server`.
   * Each input is taken as sbt takes it, because a divergence here is a divergence in what gets
   * shut down: `SBT_GLOBAL_SERVER_DIR` verbatim, present-but-empty included
   * (`CommandExchange.scala`), while the global base's own sources are trimmed and empty-filtered
   * — `SBT_CONFIG_HOME`, else `XDG_CONFIG_HOME/sbt`, else `user.home/.config/sbt`
   * (`SysProp.defaultGlobalBaseDirectory`). `user.home`, not `$HOME`: sbt reads the property, and
   * the two can differ. `-Dsbt.global.base`, first in sbt's order, is set in the user's JVM and is
   * invisible from this process, so a server launched with it derives elsewhere and is never
   * found at this socket — the refusal below, not a wrong shutdown.
   */
  def sbtServerSocket(buildDirectory: Path, env: String => Option[String], userHome: Path): Path =
    // java.io.File joins throughout, as sbt's `/` does: an empty parent resolves against the
    // root, where Path.resolve would keep the result relative.
    def file(value: String) = java.io.File(value)
    extension (parent: java.io.File) def /(child: String) = java.io.File(parent, child)
    def trimmed(name: String): Option[java.io.File] =
      env(name).filter(_.nonEmpty).map(value => file(value.trim))
    val uri = buildDirectory.resolve("project").resolve("target").resolve("active.json").toUri.toString
    val digest = java.security.MessageDigest.getInstance("SHA-1").digest(uri.getBytes(UTF_8))
    val hash = digest.map(byte => f"$byte%02x").mkString.take(20)
    val globalBase =
      trimmed("SBT_CONFIG_HOME")
        .orElse(trimmed("XDG_CONFIG_HOME").map(_ / "sbt"))
        .getOrElse(file(userHome.toString) / ".config" / "sbt")
        .getAbsoluteFile
    val serverDir = env("SBT_GLOBAL_SERVER_DIR").map(file).getOrElse(globalBase / "2" / "server")
    (serverDir / hash / "sock").toPath

  /** A chain longer than this is a cycle or an attempt at one; either way, unanswerable. */
  private val MaxSymlinkHops = 40

  /**
   * Whether a path the wrapper is about to send to could have been planted by a command. The
   * question is not where the path ends but whether resolving it ever *enters* somewhere a command
   * writes: from the first component inside, the command chooses what every later component means,
   * and a link there can send the rest anywhere — including straight back out, which is why the
   * fully resolved endpoint answers nothing. So the walk follows one hop at a time, checking
   * where each link *is located* before reading where it points, and answers yes the moment a step
   * resolves into a writable root — the leaf included, since the socket itself may be the planted
   * link. It stops at the first component absent even as a link: nothing exists beneath it, and
   * creating it would need a write to the last resolved prefix, outside every writable root by
   * then.
   *
   * The roots are the profile's writable set (`SeatbeltProfile.render`): the project, and the
   * per-project caches that persist across sessions, so a socket an *earlier* agent's command
   * planted in a cache is caught as well. Each is compared in both of its macOS spellings, the
   * firmlink aliasing every containment check here shares
   * (`SandboxProject.withMacDataVolumeAliases`). A cache that does not resolve holds nothing and
   * is skipped; the project is mandatory, so its silence, a relative target, and any unanswerable
   * walk all count as reachable. A target already lexically inside a root is reachable whatever
   * the filesystem currently shows, so that is answered before the walk begins.
   */
  def reachableThroughCommandWritable(target: Path, project: Path, caches: Seq[Path]): Boolean =
    def real(path: Path): Option[Path] =
      try Some(path.toRealPath())
      catch case _: IOException => None
    real(project) match
      case None => true
      case Some(projectRoot) =>
        val roots =
          SandboxProject.withMacDataVolumeAliases(projectRoot +: caches.flatMap(real))
        def inside(path: Path) = roots.exists(path.normalize.startsWith)
        if target.getRoot == null || inside(target) then true
        else
          try
            var resolved = target.getRoot
            var pending = target.iterator.asScala.map(_.toString).toList
            var hops = 0
            var reachable = false
            var absent = false
            while pending.nonEmpty && !reachable && !absent do
              val name = pending.head
              pending = pending.tail
              if name == "." then ()
              else if name == ".." then Option(resolved.getParent).foreach(resolved = _)
              else
                val step = resolved.resolve(name)
                if inside(step) then reachable = true
                else if !Files.exists(step, java.nio.file.LinkOption.NOFOLLOW_LINKS) then
                  absent = true
                else if Files.isSymbolicLink(step) then
                  hops += 1
                  if hops > MaxSymlinkHops then reachable = true
                  else
                    // One hop only: its target's own components are walked, and checked, next.
                    val link = Files.readSymbolicLink(step)
                    if link.isAbsolute then resolved = link.getRoot
                    pending = link.iterator.asScala.map(_.toString).toList ++ pending
                else resolved = step
            reachable
          catch case _: IOException => true

  /**
   * The user's own server, ended before the broker starts its own: a protocol shutdown, which
   * the server runs after the exec it is on, so a build in flight there completes first. The
   * socket the shutdown is sent to is derived from the build directory the way sbt derives it,
   * never read from the portfile, and the portfile's word is only compared against it: workspace
   * content must not choose where an unconfined write-and-parse goes. The derivation is
   * authorization, so it is checked as well as computed — a derived socket the project could
   * have planted is refused, since the project chooses its own content and would then be
   * choosing the target. Every doubt falls back to the refusal, naming what stopped the shutdown.
   */
  def shutdownForeignServer(
    project: Path,
    buildDirectory: Path,
    portfileSocket: Path,
    env: String => Option[String],
    log: String => Unit,
    runOnHostCaches: Seq[Path] = Seq.empty,
    userHome: Path = Path.of(System.getProperty("user.home")),
    shutdownDeadlineMillis: Long = 120_000,
    releaseDeadlineMillis: Long = 10_000,
  ): Either[String, Unit] =
    def refused(cause: String) = Left(s"${foreignServerRefusal(portfileSocket)} — $cause")
    val derived = sbtServerSocket(buildDirectory, env, userHome)
    if reachableThroughCommandWritable(derived, project, runOnHostCaches) then
      refused(
        s"the socket sbt derives for this build directory ($derived) is reachable through what a " +
          "command writes, so no shutdown is sent to it",
      )
    else if !samePath(derived, portfileSocket) then
      refused(s"its socket is not the one sbt derives for this build directory ($derived)")
    else
      log(s"shutting down the sbt server at $derived: it holds the portfile of $buildDirectory")
      RunOnHostSbtServerShutdown.shutdown(derived, shutdownDeadlineMillis) match
        case ServerAnswer.Unanswered(reason) => refused(s"the shutdown went unanswered: $reason")
        // Unreachable is the server gone between the liveness probe and now — the outcome sought.
        case ServerAnswer.ShutDown | ServerAnswer.Unreachable(_) =>
          val deadline = System.nanoTime + releaseDeadlineMillis * 1_000_000
          while livePortfileServer(buildDirectory).isDefined && System.nanoTime < deadline do
            Thread.sleep(50)
          if livePortfileServer(buildDirectory).isEmpty then Right(())
          else refused("the server answered the shutdown but still holds the portfile")

  private def samePath(a: Path, b: Path): Boolean =
    a == b || (try a.toRealPath() == b.toRealPath() catch case _: IOException => false)

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
    // The broker's runtime for this command (Runtime).
    runtime: Option[Runtime] = None,
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
        // when not dispatched by a broker: the broker owns scavenging (at its startup and before
        // each runtime it prepares), and a dispatched command scavenging the root could condemn
        // the live broker's own session. channelLog is set exactly when the broker dispatched
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
                      forwarded.flatMap(name => env(carrierName(name)).map(name -> _)), runtime,
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
    * reads, and for mill the one port of its daemon, the port a client's profile admits.
    * Created with the program's rule file as read then, in the session whose records
    * name its groups — the broker's for its launch's sbt and mill commands, or another launch's
    * broker's when this launch attaches to its runtime (BrokerRuntimes), the command's own for
    * Maven and for the acceptance test's entry — and ended with that session. */
  case class Runtime(session: Path, proxyPort: Int, proxyLog: Path, daemonPort: Option[Int] = None):
    def tmp: Path = session.resolve(RunOnHostSession.TmpDir)

  /** What a runtime's server or daemon is started with: its profile's inputs and its
    * environment, derived from the assembly, the runtime's `tmp/` and proxy port, and the
    * launch's forwards. One derivation for the starters (startSbtServer, RunOnHostMillDaemons.start) and
    * for the fingerprint another launch compares before attaching (RunOnHostRuntimeDescriptor), so that
    * equal fingerprints mean a start under the same confinement and environment. */
  case class RuntimeInputs(profile: SeatbeltProfile.ProfileInputs, environment: Map[String, String])

  def runtimeInputs(
    assembled: Assembled,
    tmp: Path,
    proxyPort: Int,
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
    network: SeatbeltProfile.Network,
    host: String => Option[String] = name => Option(System.getenv(name)),
    userName: String = System.getProperty("user.name"),
  ): RuntimeInputs =
    val prereqs = assembled.prereqs
    RuntimeInputs(
      SeatbeltProfile.ProfileInputs(
        prereqs = prereqs,
        sessionTmp = tmp,
        distribution = assembled.distribution,
        sbtGlobal = assembled.sbtGlobalGranted,
        ivyHome = assembled.ivyHomeGranted,
        gradleUserHome = assembled.gradleUserHomeGranted,
        m2Repository = assembled.m2RepositoryGranted,
        proxyPort = proxyPort,
        systemPaths = systemPaths,
        network = network,
      ),
      commandEnvironment(
        host, forwards, prereqs, assembled.sbtGlobal, assembled.ivyHome, assembled.gradleUserHome,
        assembled.m2Repository, assembled.millDownloads, assembled.millLauncherVersion, tmp, tmp, proxyPort, userName,
      ),
    )

  /** The proxy registered at `record`, logging to `proxyLog`: its bound port. */
  private def createProxy(systemPaths: SeatbeltProfile.SystemPaths)(
    program: Program, fileHosts: Vector[String], record: Path, proxyLog: Path,
  ): Either[String, Int] =
    startProxy(record, program, fileHosts, proxyLog, systemPaths)
      .flatMap(_ => awaitProxyPort(proxyLog, deadlineMillis = 30_000))

  /** What one sbt server is started from: the runtime whose proxy it uses, the request whose
    * `-D` and `-J` arguments it takes, and the record its group is registered at. */
  case class ServerStart(
    assembled: Assembled, buildDirectory: Path, hash: String, arguments: Seq[String], record: Path, runtime: Runtime,
  )

  /** What one mill daemon is started from: the runtime whose proxy it uses, and the record its
    * starter's group — the daemon's — is registered at (RunOnHostMillDaemons.start). */
  case class DaemonStart(assembled: Assembled, buildDirectory: Path, hash: String, record: Path, runtime: Runtime)

  /**
   * The broker's runtimes: one per build directory and program — a proxy, and the server or
   * daemon the program's clients attach to, sbt's server and mill's daemon — kept warm across the
   * launch's commands from that directory while its proxy lives. Visiting another build
   * directory leaves the runtimes already made alive (`live` is keyed by program and the build
   * directory's hash), so alternating between a root and a nested build keeps both warm. A
   * runtime is replaced whole only when its own proxy is gone. A server or daemon gone on its
   * own — `shutdown`, the program's idle exit — is replaced under the same proxy, the records and
   * build file deleted only when the last runtime of the hash is retired; so is a mill daemon
   * whose configuration changed, the one Mill's launcher restarts it on
   * (RunOnHostPrereqs.millDaemonConfig), assembled afresh since a changed version pin grants
   * another launcher. On a cancel the broker follows each program: a cancelled sbt command's server
   * is not retired, since stock sbt's disconnect cancels the exec and leaves the server, and a
   * cancelled mill command's daemon shuts itself down, as stock Mill's does on a disconnect
   * mid-command, so the next mill command starts one. Gradle's runtime is its proxy: the client
   * starts and matches the daemon in the launch's own registry, inside the profile, and the
   * broker records the registry's daemons after each command and ends them with its session
   * (RunOnHostGradleDaemons). Maven is never here: it runs once and exits, its proxy with the command.
   * The acceptance test's entry holds one of these over the command's own session for its one command, so
   * the one lifecycle has two callers and no second owner.
   *
   * When another launch owns the build directory's server or daemon (SECURITY.md "Run on host"),
   * this broker attaches its command to that runtime if it would start one under the same
   * confinement and environment (`attached`), and otherwise ends it by its owner's record under
   * the retirement lock and starts its own (`takeOver`) — the one case in which a broker signals
   * a live launch's group not its own; a dead launch's the scavenger collects.
   * `scavenge` runs before each preparation so a dead owner is collected by the exclusive
   * scavenger before a fresh server or daemon starts; one dying after it is taken over. Preparation and
   * the session's end share this object's monitor. Tests replace the second parameter list: they
   * register a stand-in spawn where the proxy, server or daemon would be, and stub the scavenger.
   */
  final class BrokerRuntimes(
    session: Session,
    project: Path,
    log: String => Unit,
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
  )(
    processes: RunOnHostSession.Processes = RunOnHostSession.HostProcesses,
    assemble: (Path, Program, Path) => Either[String, Assembled] =
      (project, program, buildDirectory) =>
        RunOnHostSandbox.assemble(project, program, name => Option(System.getenv(name)), buildDirectory),
    proxy: (Program, Vector[String], Path, Path) => Either[String, Int] = createProxy(systemPaths),
    server: ServerStart => Either[String, Unit] = start => startSbtServer(session, systemPaths, forwards, start),
    daemon: DaemonStart => Either[String, RunOnHostMillDaemons.Daemon] =
      start => RunOnHostMillDaemons.start(session, systemPaths, forwards, RunOnHostSession.HostProcesses, log, start),
    scavenge: () => Unit = () => (),
    // The daemons holding the launch's registry under the given tmp/ (RunOnHostGradleDaemons.daemons).
    gradleDaemons: Path => Vector[(Long, String)] = RunOnHostGradleDaemons.daemons(_, RunOnHostSession.HostProcesses),
    executable: () => Either[String, Option[Path]] = () => selfPresent(),
  ):
    /** A runtime with the rule hosts its proxy was created from and, for mill, its daemon with
      * the configuration it was started from. */
    private case class Live(
      buildDirectory: Path, hash: String, assembled: Assembled, runtime: Runtime, hosts: Vector[String],
      daemon: Option[RunOnHostMillDaemons.Daemon] = None, daemonConfig: String = "",
    )
    // Keyed by program and the build directory's hash: one runtime per (directory, program), all
    // kept warm.
    private var live = Map.empty[(Program, String), Live]
    private val env: String => Option[String] = name => Option(System.getenv(name))
    private val root = session.directory.getParent

    private def proxyRecord(program: Program, hash: String): Path =
      session.records.resolve(s"proxy-${program.name}-$hash")
    private def serverRecord(hash: String): Path = session.records.resolve(serverRecordName(hash))
    private def daemonRecord(hash: String): Path = session.records.resolve(daemonRecordName(hash))

    /** The runtime a command in `buildDirectory` runs against, None for Maven's; `arguments` are
      * the request's, for a server this call starts. Called while the command's spawn holds the
      * build lock. A dead owner is collected first, so a stale portfile or record cannot block a
      * fresh start. */
    def prepare(program: Program, buildDirectory: Path, arguments: Seq[String]): Either[String, Option[Runtime]] =
      synchronized:
        // Scavenge before every dispatched command, Maven's included: a dead owner in any build
        // directory must be collected on the next launch's next command, not only when that
        // command needs a runtime of its own.
        scavenge()
        // The word this returns is what the spawn execs the wrapper on (RunOnHostChannel.dispatch):
        // the executable's last check before that exec, Maven's included (selfPresent has why).
        executable().flatMap: _ =>
          if program == Program.Mvn then Right(None)
          else
            val hash = RunOnHostSession.buildHash(buildDirectory)
            val key = (program, hash)
            // Before a mill client or starter runs: Mill's launcher acts on the rendezvous
            // directory as it finds it, so a redirected one is refused here, never handed to it.
            val rendezvous =
              if program == Program.Mill then RunOnHostMillDaemons.rendezvousIsOwn(buildDirectory) else Right(())
            rendezvous.flatMap(_ => prepared(program, buildDirectory, hash, key, arguments))

    /** After a dispatched command ended, however it ended, and before the session's end: the
      * launch's Gradle daemons recorded, so the session's end takes them (RunOnHostGradleDaemons.record).
      * The registry is the launch's, one for every build directory, so the program alone says
      * whether there is anything to observe. */
    def commandEnded(program: Program): Unit =
      synchronized:
        if program == Program.Gradle then
          RunOnHostGradleDaemons.record(session.records, gradleDaemons(session.tmp), processes).foreach(log)

    /** prepare, past the mill rendezvous check: the runtime reused, its server or daemon
      * replaced, or the runtime created. */
    private def prepared(
      program: Program, buildDirectory: Path, hash: String, key: (Program, String), arguments: Seq[String],
    ): Either[String, Option[Runtime]] =
      live.get(key) match
        case Some(current) if lives(proxyRecord(program, hash)) && program == Program.Sbt =>
          // The client attaches to this build directory's own server: reuse only when the
          // portfile names the exact socket sbt derives for it under this session's tmp/,
          // and the record's group still lives. namesOwnDerivedSocket checks the spelling
          // and that neither the socket nor its directory is a symlink, so a portfile
          // copied from — or a socket directory redirected to — another warm build
          // directory does not send this client to that server. Otherwise the server is
          // gone or the portfile no longer names it, and a fresh one starts under the same
          // proxy (startServer sweeps first).
          val serverLives = lives(serverRecord(hash))
          if serverLives && namesDerivedSocket(buildDirectory, session.tmp) then Right(Some(current.runtime))
          else
            val why = if serverLives then "the portfile no longer names its server" else "its server is gone"
            discard(program, hash, serverRecord(hash)).flatMap: what =>
              log(s"retired ${serverRecord(hash).getFileName}, $why: $what")
              foreignRuntime(program, buildDirectory, hash).flatMap:
                case Some(shared) => Right(Some(shared))
                case None         => startServer(current, arguments).map(_ => Some(current.runtime))
        case Some(current) if lives(proxyRecord(program, hash)) && program == Program.Gradle =>
          // The runtime is the proxy: Gradle's client matches a daemon in the launch's registry
          // or starts one, inside the profile, and commandEnded records it.
          Right(Some(current.runtime))
        case Some(current) if lives(proxyRecord(program, hash)) =>
          // The client is confined to the daemon's port: reuse only the daemon proved at its
          // start, alive with its start time, under the configuration it was started from.
          // Gone — its idle exit, `shutdown`, or the cancel that ends it as stock Mill does —
          // or under a changed configuration, a fresh one starts under the same proxy, from a
          // fresh assembly: a changed version pin grants another launcher, and the assembly
          // is what grants it. The exit file of its starter is no liveness, since the starter
          // is ended, or exits, by design once the daemon is up.
          daemonConfig(buildDirectory).flatMap: config =>
            val same = config == current.daemonConfig
            if same && current.daemon.exists(daemonLives) then Right(Some(current.runtime))
            else
              val why = if same then "its daemon is gone" else "its configuration changed"
              discard(program, hash, daemonRecord(hash)).flatMap: what =>
                log(s"retired ${daemonRecord(hash).getFileName}, $why: $what")
                foreignRuntime(program, buildDirectory, hash).flatMap:
                  case Some(shared) => Right(Some(shared))
                  case None =>
                    for
                      fresh <- assemble(project, program, buildDirectory)
                      started <- startDaemon(current.copy(assembled = fresh), config)
                    yield
                      live += key -> started
                      Some(started.runtime)
        case Some(current) =>
          // The proxy is gone: replace the whole runtime for this key, its records and build
          // file deleted. Forgotten only once discarded: a retirement that throws, or leaves a
          // group alive behind its record, is retried.
          discardRuntime(program, hash, current.runtime.proxyLog).flatMap: what =>
            log(s"retired the ${program.name} runtime for $buildDirectory, its proxy is gone: $what")
            live -= key
            create(program, buildDirectory, hash, arguments)
        case None =>
          create(program, buildDirectory, hash, arguments)

    /** The runtime for a key this launch holds none for: another launch's, attached to, or this
      * launch's own, created. */
    private def create(
      program: Program, buildDirectory: Path, hash: String, arguments: Seq[String],
    ): Either[String, Option[Runtime]] =
      foreignRuntime(program, buildDirectory, hash).flatMap:
        case Some(shared) => Right(Some(shared))
        case None         => created(program, buildDirectory, hash, arguments)

    private def created(
      program: Program, buildDirectory: Path, hash: String, arguments: Seq[String],
    ): Either[String, Option[Runtime]] =
      val name = s"proxy-${program.name}-$hash"
      val proxyLog = session.directory.resolve(s"$name.log")
      // An exception after a spawn registered is a failed start like any other.
      val started =
        try
          for
            _ <- RunOnHostSession.publishBuildFile(session.directory, hash, buildDirectory)
            assembled <- assemble(project, program, buildDirectory)
            hosts <- readProgramRules(project, program)
            // A record a failed creation kept: discarded, or the spawn that would rename over it refused.
            _ <- discard(program, hash, proxyRecord(program, hash))
            port <- proxy(program, hosts, proxyRecord(program, hash), proxyLog)
            made = Live(buildDirectory, hash, assembled, Runtime(session.directory, port, proxyLog), hosts)
            current <- program match
              case Program.Sbt                  => startServer(made, arguments).map(_ => made)
              case Program.Mill                 => daemonConfig(buildDirectory).flatMap(startDaemon(made, _))
              case Program.Gradle | Program.Mvn => Right(made)
          yield current
        catch case NonFatal(ex) => Left(s"creating the runtime: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
      started match
        case Right(current) =>
          live += (program, hash) -> current
          log(s"created $name for $buildDirectory, port ${current.runtime.proxyPort}" +
            current.daemon.map(d => s", daemon ${d.pid} on port ${d.port}").getOrElse(""))
          Right(Some(current.runtime))
        case Left(reason) =>
          // A spawn that registered and never reported ready: left alone, its group would
          // outlive the record the next attempt's spawn renames over, and its late ready line
          // would be read as that attempt's.
          Left(discardRuntime(program, hash, proxyLog).fold(kept => s"$reason; $kept", _ => reason))

    /** The server of a runtime whose proxy is up, no other launch owning the build directory's
      * server (foreignRuntime, decided by every caller first), once no foreign server holds its
      * portfile; up, it is described for other launches (publishDescriptor). A start that fails,
      * by refusal or exception, leaves no group behind its record. A record an earlier failure
      * kept is discarded first, or refuses the start while its group lives: the spawn would
      * rename over it. */
    private def startServer(current: Live, arguments: Seq[String]): Either[String, Unit] =
      val record = serverRecord(current.hash)
      val started =
        try
          discard(Program.Sbt, current.hash, record).flatMap(_ => noForeignServer(current)).flatMap: _ =>
            // After any foreign server is gone, not before: shutdownForeignServer waits for the
            // user's build to finish, and sweeping its `target/` links mid-build would corrupt
            // it. Before the spawn: our server fails loading on a link into a denied store.
            sweepTargetLinks(current.assembled)
            server(ServerStart(
              current.assembled, current.buildDirectory, current.hash, arguments, record, current.runtime,
            ))
          .flatMap(_ => publishDescriptor(Program.Sbt, current, record, SeatbeltProfile.Network.ProxyOnly, None, None))
        catch case NonFatal(ex) => Left(s"starting the sbt server: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
      started.left.map: reason =>
        discard(Program.Sbt, current.hash, record).fold(kept => s"$reason; $kept", _ => reason)

    /** The daemon of a runtime whose proxy is up, no other launch owning the build directory's
      * daemon (foreignRuntime, decided by every caller first): the start itself ends a daemon of
      * the user's own, by proof and once idle (RunOnHostMillDaemons.start); up, it is described for other
      * launches (publishDescriptor). A start that fails, by refusal or exception, leaves no group
      * behind its record; a record an earlier failure kept is discarded first, as startServer
      * does. */
    private def startDaemon(current: Live, config: String): Either[String, Live] =
      val record = daemonRecord(current.hash)
      val started =
        try
          discard(Program.Mill, current.hash, record).flatMap: _ =>
            daemon(DaemonStart(current.assembled, current.buildDirectory, current.hash, record, current.runtime))
          .flatMap: found =>
            publishDescriptor(
              Program.Mill, current, record, SeatbeltProfile.Network.MillDaemon, Some(found), Some(config),
            ).map(_ => found)
        catch case NonFatal(ex) => Left(s"starting the mill daemon: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
      started match
        case Right(found) =>
          Right(current.copy(
            runtime = current.runtime.copy(daemonPort = Some(found.port)), daemon = Some(found), daemonConfig = config,
          ))
        case Left(reason) =>
          Left(discard(Program.Mill, current.hash, record).fold(kept => s"$reason; $kept", _ => reason))

    /** The runtime's descriptor, published once its server or daemon is up, for another launch
      * to attach by (RunOnHostRuntimeDescriptor): the fingerprint of this start, and the proxy's and the
      * server's or daemon's records as they now read. A descriptor that cannot be published is a
      * failed start, discarded by the caller. */
    private def publishDescriptor(
      program: Program, current: Live, record: Path, network: SeatbeltProfile.Network,
      daemon: Option[RunOnHostMillDaemons.Daemon], daemonConfig: Option[String],
    ): Either[String, Unit] =
      def read(file: Path): Either[String, RunOnHostSession.Record] =
        (try RunOnHostSession.parseRecord(Files.readString(file, UTF_8)) catch case _: IOException => None)
          .toRight(s"${file.getFileName} does not parse as a record")
      for
        proxy <- read(proxyRecord(program, current.hash))
        group <- read(record)
        inputs = runtimeInputs(
          current.assembled, session.tmp, current.runtime.proxyPort, systemPaths, forwards, network,
        )
        _ <- RunOnHostRuntimeDescriptor.publish(
          RunOnHostRuntimeDescriptor.file(session.directory, program, current.hash),
          RunOnHostRuntimeDescriptor(
            RunOnHostRuntimeDescriptor.fingerprint(inputs, egressRuleText(program, current.hosts)),
            current.runtime.proxyPort, proxy, group, daemon, daemonConfig.map(RunOnHostRuntimeDescriptor.digest),
          ),
        )
      yield ()

    private def daemonLives(found: RunOnHostMillDaemons.Daemon): Boolean =
      processes.startOf(found.pid).contains(found.start)

    private def daemonConfig(buildDirectory: Path): Either[String, String] =
      try Right(millDaemonConfig(buildDirectory, readLines))
      catch case ex: Unreadable => Left(wording(ex.refusal))

    /** The links a tree the user's own sbt built leaves under `target/` (cleanForeignTargetLinks),
      * which our server would fail loading on. Run only when a server starts, after any foreign
      * server for the directory is shut down. */
    private def sweepTargetLinks(assembled: Assembled): Unit =
      val project = assembled.prereqs.project
      val swept = cleanForeignTargetLinks(project, project +: assembled.sbtCachesGranted)
      if swept.nonEmpty then
        log(s"removed ${swept.size} target/ links resolving outside the command's roots (first: ${swept.head})")

    /**
     * No server but this broker's may hold the build directory's portfile when its own starts
     * (SECURITY.md "Run on host", one server per build directory), another launch's ownership
     * decided before this (foreignRuntime): another launch's is attached to, or ended by its
     * record, never through the portfile. Beyond that:
     *
     *  - This launch's own derived socket, live but proved by no record, is a server it left
     *    unaccounted; refused, to be ended by hand — starting a second on the same socket would
     *    fail at the bind.
     *  - Any other live portfile socket is the user's own server, ended by protocol at the
     *    socket sbt derives (shutdownForeignServer); the portfile's own spelling is never
     *    connected to. A stale or planted portfile naming some other socket, and a missing
     *    portfile, authorize a start — which writes this directory's own portfile — only once the
     *    ownership check has passed.
     */
    private def noForeignServer(current: Live): Either[String, Unit] =
      val derived = expectedServerSocket(session.tmp, current.buildDirectory)
      livePortfileServer(current.buildDirectory) match
        case Some(socket) if namesDerivedSocket(current.buildDirectory, session.tmp) =>
          Left(
            s"a live sbt server holds the portfile of ${current.buildDirectory} at its own derived socket " +
              s"$socket, which no record of this launch proves; end it by hand and retry",
          )
        case Some(socket) if socket == derived || RunOnHostSession.containedSocket(socket, session.tmp).isDefined =>
          Right(()) // a stale or planted/redirected portfile under this launch; our start overwrites it
        case Some(socket) =>
          // The profile's own persistent writable set, so a socket an earlier command planted
          // in a cache is no more a shutdown target than one planted in the project.
          shutdownForeignServer(
            project, current.buildDirectory, socket, env, log,
            runOnHostCaches = Seq(current.assembled.prereqs.coursierV1) ++ current.assembled.sbtCachesGranted,
          )
        case None => Right(())

    /**
     * Another launch's runtime for the build directory, attached to, or None once no other launch
     * owns one — none did, or this launch took it over: asked wherever this launch is about to
     * start a server or daemon — a fresh runtime, or the replacement under its own live proxy —
     * since the owner's is the one runtime the directory may have. Another launch owns the
     * directory's sbt server or mill daemon when its session — live under the root, or in
     * `condemned/` while its teardown or the scavenger is still collecting it — has a
     * `server-sbt-<hash>` or `daemon-mill-<hash>` record whose group is not proved gone
     * (`runtimeOwner`). The record is the ownership, not `build-<hash>`, so a launch that ran only
     * Mill in the directory — which publishes `build-<hash>` but no sbt server — reserves nothing.
     * The condemned scan keeps the claim through the owner's teardown, when its socket path has
     * moved with the rename and a missing portfile would otherwise read as free. A dead owner is
     * collected by `scavenge` (run first in prepare) before this check, so what remains is a
     * launch still running, or one that died since. Its runtime is attached to when this launch
     * would start the same (`attached`), and ended otherwise (`takeOver`), for this launch's own
     * to start in its place. Gradle's and Maven's runtimes are the launch's own and another launch
     * reads nothing of them.
     */
    private def foreignRuntime(program: Program, buildDirectory: Path, hash: String): Either[String, Option[Runtime]] =
      val owner = program match
        case Program.Sbt                  => runtimeOwner(serverRecordName(hash))
        case Program.Mill                 => runtimeOwner(daemonRecordName(hash))
        case Program.Gradle | Program.Mvn => None
      owner match
        case Some(other) =>
          attached(program, buildDirectory, hash, other).flatMap:
            case Attachment.Attached(runtime) =>
              log(s"attached to ${other.getFileName}'s ${program.name} runtime for $buildDirectory")
              Right(Some(runtime))
            case Attachment.Unattachable(why) =>
              takeOver(program, buildDirectory, hash, other, why).map(_ => None)
        case None => Right(None)

    /** What another launch's runtime is to this launch's command: run against, or not, for the
      * reason a takeover names. */
    private enum Attachment:
      case Attached(runtime: Runtime)
      case Unattachable(why: String)

    /**
     * The runtime `owner`, another launch's broker session, holds for the build directory, for
     * this launch's command to run against, or why it cannot; Left is this launch's own failure
     * to assemble what it would start. Attached to when the server or daemon this launch would
     * start has the running one's confinement and environment
     * (RunOnHostRuntimeDescriptor.fingerprint has what that covers and leaves out): the owner is
     * live — locked under the root; one ending or dead is never attached to — its descriptor
     * (RunOnHostRuntimeDescriptor) carries the fingerprint of this launch's own would-be start,
     * derived with the owner's `tmp/` and proxy port and the rule file as read now, and is bound
     * to the owner's present records, whose proxy spawn lives; for sbt the server spawn lives and
     * the portfile names the socket derived under the owner's `tmp/`, unredirected; for mill the
     * daemon bears its start time and its configuration is the build directory's now —
     * `spawnLives` is no liveness for a mill runtime, whose starter has exited by design. The
     * command then runs against the owner's session, proxy and daemon port, exactly as the
     * owner's own commands do (`Runtime`), and this launch records and keeps nothing of it: the
     * next command asks again. What the sharer gives up (run-on-host.md "The channel and the
     * command"): a cancel is the program's own, the server not being this launch's to retire; the
     * owner's end takes the runtime, a build of this launch included; and this launch's audit
     * lines land in the owner's proxy log.
     */
    private def attached(
      program: Program, buildDirectory: Path, hash: String, owner: Path,
    ): Either[String, Attachment] =
      val (network, groupRecord) = program match
        case Program.Mill => (SeatbeltProfile.Network.MillDaemon, daemonRecordName(hash))
        case _            => (SeatbeltProfile.Network.ProxyOnly, serverRecordName(hash))
      val ownerRecords = owner.resolve(RunOnHostSession.RecordsDir)
      def record(name: String): Option[RunOnHostSession.Record] =
        try RunOnHostSession.parseRecord(Files.readString(ownerRecords.resolve(name), UTF_8))
        catch case _: IOException => None
      val ownerTmp = owner.resolve(RunOnHostSession.TmpDir)
      val proxyName = s"proxy-${program.name}-$hash"
      if !RunOnHostSession.liveBrokerSessions(root, session.directory).contains(owner) then
        Right(Attachment.Unattachable("that launch is ending, or gone and not yet collected"))
      else
        RunOnHostRuntimeDescriptor.read(RunOnHostRuntimeDescriptor.file(owner, program, hash)) match
          case None => Right(Attachment.Unattachable("no runtime descriptor this launcher reads is published for it"))
          case Some(descriptor) =>
            for
              assembled <- assemble(project, program, buildDirectory)
              hosts <- readProgramRules(project, program)
              config <- if program == Program.Mill then daemonConfig(buildDirectory).map(Some(_)) else Right(None)
            yield
              val inputs = runtimeInputs(assembled, ownerTmp, descriptor.proxyPort, systemPaths, forwards, network)
              val own = RunOnHostRuntimeDescriptor.fingerprint(inputs, egressRuleText(program, hosts))
              val checked =
                for
                  _ <-
                    if descriptor.fingerprint == own then Right(())
                    else Left("its profile, environment or rule lines differ from what this launch would start")
                  _ <-
                    if record(proxyName).contains(descriptor.proxy) && record(groupRecord).contains(descriptor.group)
                    then Right(())
                    else Left("its descriptor names records other than the present ones")
                  _ <- if lives(ownerRecords.resolve(proxyName)) then Right(()) else Left("its proxy is gone")
                  _ <- config match
                    case Some(present) =>
                      if !descriptor.daemon.exists(daemonLives) then Left("its daemon is gone")
                      else if !descriptor.daemonConfig.contains(RunOnHostRuntimeDescriptor.digest(present)) then
                        Left("its daemon's configuration is not the build directory's")
                      else Right(())
                    case None =>
                      if !lives(ownerRecords.resolve(groupRecord)) then Left("its server is gone")
                      else if !namesDerivedSocket(buildDirectory, ownerTmp) then
                        Left("the portfile does not name its server's socket, or the socket is redirected")
                      else Right(())
                yield Runtime(
                  owner, descriptor.proxyPort, owner.resolve(s"$proxyName.log"), descriptor.daemon.map(_.port),
                )
              checked.fold(Attachment.Unattachable(_), Attachment.Attached(_))

    /**
     * The runtime `owner` holds for the build directory ended, for this launch's own to start in
     * its place — `why` is what kept this launch from attaching — or the refusal when its group is
     * not proved ended. One more holder of the record's retirement lock
     * (RunOnHostSession.retirementLockFile): under the build lock its command holds, the group
     * is ended by `endRecordedGroup`'s own proof — the record read only under the lock, the
     * leader's pid bearing the recorded start time, the signal to the pgid — and the record is
     * left to its owner, whose next command finds the group dead, replaces the runtime under its
     * own proxy, and decides here again: attach to this launch's, or take it over. Two launches
     * whose runtimes differ alternate restarts, the cost of the difference. The owner's proxy is
     * left running: the owner replaces the server or daemon under it. Nothing is connected to and no
     * portfile is read: the record is the attribution, per program and build directory by
     * construction, so neither a planted portfile nor a link under the owner's `tmp/` can send
     * this launch to another directory's server; the start that follows treats the portfile as
     * any start does (noForeignServer). An owner tearing itself down holds the lock through its
     * own end of the group, so the wait on the lock — bounded by `RetirementDeadlineMillis` — is
     * the wait for it; between the owner's lookup and this read its session can move into
     * `condemned/` (RunOnHostSession.runtimeOwner has the rename), so a record gone from where
     * it was looked up is looked up once more, and one gone from both is a finished teardown,
     * whose group ended before the record was deleted. A group listed after its KILL, or
     * leaderless, keeps the record and admission blocked, as it does under `discard`.
     */
    private def takeOver(
      program: Program, buildDirectory: Path, hash: String, owner: Path, why: String,
    ): Either[String, Unit] =
      val (what, name) = program match
        case Program.Mill => ("mill daemon", daemonRecordName(hash))
        case _            => ("sbt server", serverRecordName(hash))
      def end(ownerNow: Path): Option[RunOnHostSession.Collected] =
        RunOnHostSession.endRecordedGroup(root, ownerNow.resolve(RunOnHostSession.RecordsDir).resolve(name), processes)
      val outcome = end(owner).orElse(runtimeOwner(name).flatMap(end))
      outcome match
        case Some(kept) if kept.keeps =>
          Left(
            s"another launch's broker (${owner.getFileName}) owns the $what for $buildDirectory; this launch " +
              s"cannot attach to it — $why — and its group is not ended: $kept; retry, or use a different build " +
              "directory",
          )
        case _ =>
          log(
            s"took over ${owner.getFileName}'s $what for $buildDirectory, which this launch cannot attach to " +
              s"($why): ${outcome.map(_.toString).getOrElse("no record")}",
          )
          Right(())

    /** The session of another launch that holds the ownership record `record`, or None
      * (RunOnHostSession.runtimeOwner: live sessions, then condemned, race-safe across the
      * teardown rename, a record whose group is dead ignored). Read here; signalled only by
      * `takeOver`, under the retirement lock. */
    private def runtimeOwner(record: String): Option[Path] =
      RunOnHostSession.runtimeOwner(root, session.directory, record, processes)

    /** Whether `buildDirectory`'s portfile names the server a launch whose session `tmp/` is `tmp`
      * runs for it: the exact socket sbt derives under that `tmp/`, connectable, with neither the
      * socket entry nor its parent a symlink. The symlink checks matter because the server
      * profile grants the build write across `tmp/`: without them, moving the socket directory
      * aside and linking it to another warm directory's would redirect this client while the
      * spelling stayed the same. */
    private def namesDerivedSocket(buildDirectory: Path, tmp: Path): Boolean =
      val derived = expectedServerSocket(tmp, buildDirectory)
      livePortfileServer(buildDirectory).contains(derived)
        && !Files.isSymbolicLink(derived) && !Files.isSymbolicLink(derived.getParent)

    private def lives(record: Path): Boolean = RunOnHostSession.spawnLives(record, processes)

    /** End what the runtime's records prove — the server or daemon, then the proxy — and delete
      * them with the proxy log, since a successor of the same name would read this proxy's ready
      * line as its own, and the build file last, once no record of the hash remains: another
      * program's runtime for the same directory still publishes under it. Answers what became
      * of the groups. */
    /** The runtime's records discarded, server or daemon first, then the proxy; Left, with the
      * proxy's group still ended, when a group outlives its KILL (`discard`). */
    private def discardRuntime(program: Program, hash: String, proxyLog: Path): Either[String, String] =
      val attached = program match
        case Program.Sbt  => Some(discard(program, hash, serverRecord(hash)).map(what => s"server $what"))
        case Program.Mill => Some(discard(program, hash, daemonRecord(hash)).map(what => s"daemon $what"))
        case _            => None
      val proxy = discard(program, hash, proxyRecord(program, hash)).map(what => s"proxy $what")
      try
        Files.deleteIfExists(proxyLog)
        Files.deleteIfExists(proxyProfileFile(proxyLog))
        Files.deleteIfExists(session.directory.resolve(s"${serverRecordName(hash)}.sb"))
        Files.deleteIfExists(session.directory.resolve(s"${daemonRecordName(hash)}.sb"))
        val recordsOfHash =
          Program.values.map(proxyRecord(_, hash)) ++ Seq(serverRecord(hash), daemonRecord(hash))
        if !recordsOfHash.exists(Files.exists(_)) then
          Files.deleteIfExists(RunOnHostSession.buildFile(session.directory, hash))
      catch case ex: IOException => log(s"discarding the runtime for hash $hash: ${ex.getMessage}")
      val outcomes = attached.toSeq :+ proxy
      outcomes.collectFirst { case Left(kept) => kept }
        .toLeft(outcomes.collect { case Right(what) => what }.mkString(", "))

    /** End the group one record of the runtime `program` and `hash` name proves, under its
      * retirement lock, and delete the record and its exit file — unless the group outlives its
      * KILL, or the lock is not free within the bound: then the record stays, and Left says so,
      * for the caller to start nothing whose spawn would rename its record over the kept one.
      * The runtime's descriptor goes first, before any of its groups is ended, so another launch
      * attaches to nothing ending; the start that follows republishes it. */
    private def discard(program: Program, hash: String, record: Path): Either[String, String] =
      try Files.deleteIfExists(RunOnHostRuntimeDescriptor.file(session.directory, program, hash))
      catch
        case ex: IOException =>
          log(s"discarding the ${program.name} runtime descriptor for hash $hash: ${ex.getMessage}")
      val ended = if Files.exists(record) then RunOnHostSession.endRecordedGroup(root, record, processes) else None
      ended match
        case Some(kept) if kept.keeps =>
          Left(s"${record.getFileName} kept for the next start to retry: $kept")
        case _ =>
          try
            Files.deleteIfExists(record)
            Files.deleteIfExists(RunOnHostSession.exitRecord(record))
          catch case ex: IOException => log(s"discarding ${record.getFileName}: ${ex.getMessage}")
          Right(ended.map(_.toString).getOrElse("no record"))

  /** The ownership records of one build directory's server and daemon, by the directory's hash:
    * what another launch's broker reads to attach or take over (RunOnHostSession.runtimeOwner). */
  def serverRecordName(hash: String): String = s"server-sbt-$hash"
  def daemonRecordName(hash: String): String = s"daemon-mill-$hash"

  // The thin client's own classes of launcher flag (NetworkClient.parseArgs, v2.0.9): a value
  // flag takes the next argument or an `=` value; a no-value flag and an `=`-prefixed one are
  // the client's own and reach no server; the empty-build flags are launcher flags even after
  // the first command.
  private val LauncherValueFlags = Set(
    "-mem", "--mem", "-jvm-debug", "--jvm-debug", "-sbt-jar", "--sbt-jar", "-sbt-cache", "--sbt-cache",
    "-sbt-version", "--sbt-version", "-java-home", "--java-home", "-ivy", "--ivy", "-sbt-boot", "--sbt-boot",
    "-sbt-dir", "--sbt-dir",
  )
  private val LauncherNoValueFlags = Set(
    "-client", "--client", "--server", "--jvm-client", "-h", "-help", "--help", "-v", "-verbose", "--verbose",
    "-V", "-version", "--version", "--numeric-version", "--script-version", "-d", "-debug", "--debug",
    "-debug-inc", "--debug-inc", "-batch", "--batch", "--no-hide-jdk-warnings", "-no-colors", "--no-colors",
    "-timings", "--timings", "-traces", "--traces", "-no-share", "--no-share", "-no-global", "--no-global",
    "shutdownall", "-bsp", "--bsp", "bsp", "-no-server", "--no-server",
  )
  private val LauncherEqPrefixes =
    Seq("--supershell=", "-supershell=", "--color=", "-color=", "--autostart=", "-autostart=")
  private val EmptyBuildFlags = Set("-allow-empty", "--allow-empty", "-sbt-create", "--sbt-create")

  /** Flags naming a program to run — the JVM, the launcher jar, the runner script — which the
    * profile's grants decide and no request may: the JDK is the launcher's, the script the
    * validated one, and `sbt.script` is what a server forks later. */
  private val ProgramFlags = Set("-java-home", "--java-home", "-sbt-jar", "--sbt-jar")

  /**
   * The server command line as sbt's thin client issues it when it starts a server
   * (NetworkClient.serverCommand, v1.13.0 and v2.0.9): the request's launcher flags as the client
   * classifies them — its `-D` properties, its value flags with their values, the empty-build
   * flags wherever they stand, and any other flag the client does not keep for itself — before
   * `--detach-stdio --server`. As the client, it drops `-J`, which the runner applies to the JVM
   * it starts, the client's; the no-value and `=`-form flags of the client's own; and the
   * commands, which the client sends over the socket. Beyond the client it drops the program
   * flags (ProgramFlags). `.sbtopts` and `.jvmopts` the script reads from the build directory as
   * it always does.
   */
  def serverCommand(executable: Path, sbtGlobal: Path, arguments: Seq[String]): Seq[String] =
    val forwarded = Vector.newBuilder[String]
    var commands = false
    var index = 0
    while index < arguments.length do
      val argument = arguments(index)
      val flag = argument.takeWhile(_ != '=')
      if commands then
        if EmptyBuildFlags(argument) then forwarded += argument
      else if argument.startsWith("--sbt-script=") || argument.startsWith("--sbt-launch-jar=") then ()
      else if (argument == "--sbt-script" || argument == "--sbt-launch-jar") && index + 1 < arguments.length then
        index += 1
      else if LauncherValueFlags(argument) then
        if index + 1 < arguments.length then
          if !ProgramFlags(argument) then forwarded ++= Seq(argument, arguments(index + 1))
          index += 1
      else if LauncherValueFlags(flag) && argument.length > flag.length + 1 then
        if !ProgramFlags(flag) then forwarded ++= Seq(flag, argument.drop(flag.length + 1))
      else if LauncherNoValueFlags(argument) || LauncherEqPrefixes.exists(argument.startsWith) then ()
      else if argument.startsWith("-J") || argument.startsWith("-Dsbt.script=") then ()
      else if !argument.startsWith("-") then commands = true
      else forwarded += argument
      index += 1
    sbtCommand(executable, sbtGlobal) ++ Seq(s"-Dsbt.script=$executable") ++
      forwarded.result() ++ Seq("--detach-stdio", "--server")

  /** The socket sbt derives for a build directory's server under this session's `tmp/`: the
    * server runs with `SBT_GLOBAL_SERVER_DIR` set to `tmp/`, so its portfile names
    * `<tmp>/<SHA-1 of the portfile URI>/sock` (sbtServerSocket). The reuse and startup checks
    * compare the portfile against this exact path, not merely "a socket under tmp/", so a
    * portfile copied from another build directory never authorizes reuse or "up". */
  def expectedServerSocket(sessionTmp: Path, buildDirectory: Path): Path =
    val serverDir: String => Option[String] =
      name => Option.when(name == "SBT_GLOBAL_SERVER_DIR")(sessionTmp.toString)
    sbtServerSocket(buildDirectory, serverDir, Path.of("/"))

  /** Where a server's output goes, stdout and stderr: in the session directory, which the profile
    * grants no process, rather than under `tmp/`, where the server could replace the file with a
    * link or a FIFO before the broker opens it for the next server; appendSessionLogs keeps it
    * there with the session's other logs. Appended to across the servers of one build directory. */
  def serverLog(session: Session, hash: String): Path = session.directory.resolve(s"server-sbt-$hash.log")

  /** How long a starting server may make no progress — neither its log nor the proxy
    * log growing, and no portfile — before the start fails. Progress rather than time, because
    * a first start resolves sbt's own dependencies through the proxy; sbt's own client waits
    * with no bound at all (doc/TODO.md, "a bound on a silent host command"). */
  val ServerStartSilenceMillis = 120_000L

  /** The server (run-on-host.md "sbt"): a registered spawn under the server profile, the build
    * directory its working directory, stdin `/dev/null`, stdout and stderr to serverLog, and
    * the closed environment with the broker's `tmp/` as its temporary and socket directory. Up
    * when the build directory's portfile names a connectable socket under that `tmp/`. */
  private def startSbtServer(
    session: Session,
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
    start: ServerStart,
  ): Either[String, Unit] =
    val assembled = start.assembled
    val prereqs = assembled.prereqs
    val output = serverLog(session, start.hash)
    val inputs = runtimeInputs(
      assembled, session.tmp, start.runtime.proxyPort, systemPaths, forwards, SeatbeltProfile.Network.ProxyOnly,
    )
    for
      profile <- SeatbeltProfile.render(inputs.profile)
      spawn <-
        try
          val profileFile = session.directory.resolve(s"server-sbt-${start.hash}.sb")
          Files.writeString(profileFile, profile, UTF_8)
          val builder = ProcessBuilder(
            RunOnHostSession.registeredSpawn(
              start.record,
              Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString)
                ++ serverCommand(prereqs.executable, assembled.sbtGlobal, start.arguments),
            )*,
          )
          builder.directory(start.buildDirectory.toFile)
          builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
          // Both streams: sbt asks on stdout whether to create a build where it finds none, and a
          // refused start names what it said.
          builder.redirectOutput(ProcessBuilder.Redirect.appendTo(output.toFile))
          builder.redirectError(ProcessBuilder.Redirect.appendTo(output.toFile))
          builder.environment.clear()
          builder.environment.putAll(inputs.environment.asJava)
          Right(builder.start())
        catch case ex: IOException => Left(s"starting the sbt server: ${ex.getMessage}")
      _ <- awaitServer(session, start, spawn, output)
    yield ()

  private def awaitServer(session: Session, start: ServerStart, spawn: Process, output: Path): Either[String, Unit] =
    val exit = RunOnHostSession.exitRecord(start.record)
    def said = s"its output:\n${sessionLogTail(output, 4096).getOrElse("(nothing was written)\n")}"
    def sizes = (logLength(output), logLength(start.runtime.proxyLog))
    var last = sizes
    var since = System.nanoTime
    var result: Option[Either[String, Unit]] = None
    while result.isEmpty do
      val spawnEnded = !spawn.isAlive // read before the file: a spawn dying after its rename still answers
      if Files.exists(exit) then
        val status = try Files.readString(exit, UTF_8).trim catch case _: IOException => "?"
        result = Some(Left(s"the sbt server exited ($status) before publishing its portfile; $said"))
      else if spawnEnded then
        result = Some(Left(s"the sbt server's spawn ended (exit ${spawn.exitValue}) without registering it"))
      else
        livePortfileServer(start.buildDirectory) match
          case Some(socket)
              if socket == expectedServerSocket(session.tmp, start.buildDirectory)
                && !Files.isSymbolicLink(socket) && !Files.isSymbolicLink(socket.getParent) =>
            result = Some(Right(()))
          case Some(socket) =>
            result = Some(Left(
              s"a live sbt server holds the portfile of ${start.buildDirectory} at $socket, and it is not the " +
                "unredirected socket this launch's server derives",
            ))
          case None =>
            val now = sizes
            if now != last then
              last = now
              since = System.nanoTime
            else if System.nanoTime - since > ServerStartSilenceMillis * 1_000_000 then
              result = Some(Left(
                s"the sbt server published no portfile, and neither its output nor the proxy log grew, for " +
                  s"${ServerStartSilenceMillis / 1000}s; $said",
              ))
            else Thread.sleep(100)
    result.get

  private def runInSession(
    session: Session,
    assembled: Assembled,
    commandArgs: Seq[String],
    systemPaths: SeatbeltProfile.SystemPaths,
    workingDirectory: Option[Path],
    log: String => Unit,
    forwards: Vector[(String, String)],
    brokerRuntime: Option[Runtime],
  ): Either[String, Int] =
    val program = assembled.prereqs.program
    val buildDirectory = workingDirectory.getOrElse(assembled.prereqs.project)
    for
      runtime <- brokerRuntime.map(Right(_)).getOrElse(
        ownRuntime(session, assembled, buildDirectory, commandArgs, systemPaths, forwards, log),
      )
      // The broker's log has served earlier commands: the report reads what this one adds.
      reportFrom = logLength(runtime.proxyLog)
      (tmp, socketDir) = temporaryDirectories(program, session.tmp, runtime.tmp)
      network <- program match
        case Program.Sbt => Right(SeatbeltProfile.Network.SbtClient(runtime.tmp))
        case Program.Mill =>
          runtime.daemonPort.map(SeatbeltProfile.Network.MillClient(_))
            .toRight("the mill runtime names no daemon port")
        case Program.Gradle => Right(SeatbeltProfile.Network.Gradle)
        case Program.Mvn    => Right(SeatbeltProfile.Network.ProxyOnly)
      profile <- SeatbeltProfile.render(
        SeatbeltProfile.ProfileInputs(
          prereqs = assembled.prereqs,
          sessionTmp = tmp,
          distribution = assembled.distribution,
          sbtGlobal = assembled.sbtGlobalGranted,
          ivyHome = assembled.ivyHomeGranted,
          gradleUserHome = assembled.gradleUserHomeGranted,
          m2Repository = assembled.m2RepositoryGranted,
          proxyPort = runtime.proxyPort,
          systemPaths = systemPaths,
          network = network,
        ),
      )
      exit <- runCommand(session, assembled, profile, runtime, commandArgs, workingDirectory, forwards, tmp, socketDir)
    yield
      // Under the broker the daemons are the broker's to record (BrokerRuntimes.commandEnded).
      if program == Program.Gradle && brokerRuntime.isEmpty then
        val processes = RunOnHostSession.HostProcesses
        val found = RunOnHostGradleDaemons.daemons(runtime.tmp, processes)
        RunOnHostGradleDaemons.record(session.records, found, processes).foreach(log)
      reportDenied(runtime.proxyLog, reportFrom, program, log)
      if exit != 0 then reportUnwritableProxyLog(runtime, log)
      exit

  /** The runtime a command without the broker's runs against: the acceptance test's entry, and Maven under
    * the broker. Created in the command's own session — by the broker's functions for the
    * programs whose runtime the broker holds, and as the command's proxy alone for Maven — and
    * ended with the session. */
  private def ownRuntime(
    session: Session,
    assembled: Assembled,
    buildDirectory: Path,
    commandArgs: Seq[String],
    systemPaths: SeatbeltProfile.SystemPaths,
    forwards: Vector[(String, String)],
    log: String => Unit,
  ): Either[String, Runtime] =
    val program = assembled.prereqs.program
    BrokerRuntimes(session, assembled.prereqs.project, log, systemPaths, forwards)(
      assemble = (_, _, _) => Right(assembled),
    )
      .prepare(program, buildDirectory, commandArgs)
      .flatMap:
        case Some(runtime) => Right(runtime)
        case None =>
          val proxyLog = session.directory.resolve("proxy.log")
          readProgramRules(assembled.prereqs.project, program)
            .flatMap(createProxy(systemPaths)(program, _, session.records.resolve("proxy"), proxyLog))
            .map(Runtime(session.directory, _, proxyLog))

  private[launcher] def logLength(file: Path): Long =
    try Files.size(file)
    catch case _: IOException => 0L

  /**
   * The proxy profile's inputs for this executable (SeatbeltProfile.ProxyInputs): the native
   * image alone, or the JDK and each class-path entry of the jar form — what selfInvocation
   * runs, the executable itself checked first (selfPresent, both forms). Any other entry that
   * does not exist is skipped, as the JVM skips it; a relative or empty one is resolved as
   * selfClassPath spells it. The JDK and class path are parameters for the acceptance test's emitter, which
   * renders the profile from inside sbt's JVM for the java it runs the rows with.
   */
  def proxyInputs(
    systemPaths: SeatbeltProfile.SystemPaths,
    javaHome: String = System.getProperty("java.home"),
    classPath: String = System.getProperty("java.class.path"),
    self: Option[Path] = launchFile,
  ): Either[String, SeatbeltProfile.ProxyInputs] =
    selfPresent(self).flatMap: executable =>
      if isNativeImage then
        executable.toRight("the native image cannot name itself")
          .map(binary => SeatbeltProfile.ProxyInputs(Seq(binary), Seq.empty, systemPaths))
      else
        realPath(Path.of(javaHome)).toRight(s"the JDK $javaHome is not readable").map: jdk =>
          SeatbeltProfile.ProxyInputs(Seq(jdk), selfClassPath(classPath).map(Path.of(_)).flatMap(realPath), systemPaths)

  /** The proxy's profile, beside its log. */
  private def proxyProfileFile(proxyLog: Path): Path =
    proxyLog.resolveSibling(proxyLog.getFileName.toString.stripSuffix(".log") + ".sb")

  /** The proxy under its profile (SeatbeltProfile.renderProxy), beside its log. */
  private def startProxy(
    record: Path, program: Program, fileHosts: Vector[String], proxyLog: Path,
    systemPaths: SeatbeltProfile.SystemPaths,
  ): Either[String, Process] =
    proxyInputs(systemPaths).flatMap(SeatbeltProfile.renderProxy).flatMap: profile =>
      try
        val profileFile = proxyProfileFile(proxyLog)
        Files.writeString(profileFile, profile, UTF_8)
        // The property the command's environment sets (commandEnvironment), on the
        // command line since the proxy's environment is closed: a dual-stack JVM binds
        // ::ffff:127.0.0.1, which the profile's "localhost" class does not cover (measured: the
        // acceptance test's proxy rows).
        val invocation = selfInvocation("--serve-proxy-on-host")
        val command = RunOnHostSession.registeredSpawn(
          record,
          Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString)
            ++ (invocation.head +: "-Djava.net.preferIPv4Stack=true" +: invocation.tail),
        )
        val builder = ProcessBuilder(command*)
        // The JVM asks for its working directory at start (SystemProps), and the profile grants
        // no directory of the starter's; the root it does grant.
        builder.directory(java.io.File("/"))
        // Closed like the command's: the proxy needs its own settings and, to leave through an
        // upstream proxy as the container's copy does, the one selected variable. Nothing else of
        // the launcher's environment has a reader here.
        builder.environment.clear()
        upstreamProxyVariable(name => Option(System.getenv(name))).foreach(builder.environment.put(_, _))
        builder.environment.put("EGRESS_PROFILE", "deny-unless-allowed")
        builder.environment.put("EGRESS_RULE", egressRuleText(program, fileHosts))
        builder.environment.put("EGRESS_BIND", "127.0.0.1:0")
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
        // Its stderr is its log, opened here and inherited: the profile grants no write
        // (serverLog), and what sandbox-exec or the JVM says before the proxy prints anything
        // lands where the ready line is awaited.
        builder.redirectError(ProcessBuilder.Redirect.appendTo(proxyLog.toFile))
        Right(builder.start())
      catch case ex: IOException => Left(s"starting the proxy: ${ex.getMessage}")

  /**
   * Where a command's processes keep temporary files, and where sbt's sockets are: `(tmp,
   * socketDir)`. Under sbt the command's own `tmp/`, and the broker's for the sockets its server
   * listens under. Under mill the broker's `tmp/` for both: the daemon's forked JVMs — a `run`,
   * a test — inherit the daemon's profile, which grants the broker's `tmp/`, but get the client's
   * environment (`RunModule.scala`, `ctx.env`), so a `TMPDIR` or `java.io.tmpdir` naming the
   * command's own `tmp/` would be denied there; and with one directory the starter's environment
   * and every client's are one map, so an option file Mill interpolates from the environment
   * (`MillProcessLauncher.loadMillConfig`) yields the same value in both, and a client never meets
   * a fingerprint mismatch of the wrapper's own making. Under Gradle the broker's too, for the
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
      Seq("/usr/bin/sandbox-exec", "-f", profileFile.toString) ++ programCommand,
    )
    val builder = ProcessBuilder(command*)
    builder.directory(buildDirectory.toFile)
    // Not the wrapper's own stdin, which under the broker is its liveness pipe (runCommandMain).
    builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
    builder.redirectOutput(ProcessBuilder.Redirect.INHERIT)
    builder.redirectError(ProcessBuilder.Redirect.INHERIT)
    builder.environment.clear()
    builder.environment.putAll(
      commandEnvironment(
        name => Option(System.getenv(name)), forwards, prereqs, assembled.sbtGlobal, assembled.ivyHome,
        assembled.gradleUserHome, assembled.m2Repository, assembled.millDownloads, assembled.millLauncherVersion,
        tmp, socketDir, runtime.proxyPort, System.getProperty("user.name"),
      ).asJava,
    )

    // The spawn publishes the command's exit status and then stays as the group's provable leader
    // (RunOnHostSession), so the answer is the exit file, never the spawn's own end.
    try RunOnHostSession.awaitExit(RunOnHostSession.exitRecord(record), builder.start())
    catch case ex: IOException => Left(s"starting the command: ${ex.getMessage}")

  /**
   * The distribution's own `gradle`, not the project's `gradlew` (run-on-host.md "Gradle"), with
   * its settings on the command line, where a `-D` outranks every gradle.properties. The daemon
   * registry is the launch's own, under the broker's `tmp/`, which every Gradle process of the
   * launch is granted and which ends with the launch: `gradle --stop` stops every daemon in the
   * registry, whatever its JVM (`DaemonStopClient`), so a registry under the per-project user
   * home would let one launch's `--stop` end another launch's builds on the project. Attaching
   * is already the launch's own: the client's `java.io.tmpdir`, the broker's `tmp/`, is among the
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

  /** Never the forwarded value. The version overrides: the wrapper resolved the version from the
    * build directory alone and granted that launcher (RunOnHostPrereqs.millVersion,
    * millLauncherVersion), and either would make the bootstrap select another; `MILL_VERSION` is
    * the wrapper's own setting for a mill command, naming that launcher. The output-directory
    * overrides (`OutFiles.java`): the daemon's rendezvous, its port candidate and the foreign
    * daemons are all looked for under `out/`, and Mill sent elsewhere would be checked nowhere. */
  val MillOverrides = Set("MILL_VERSION", "DEFAULT_MILL_VERSION", "MILL_OUTPUT_DIR", "MILL_BSP_OUTPUT_DIR")

  /** The variable the host-served proxy leaves through, as the proxy itself selects it
    * (TransportHelper.UpstreamProxyVariables): uppercase first, an empty value as unset. */
  def upstreamProxyVariable(read: String => Option[String]): Option[(String, String)] =
    agentsandbox.egress.TransportHelper.UpstreamProxyVariables.iterator
      .flatMap(name => read(name).filter(_.nonEmpty).map(name -> _))
      .nextOption()

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
   * the wrapper's own settings, which win. doc/run-on-host.md, "The command's lifetime and environment",
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
    // sbt, the command's own for the other programs.
    socketDir: Path,
    proxyPort: Int,
    userName: String,
  ): Map[String, String] =
    val passed = PassedThrough.flatMap(name => host(name).map(name -> _)).toMap
    // The settings must reach the JVMs the command forks — a forked test or `run` — and such a JVM
    // inherits the environment and nothing else: its options come from the build definition, so
    // SBT_OPTS and JAVA_OPTS, which the sbt script and the mill executable do read, would reach
    // only the program's own JVMs. sbt 2.0.9 also copies JAVA_TOOL_OPTIONS and JDK_JAVA_OPTIONS
    // into argv without unquoting them; _JAVA_OPTIONS reaches HotSpot unchanged. HotSpot applies
    // it after argv, so the wrapper's properties also win over command-line properties.
    // The shim handles the resulting startup banner.
    val javaOptions = (Seq(
      jvmProperty("java.io.tmpdir", sessionTmp.toString),
      jvmProperty("java.util.prefs.userRoot", sessionTmp.toString),
      // ipcsocket extracts its native socket library to sbt.ipcsocket.tmpdir, else
      // $XDG_RUNTIME_DIR, else java.io.tmpdir (org.scalasbt.ipcsocket.NativeLoader). An sbt
      // client's XDG_RUNTIME_DIR is the broker's tmp/, which its profile grants no write or
      // exec, so the load fails there; this points it at the command's own tmp/, always
      // read-write-exec. The rendezvous sockets still go under XDG_RUNTIME_DIR.
      jvmProperty("sbt.ipcsocket.tmpdir", sessionTmp.toString),
      jvmProperty("sbt.global.base", sbtGlobal.toString),
      jvmProperty("sbt.ivy.home", ivyHome.toString),
      jvmProperty("maven.repo.local", m2Repository.toString),
      // Maven's resolver ignores the JVM proxy properties unless told (run-on-host.md "Maven").
      "-Daether.connector.http.useSystemProperties=true",
      "-Dhttps.proxyHost=127.0.0.1", s"-Dhttps.proxyPort=$proxyPort",
      "-Dhttp.proxyHost=127.0.0.1", s"-Dhttp.proxyPort=$proxyPort",
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
      commandProxyVariables(proxyPort)
    passed ++ (forwards.toMap -- MillOverrides) ++ own

  /**
   * The proxy variables the command's environment gets, both spellings, as the sandbox container
   * gets its own: the command's proxy for the programs that read the environment rather than the JVM
   * properties, loopback exempt so a test server on it is reached directly. The rest of the
   * family — ALL_PROXY, FTP_PROXY — requires explicit forwarding. The launcher's own HTTPS_PROXY is absent: that
   * one names an upstream proxy the confinement refuses, with a credential the command has no
   * business reading.
   */
  def commandProxyVariables(proxyPort: Int): Map[String, String] =
    val proxy = s"http://127.0.0.1:$proxyPort"
    Map(
      "HTTPS_PROXY" -> proxy, "https_proxy" -> proxy, "HTTP_PROXY" -> proxy, "http_proxy" -> proxy,
      "NO_PROXY" -> "localhost,127.0.0.1", "no_proxy" -> "localhost,127.0.0.1",
    )

  /**
   * The cost of switching where a build runs, paid before each sbt server starts or is reused
   * (BrokerRuntimes.sweepTargetLinks). sbt 2 leaves `target/` outputs as
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
    val roots = granted.flatMap(root => try Some(root.toRealPath()) catch case _: IOException => None)
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
        else if Files.isDirectory(entry) && name != ".git" && name != ".ko-agent-sandbox" then
          walk(entry, inTarget || name == "target")
    walk(project, inTarget = false)
    removed.result()

  /** The hosts the proxy refused, from its audit log's `deny <host> CONNECT` lines at byte
    * offset `from` and after. */
  def deniedHosts(proxyLog: Path, from: Long = 0): Vector[String] =
    val Deny = raw""".*\bdeny (\S+) CONNECT.*""".r
    if !Files.exists(proxyLog) then Vector.empty
    else
      val bytes = Files.readAllBytes(proxyLog)
      String(bytes, math.min(from, bytes.length).toInt, bytes.length - math.min(from, bytes.length).toInt, UTF_8)
        .linesIterator.collect { case Deny(host) => host }.toVector.distinct

  /**
   * The reason the proxy on `port` serves nothing, when a write to its log failed: the `details`
   * of its Proxy-Status field (HTTPHelper.proxyStatus). Asked of the proxy, since the log that
   * would say so is what failed, and the programs need not print it (run-on-host.md has what
   * sbt and mill print). `OPTIONS *` is HTTP's request about the server itself, and no
   * CONNECT: a proxy still logging answers 400 and logs `deny - -`, which deniedHosts does not
   * read as a refused host. `Max-Forwards: 0` is for a recipient that is not this proxy, should
   * the proxy have died and another program taken its port: an HTTP proxy there must answer
   * itself, not forward (RFC 9110, 7.6.2). This proxy forwards no OPTIONS and does not read it.
   */
  def unwritableProxyLog(port: Int): Option[String] =
    try
      scala.util.Using.resource(java.net.Socket()): socket =>
        socket.connect(java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress, port), 2_000)
        socket.setSoTimeout(2_000)
        socket.getOutputStream.write("OPTIONS * HTTP/1.1\r\nHost: localhost\r\nMax-Forwards: 0\r\n\r\n".getBytes(UTF_8))
        socket.getOutputStream.flush()
        val Details = raw"""(?i)Proxy-Status:.*; details="((?:[^"\\]|\\.)*)".*""".r
        String(socket.getInputStream.readNBytes(4096), UTF_8).linesIterator.takeWhile(_.nonEmpty)
          .collectFirst { case Details(details) => details.replaceAll(raw"\\(.)", "$1") }
          .filter(_.startsWith(agentsandbox.egress.AgentEgressProxy.AuditLogUnwritable))
    catch case _: IOException => None

  private def reportUnwritableProxyLog(runtime: Runtime, log: String => Unit): Unit =
    unwritableProxyLog(runtime.proxyPort).foreach: reason =>
      log(
        s"The host command sandbox's proxy serves no new connection: $reason.\n" +
          s"Tell the user: make ${runtime.proxyLog} writable again, then relaunch.",
      )

  /** The denied-host report, once per refused host, after the command — never an automatic addition. */
  private def reportDenied(proxyLog: Path, from: Long, program: Program, log: String => Unit): Unit =
    val hosts = deniedHosts(proxyLog, from)
    if hosts.nonEmpty then
      log((("Command requested network access to:" +: hosts.map(host => s"  $host")) :+
        ("Not permitted by the host command sandbox. If the command should reach it, add an" +
          s" `$ProgramRuleForm` line to .ko-agent-sandbox/run-on-host/${program.name}/egress/rule."))
        .mkString("\n"))
