// What the Scala CLI drivers that run on the host share: the BPF backend's suites
// (ko-agent-fs/bpf/test/podman/), the run-on-host checks (src/test/run-on-host/) and the run-on-host probes
// (src/probe/). Each driver pulls this file in with `//> using file`. Scala CLI does not follow a `using file` from a
// file that was itself pulled in, so each driver names this file itself. sbt compiles this file with the tests, which
// keeps it compiling without a driver run.
//
// It holds:
//
// - the transcript, to which every row is printed and appended;
// - running a command on the host, recorded in the transcript or not;
// - finding a program on PATH and listing a directory;
// - polling for a state with a bound;
// - the refusals before a run, and the run's exit status.

package agentsandbox.launcher

import scala.jdk.CollectionConverters.*
import scala.util.Using

import java.lang.ProcessBuilder.Redirect
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardOpenOption}
import java.util.concurrent.TimeUnit

object HostDriver:

  extension (path: Path)
    def /(child: String): Path = path.resolve(child)
    def /(child: Path): Path = path.resolve(child)

  def workingDir: Path = Path.of("").toAbsolutePath

  /** The value, or else the message on stderr and exit status 2: a refusal before the transcript exists. */
  def orExit[A](either: Either[String, A]): A = either match
    case Right(value) => value
    case Left(message) =>
      System.err.println(message)
      sys.exit(2)

  /** The working directory, when it holds every path given. Scala CLI gives a script no path of its own,
    * so a driver runs from the repository root and refuses to run elsewhere. */
  def repositoryRoot(required: String*): Either[String, Path] =
    val root = workingDir
    Either.cond(required.forall(path => Files.exists(root.resolve(path))), root,
      s"$root is not the repository root; run this from it")

  /** Prints every line and appends it to the file, and counts the PASS, FAIL and SKIP rows. It also gives the
    * two ways a driver's step ends early, as `Either` for the chain of steps: `refuse` says why and gives
    * exit status 2 before any row is measured; `gate` records a FAIL and gives 1.
    *
    * Rows measured on several threads each go to a `part`: a transcript of its own file that shares this one's
    * counts, and whose lines on the console carry the part's prefix. With `timestamps`, every logged line starts with
    * the time, HH:mm:ss, so that the gap between two lines shows what took the time; a command's recorded output
    * does not. */
  class Transcript(val path: Path, prefix: String = "",
      counts: java.util.concurrent.atomic.AtomicIntegerArray = java.util.concurrent.atomic.AtomicIntegerArray(3),
      timestamps: Boolean = false):
    def passed: Int = counts.get(0)
    def failed: Int = counts.get(1)
    def skipped: Int = counts.get(2)
    Files.writeString(path, "")
    def part(partPath: Path, partPrefix: String): Transcript =
      Transcript(partPath, s"[$partPrefix] ", counts, timestamps)
    def record(text: String): Unit =
      Files.writeString(path, text.stripLineEnd + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND)
    def log(text: String): Unit =
      val time = if timestamps && text.nonEmpty then java.time.LocalTime.now.withNano(0).toString + " " else ""
      Transcript.console.synchronized(println(if text.isEmpty then text else time + prefix + text))
      record(time + text)
    def info(text: String): Unit = log("INFO " + text)
    def pass(text: String): Unit =
      counts.incrementAndGet(0)
      log("PASS " + text)
    def fail(text: String): Unit =
      counts.incrementAndGet(1)
      log("FAIL " + text)
    /** A row that this run could not measure, with the reason in `text`. */
    def skip(text: String): Unit =
      counts.incrementAndGet(2)
      log("SKIP " + text)
    def check(description: String, ok: Boolean): Boolean =
      if ok then pass(description) else fail(description)
      ok
    def step(text: String): Unit =
      log("")
      log("== " + text)
    def indent(text: String): Unit = text.linesIterator.filter(_.nonEmpty).foreach(line => log("  " + line))
    def refuse(ok: Boolean, message: String): Either[Int, Unit] =
      if ok then Right(())
      else
        log(message)
        Left(2)
    def gate(description: String, ok: Boolean): Either[Int, Unit] = Either.cond(check(description, ok), (), 1)

  object Transcript:
    /** The lock that keeps the parts' console lines whole. */
    private val console = Object()

  /** Runs the measurement and exits with its status. The cleanup runs however the run ends: by the `Using` block, or
    * by the shutdown hook on a signal. The cleanup must therefore be idempotent. An exception counts as a FAIL row and
    * gives status 2. */
  def runMeasured(transcript: Transcript, cleanup: AutoCloseable)(measure: => Int): Nothing =
    Runtime.getRuntime.addShutdownHook(Thread(() => cleanup.close()))
    val status = Using.resource(cleanup): _ =>
      try measure
      catch
        case ex: Exception =>
          transcript.fail(s"the driver failed: ${ex.getMessage}")
          2
    sys.exit(status)

  /** What a command printed, both streams merged, and its exit status. */
  case class Output(status: Int, text: String):
    def ok: Boolean = status == 0
    def has(needle: String): Boolean = text.contains(needle)

  /** A command on the host. Its output is recorded unless it is polled; both streams are merged, and
    * stdin is closed unless inherited. With `timeoutSeconds`, a command still running at the timeout is
    * killed and answers status -1. `environment` is added to the driver's own, or replaces it when
    * `inheritEnvironment` is false. */
  def host(transcript: Transcript, command: Seq[String], cwd: Path = workingDir, inheritStdin: Boolean = false,
      record: Boolean = true, timeoutSeconds: Option[Int] = None, environment: Map[String, String] = Map.empty,
      inheritEnvironment: Boolean = true): Output =
    val output = run(command, cwd, inheritStdin, timeoutSeconds, environment, inheritEnvironment)
    if record then transcript.record(output.text)
    output

  /** A host command's process builder, for a caller that starts the process itself. On Windows, the child finds
    * Windows OpenSSH first on PATH, as under `run`. */
  def hostProcess(command: Seq[String]): ProcessBuilder = preferringWindowsOpenSsh(ProcessBuilder(command*))

  private def preferringWindowsOpenSsh(builder: ProcessBuilder): ProcessBuilder =
    if scala.util.Properties.isWin then windowsOpenSsh.foreach(preferOnPath(builder.environment, _))
    builder

  /** Windows OpenSSH's directory, when it holds `ssh.exe`. A driver's `podman machine ssh` must find that `ssh` first:
    * Git's MSYS `ssh` writes the host keys meant for `NUL` into a file `NUL` in the driver's working directory
    * (doc/design-win.md, "Every process the launcher starts finds Windows OpenSSH first"). This file depends on the
    * JDK alone, so it copies HostCommands.hostProcess rather than calling it. */
  private lazy val windowsOpenSsh: Option[Path] =
    Option(System.getenv("SystemRoot")).map(Path.of(_, "System32", "OpenSSH"))
      .filter(directory => Files.isExecutable(directory / "ssh.exe"))

  /** Puts `directory` first on the child's Windows PATH, under the name the PATH already has: the map compares names
    * with case, so a put under another spelling would add a second PATH (HostCommands.preferOnPath). */
  private def preferOnPath(environment: java.util.Map[String, String], directory: Path): Unit =
    val names = environment.keySet.asScala.filter(_.equalsIgnoreCase("PATH")).toVector
    val inherited = names.headOption.map(environment.get).filter(_.nonEmpty)
    names.foreach(environment.remove)
    environment.put(names.headOption.getOrElse("Path"), inherited.fold(directory.toString)(path => s"$directory;$path"))

  /** A command on the host, as `host` runs it, for a caller that keeps no transcript. With `discardStderr`, the
    * output is stdout alone: a JVM-based tool's warnings go to stderr. */
  def run(command: Seq[String], cwd: Path = workingDir, inheritStdin: Boolean = false,
      timeoutSeconds: Option[Int] = None, environment: Map[String, String] = Map.empty,
      inheritEnvironment: Boolean = true, discardStderr: Boolean = false): Output =
    val builder = ProcessBuilder(command*).directory(cwd.toFile)
    if discardStderr then builder.redirectError(Redirect.DISCARD) else builder.redirectErrorStream(true)
    if !inheritEnvironment then builder.environment.clear()
    environment.foreach(builder.environment.put(_, _))
    // After the environment is set, so that a cleared or given PATH still gets OpenSSH first.
    preferringWindowsOpenSsh(builder)
    if inheritStdin then builder.redirectInput(Redirect.INHERIT)
    // With a timeout, the output goes to a file: a pipe's reader would block past the deadline.
    val captured = timeoutSeconds.map(_ => Files.createTempFile("host-driver", ".out"))
    captured.foreach(file => builder.redirectOutput(file.toFile))
    val process = builder.start()
    if !inheritStdin then process.getOutputStream.close()
    val (status, text) = (captured, timeoutSeconds) match
      case (Some(file), Some(seconds)) =>
        val finished = process.waitFor(seconds.toLong, TimeUnit.SECONDS)
        if !finished then
          process.destroyForcibly()
          process.waitFor()
        val output = String(Files.readAllBytes(file), UTF_8)
        Files.delete(file)
        if finished then (process.exitValue, output)
        else (-1, s"$output\n(${command.mkString(" ")} killed after ${seconds}s)")
      case _ =>
        val output = String(process.getInputStream.readAllBytes(), UTF_8)
        (process.waitFor(), output)
    Output(status, text)

  /** The first executable of that name on PATH, as `command -v` finds it. */
  def onPath(name: String): Option[Path] =
    sys.env.get("PATH").toSeq.flatMap(_.split(':')).filter(_.nonEmpty).map(Path.of(_, name))
      .find(candidate => Files.isRegularFile(candidate) && Files.isExecutable(candidate))

  /** The names in the directory, sorted and without dot entries, as `ls -1` lists them. */
  def listedNames(dir: Path): Vector[String] =
    Using.resource(Files.list(dir))(_.iterator.asScala.map(_.getFileName.toString).filterNot(_.startsWith("."))
      .toVector.sorted)

  /** Whether `condition` holds within `seconds`, tested every `intervalMillis`. A row whose state changes
    * after the causing command returns waits with this for the state itself, never for a fixed time.
    * A test that answers true only after the deadline counts as false: a slow command must not stretch the bound
    * that the row reports. */
  def within(seconds: Int, intervalMillis: Int = 250)(condition: => Boolean): Boolean =
    val deadline = System.nanoTime() + seconds * 1_000_000_000L
    @scala.annotation.tailrec def poll(): Boolean =
      val held = condition
      val remainingNanos = deadline - System.nanoTime()
      if remainingNanos < 0 then false
      else if held then true
      else
        Thread.sleep(math.min(intervalMillis.toLong, remainingNanos / 1_000_000L + 1))
        poll()
    poll()
