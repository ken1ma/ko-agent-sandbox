// The sandbox → host build channel: the FIFO protocol both sides speak, and the host-side broker
// that serves it (PLAN-SBT-ON-HOST.md §6). The sandbox side is the image's sandbox-run-on-host
// shim; the broker is a detached process of the launcher's own vehicle, spawned per session under
// --run-on-host. SECURITY.md "Run on host" has what the channel grants and withholds.

package agentsandbox.launcher

import java.io.{ByteArrayOutputStream, IOException, InputStream, OutputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

import HostCommands.Os

object RunOnHostChannel:

  /**
   * One well-known FIFO, `req`, made by the broker's first exec so that a session without the
   * channel has none and the shim fails at once; everything else is transaction-scoped. The shim
   * takes the lock, creates its own `ctl.<pid>`, `out.<pid>`, `err.<pid>` and `exit.<pid>`,
   * writes its pid to `req` as one line — a single write, so it frames itself — and then sends
   * the request over `ctl.<pid>`: `<tool> <argc>\n`, then argc+1 NUL-terminated fields, the
   * working directory in its container spelling and then the arguments. It holds `ctl.<pid>`
   * open for the life of the transaction and reads `out`/`err` to EOF and its exit code from
   * `exit`.
   *
   * The request travels on the liveness descriptor, so no request is ever runnable without its
   * liveness: the broker acts on `ctl`'s EOF alone — an interrupted shim, a killed one and a
   * dead container all close the descriptor, and the running build is ended with SIGTERM, the
   * wrapper's own measured teardown (§4). A handshake whose `ctl` never opens, or whose request
   * never completes, is declared stillborn on a deadline with no build started. The data FIFOs
   * are the transaction's own, so a later shim — the lock frees when its holder dies — cannot
   * attach to a predecessor's streams; a reused pid takes fresh inodes, never leftovers.
   *
   * The broker reads `req` through one exec at a time — each serving every handshake it
   * delivers, in order — and answers through short ones, so the sandbox opens nothing outward
   * and the host runs nothing it did not start. A second
   * writer scribbling on `req` or a transaction's FIFOs is the agent breaking its own channel —
   * the broker drops what it cannot frame, and the authority it enforces is unaffected.
   */
  val SandboxDir = "/tmp/ko-agent-sandbox/host-command"

  /** What the project is mounted at inside the container: the spelling requests arrive in. */
  val WorkspaceMount = "/workspace"

  /**
   * Set in the sandbox to the tools `--run-on-host` names: the shim's cue to wait for a `req`
   * the broker may not have made yet, and the agent's one variable saying the channel exists.
   */
  val RunOnHostVariable = "KO_AGENT_SANDBOX_RUN_ON_HOST"

  val SandboxHandshakeReader: String =
    s"trap \"\" INT HUP TERM; d=$SandboxDir; mkdir -p -m 700 $$d; " +
      s"[ -p $$d/req ] || mkfifo -m 600 $$d/req; cat $$d/req"

  /** A pid, and interpolated into the transaction's FIFO names, so nothing else is accepted. */
  private val TransactionId = "[0-9]{1,18}".r

  /** A request is small — a path and a command line — so a huge one is framing gone wrong, not a
    * build to run; refused before memory is committed to it. The broker parses these bytes on
    * the host, so every read is bounded: the handshake, the header, and the fields as a whole.
    * An over-bound frame is still drained (never stored) up to DrainBytes — comfortably past any
    * ARG_MAX — because the requester opens its response readers only after writing the whole
    * request, and a refusal it never gets to read is a hang, not an answer. */
  val MaxArguments = 4096
  val MaxRequestBytes = 8 << 20
  val MaxLineBytes = 4096
  val DrainBytes = 64 << 20

  final case class Request(tool: String, workingDirectory: String, arguments: Vector[String])

  /** One request off the stream: Right(None) is EOF at a request boundary; Left is a stream that
    * can no longer be trusted to frame anything, the caller's cue to drop it whole. */
  def readRequest(in: InputStream): Either[String, Option[Request]] =
    readLine(in).flatMap:
      case None => Right(None)
      case Some(header) =>
        header.split(" ", 2) match
          case Array(tool, count) if count.forall(_.isDigit) && count.nonEmpty =>
            count.toIntOption match
              case None =>
                Left(s"request names $count arguments, which is no count at all")
              case Some(argc) if argc > MaxArguments =>
                drainFields(in, argc.toLong + 1)
                Left(s"request names $argc arguments, over the $MaxArguments bound")
              case Some(argc) =>
                val fields = Vector.newBuilder[String]
                var failed: Option[String] = None
                var index = 0
                var budget = MaxRequestBytes
                while failed.isEmpty && index <= argc do
                  readField(in, budget) match
                    case Right((field, bytes)) =>
                      fields += field
                      budget -= bytes
                    case Left(reason) =>
                      // Mid-field: its own NUL is the first of the remainder being drained.
                      drainFields(in, argc.toLong + 1 - index)
                      failed = Some(reason)
                  index += 1
                failed.toLeft(()).map: _ =>
                  val all = fields.result()
                  Some(Request(tool, all.head, all.tail))
          case _ => Left(s"request header is not `<tool> <argc>`: $header")

  /** Right(None) at EOF before any byte; Left on a line passing the bound — unframeable. */
  def readLine(in: InputStream): Either[String, Option[String]] =
    val buffer = ByteArrayOutputStream()
    var result: Option[Either[String, Option[String]]] = None
    while result.isEmpty do
      in.read() match
        case -1 =>
          result = Some(
            if buffer.size == 0 then Right(None)
            else Left("the stream ended inside a line"),
          )
        case '\n' => result = Some(Right(Some(String(buffer.toByteArray, UTF_8))))
        case byte =>
          if buffer.size >= MaxLineBytes then
            result = Some(Left(s"a line passed the $MaxLineBytes-byte bound"))
          else buffer.write(byte)
    result.get

  /** Consume the rest of an over-bound frame without storing it, so the requester finishes its
    * write and reaches the readers the refusal answers on; EOF or DrainBytes ends the attempt —
    * past DrainBytes nothing legitimate is writing, and the caller's refusal is bounded anyway.
    * Every consumed byte is charged, the NUL delimiters included: a NUL-dense frame must exhaust
    * the byte budget, never buy itself a field-counted pass through the parser. */
  private def drainFields(in: InputStream, fields: Long): Unit =
    var remaining = fields
    var budget = DrainBytes
    var open = true
    while open && remaining > 0 && budget > 0 do
      val byte = in.read()
      budget -= 1
      byte match
        case -1 => open = false
        case 0  => remaining -= 1
        case _  => ()

  private def readField(in: InputStream, budget: Int): Either[String, (String, Int)] =
    val buffer = ByteArrayOutputStream()
    var result: Option[Either[String, (String, Int)]] = None
    while result.isEmpty do
      in.read() match
        case -1 => result = Some(Left("the stream ended inside a request"))
        case 0  => result = Some(Right((String(buffer.toByteArray, UTF_8), buffer.size)))
        case byte =>
          if buffer.size >= budget then
            result = Some(Left(s"the request passed the $MaxRequestBytes-byte bound"))
          else buffer.write(byte)
    result.get

  // ---------------------------------------------------------------------------
  // The broker
  // ---------------------------------------------------------------------------

  /**
   * How the broker reaches the sandbox, as data so the gate and the tests can substitute a local
   * shell for `podman exec -i <container>`: the transport is what they stub, never the protocol.
   */
  final case class Endpoint(execPrefix: Seq[String], sandboxRunning: () => Boolean)

  /** Everything one session's broker serves with: the launcher's canonical project root, the
    * tools `--run-on-host` named, and how a validated request becomes a wrapper command. */
  final case class Service(
    project: Path,
    tools: Set[String],
    buildCommand: (String, Path, Seq[String]) => Seq[String],
    os: Os,
    canonicalize: Path => Option[Path] = RunOnHostPolicy.realPath,
    mount: String = WorkspaceMount,
    /** How long a handshake may sit without a complete request before it is stillborn. */
    requestDeadlineMillis: Long = 30_000,
  )

  /**
   * The broker's life: wait for the sandbox to run, then serve handshakes cycle by cycle while
   * it still runs — ClipboardBroker.serve's loop, with builds where the clipboard was; each
   * cycle is one reader exec and every transaction its stream delivers. Both waits are bounded
   * pacing, not correctness: an idle cycle blocks in the handshake reader's own open.
   */
  def serve(endpoint: Endpoint, service: Service, log: String => Unit): Unit =
    var waited = 0
    while !endpoint.sandboxRunning() && waited < 600 do
      Thread.sleep(1000)
      waited += 1
    while endpoint.sandboxRunning() do
      val served =
        try cycle(endpoint, service, log)
        catch
          case ex: IOException =>
            log(s"cycle failed: ${ex.getMessage}")
            false
      if !served then Thread.sleep(1000)

  private def sandboxShell(endpoint: Endpoint, script: String): ProcessBuilder =
    ProcessBuilder((endpoint.execPrefix ++ Seq("sh", "-c", script))*)

  /**
   * A transport exec is killed whole, descendants first: the shell behind it may have forked the
   * command it ran (measured — a stubbed exec left its `cat` alive under pid 1 after
   * destroyForcibly took only the shell), and a surviving grandchild holds both the FIFO and
   * this side's pipe open past the transaction, wedging the broker in a read no EOF ends.
   */
  private def end(process: Process): Unit =
    process.descendants().forEach(_.destroyForcibly())
    process.destroyForcibly()
    ()

  /**
   * One reader exec, every handshake it delivers: the reader lives while a transaction runs, so
   * a shim whose predecessor just died can hand its id to the *same* cat — queued in the stream,
   * and consumed here in order rather than discarded with the exec. False is a cycle that served
   * nothing, the caller's cue to pace; garbage still dies with its reader.
   */
  private def cycle(endpoint: Endpoint, service: Service, log: String => Unit): Boolean =
    val reader = sandboxShell(endpoint, SandboxHandshakeReader)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    reader.getOutputStream.close()
    var served = false
    try
      var open = true
      while open do
        readLine(reader.getInputStream) match
          case Right(Some(id)) if TransactionId.matches(id) =>
            transact(endpoint, service, id, log)
            served = true
          case Right(Some(other)) =>
            log(s"dropped a handshake that is no transaction id: ${other.take(80)}")
            open = false
          case Right(None) => open = false
          case Left(reason) =>
            log(s"dropped an unframeable handshake: $reason")
            open = false
      served
    finally
      end(reader)
      reader.waitFor(10, TimeUnit.SECONDS)

  /** The build a broker is currently running, for the shutdown hook: a TERM to the broker ends
    * the build too, rather than silently leaving it to finish. */
  @volatile private var currentBuild: Option[Process] = None

  def endCurrentBuild(): Unit = currentBuild.foreach(_.destroy())

  private def transact(
    endpoint: Endpoint,
    service: Service,
    id: String,
    log: String => Unit,
  ): Unit =
    // The transaction's liveness and its request are one stream: the exec ends when the shim
    // does, or when the container dies — the same signal either way.
    val ctl = sandboxShell(endpoint, s"cat $SandboxDir/ctl.$id")
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    ctl.getOutputStream.close()

    // The shim may have died between its handshake and opening ctl, leaving the open above with
    // no writer ever: a request not complete by the deadline is stillborn, no build started.
    val requestArrived = AtomicBoolean(false)
    val stillborn = Thread(() =>
      try Thread.sleep(service.requestDeadlineMillis)
      catch case _: InterruptedException => ()
      finally if !requestArrived.get then end(ctl),
    )
    stillborn.setDaemon(true)
    stillborn.start()

    try
      readRequest(ctl.getInputStream) match
        case Left(reason) =>
          // Answered, never silently dropped: the requester is real and at its FIFOs — over the
          // argument bound is the reachable case — and a drop would leave it waiting for streams
          // nothing will open.
          refuse(endpoint, id, s"CHANNEL_UNAVAILABLE: the request could not be read: $reason", log)
        case Right(None) =>
          log(s"stillborn transaction $id: the requester never spoke")
        case Right(Some(request)) =>
          requestArrived.set(true)
          answer(endpoint, service, id, ctl, request, log)
    finally
      requestArrived.set(true) // the deadline has nothing left to bound
      end(ctl)
      ctl.waitFor(10, TimeUnit.SECONDS)

  private def writer(endpoint: Endpoint, id: String, name: String): Process =
    sandboxShell(endpoint, s"cat > $SandboxDir/$name.$id")
      .redirectOutput(ProcessBuilder.Redirect.DISCARD)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()

  private def writeAll(stream: OutputStream, text: String): Unit =
    try
      stream.write(text.getBytes(UTF_8))
      stream.close()
    catch case _: IOException => ()

  /** Bounded, and safe to bound: it runs only after the output writers have drained, so a live
    * shim is already at its exit read, and a dead one has nobody waiting. */
  private def writeExit(endpoint: Endpoint, id: String, code: Int): Unit =
    try
      val exitWriter = writer(endpoint, id, "exit")
      writeAll(exitWriter.getOutputStream, s"$code\n")
      if !exitWriter.waitFor(10, TimeUnit.SECONDS) then end(exitWriter)
    catch case _: IOException => ()

  /** No build ran: the message on stderr, exit 2, every wait bounded — a requester that died
    * mid-request cannot hold this open. */
  private def refuse(endpoint: Endpoint, id: String, message: String, log: String => Unit): Unit =
    log(s"refused: $message")
    val outWriter = writer(endpoint, id, "out")
    val errWriter = writer(endpoint, id, "err")
    writeAll(outWriter.getOutputStream, "")
    writeAll(errWriter.getOutputStream, message + "\n")
    Seq(outWriter, errWriter).foreach: process =>
      if !process.waitFor(10, TimeUnit.SECONDS) then end(process)
    writeExit(endpoint, id, 2)

  private def answer(
    endpoint: Endpoint,
    service: Service,
    id: String,
    ctl: Process,
    request: Request,
    log: String => Unit,
  ): Unit =
    validated(service, request) match
      case Left(refusal) => refuse(endpoint, id, refusal, log)
      case Right(workingDirectory) =>
        val outWriter = writer(endpoint, id, "out")
        val errWriter = writer(endpoint, id, "err")
        val command = service.buildCommand(request.tool, workingDirectory, request.arguments)
        log(s"${request.tool} in $workingDirectory: ${request.arguments.mkString(" ")}")
        try
          val child = ProcessBuilder(command*)
            .redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
            .start()
          currentBuild = Some(child)
          val ended = AtomicBoolean(false)
          val requesterGone = AtomicBoolean(false)
          // The writers die only with their requester: a slow reader is the requester's own
          // pace, never a reason to truncate its output — while a gone one unblocks everything
          // this transaction still holds.
          ctl.onExit.thenRun: () =>
            if !ended.get then
              requesterGone.set(true)
              log("the requester is gone; ending the build")
              child.destroy()
              end(outWriter)
              end(errWriter)
          val pumps = Seq(
            pump(child.getInputStream, outWriter.getOutputStream),
            pump(child.getErrorStream, errWriter.getOutputStream),
          )
          val exit = child.waitFor()
          currentBuild = None
          pumps.foreach(_.join())
          if requesterGone.get then log(s"ended with $exit for a requester already gone")
          else
            // Only after both writers have drained: the shim reads the exit code last, and an
            // exit writer given up on while the shim was still draining output would leave the
            // shim blocked on a FIFO no writer will ever open.
            outWriter.waitFor()
            errWriter.waitFor()
            writeExit(endpoint, id, exit)
            log(s"exit $exit")
          ended.set(true)
        catch
          case ex: IOException =>
            log(s"could not start the wrapper: ${ex.getMessage}")
            writeAll(outWriter.getOutputStream, "")
            writeAll(errWriter.getOutputStream, s"could not start the build wrapper: ${ex.getMessage}\n")
            writeExit(endpoint, id, 2)
        finally
          currentBuild = None
          Seq(outWriter, errWriter).foreach: process =>
            if !process.waitFor(10, TimeUnit.SECONDS) then end(process)

  private def pump(from: InputStream, to: OutputStream): Thread =
    val thread = Thread(() =>
      try { from.transferTo(to); () }
      catch case _: IOException => ()
      finally
        try to.close()
        catch case _: IOException => (),
    )
    thread.start()
    thread

  /** §6.2's boundary work: the tool must be one the launch named, and the working directory —
    * the one value arriving from inside the sandbox — is translated and proven inside the
    * project before anything is derived from it. */
  def validated(service: Service, request: Request): Either[String, Path] =
    if !service.tools(request.tool) then
      Left(
        s"CHANNEL_UNAVAILABLE: this session's --run-on-host does not name ${request.tool}; " +
          s"it serves ${service.tools.toSeq.sorted.mkString(", ")}",
      )
    else
      RunOnHostPolicy
        .workingDirectory(
          request.workingDirectory, service.mount, service.project, service.canonicalize, service.os,
        )
        .left.map(_ =>
          s"CHANNEL_UNAVAILABLE: working directory ${request.workingDirectory} is not the " +
            "project or beneath it",
        )

  // ---------------------------------------------------------------------------
  // The production main, behind the launcher's private verb
  // ---------------------------------------------------------------------------

  /**
   * Detached like the reaper: stdio to /dev/null, the broker must outlive the launcher's exec,
   * and the terminal's INT and HUP are ignored before the exec — sh's ignore is inherited, and a
   * JVM leaves an inherited SIG_IGN in place — so a Ctrl-C at the session's terminal cannot take
   * the broker before its sandbox. TERM stays live: a deliberate kill ends the broker, and its
   * shutdown hook ends the running build with it.
   */
  def spawnBroker(
    podman: String,
    container: String,
    project: Path,
    tools: Seq[String],
    logFile: Path,
  ): Boolean =
    try
      val builder = ProcessBuilder(
        (Seq("/bin/sh", "-c", "trap '' INT HUP; exec \"$@\"", "ko-agent-run-on-host-broker")
          ++ RunOnHostSandbox.selfInvocation(
            "--serve-run-on-host", podman, container, project.toString,
            tools.mkString(","), logFile.toString,
          ))*,
      )
      builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
      builder.redirectError(ProcessBuilder.Redirect.DISCARD)
      builder.start()
      true
    catch case _: IOException => false

  /** `--serve-run-on-host <podman> <container> <project> <tools-csv> <log-file> [mount]`: spawned
    * by the launcher before it hands over to podman, detached like the reaper. The trailing mount
    * override is the gate's, whose shim runs at the project's own path rather than /workspace. */
  def serveMain(args: Seq[String]): Unit =
    args match
      case Seq(podman, container, projectArg, toolsCsv, logFile, rest*) if rest.sizeIs <= 1 =>
        val logPath = Path.of(logFile)
        def log(line: String): Unit =
          try
            java.nio.file.Files.writeString(
              logPath,
              s"${java.time.Instant.now()} $line\n",
              java.nio.file.StandardOpenOption.CREATE,
              java.nio.file.StandardOpenOption.APPEND,
            )
          catch case _: IOException => ()
        val project =
          try Path.of(projectArg).toRealPath()
          catch
            case ex: IOException =>
              log(s"project $projectArg: ${ex.getMessage}")
              sys.exit(1)
        Runtime.getRuntime.addShutdownHook(Thread(() => endCurrentBuild()))
        val endpoint = Endpoint(
          execPrefix = Seq(podman, "exec", "-i", container),
          sandboxRunning = () =>
            try
              HostCommands
                .run(podman, "container", "inspect", "--format", "{{.State.Running}}", container)
                .text.trim == "true"
            catch case _: IOException => false,
        )
        val service = Service(
          project = project,
          tools = toolsCsv.split(",").toSet,
          buildCommand = (tool, workingDirectory, arguments) =>
            RunOnHostSandbox.selfInvocation(
              "--run-build-on-host", tool, project.toString, workingDirectory.toString, "--",
            ) ++ arguments,
          os = Os.Mac,
          mount = rest.headOption.getOrElse(WorkspaceMount),
        )
        log(s"serving $toolsCsv for $project in $container")
        serve(endpoint, service, log)
        log("the sandbox is gone; exiting")
      case other =>
        Console.err.println(s"--serve-run-on-host: unexpected arguments: ${other.mkString(" ")}")
        sys.exit(2)
