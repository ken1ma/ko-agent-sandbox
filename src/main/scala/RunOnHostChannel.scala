// The sandbox → host command channel: the FIFO protocol both sides speak, and the host-side broker
// that serves it. The sandbox side is the image's sandbox-run-on-host
// shim; the broker is a detached process of the launcher's own executable — the jar or native
// binary — spawned per session under --run-on-host. SECURITY.md "Run on host" has what the
// channel grants and withholds.

package agentsandbox.launcher

import java.io.{ByteArrayOutputStream, IOException, InputStream, OutputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.{AtomicBoolean, AtomicReference}

import scala.util.control.NonFatal

import HostCommands.Os

object RunOnHostChannel:

  /**
   * One well-known FIFO, `req`, made by the broker's first exec so that a session without the
   * channel has none and the shim fails at once; everything else is transaction-scoped. The shim
   * takes the lock, creates its own `ctl.<pid>`, `out.<pid>`, `err.<pid>` and `exit.<pid>`,
   * writes its pid to `req` as one line — a single write, so it frames itself — and then sends
   * the request over `ctl.<pid>`: `<program> <argc>\n`, then argc+1 NUL-terminated fields, the
   * working directory in its container spelling and then the arguments. It holds `ctl.<pid>`
   * open for the life of the transaction and reads `out`/`err` to EOF and its exit code from
   * `exit`.
   *
   * The request travels on the liveness descriptor, so no request is ever runnable without its
   * liveness: the broker acts on `ctl`'s EOF alone — an interrupted shim, a killed one and a
   * dead container all close the descriptor, and the running command is ended with SIGTERM, the
   * wrapper's own measured teardown (RunOnHostSession). A handshake whose `ctl` never opens, or whose request
   * never completes, expires on a deadline with no command started. The shim bounds startup
   * through opening both output streams, then separately the exit-status read, and exits 70 on
   * either timeout. Waiting for the lock and draining command output have no deadline. The data FIFOs
   * are the transaction's own, so a later shim — the lock frees when its holder dies — cannot
   * attach to a predecessor's streams; a reused pid takes fresh inodes, never leftovers.
   *
   * The broker reads `req` through one exec at a time — each serving every handshake it
   * delivers, in order — and answers through short ones, so the sandbox opens nothing outward
   * and the host runs nothing it did not start. A second
   * writer scribbling on `req` or a transaction's FIFOs is the agent breaking its own channel —
   * the broker drops what it cannot frame, and the authority it enforces is unaffected.
   */
  val SandboxDir = "/tmp/ko-agent-sandbox/run-on-host"

  /** What the project is mounted at inside the container: the spelling requests arrive in. */
  val WorkspaceMount = "/workspace"

  /**
   * Set in the sandbox to the programs `--run-on-host` names: the shim's cue to wait for a `req`
   * the broker may not have made yet, and the agent's one variable saying the channel exists.
   */
  val RunOnHostVariable = "KO_AGENT_SANDBOX_RUN_ON_HOST"

  def handshakeReader(sandboxDir: String): String =
    s"trap \"\" INT HUP TERM; d=$sandboxDir; mkdir -p -m 700 $$d; " +
      s"[ -p $$d/req ] || mkfifo -m 600 $$d/req; cat $$d/req"

  /** A pid, and interpolated into the transaction's FIFO names, so nothing else is accepted. */
  private val TransactionId = "[0-9]{1,18}".r

  /** A request is small — a path and a command line — so a huge one is framing gone wrong, not a
    * command to run; refused before memory is committed to it. The broker parses these bytes on
    * the host, so every read is bounded: the handshake, the header, and the fields as a whole.
    * An over-bound frame is still drained (never stored) up to DrainBytes — comfortably past any
    * ARG_MAX — because the requester opens its response readers only after writing the whole
    * request, and a refusal it never gets to read is a hang, not an answer. */
  val MaxArguments = 4096
  val MaxRequestBytes = 8 << 20
  val MaxLineBytes = 4096
  val DrainBytes = 64 << 20

  final case class Request(program: String, workingDirectory: String, arguments: Vector[String])

  /** One request off the stream: Right(None) is EOF at a request boundary; Left is a stream that
    * can no longer be trusted to frame anything, the caller's cue to drop it whole. */
  def readRequest(in: InputStream): Either[String, Option[Request]] =
    readLine(in).flatMap:
      case None => Right(None)
      case Some(header) =>
        header.split(" ", 2) match
          case Array(program, count) if count.forall(_.isDigit) && count.nonEmpty =>
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
                  Some(Request(program, all.head, all.tail))
          case _ => Left(s"request header is not `<program> <argc>`: $header")

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
    * the byte budget, never obtain a field-counted pass through the parser. */
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
  final case class Transport(
    execPrefix: Seq[String],
    sandboxRunning: () => Boolean,
    /** Where the FIFOs are inside the sandbox: the shim's own constant, and a parameter only so
      * a test can put both sides somewhere that is not a live session's channel. */
    sandboxDir: String = SandboxDir,
  )

  /** Everything one session's broker serves with: the launcher's canonical project root, the
    * programs `--run-on-host` named, and how a validated request — program, working directory,
    * build lock file, arguments — becomes a wrapper command. */
  final case class Service(
    project: Path,
    programs: Set[String],
    /** A locked spawn of the wrapper (RunOnHostSession.lockedSpawn, under the broker): dispatch
      * speaks its protocol. */
    wrapperCommand: (String, Path, Path, Seq[String]) => Seq[String],
    os: Os,
    /** The build lock file of a program and build directory (RunOnHostSession.buildLockFile),
      * which the wrapper holds for its life. */
    buildLock: (String, Path) => Either[String, Path],
    /** The runtime a program's command in a build directory runs against, given the request's
      * arguments, prepared while the spawn holds the build lock: the wrapper options naming it
      * (RunOnHostSandbox.runtimeOptions), none for a program whose wrapper creates its own. */
    runtime: (String, Path, Seq[String]) => Either[String, Seq[String]],
    /** After a dispatched spawn ended — its command run, refused, or ended with its requester —
      * with the request's program: what the runtime records once the command is over
      * (RunOnHostSandbox.BrokerRuntimes.commandEnded). */
    ended: String => Unit = _ => (),
    canonicalize: Path => Option[Path] = RunOnHostPrereqs.realPath,
    mount: String = WorkspaceMount,
    /** How long the broker waits for a complete request before the handshake expires. */
    requestDeadlineMillis: Long = 30_000,
  )

  /**
   * The broker's life: wait for the sandbox to run, then serve handshakes cycle by cycle while
   * it still runs — ClipboardBroker.serve's loop, with commands where the clipboard was; each
   * cycle is one reader exec and every transaction its stream delivers. Both waits are bounded
   * pacing, not correctness: an idle cycle blocks in the handshake reader's own open.
   */
  def serve(transport: Transport, service: Service, log: String => Unit): Unit =
    var waited = 0
    while !transport.sandboxRunning() && waited < 600 do
      Thread.sleep(1000)
      waited += 1
    while transport.sandboxRunning() do
      val served =
        try cycle(transport, service, log)
        catch
          case ex: IOException =>
            log(s"cycle failed: ${ex.getMessage}")
            false
      if !served then Thread.sleep(1000)

  private def sandboxShell(transport: Transport, script: String): ProcessBuilder =
    ProcessBuilder((transport.execPrefix ++ Seq("sh", "-c", script))*)

  /**
   * A transport exec is killed whole, descendants first: the shell behind it may have forked the
   * command it ran (measured — a stubbed exec left its `cat` alive under pid 1 after
   * destroyForcibly took only the shell), and a surviving grandchild holds both the FIFO and
   * this side's pipe open past the transaction, leaving the broker blocked on a read because the
   * surviving grandchild prevents EOF.
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
  private def cycle(transport: Transport, service: Service, log: String => Unit): Boolean =
    val reader = sandboxShell(transport, handshakeReader(transport.sandboxDir))
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    reader.getOutputStream.close()
    var served = false
    try
      var open = true
      while open do
        readLine(reader.getInputStream) match
          case Right(Some(id)) if TransactionId.matches(id) =>
            transact(transport, service, id, log)
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

  /** How to end the command a broker is currently running, for the shutdown hook: a TERM to the
    * broker ends the command too, rather than silently leaving it to finish, and returns only
    * when the wrapper has ended, its teardown included, before the broker's own session is
    * ended. */
  @volatile private var currentCommand: Option[() => Unit] = None

  def endCurrentCommand(): Unit = currentCommand.foreach(end => end())

  /** Where a dispatched spawn is, for an end asked of it — the requester gone, endCurrentCommand.
    * Waiting for the build lock, it is destroyed at once. Preparing the runtime, it holds the
    * lock the preparation runs under, so the end is applied once the word is out: the refusal,
    * which it exits on by itself. Running the wrapper, it is destroyed, the wrapper's teardown
    * answering. */
  private enum SpawnPhase:
    case Waiting, Preparing, Running, Ending

  private def transact(
    transport: Transport,
    service: Service,
    id: String,
    log: String => Unit,
  ): Unit =
    // The transaction's liveness and its request are one stream: the exec ends when the shim
    // does, or when the container dies — the same signal either way.
    val ctl = sandboxShell(transport, s"cat ${transport.sandboxDir}/ctl.$id")
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    ctl.getOutputStream.close()

    // The shim may have died between its handshake and opening ctl, leaving the open above with
    // no writer ever: a request not complete by the deadline expires, no command started.
    val requestArrived = AtomicBoolean(false)
    val expiryThread = Thread(() =>
      try Thread.sleep(service.requestDeadlineMillis)
      catch case _: InterruptedException => ()
      finally if !requestArrived.get then end(ctl),
    )
    expiryThread.setDaemon(true)
    expiryThread.start()

    try
      readRequest(ctl.getInputStream) match
        case Left(reason) =>
          // Answered, never silently dropped: the requester is real and at its FIFOs — over the
          // argument bound is the reachable case — and a drop would leave it waiting for streams
          // nothing will open.
          refuse(transport, id, s"CHANNEL_UNAVAILABLE: the request could not be read: $reason", log)
        case Right(None) =>
          log(s"expired transaction $id: the requester never sent a request")
        case Right(Some(request)) =>
          requestArrived.set(true)
          answer(transport, service, id, ctl, request, log)
    finally
      requestArrived.set(true) // the deadline has nothing left to bound
      end(ctl)
      ctl.waitFor(10, TimeUnit.SECONDS)

  private def writer(transport: Transport, id: String, name: String): Process =
    sandboxShell(transport, s"cat > ${transport.sandboxDir}/$name.$id")
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
  private def writeExit(transport: Transport, id: String, code: Int): Unit =
    try
      val exitWriter = writer(transport, id, "exit")
      writeAll(exitWriter.getOutputStream, s"$code\n")
      if !exitWriter.waitFor(10, TimeUnit.SECONDS) then end(exitWriter)
    catch case _: IOException => ()

  /** No command ran: the message on stderr, exit 2, every wait bounded — a requester that died
    * mid-request cannot hold this open. */
  private def refuse(transport: Transport, id: String, message: String, log: String => Unit): Unit =
    log(s"refused: $message")
    val outWriter = writer(transport, id, "out")
    val errWriter = writer(transport, id, "err")
    writeAll(outWriter.getOutputStream, "")
    writeAll(errWriter.getOutputStream, message + "\n")
    Seq(outWriter, errWriter).foreach: process =>
      if !process.waitFor(10, TimeUnit.SECONDS) then end(process)
    writeExit(transport, id, 2)

  private def answer(
    transport: Transport,
    service: Service,
    id: String,
    ctl: Process,
    request: Request,
    log: String => Unit,
  ): Unit =
    validated(service, request) match
      case Left(refusal) => refuse(transport, id, refusal, log)
      case Right(workingDirectory) =>
        service.buildLock(request.program, workingDirectory) match
          case Left(reason)    => refuse(transport, id, s"CHANNEL_UNAVAILABLE: $reason", log)
          case Right(lockFile) => dispatch(transport, service, id, ctl, request, workingDirectory, lockFile, log)

  private def dispatch(
    transport: Transport,
    service: Service,
    id: String,
    ctl: Process,
    request: Request,
    workingDirectory: Path,
    lockFile: Path,
    log: String => Unit,
  ): Unit =
    val outWriter = writer(transport, id, "out")
    val errWriter = writer(transport, id, "err")
    val command = service.wrapperCommand(request.program, workingDirectory, lockFile, request.arguments)
    log(s"${request.program} in $workingDirectory: ${request.arguments.mkString(" ")}")
    try
      // The wrapper's stdin is this broker's pipe, written once — the word below — and then
      // held: its EOF is the broker gone, killed or ended, and the wrapper ends the command at
      // it (RunOnHostSandbox.runCommandMain) as this broker ends it at ctl's.
      val child = ProcessBuilder(command*).start()
      val ended = AtomicBoolean(false)
      val requesterGone = AtomicBoolean(false)
      val phase = AtomicReference(SpawnPhase.Waiting)
      val endAsked = AtomicBoolean(false)
      def endChild(): Unit =
        endAsked.set(true)
        if phase.get == SpawnPhase.Running || phase.compareAndSet(SpawnPhase.Waiting, SpawnPhase.Ending) then
          child.destroy()
      currentCommand = Some(() => { endChild(); child.waitFor(); () })
      // The writers die only with their requester: a slow reader is the requester's own
      // pace, never a reason to truncate its output — while a gone one unblocks everything
      // this transaction still holds.
      ctl.onExit.thenRun: () =>
        if !ended.get then
          requesterGone.set(true)
          log("the requester is gone; ending the command")
          endChild()
          end(outWriter)
          end(errWriter)
      // stderr from the start: the spawn's wait for the build lock is announced there.
      val errPump = pump(child.getErrorStream, errWriter.getOutputStream)
      // The spawn's first line says it holds the build lock; the word — the runtime's options,
      // or the refusal the spawn prints and exits 2 on — is what it execs the wrapper on.
      // Anything else is the spawn ending before the lock, or ended while it waited, and its
      // exit is the answer.
      readLine(child.getInputStream) match
        case Right(Some(RunOnHostSession.LockedLine))
            if phase.compareAndSet(SpawnPhase.Waiting, SpawnPhase.Preparing) =>
          // Any failure to prepare is the refusal: an exception would leave the spawn waiting
          // for a word, the lock held.
          val prepared =
            try service.runtime(request.program, workingDirectory, request.arguments)
            catch case NonFatal(ex) => Left(s"preparing the runtime: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
          val word = prepared match
            case Right(arguments) if !endAsked.get =>
              phase.set(SpawnPhase.Running)
              RunOnHostSession.runWord(arguments)
            case Right(_) =>
              phase.set(SpawnPhase.Ending)
              RunOnHostSession.refusedWord("refused: the command was ended before it started")
            case Left(reason) =>
              log(s"refused: $reason")
              phase.set(SpawnPhase.Ending)
              RunOnHostSession.refusedWord(s"refused: $reason")
          try
            child.getOutputStream.write(word.getBytes(UTF_8))
            child.getOutputStream.flush()
          catch case _: IOException => () // the spawn is gone; waited for below
          if endAsked.get && phase.get == SpawnPhase.Running then child.destroy()
        case _ => ()
      val pumps = Seq(pump(child.getInputStream, outWriter.getOutputStream), errPump)
      val exit = child.waitFor()
      currentCommand = None
      pumps.foreach(_.join())
      try service.ended(request.program)
      catch case NonFatal(ex) => log(s"after the command: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
      // Nothing is retired here on a cancel; the broker follows each program, and the two differ.
      // Stock sbt's server survives a client's disconnect: the disconnect cancels the exec
      // (CommandExchange.removeChannel, force=false) and the warm server serves the next
      // command. Stock Mill's daemon shuts itself down on a client's disconnect mid-command
      // (Server.scala), so the next mill command starts one (BrokerRuntimes.prepare).
      if requesterGone.get then log(s"ended with $exit for a requester already gone")
      else
        // Only after both writers have drained: the shim reads the exit code last, and an
        // exit writer given up on while the shim was still draining output would leave the
        // shim blocked on a FIFO no writer will ever open.
        outWriter.waitFor()
        errWriter.waitFor()
        // Set before the exit code goes out: the shim exits as soon as it has read the code,
        // and on the host its ctl closes before the exit writer's end is observed here. The
        // command has exited and both streams have drained, so nothing is left to end;
        // writeExit's bound covers a requester gone before reading the code.
        ended.set(true)
        writeExit(transport, id, exit)
        log(s"exit $exit")
    catch
      case ex: IOException =>
        log(s"could not start the wrapper: ${ex.getMessage}")
        writeAll(outWriter.getOutputStream, "")
        writeAll(errWriter.getOutputStream, s"could not start the command wrapper: ${ex.getMessage}\n")
        writeExit(transport, id, 2)
    finally
      currentCommand = None
      Seq(outWriter, errWriter).foreach: process =>
        if !process.waitFor(10, TimeUnit.SECONDS) then end(process)

  private def pump(from: InputStream, to: OutputStream): Thread =
    // The JVM buffers writes to podman exec's stdin; short build output must reach the agent before EOF.
    val thread = Thread(() =>
      try
        val buffer = new Array[Byte](8192)
        var count = from.read(buffer)
        while count != -1 do
          to.write(buffer, 0, count)
          to.flush()
          count = from.read(buffer)
      catch case _: IOException => ()
      finally
        try to.close()
        catch case _: IOException => (),
    )
    thread.start()
    thread

  /** The channel's boundary work: the program must be among those `--run-on-host` named, and the working
    * directory — the one value arriving from inside the sandbox — is translated and proven inside the
    * project before anything is derived from it. */
  def validated(service: Service, request: Request): Either[String, Path] =
    if !service.programs(request.program) then
      Left(
        s"CHANNEL_UNAVAILABLE: this session's --run-on-host does not name ${request.program}; " +
          s"it serves ${service.programs.toSeq.sorted.mkString(", ")}",
      )
    else
      RunOnHostPrereqs
        .workingDirectory(
          request.workingDirectory, service.mount, service.project, service.canonicalize, service.os,
        )
        .left.map(_ =>
          s"CHANNEL_UNAVAILABLE: working directory ${request.workingDirectory} is not the " +
            "project or beneath it",
        )

  // ---------------------------------------------------------------------------
  // The production main, behind the launcher's private action
  // ---------------------------------------------------------------------------

  /**
   * Detached like the reaper: stdio to /dev/null, the broker must outlive the launcher's exec,
   * and the terminal's INT and HUP are ignored before the exec — sh's ignore is inherited, and a
   * JVM leaves an inherited SIG_IGN in place — so a Ctrl-C at the session's terminal cannot take
   * the broker before its sandbox. TERM stays live: a deliberate kill ends the broker, and its
   * shutdown hook ends the running command and the broker's session with it.
   */
  def spawnBroker(
    podman: String,
    container: String,
    project: Path,
    programs: Seq[String],
    logFile: Path,
    // `--env` as launched: the names travel as arguments down to each command, the values through
    // this process's environment under inert carrier names (RunOnHostSandbox.carrierName), so no
    // argument below the launcher carries a value and an explicit one is read by no trusted
    // helper. A name-only forward's own variable is in this environment regardless, inherited as
    // the launcher's whole environment is.
    forwards: Vector[AgentSandboxLauncher.EnvForward] = Vector.empty,
  ): Boolean =
    try
      val builder = ProcessBuilder(
        (Seq("/bin/sh", "-c", "trap '' INT HUP; exec \"$@\"", "ko-agent-run-on-host-broker")
          ++ RunOnHostSandbox.selfInvocation(
            (Seq(
              "--serve-run-on-host", podman, container, project.toString,
              programs.mkString(","), logFile.toString,
            ) ++ forwards.map(forward => RunOnHostSandbox.EnvOption + forward.name))*,
          ))*,
      )
      forwards.foreach: forward =>
        forward.value.orElse(Option(System.getenv(forward.name))).foreach: value =>
          builder.environment.put(RunOnHostSandbox.carrierName(forward.name), value)
      builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
      builder.redirectError(ProcessBuilder.Redirect.DISCARD)
      builder.start()
      true
    catch case _: IOException => false

  /** `--serve-run-on-host <podman> <container> <project> <programs-csv> <log-file>
    * [--env=<name>...] [mount]`: spawned by the launcher before it hands over to podman, detached
    * like the reaper. The trailing mount override is the gate's, whose shim runs at the project's
    * own path rather than /workspace. */
  def serveMain(args: Seq[String]): Unit =
    def isOption(arg: String) = arg.startsWith(RunOnHostSandbox.EnvOption)
    args match
      case Seq(podman, container, projectArg, programsCsv, logFile, rest*) if rest.filterNot(isOption).sizeIs <= 1 =>
        val forwardedNames = RunOnHostSandbox.forwardedNames(rest)
        val trailing = rest.filterNot(isOption)
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
        val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
        val root = RunOnHostSession.root(uid)
        // The broker's session: published for the launch's lifetime, after the scavenge every
        // start runs, and ended at the serve loop's end or from the TERM hook. Its tmp/ is the
        // sbt server's socket directory, so the socket path budget applies to it.
        val session =
          RunOnHostSession.ensureRoot(root, uid).flatMap { _ =>
            RunOnHostSession
              .scavenge(root, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_))
              .foreach((entry, actions) => log(s"scavenged ${entry.getFileName}: ${actions.mkString(", ")}"))
            RunOnHostSession.publish(root, project, RunOnHostSession.Kind.Broker)
          }.flatMap: session =>
            RunOnHostPrereqs.sessionTmpFits(session.tmp).map(_ => session).left.map(RunOnHostPrereqs.wording)
          match
            case Right(session) => session
            case Left(reason) =>
              log(s"the broker's session: $reason")
              sys.exit(1)
        try java.nio.file.Files.writeString(session.directory.resolve(RunOnHostSession.RunFile), container + "\n")
        catch case ex: IOException => log(s"the broker's run file: ${ex.getMessage}")
        // The forwarded values, from this process's environment under their carrier names, as
        // the wrapper reads them; the runtime authority the artifact bundles, as the wrapper's.
        val runtimes = RunOnHostSandbox.BrokerRuntimes(
          session, project, log, RunOnHostSandbox.bundledRuntimeAuthority(),
          forwardedNames.flatMap(name => Option(System.getenv(RunOnHostSandbox.carrierName(name))).map(name -> _)),
        )(scavenge = () =>
          RunOnHostSession
            .scavenge(
              root, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_),
              ownSession = Some(session.directory),
            )
            .foreach((entry, actions) => log(s"scavenged ${entry.getFileName}: ${actions.mkString(", ")}")))
        // The runtimes' groups end with the session, their audit logs appended to this log
        // first; under the runtimes' monitor, for the reason BrokerRuntimes gives.
        val teardown = RunOnHostSession.Teardown: _ =>
          runtimes.synchronized:
            // A daemon a command still running at the broker's end started is observed here,
            // after endCurrentCommand and before the records are read.
            runtimes.commandEnded(RunOnHostPrereqs.Program.Gradle)
            RunOnHostSession
              .endSession(root, session, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_),
                beforeRemoval = condemned =>
                  RunOnHostSandbox.appendSessionLogs(
                    logPath, condemned, s"the broker's session ${condemned.getFileName} ended",
                  ))
              .foreach(action => log(s"the broker's session ended: $action"))
        Runtime.getRuntime.addShutdownHook(Thread(() =>
          endCurrentCommand()
          teardown(bySignal = true)))
        val transport = Transport(
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
          programs = programsCsv.split(",").toSet,
          wrapperCommand = (program, workingDirectory, lockFile, arguments) =>
            RunOnHostSession.lockedSpawn(
              lockFile,
              RunOnHostSandbox.selfInvocation(
                (Seq("--run-command-on-host", program, project.toString, workingDirectory.toString)
                  ++ forwardedNames.map(RunOnHostSandbox.EnvOption + _)
                  ++ Seq(RunOnHostSandbox.ChannelLogOption + logPath, "--"))*,
              ) ++ arguments,
              underBroker = true,
            ),
          os = Os.Mac,
          buildLock = RunOnHostSession.buildLockFile(root, _, _),
          runtime = (programName, buildDirectory, arguments) =>
            RunOnHostPrereqs.Program.values.find(_.name == programName)
              .toRight(s"unknown program $programName")
              .flatMap(runtimes.prepare(_, buildDirectory, arguments))
              .map(_.toSeq.flatMap(RunOnHostSandbox.runtimeOptions)),
          ended = programName =>
            RunOnHostPrereqs.Program.values.find(_.name == programName).foreach(runtimes.commandEnded),
          mount = trailing.headOption.getOrElse(WorkspaceMount),
        )
        log(s"serving $programsCsv for $project in $container")
        serve(transport, service, log)
        teardown(bySignal = false)
        log("the sandbox is gone; exiting")
      case other =>
        Console.err.println(s"--serve-run-on-host: unexpected arguments: ${other.mkString(" ")}")
        sys.exit(2)
