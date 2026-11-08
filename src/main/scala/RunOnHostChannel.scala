// The sandbox → host command channel: the FIFO protocol both sides speak, and the host-side runner that serves it.
//
// - The sandbox side is the image's ko-sandbox-run-on-host shim.
// - The runner is a detached process of the launcher's own executable, the jar or the native binary. The launcher
//   spawns one runner per session under --run-on-host.
// - SECURITY.md, "Run on host", has what the channel grants and withholds.

package agentsandbox.launcher

import java.io.{ByteArrayOutputStream, IOException, InputStream, OutputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.{AtomicBoolean, AtomicReference}

import scala.util.control.NonFatal

import agentsandbox.egress.{BrokeredCredential, CredentialGrammar}

import HostCommands.Os

object RunOnHostChannel:

  /**
   * The channel's directory in the sandbox.
   *
   * The directory holds one well-known FIFO, `req`, and everything else in it is scoped to a transaction.
   *
   *   - The runner's first exec makes `req`. A session without the channel thus has no `req`, and the shim fails at
   *     once.
   *   - The shim takes the lock and creates its own `ctl.<pid>`, `out.<pid>`, `err.<pid>` and `exit.<pid>`.
   *   - The shim writes its pid to `req` as one line. A single write frames itself.
   *   - The shim then sends the request over `ctl.<pid>`: `<program> <argc>\n`, then argc+1 NUL-terminated fields.
   *     The fields are the working directory in its container spelling, then the arguments.
   *   - The shim holds `ctl.<pid>` open for the life of the transaction. The shim reads `out` and `err` to EOF, and
   *     its exit code from `exit`.
   *
   * The request travels on the liveness descriptor, so no request is ever runnable without its liveness.
   *
   *   - The runner acts on `ctl`'s EOF alone. An interrupted shim, a killed shim and a dead container all close the
   *     descriptor.
   *   - The runner then ends the running command with SIGTERM, the supervisor's own measured teardown
   *     (RunOnHostSession).
   *   - A handshake whose `ctl` never opens, or whose request never completes, expires on a deadline with no command
   *     started.
   *   - The shim bounds its startup until both output streams are open, then separately bounds the exit-status read.
   *     The shim exits 70 on either timeout.
   *   - Waiting for the lock and draining command output have no deadline.
   *   - The data FIFOs belong to the transaction. A later shim therefore cannot attach to a predecessor's streams,
   *     even though the lock frees when its holder dies. A reused pid takes fresh inodes, never leftovers.
   *
   * The runner reads `req` through one exec at a time, and each exec serves every handshake it delivers, in order.
   * The runner answers through short execs. The sandbox thus opens nothing outward, and the host runs nothing it
   * did not start.
   *
   * A second writer scribbling on `req` or on a transaction's FIFOs is the agent breaking its own channel. The
   * runner drops what it cannot frame, and the authority it enforces is unaffected.
   */
  val SandboxDir = "/tmp/ko-agent-sandbox/run-on-host"

  /**
   * Set in the sandbox to the programs that `--run-on-host` names.
   *
   *   - The variable tells the shim to wait for a `req` that the runner may not have made yet.
   *   - The variable is the one place that tells the agent the channel exists.
   */
  val RunOnHostVariable = "KO_AGENT_SANDBOX_RUN_ON_HOST"

  def handshakeReader(sandboxDir: String): String =
    s"trap \"\" INT HUP TERM; d=$sandboxDir; mkdir -p -m 700 $$d; " +
      s"[ -p $$d/req ] || mkfifo -m 600 $$d/req; cat $$d/req"

  /** A pid. The id is interpolated into the transaction's FIFO names, so nothing else is accepted. */
  private val TransactionId = "[0-9]{1,18}".r

  /** The bounds on a request.
    *
    *   - A request is small: a path and a command line. A huge request is framing gone wrong, not a command to run,
    *     and the runner refuses it before committing memory to it.
    *   - The runner parses these bytes on the host, so every read is bounded: the handshake, the header, and the
    *     fields as a whole.
    *   - The runner still drains an over-bound frame, without storing it, up to DrainBytes, which lies comfortably
    *     past any ARG_MAX. The requester opens its response readers only after writing the whole request, and a
    *     refusal it never gets to read is a hang, not an answer. */
  val MaxArguments = 4096
  val MaxRequestBytes = 8 << 20
  val MaxLineBytes = 4096
  val DrainBytes = 64 << 20

  final case class Request(program: String, workingDirectory: String, arguments: Vector[String])

  /** One request off the stream. Right(None) is EOF at a request boundary. Left means that the stream can no longer be
    * trusted to frame anything, and tells the caller to drop the stream whole. */
  def readRequest(in: InputStream): Either[String, Option[Request]] =
    readLine(in).flatMap:
      case None => Right(None)
      case Some(header) =>
        header.split(" ", 2) match
          case Array(program, count) if agentsandbox.egress.HTTPHelper.isDecimal(count) =>
            count.toIntOption match
              case None =>
                Left(s"request names $count arguments, over the $MaxArguments bound")
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
                      // The read stopped inside a field, so that field's own NUL is the first of the remainder
                      // being drained.
                      drainFields(in, argc.toLong + 1 - index)
                      failed = Some(reason)
                  index += 1
                failed.toLeft(()).map: _ =>
                  val all = fields.result()
                  Some(Request(program, all.head, all.tail))
          case _ => Left(s"request header is not `<program> <argc>`: $header")

  /** Right(None) at EOF before any byte. Left on a line that passes the bound, since such a line cannot be framed. */
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

  /** Consumes the rest of an over-bound frame without storing it, so that the requester finishes its write and
    * reaches the readers on which the refusal answers.
    *
    *   - EOF or DrainBytes ends the attempt. Past DrainBytes, nothing legitimate is writing, and the caller's refusal
    *     is bounded anyway.
    *   - Every consumed byte is charged, the NUL delimiters included. A NUL-dense frame must exhaust the byte budget,
    *     and never obtain a field-counted pass through the parser. */
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

  /** The field and the bytes it consumed, its NUL included, as drainFields charges them. The bound is tested before
    * each read. A field refused after its NUL was read would leave the caller's drain waiting for one NUL more than
    * the requester writes. */
  private def readField(in: InputStream, budget: Int): Either[String, (String, Int)] =
    val buffer = ByteArrayOutputStream()
    var result: Option[Either[String, (String, Int)]] = None
    while result.isEmpty do
      if buffer.size >= budget then
        result = Some(Left(s"the request passed the $MaxRequestBytes-byte bound"))
      else
        in.read() match
          case -1   => result = Some(Left("the stream ended inside a request"))
          case 0    => result = Some(Right((String(buffer.toByteArray, UTF_8), buffer.size + 1)))
          case byte => buffer.write(byte)
    result.get

  // ---------------------------------------------------------------------------
  // The runner
  // ---------------------------------------------------------------------------

  /**
   * How the runner reaches the sandbox. The transport is data, so that the acceptance test and the tests can
   * substitute a local shell for `podman exec` (HostCommands.ExecWithInput). The tests stub the transport, never the
   * protocol.
   */
  final case class Transport(
    execPrefix: Seq[String],
    sandboxRunning: () => Boolean,
    /** Where the FIFOs are inside the sandbox. The value is the shim's own constant, and it is a parameter only so
      * that a test can put both sides somewhere that is not a live session's channel. */
    sandboxDir: String = SandboxDir,
  )

  /** Everything one session's runner serves with:
    *
    *   - the launcher's canonical workspace root;
    *   - the programs that `--run-on-host` named;
    *   - how a validated request becomes a supervisor command. The request's parts are the program, the working
    *     directory, the build lock file and the arguments. */
  final case class Service(
    workspaceRoot: Path,
    programs: Set[String],
    /** The supervisor under the build lock (RunOnHostSession.lockedSpawn, under the runner). dispatch speaks the lock
      * holder's protocol. */
    supervisorCommand: (String, Path, Path, Seq[String]) => Seq[String],
    /** The build lock file of a program and build directory (RunOnHostSession.buildLockFile). The supervisor holds
      * the lock for its life. */
    buildLock: (String, Path) => Either[String, Path],
    /** The runtime that a program's command in a build directory runs against, given the request's arguments.
      *
      *   - The runtime is prepared while the lock holder has the build lock.
      *   - The result is the supervisor options that name the runtime (RunOnHostSandbox.runtimeOptions). The result is
      *     empty for a program whose supervisor creates its own runtime. */
    runtime: (String, Path, Seq[String]) => Either[String, Seq[String]],
    /** What the runtime records once the command is over (RunnerRuntimes.commandEnded). The runner calls this
      * function with the request's program after a dispatched child ended: after its command ran, was refused, or
      * ended with its requester. */
    ended: String => Unit = _ => (),
    /** The path at which the workspace root is mounted inside the container, which is the root's own path
      * (SandboxWorkspace.mountPathOf). Requests arrive in this spelling. */
    mount: String,
    /** How long the runner waits for a complete request before the handshake expires. */
    requestDeadlineMillis: Long = 30_000,
    /** The brokered credentials that a program's supervisor reads after the word, given the program and the runtime
      * options that its word carries.
      *
      *   - The supervisor needs the credentials for the proxy it starts itself when the runner holds no runtime for the
      *     program (RunOnHostSandbox.CredentialsOption).
      *   - The text is as CredentialGrammar.bindingInput writes it. */
    credentialsFrame: (String, Seq[String]) => Option[String] = (_, _) => None,
  )

  /**
   * The runner's life: waits for the sandbox to run, then serves handshakes cycle by cycle while the sandbox still
   * runs.
   *
   *   - The loop is ClipboardRelay.serve's loop, with commands where the clipboard was.
   *   - Each cycle is one reader exec and every transaction that the exec's stream delivers.
   *   - Both waits are bounded pacing, not correctness. An idle cycle blocks in the handshake reader's own open.
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
   * Kills a transport exec whole, descendants first.
   *
   *   - The shell behind the exec may have forked the command it ran. A stubbed exec left its `cat` alive under
   *     pid 1 after destroyForcibly took only the shell (measured).
   *   - A surviving grandchild holds both the FIFO and this side's pipe open past the transaction. The grandchild
   *     then prevents EOF, and the runner stays blocked on a read.
   */
  private def end(process: Process): Unit =
    process.descendants().forEach(_.destroyForcibly())
    process.destroyForcibly()
    ()

  /**
   * Serves one reader exec and every handshake it delivers.
   *
   *   - The reader lives while a transaction runs. A shim whose predecessor just died can therefore hand its id to
   *     the *same* cat. The id is queued in the stream, and this method consumes it in order rather than discarding
   *     it with the exec.
   *   - False means that the cycle served nothing, and tells the caller to pace.
   *   - Garbage still dies with its reader.
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

  /** How to end the command that the runner is currently running, for the shutdown hook.
    *
    *   - A TERM to the runner ends the command too, rather than silently leaving it to finish.
    *   - The call returns only when the supervisor has ended, its teardown included. The runner's own session ends
    *     after that. */
  @volatile private var currentCommand: Option[() => Unit] = None

  def endCurrentCommand(): Unit = currentCommand.foreach(end => end())

  /** Where a dispatched child is, for an end asked of it, when the requester is gone or by endCurrentCommand.
    *
    *   - A child waiting for the build lock is destroyed at once.
    *   - A child preparing the runtime holds the lock that the preparation runs under. The end is therefore applied
    *     once the word is out: the word is the refusal, on which the child exits by itself.
    *   - A child running the supervisor is destroyed, and the supervisor's teardown answers. */
  private enum ChildPhase:
    case Waiting, Preparing, Running, Ending

  private def transact(
    transport: Transport,
    service: Service,
    id: String,
    log: String => Unit,
  ): Unit =
    // The transaction's liveness and its request are one stream. The exec ends when the shim ends or when the
    // container dies, and either way the signal is the same.
    val ctl = sandboxShell(transport, s"cat ${transport.sandboxDir}/ctl.$id")
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    ctl.getOutputStream.close()

    // The shim may have died between its handshake and opening ctl. The open above then never gets a writer, so a
    // request not complete by the deadline expires with no command started.
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
          // Answered, never silently dropped. The requester is real and waits at its FIFOs; a request over the
          // argument bound is the reachable case. A drop would leave the requester waiting for streams that nothing
          // will open.
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

  /** `dd conv=nocreat`, which opens without `O_CREAT`.
    *
    *   - A requester that died mid-request removed its FIFOs. A shell `>` would then leave a regular file where the
    *     next shim of that pid expects to make a FIFO.
    *   - dd writes each read's bytes as they come, as `cat` writes them. */
  private def writer(transport: Transport, id: String, name: String): Process =
    sandboxShell(transport, s"dd of=${transport.sandboxDir}/$name.$id conv=nocreat bs=65536 status=none")
      .redirectOutput(ProcessBuilder.Redirect.DISCARD)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()

  private def writeAll(stream: OutputStream, text: String): Unit =
    try
      stream.write(text.getBytes(UTF_8))
      stream.close()
    catch case _: IOException => ()

  /** Bounded, and safe to bound. This method runs only after the output writers have drained, so a live shim is
    * already at its exit read, and a dead shim has nobody waiting. */
  private def writeExit(transport: Transport, id: String, code: Int): Unit =
    try
      val exitWriter = writer(transport, id, "exit")
      writeAll(exitWriter.getOutputStream, s"$code\n")
      if !exitWriter.waitFor(10, TimeUnit.SECONDS) then end(exitWriter)
    catch case _: IOException => ()

  /** Answers that no command ran: the message on stderr and exit 2. Every wait is bounded, so a requester that died
    * mid-request cannot hold this method open. */
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
    val command = service.supervisorCommand(request.program, workingDirectory, lockFile, request.arguments)
    log(s"${request.program} in $workingDirectory: ${request.arguments.mkString(" ")}")
    try
      // The supervisor's stdin is this runner's pipe. The runner writes the word below once, and then holds the pipe.
      // The pipe's EOF means that the runner is gone, killed or ended. The supervisor ends the command at that EOF
      // (RunOnHostSandbox.runCommandMain), as this runner ends the command at ctl's EOF.
      val child = ProcessBuilder(command*).start()
      val ended = AtomicBoolean(false)
      val requesterGone = AtomicBoolean(false)
      val phase = AtomicReference(ChildPhase.Waiting)
      val endAsked = AtomicBoolean(false)
      def endChild(): Unit =
        endAsked.set(true)
        if phase.get == ChildPhase.Running || phase.compareAndSet(ChildPhase.Waiting, ChildPhase.Ending) then
          child.destroy()
      currentCommand = Some(() => { endChild(); child.waitFor(); () })
      // The writers die only with their requester. A slow reader is the requester's own pace, never a reason to
      // truncate its output. A requester that is gone unblocks everything this transaction still holds.
      ctl.onExit.thenRun: () =>
        if !ended.get then
          requesterGone.set(true)
          log("the requester is gone; ending the command")
          endChild()
          end(outWriter)
          end(errWriter)
      // stderr is pumped from the start, because the child announces its wait for the build lock there.
      val errPump = pump(child.getErrorStream, errWriter.getOutputStream)
      // The child's first line says that it holds the build lock. The child then execs the supervisor on the word.
      // The word is the runtime's options, or the refusal that the child prints before exiting 2. Any other first
      // line means that the child ended before the lock or was ended while it waited, and its exit is the answer.
      readLine(child.getInputStream) match
        case Right(Some(RunOnHostSession.LockedLine))
            if phase.compareAndSet(ChildPhase.Waiting, ChildPhase.Preparing) =>
          // Any failure to prepare becomes the refusal. An exception would leave the child waiting for a word, with
          // the lock held.
          val prepared =
            try service.runtime(request.program, workingDirectory, request.arguments)
            catch case NonFatal(ex) => Left(s"preparing the runtime: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
          val word = prepared match
            case Right(arguments) if !endAsked.get =>
              phase.set(ChildPhase.Running)
              // The frame goes after the word, not in it. The lock holder makes the word's fields the supervisor's
              // arguments, which other processes read (RunOnHostSession.LockScript).
              service.credentialsFrame(request.program, arguments) match
                case Some(frame) => RunOnHostSession.runWord(arguments :+ RunOnHostSandbox.CredentialsOption) + frame
                case None        => RunOnHostSession.runWord(arguments)
            case Right(_) =>
              phase.set(ChildPhase.Ending)
              RunOnHostSession.refusedWord("refused: the command was ended before it started")
            case Left(reason) =>
              log(s"refused: $reason")
              phase.set(ChildPhase.Ending)
              RunOnHostSession.refusedWord(s"refused: $reason")
          try
            child.getOutputStream.write(word.getBytes(UTF_8))
            child.getOutputStream.flush()
          catch case _: IOException => () // the child is gone; waited for below
          if endAsked.get && phase.get == ChildPhase.Running then child.destroy()
        case _ => ()
      val pumps = Seq(pump(child.getInputStream, outWriter.getOutputStream), errPump)
      val exit = child.waitFor()
      currentCommand = None
      pumps.foreach(_.join())
      try service.ended(request.program)
      catch case NonFatal(ex) => log(s"after the command: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
      // Nothing is retired here on a cancel. The runner follows each program, and sbt and Mill differ:
      //
      // - Stock sbt's server survives a client's disconnect. The disconnect cancels the exec
      //   (CommandExchange.removeChannel, force=false), and the warm server serves the next command.
      // - Stock Mill's daemon shuts itself down on a client's disconnect mid-command (Server.scala). The next mill
      //   command therefore starts a new daemon (RunnerRuntimes.prepare).
      if requesterGone.get then log(s"ended with $exit for a requester already gone")
      else
        // Only after both writers have drained. The shim reads the exit code last. An exit writer given up on while
        // the shim was still draining output would leave the shim blocked on a FIFO that no writer will ever open.
        outWriter.waitFor()
        errWriter.waitFor()
        // Set before the exit code goes out. The shim exits as soon as it has read the code, and on the host its ctl
        // closes before the exit writer's end is observed here. The command has exited and both streams have
        // drained, so nothing is left to end. writeExit's bound covers a requester gone before reading the code.
        ended.set(true)
        writeExit(transport, id, exit)
        log(s"exit $exit")
    catch
      case ex: IOException =>
        log(s"could not start the supervisor: ${ex.getMessage}")
        writeAll(outWriter.getOutputStream, "")
        writeAll(errWriter.getOutputStream, s"could not start the command supervisor: ${ex.getMessage}\n")
        writeExit(transport, id, 2)
    finally
      currentCommand = None
      Seq(outWriter, errWriter).foreach: process =>
        if !process.waitFor(10, TimeUnit.SECONDS) then end(process)

  private def pump(from: InputStream, to: OutputStream): Thread =
    // The JVM buffers writes to podman exec's stdin, and short build output must reach the agent before EOF.
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

  /** The channel's boundary work.
    *
    *   - The program must be among those that `--run-on-host` named.
    *   - The working directory is the one value that arrives from inside the sandbox. This method translates it and
    *     checks that it resolves inside the workspace, before anything is derived from it. */
  def validated(service: Service, request: Request): Either[String, Path] =
    if !service.programs(request.program) then
      Left(
        s"CHANNEL_UNAVAILABLE: this session's --run-on-host does not name ${request.program}; " +
          s"it serves ${service.programs.toSeq.sorted.mkString(", ")}",
      )
    else
      RunOnHostPrereqs
        .workingDirectory(
          request.workingDirectory, service.mount, service.workspaceRoot, FileHelper.realPath, Os.Mac,
        )
        .left.map(_ =>
          s"CHANNEL_UNAVAILABLE: working directory ${request.workingDirectory} is not the " +
            "workspace root or beneath it",
        )

  // ---------------------------------------------------------------------------
  // The production main, behind the launcher's private action
  // ---------------------------------------------------------------------------

  /**
   * Spawns the runner, detached like the reaper.
   *
   *   - The runner's stdio goes to /dev/null, and the runner must outlive the launcher's exec.
   *   - The terminal's INT and HUP are ignored before the exec. sh's ignore is inherited, and a JVM leaves an
   *     inherited SIG_IGN in place. A Ctrl-C at the session's terminal therefore cannot take the runner before its
   *     sandbox.
   *   - TERM stays live. A deliberate kill ends the runner, and the runner's shutdown hook ends the running command
   *     and the runner's session with it.
   */
  def spawnRunner(
    podman: String,
    container: String,
    workspaceRoot: Path,
    programs: Seq[String],
    logFile: Path,
    mount: String,
    // `--env` as launched.
    //
    // - The names travel as arguments down to each command.
    // - The values travel through this process's environment under inert carrier names
    //   (RunOnHostSandbox.carrierName). No argument below the launcher thus carries a value, and no trusted helper
    //   reads an explicit value.
    // - A name-only forward's own variable is in this environment regardless, inherited as the launcher's whole
    //   environment is.
    forwards: Vector[CommandLine.EnvForward] = Vector.empty,
    // The launch's resolved file rules. Every profile that the runner and its commands render denies writes to the
    // files they name (RunOnHostSandbox.fileRulesOf).
    fileRules: Option[Path] = None,
    // The brokered credentials, written to the runner's standard input. The credentials go by pipe, as everywhere below
    // the launcher, never by an environment variable or an argument (design.md, "Credential brokering at the egress
    // proxy").
    credentials: Seq[BrokeredCredential] = Seq.empty,
  ): Boolean =
    try
      val builder = ProcessBuilder(
        (Seq("/bin/sh", "-c", "trap '' INT HUP; exec \"$@\"", "ko-agent-run-on-host-runner")
          ++ RunOnHostSandbox.selfInvocation(
            (Seq(
              "--serve-run-on-host", podman, container, workspaceRoot.toString,
              programs.mkString(","), logFile.toString,
            ) ++ forwards.map(forward => RunOnHostSandbox.EnvOption + forward.name)
              ++ fileRules.map(file => RunOnHostSandbox.FileRulesOption + file)
              ++ Option.when(credentials.nonEmpty)(RunOnHostSandbox.CredentialsOption) :+ mount)*,
          ))*,
      )
      EgressCredentials.scrub(builder)
      forwards.foreach: forward =>
        forward.value.orElse(Option(System.getenv(forward.name))).foreach: value =>
          builder.environment.put(RunOnHostSandbox.carrierName(forward.name), value)
      if credentials.isEmpty then builder.redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
      builder.redirectOutput(ProcessBuilder.Redirect.DISCARD)
      builder.redirectError(ProcessBuilder.Redirect.DISCARD)
      val runner = builder.start()
      val input = runner.getOutputStream
      try if credentials.nonEmpty then input.write(CredentialGrammar.bindingBytes(credentials))
      finally input.close()
      true
    catch case _: IOException => false

  /** `--serve-run-on-host <podman> <container> <workspace-root> <programs-csv> <log-file>
    * [--env=<name>...] [--file-rules=<file>] [--credentials-on-stdin] <mount>`.
    *
    *   - The launcher spawns the runner before it hands over to podman, detached like the reaper.
    *   - The trailing mount is the path at which the workspace root is mounted inside the container. The acceptance
    *     test's shim also passes the root's own path. */
  def serveMain(args: Seq[String]): Unit =
    def isOption(arg: String) =
      arg.startsWith(RunOnHostSandbox.EnvOption) || arg.startsWith(RunOnHostSandbox.FileRulesOption)
        || arg == RunOnHostSandbox.CredentialsOption
    args match
      case Seq(podman, container, workspaceArg, programsCsv, logFile, rest*) if rest.filterNot(isOption).sizeIs == 1 =>
        // Read first, because the launcher wrote the credentials before the runner could read anything else.
        val credentials =
          if !rest.contains(RunOnHostSandbox.CredentialsOption) then Vector.empty
          else
            RunOnHostSandbox.readStdinCredentials().fold(
              reason => { Console.err.println(s"--serve-run-on-host: the brokered credentials: $reason"); sys.exit(2) },
              identity,
            )
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
        val workspaceRoot =
          try Path.of(workspaceArg).toRealPath()
          catch
            case ex: IOException =>
              log(s"workspace root $workspaceArg: ${ex.getMessage}")
              sys.exit(1)
        val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
        val root = RunOnHostSession.root(uid)
        // The runner's session is published for the launch's lifetime, after the scavenge that every start runs. The
        // session ends at the serve loop's end or from the TERM hook. The session's tmp/ is the sbt server's socket
        // directory, so the socket path budget applies to that directory.
        val session =
          RunOnHostSession.ensureRoot(root, uid).flatMap { _ =>
            RunOnHostSession
              .scavenge(root, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_))
              .foreach((entry, actions) => log(s"scavenged ${entry.getFileName}: ${actions.mkString(", ")}"))
            RunOnHostSession.publish(root, workspaceRoot, RunOnHostSession.Kind.Runner)
          }.flatMap: session =>
            RunOnHostPrereqs.sessionTmpFits(session.tmp).map(_ => session).left.map(RunOnHostPrereqs.wording(_))
          match
            case Right(session) => session
            case Left(reason) =>
              log(s"the runner's session: $reason")
              sys.exit(1)
        try java.nio.file.Files.writeString(session.directory.resolve(RunOnHostSession.RunFile), container + "\n")
        catch case ex: IOException => log(s"the runner's run file: ${ex.getMessage}")
        val fileRulesOption = rest.filter(_.startsWith(RunOnHostSandbox.FileRulesOption))
        val fileRules = RunOnHostSandbox.fileRulesOf(fileRulesOption, workspaceRoot) match
          case Right(resolved) => resolved
          case Left(reason) =>
            log(s"the file rules: $reason")
            sys.exit(1)
        // The forwarded values come from this process's environment under their carrier names, as the supervisor
        // reads them. The system paths are the ones the artifact bundles, as the supervisor's are.
        val runtimes = RunnerRuntimes(
          session, workspaceRoot, log, RunOnHostSandbox.bundledSystemPaths(),
          forwardedNames.flatMap(name => Option(System.getenv(RunOnHostSandbox.carrierName(name))).map(name -> _)),
          fileRules,
          credentials,
          Some(logPath),
        )(scavenge = () =>
          RunOnHostSession
            .scavenge(
              root, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_),
              ownSession = Some(session.directory),
            )
            .foreach((entry, actions) => log(s"scavenged ${entry.getFileName}: ${actions.mkString(", ")}")))
        // The runtimes' groups end with the session, after their audit logs are appended to this log. The teardown
        // runs under the runtimes' monitor, for the reason RunnerRuntimes gives.
        val teardown = RunOnHostSession.Teardown: _ =>
          runtimes.synchronized:
            // A command may still run at the runner's end and may have started a daemon. That daemon is observed
            // here, after endCurrentCommand and before the records are read.
            runtimes.commandEnded(RunOnHostPrereqs.Program.Gradle)
            RunOnHostSession
              .endSession(root, session, RunOnHostSession.HostProcesses, RunOnHostSbtServerShutdown.shutdown(_),
                beforeRemoval = condemned =>
                  RunOnHostSandbox.appendSessionLogs(
                    logPath, condemned, s"the runner's session ${condemned.getFileName} ended",
                  ))
              .foreach(action => log(s"the runner's session ended: $action"))
        Runtime.getRuntime.addShutdownHook(Thread(() =>
          endCurrentCommand()
          teardown(bySignal = true)))
        val transport = Transport(
          execPrefix = podman +: HostCommands.ExecWithInput :+ container,
          sandboxRunning = () => HostCommands.containerRunning(podman, container),
        )
        val service = Service(
          workspaceRoot = workspaceRoot,
          programs = programsCsv.split(",").toSet,
          supervisorCommand = (program, workingDirectory, lockFile, arguments) =>
            RunOnHostSession.lockedSpawn(
              lockFile,
              RunOnHostSandbox.selfInvocation(
                (Seq("--run-command-on-host", program, workspaceRoot.toString, workingDirectory.toString)
                  ++ forwardedNames.map(RunOnHostSandbox.EnvOption + _) ++ fileRulesOption
                  ++ Seq(RunOnHostSandbox.ChannelLogOption + logPath, "--"))*,
              ) ++ arguments,
              underRunner = true,
            ),
          buildLock = RunOnHostSession.buildLockFile(root, _, _),
          runtime = (programName, buildDirectory, arguments) =>
            RunOnHostPrereqs.Program.named(programName)
              .toRight(s"unknown program $programName")
              .flatMap(runtimes.prepare(_, buildDirectory, arguments))
              .map(_.toSeq.flatMap(RunOnHostSandbox.runtimeOptions)),
          ended = programName =>
            RunOnHostPrereqs.Program.named(programName).foreach(runtimes.commandEnded),
          mount = trailing.head,
          // A command the runner holds a runtime for uses that runtime's proxy, which the runner started.
          credentialsFrame = (programName, runtimeArguments) =>
            RunOnHostPrereqs.Program.named(programName)
              .filter(_ => runtimeArguments.isEmpty)
              .flatMap(program => RunOnHostPrereqs.readProgramRules(workspaceRoot, program).toOption.map(program -> _))
              .map((program, hosts) => RunOnHostSandbox.credentialsFor(program, hosts, credentials))
              .filter(_.nonEmpty)
              .map(CredentialGrammar.bindingInput),
        )
        log(s"serving $programsCsv for $workspaceRoot in $container")
        serve(transport, service, log)
        teardown(bySignal = false)
        log("the sandbox is gone; exiting")
      case other =>
        Console.err.println(s"--serve-run-on-host: unexpected arguments: ${other.mkString(" ")}")
        sys.exit(2)
