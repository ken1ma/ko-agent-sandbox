// The runner's runtimes, kept for a launch's commands: per build directory and program, a proxy and the sbt server or
// mill daemon that the program's clients attach to. RunOnHostSandbox.scala holds one command's steps.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{Files, Path}

import scala.util.control.NonFatal

import agentsandbox.egress.{BrokeredCredential, LogHelper}

import RunOnHostPrereqs.*
import RunOnHostProxy.*
import RunOnHostSandbox.*
import RunOnHostSbtServer.*
import RunOnHostSession.{daemonRecordName, proxyRecordName, serverRecordName, Session}

/**
 * The runner's runtimes: one per build directory and program.
 *
 *   - A runtime is a proxy, and the server or daemon that the program's clients attach to: sbt's server or mill's
 *     daemon.
 *   - A runtime is kept warm across the launch's commands from that directory while its proxy lives.
 *   - Visiting another build directory leaves the runtimes already made alive, since `live` is keyed by program and
 *     the build directory's hash. Alternating between a root and a nested build therefore keeps both warm.
 *   - A runtime is replaced whole only when its own proxy is gone.
 *   - A server or daemon that went away on its own, by `shutdown` or the program's idle exit, is replaced under the
 *     same proxy. The records and the build file are deleted only when the last runtime of the hash is retired.
 *   - A mill daemon whose configuration changed is replaced the same way. The configuration is the one Mill's
 *     launcher restarts the daemon on (RunOnHostPrereqs.millDaemonConfig). The replacement is assembled afresh,
 *     since a changed version pin grants another launcher.
 *   - On a cancel, the runner follows each program:
 *     - A cancelled sbt command's server is not retired, since stock sbt's disconnect cancels the exec and leaves the
 *       server.
 *     - A cancelled mill command's daemon shuts itself down, as stock Mill's daemon does on a disconnect
 *       mid-command, so the next mill command starts a new daemon.
 *   - Gradle's runtime is its proxy. The client starts and matches the daemon in the launch's own registry, inside
 *     the profile. The runner records the registry's daemons after each command and ends them with its session
 *     (RunOnHostGradleDaemons).
 *   - A mill launcher that runs its build without a daemon (Assembled.millWithoutDaemon) has a runtime that is its
 *     proxy, as Gradle's is.
 *   - Maven is never here: Maven runs once and exits, and its proxy ends with the command.
 *   - The acceptance test's entry holds one of these objects over the command's own session for its one command. The
 *     one lifecycle thus has two callers and no second owner.
 *
 * Another launch may own the build directory's server or daemon (SECURITY.md, "Run on host").
 *
 *   - This runner attaches its command to that runtime if the runner would start one under the same confinement and
 *     environment (`attached`).
 *   - Otherwise, this runner ends that runtime by its owner's record under the retirement lock, and starts its own
 *     (`takeOver`). The takeover is the one case in which a runner signals a live launch's group that is not its own.
 *     The scavenger collects a dead launch's group.
 *   - `scavenge` runs before each preparation, so that the exclusive scavenger collects a dead owner before a fresh
 *     server or daemon starts. An owner that dies after the scavenge is taken over.
 *   - Preparation and the session's end share this object's monitor.
 *   - Tests replace the second parameter list, and register a stand-in leader where the proxy, server or daemon
 *     would be, and they stub the scavenger.
 */
final class RunnerRuntimes(
  session: Session,
  workspaceRoot: Path,
  log: String => Unit,
  systemPaths: SeatbeltProfile.SystemPaths,
  forwards: Vector[(String, String)],
  fileRules: FileRules.Resolved,
  credentials: Vector[BrokeredCredential] = Vector.empty,
  // The launch's channel log. Each proxy's audit log is kept beside it (RunOnHostProxy.keepAuditLog).
  channelLog: Option[Path] = None,
)(
  processes: RunOnHostSession.Processes = RunOnHostSession.HostProcesses,
  assemble: (Path, Program, Path) => Either[String, Assembled] =
    (workspaceRoot, program, buildDirectory) =>
      RunOnHostSandbox.assemble(workspaceRoot, program, name => Option(System.getenv(name)), buildDirectory),
  proxy: (Program, Vector[String], Path, Path) => Either[String, Int] =
    createProxy(systemPaths, credentials, channelLog),
  server: RuntimeStart => Either[String, Unit] = start => startSbtServer(session, start),
  daemon: RuntimeStart => Either[String, RunOnHostMillDaemons.Daemon] =
    start => RunOnHostMillDaemons.start(session, RunOnHostSession.HostProcesses, log, start),
  scavenge: () => Unit = () => (),
  // The daemons in the launch's registry under the given tmp/ (RunOnHostGradleDaemons.daemons).
  gradleDaemons: Path => Vector[(Long, String)] = RunOnHostGradleDaemons.daemons(_, RunOnHostSession.HostProcesses),
  executable: () => Either[String, Option[Path]] = () => selfPresent(),
):
  /** A runtime with the rule hosts that its proxy was created from. For mill, it also holds the daemon and the
    * configuration the daemon was started from. */
  private case class Live(
    buildDirectory: Path, hash: String, assembled: Assembled, runtime: Runtime, hosts: Vector[String],
    daemon: Option[RunOnHostMillDaemons.Daemon] = None, daemonConfig: String = "",
  )
  // Keyed by program and the build directory's hash: one runtime per (directory, program), all kept warm.
  private var live = Map.empty[(Program, String), Live]
  private val env: String => Option[String] = name => Option(System.getenv(name))
  private val root = session.directory.getParent

  private def proxyRecord(program: Program, hash: String): Path =
    session.records.resolve(proxyRecordName(program, hash))
  private def serverRecord(hash: String): Path = session.records.resolve(serverRecordName(hash))
  private def daemonRecord(hash: String): Path = session.records.resolve(daemonRecordName(hash))

  /** The runtime that a command in `buildDirectory` runs against, or None for Maven.
    *
    *   - `arguments` are the request's, for a server that this call starts.
    *   - The caller calls this while the command's lock holder has the build lock.
    *   - A dead owner is collected first, so a stale portfile or record cannot block a fresh start. */
  def prepare(program: Program, buildDirectory: Path, arguments: Seq[String]): Either[String, Option[Runtime]] =
    synchronized:
      // Scavenge before every dispatched command, Maven's included. A dead owner in any build directory must be
      // collected on the next launch's next command, not only when that command needs a runtime of its own.
      scavenge()
      // The lock holder execs the supervisor on the word that this method returns (RunOnHostChannel.dispatch). The
      // check here is therefore the executable's last check before that exec, Maven's included
      // (RunOnHostSandbox.selfPresent explains why).
      executable().flatMap: _ =>
        if program == Program.Mvn then Right(None)
        else
          val hash = RunOnHostSession.buildHash(buildDirectory)
          val key = (program, hash)
          // Checked before a mill client or starter runs. Mill's launcher acts on the rendezvous directory as it finds
          // it, so a redirected directory is refused here, never handed to the launcher.
          val rendezvous =
            if program == Program.Mill then RunOnHostMillDaemons.rendezvousIsOwn(buildDirectory) else Right(())
          rendezvous.flatMap(_ => prepared(program, buildDirectory, hash, key, arguments))

  /** Records the launch's Gradle daemons after a dispatched command ended, however it ended, and before the session's
    * end, so that the session's end takes them (RunOnHostGradleDaemons.record). The registry is the launch's, one for
    * every build directory, so the program alone says whether there is anything to observe. */
  def commandEnded(program: Program): Unit =
    synchronized:
      if program == Program.Gradle then
        RunOnHostGradleDaemons.record(session.records, gradleDaemons(session.tmp), processes).foreach(log)

  /** prepare, past the mill rendezvous check: reuses the runtime, replaces its server or daemon, or creates the
    * runtime. */
  private def prepared(
    program: Program, buildDirectory: Path, hash: String, key: (Program, String), arguments: Seq[String],
  ): Either[String, Option[Runtime]] =
    live.get(key) match
      case Some(current) if lives(proxyRecord(program, hash)) && program == Program.Sbt =>
        // The client attaches to this build directory's own server.
        //
        // - Reuse only when the portfile names the exact socket that sbt derives for it under this session's tmp/, and
        //   the record's group still lives.
        // - namesDerivedSocket checks the spelling, and that neither the socket nor its directory is a symlink. A
        //   portfile copied from another warm build directory, or a socket directory redirected to one, therefore does
        //   not send this client to that directory's server.
        // - Otherwise the server is gone or the portfile no longer names it. A fresh server then starts under the same
        //   proxy (startServer sweeps first).
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
        // The runtime is the proxy. Gradle's client matches a daemon in the launch's registry or starts one, inside
        // the profile, and commandEnded records the daemon.
        Right(Some(current.runtime))
      case Some(current) if lives(proxyRecord(program, hash)) =>
        // The client is confined to the daemon's port.
        //
        // - Reuse only the daemon identified at its start, alive with its start time, under the configuration it was
        //   started from.
        // - A daemon may be gone, by its idle exit, by `shutdown`, or by the cancel that ends it as stock Mill does. A
        //   daemon may also run under a changed configuration. In either case, a fresh daemon starts under the same
        //   proxy, from a fresh assembly: a changed version pin grants another launcher, and the assembly is what
        //   grants it.
        // - The exit file of the daemon's starter shows no liveness, since the starter is ended, or exits, by design
        //   once the daemon is up.
        // - A runtime for a launcher that runs without a daemon is its proxy, reused until the configuration changes.
        daemonConfig(buildDirectory).flatMap: config =>
          val same = config == current.daemonConfig
          if same && (current.assembled.millWithoutDaemon || current.daemon.exists(daemonLives)) then
            Right(Some(current.runtime))
          else
            val why = if same then "its daemon is gone" else "its configuration changed"
            discard(program, hash, daemonRecord(hash)).flatMap: what =>
              log(s"retired ${daemonRecord(hash).getFileName}, $why: $what")
              foreignRuntime(program, buildDirectory, hash).flatMap:
                case Some(shared) => Right(Some(shared))
                case None =>
                  for
                    fresh <- assemble(workspaceRoot, program, buildDirectory)
                    started <- daemonFor(current.copy(assembled = fresh), config)
                  yield
                    live += key -> started
                    Some(started.runtime)
      case Some(current) =>
        // The proxy is gone, so the whole runtime for this key is replaced, and its records and build file are deleted.
        // The runtime is forgotten only once discarded. A retirement that throws, or that leaves a group alive behind
        // its record, is retried.
        discardRuntime(program, hash, current.runtime.proxyLog).flatMap: what =>
          log(s"retired the ${program.name} runtime for $buildDirectory, its proxy is gone: $what")
          live -= key
          create(program, buildDirectory, hash, arguments)
      case None =>
        create(program, buildDirectory, hash, arguments)

  /** The runtime for a key that this launch holds no runtime for: another launch's runtime, attached to, or this
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
    val name = proxyRecordName(program, hash)
    val proxyLog = session.directory.resolve(s"$name.log")
    // An exception after a leader registered is a failed start like any other.
    val started =
      try
        for
          _ <- RunOnHostSession.publishBuildFile(session.directory, hash, buildDirectory)
          assembled <- assemble(workspaceRoot, program, buildDirectory)
          hosts <- readProgramRules(workspaceRoot, program)
          // A record that a failed creation kept is discarded. Otherwise the leader that would rename over it is
          // refused.
          _ <- discard(program, hash, proxyRecord(program, hash))
          port <- proxy(program, hosts, proxyRecord(program, hash), proxyLog)
          made = Live(buildDirectory, hash, assembled, Runtime(session.directory, port, proxyLog), hosts)
          current <- program match
            case Program.Sbt                  => startServer(made, arguments).map(_ => made)
            case Program.Mill                 => daemonConfig(buildDirectory).flatMap(daemonFor(made, _))
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
        // A leader may have registered while its proxy never reported ready. Left alone, its group would outlive the
        // record that the next attempt's leader renames over, and its late ready line would be read as that attempt's.
        Left(discardRuntime(program, hash, proxyLog).fold(kept => s"$reason; $kept", _ => reason))

  /** What `current`'s server or daemon is started from, registered at `record` and under `network`. */
  private def runtimeStart(
    current: Live, record: Path, network: SeatbeltProfile.Network, arguments: Seq[String] = Seq.empty,
  ): RuntimeStart =
    RuntimeStart(
      current.assembled, current.buildDirectory, current.hash, record, current.runtime,
      runtimeInputs(
        current.assembled, session.tmp, current.runtime.proxyPort, current.runtime.trust, systemPaths, forwards,
        network, fileRules,
      ),
      arguments,
    )

  /** Starts the server of a runtime whose proxy is up.
    *
    *   - No other launch owns the build directory's server. Every caller decides that first (foreignRuntime).
    *   - The server starts once no foreign server holds its portfile.
    *   - Once up, the server is described for other launches (publishDescriptor).
    *   - A start that fails, by refusal or exception, leaves no group behind its record.
    *   - A record that an earlier failure kept is discarded first. While that record's group lives, the record
    *     refuses the start, because the leader would rename over it. */
  private def startServer(current: Live, arguments: Seq[String]): Either[String, Unit] =
    val record = serverRecord(current.hash)
    val start = runtimeStart(current, record, SeatbeltProfile.Network.ProxyOnly, arguments)
    val started =
      try
        discard(Program.Sbt, current.hash, record).flatMap(_ => noForeignServer(current)).flatMap: _ =>
          // After any foreign server is gone, not before: RunOnHostSbtServer.shutdownForeignServer waits for the user's
          // build to finish, and sweeping its `target/` links mid-build would corrupt the build. Before the start,
          // because our server fails loading on a link into a denied store.
          sweepTargetLinks(current.assembled)
          server(start)
        .flatMap(_ => publishDescriptor(Program.Sbt, current, start, None, None))
      catch case NonFatal(ex) => Left(s"starting the sbt server: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
    started.left.map: reason =>
      discard(Program.Sbt, current.hash, record).fold(kept => s"$reason; $kept", _ => reason)

  /** The runtime under `config` once its proxy is up: with the daemon that startDaemon starts, or with no daemon for a
    * launcher that runs without one (Assembled.millWithoutDaemon). */
  private def daemonFor(current: Live, config: String): Either[String, Live] =
    if current.assembled.millWithoutDaemon then
      Right(current.copy(
        runtime = current.runtime.copy(daemonPort = None, daemonPid = None),
        daemon = None,
        daemonConfig = config,
      ))
    else startDaemon(current, config)

  /** Starts the daemon of a runtime whose proxy is up.
    *
    *   - No other launch owns the build directory's daemon. Every caller decides that first (foreignRuntime).
    *   - The start itself ends a daemon of the user's own, once idle and after its start-time check
    *     (RunOnHostMillDaemons.start).
    *   - Once up, the daemon is described for other launches (publishDescriptor).
    *   - A start that fails, by refusal or exception, leaves no group behind its record.
    *   - A record that an earlier failure kept is discarded first, as startServer does. */
  private def startDaemon(current: Live, config: String): Either[String, Live] =
    val record = daemonRecord(current.hash)
    val start = runtimeStart(current, record, SeatbeltProfile.Network.MillDaemon)
    val started =
      try
        discard(Program.Mill, current.hash, record).flatMap(_ => daemon(start)).flatMap: found =>
          publishDescriptor(Program.Mill, current, start, Some(found), Some(config)).map(_ => found)
      catch case NonFatal(ex) => Left(s"starting the mill daemon: ${ex.getClass.getSimpleName}: ${ex.getMessage}")
    started match
      case Right(found) =>
        Right(current.copy(
          runtime = current.runtime.copy(daemonPort = Some(found.port), daemonPid = Some(found.pid)),
          daemon = Some(found),
          daemonConfig = config,
        ))
      case Left(reason) =>
        Left(discard(Program.Mill, current.hash, record).fold(kept => s"$reason; $kept", _ => reason))

  /** Publishes the runtime's descriptor once its server or daemon is up, so that another launch can attach by it
    * (RunOnHostRuntimeDescriptor).
    *
    *   - The descriptor holds the fingerprint of this start, and the proxy's record and the server's or daemon's
    *     record as they now read.
    *   - A descriptor that cannot be published is a failed start, which the caller discards. */
  private def publishDescriptor(
    program: Program, current: Live, start: RuntimeStart,
    daemon: Option[RunOnHostMillDaemons.Daemon], daemonConfig: Option[String],
  ): Either[String, Unit] =
    def read(file: Path): Either[String, RunOnHostSession.Record] =
      RunOnHostSession.readRecord(file).toRight(s"${file.getFileName} does not parse as a record")
    for
      proxy <- read(proxyRecord(program, current.hash))
      group <- read(start.record)
      _ <- RunOnHostRuntimeDescriptor.publish(
        RunOnHostRuntimeDescriptor.file(session.directory, program, current.hash),
        RunOnHostRuntimeDescriptor(
          RunOnHostRuntimeDescriptor.fingerprint(start.inputs, egressRuleText(program, current.hosts)),
          current.runtime.proxyPort, proxy, group, daemon, daemonConfig.map(LogHelper.sha256Hex),
        ),
      )
    yield ()

  private def daemonLives(found: RunOnHostMillDaemons.Daemon): Boolean =
    processes.startOf(found.pid).contains(found.start)

  private def daemonConfig(buildDirectory: Path): Either[String, String] =
    try Right(millDaemonConfig(buildDirectory, readLines, millJavaHomeText(buildDirectory)))
    catch case ex: Unreadable => Left(wording(ex.refusal))

  /** Removes the links that a tree the user's own sbt built leaves under `target/`
    * (RunOnHostSandbox.cleanForeignTargetLinks). Our server would fail loading on them. The sweep runs only when a
    * server starts, after any foreign server for the directory is shut down. */
  private def sweepTargetLinks(assembled: Assembled): Unit =
    val workspaceRoot = assembled.prereqs.workspaceRoot
    val swept = cleanForeignTargetLinks(workspaceRoot, workspaceRoot +: assembled.sbtCachesGranted)
    if swept.nonEmpty then
      log(s"removed ${swept.size} target/ links resolving outside the command's roots (first: ${swept.head})")

  /**
   * Checks that no server but this runner's holds the build directory's portfile when the runner's own server starts
   * (SECURITY.md, "Run on host", one server per build directory).
   *
   * Another launch's ownership is decided before this check (foreignRuntime). Another launch's server is attached to,
   * or ended by its record, never through the portfile. Beyond that:
   *
   *   - This launch's own derived socket may be live while this launch has no record identifying that server. That
   *     server is one this launch left unaccounted. The start is refused, so that the user ends the server by hand:
   *     starting a second server on the same socket would fail at the bind.
   *   - Any other live portfile socket is the user's own server, which is ended by protocol at the socket that sbt
   *     derives (RunOnHostSbtServer.shutdownForeignServer). The portfile's own spelling is never connected to.
   *   - A stale or planted portfile that names some other socket, and a missing portfile, authorize a start only once
   *     the ownership check has passed. The start writes this directory's own portfile.
   */
  private def noForeignServer(current: Live): Either[String, Unit] =
    val derived = expectedServerSocket(session.tmp, current.buildDirectory)
    livePortfileServer(current.buildDirectory) match
      case Some(socket) if namesDerivedSocket(current.buildDirectory, session.tmp) =>
        Left(
          s"a live sbt server holds the portfile of ${current.buildDirectory} at its own derived socket " +
            s"$socket, while this launch has no record identifying this server; end it by hand and retry",
        )
      case Some(socket) if socket == derived || RunOnHostSession.containedSocket(socket, session.tmp).isDefined =>
        Right(()) // a stale, planted or redirected portfile under this launch, which our start overwrites
      case Some(socket) =>
        // The profile's own persistent writable set. A socket that an earlier command planted in a cache is then no
        // more a shutdown target than a socket planted in the workspace.
        shutdownForeignServer(
          workspaceRoot, current.buildDirectory, socket, env, log,
          runOnHostCaches = Seq(current.assembled.prereqs.coursierV1) ++ current.assembled.sbtCachesGranted,
        )
      case None => Right(())

  /**
   * Another launch's runtime for the build directory, attached to, or None once no other launch owns one. None means
   * that no other launch owned one, or that this launch took it over.
   *
   *   - This launch asks wherever it is about to start a server or daemon: for a fresh runtime, or for the replacement
   *     under its own live proxy. The owner's runtime is the one runtime the directory may have.
   *   - Another launch owns the directory's sbt server or mill daemon when its session has a `server-sbt-<hash>` or
   *     `daemon-mill-<hash>` record whose group is not known to be gone (`runtimeOwner`). The session may be live
   *     under the root, or in `condemned/` while its teardown or the scavenger is still collecting it.
   *   - The record is the ownership, not `build-<hash>`. A launch that ran only Mill in the directory publishes
   *     `build-<hash>` but no sbt server, so it reserves nothing for sbt.
   *   - The condemned scan keeps the claim through the owner's teardown. The owner's socket path has then moved with
   *     the rename, and a missing portfile would otherwise read as free.
   *   - `scavenge`, run first in prepare, collects a dead owner before this check. What remains is a launch still
   *     running, or a launch that died since.
   *   - The owner's runtime is attached to when this launch would start the same runtime (`attached`). Otherwise it is
   *     ended (`takeOver`), so that this launch's own runtime starts in its place.
   *   - Gradle's and Maven's runtimes are the launch's own, and another launch reads nothing of them.
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

  /** What another launch's runtime is to this launch's command: run against, or not, for the reason that a takeover
    * names. */
  private enum Attachment:
    case Attached(runtime: Runtime)
    case Unattachable(why: String)

  /**
   * The runtime that `owner`, another launch's runner session, holds for the build directory, for this launch's
   * command to run against, or why the command cannot. Left is this launch's own failure to assemble what it would
   * start.
   *
   * The runtime is attached to when the server or daemon that this launch would start has the running one's
   * confinement and environment (RunOnHostRuntimeDescriptor.fingerprint has what that covers and leaves out). All of
   * these must hold:
   *
   *   - The owner is live, which means locked under the root. An owner that is ending or dead is never attached to.
   *   - The owner's descriptor (RunOnHostRuntimeDescriptor) carries the fingerprint of this launch's own would-be
   *     start. This launch derives that fingerprint with the owner's `tmp/` and proxy port, and the rule file as read
   *     now.
   *   - The descriptor is bound to the owner's present records, and the leader of the owner's proxy lives.
   *   - For sbt, the server's leader lives, and the portfile names the socket derived under the owner's `tmp/`,
   *     unredirected.
   *   - For mill, the daemon bears its start time, and its configuration is the build directory's current one.
   *     `leaderLives` shows no liveness for a mill runtime, whose starter has exited by design.
   *
   * The command then runs against the owner's session, proxy and daemon port, exactly as the owner's own commands do
   * (`Runtime`). This launch records and keeps nothing of the runtime, and the next command asks again.
   *
   * What the sharer gives up (run-on-host-internals.md, "The channel and the command"):
   *
   *   - A cancel is the program's own, because the server or daemon is not this launch's to retire.
   *   - The owner's end takes the runtime, a build of this launch included.
   *   - This launch's audit lines land in the owner's proxy log.
   */
  private def attached(
    program: Program, buildDirectory: Path, hash: String, owner: Path,
  ): Either[String, Attachment] =
    val (network, groupRecord) = program match
      case Program.Mill => (SeatbeltProfile.Network.MillDaemon, daemonRecordName(hash))
      case _            => (SeatbeltProfile.Network.ProxyOnly, serverRecordName(hash))
    val ownerRecords = owner.resolve(RunOnHostSession.RecordsDir)
    def record(name: String): Option[RunOnHostSession.Record] =
      RunOnHostSession.readRecord(ownerRecords.resolve(name))
    val ownerTmp = owner.resolve(RunOnHostSession.TmpDir)
    val proxyName = proxyRecordName(program, hash)
    if !RunOnHostSession.liveRunnerSessions(root, session.directory).contains(owner) then
      Right(Attachment.Unattachable("that launch is ending, or gone and not yet collected"))
    else
      RunOnHostRuntimeDescriptor.read(RunOnHostRuntimeDescriptor.file(owner, program, hash)) match
        case None => Right(Attachment.Unattachable("no runtime descriptor this launcher reads is published for it"))
        case Some(descriptor) =>
          for
            assembled <- assemble(workspaceRoot, program, buildDirectory)
            hosts <- readProgramRules(workspaceRoot, program)
            config <- if program == Program.Mill then daemonConfig(buildDirectory).map(Some(_)) else Right(None)
          yield
            val ownerProxyLog = owner.resolve(s"$proxyName.log")
            val inputs = runtimeInputs(
              assembled, ownerTmp, descriptor.proxyPort, RunOnHostInspection.trustDirectory(ownerProxyLog),
              systemPaths, forwards, network, fileRules,
            )
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
                    else if !descriptor.daemonConfig.contains(LogHelper.sha256Hex(present)) then
                      Left("its daemon's configuration is not the build directory's")
                    else Right(())
                  case None =>
                    if !lives(ownerRecords.resolve(groupRecord)) then Left("its server is gone")
                    else if !namesDerivedSocket(buildDirectory, ownerTmp) then
                      Left("the portfile does not name its server's socket, or the socket is redirected")
                    else Right(())
              yield Runtime(
                owner, descriptor.proxyPort, ownerProxyLog,
                descriptor.daemon.map(_.port), descriptor.daemon.map(_.pid),
              )
            checked.fold(Attachment.Unattachable(_), Attachment.Attached(_))

  /**
   * Ends the runtime that `owner` holds for the build directory, so that this launch's own runtime starts in its
   * place, or gives the refusal when its group is not observed ended. `why` is what kept this launch from attaching.
   *
   * This method is one more holder of the record's retirement lock (RunOnHostSession.retirementLockFile).
   *
   *   - Under the build lock that its command holds, this method ends the group by `endRecordedGroup`'s own steps: the
   *     record is read only under the lock, the leader's pid must bear the recorded start time, and the signal goes
   *     to the pgid.
   *   - The record is left to its owner. The owner's next command finds the group dead, replaces the runtime under
   *     its own proxy, and decides here again: attach to this launch's runtime, or take it over.
   *   - Two launches whose runtimes differ therefore alternate restarts. That is the cost of the difference.
   *   - The owner's proxy is left running, and the owner replaces the server or daemon under it.
   *
   * Nothing is connected to, and no portfile is read.
   *
   *   - The record is the attribution, per program and build directory by construction. Neither a planted portfile
   *     nor a link under the owner's `tmp/` can therefore send this launch to another directory's server.
   *   - The start that follows treats the portfile as any start does (noForeignServer).
   *
   * Races with the owner's teardown:
   *
   *   - An owner tearing itself down holds the lock through its own end of the group. The wait on the lock, bounded
   *     by `RetirementDeadlineMillis`, is therefore the wait for that end.
   *   - Between the owner's lookup and this read, the owner's session can move into `condemned/`
   *     (RunOnHostSession.runtimeOwner has the rename). A record gone from where it was looked up is therefore looked
   *     up once more.
   *   - A record gone from both places is a finished teardown, whose group ended before the record was deleted.
   *   - A group listed after its KILL, or a leaderless group, keeps the record and keeps admission blocked, as it does
   *     under `discard`.
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
          s"another launch's runner (${owner.getFileName}) owns the $what for $buildDirectory; this launch " +
            s"cannot attach to it ($why), and its group is not ended: $kept; retry, or use a different build " +
            "directory",
        )
      case _ =>
        log(
          s"took over ${owner.getFileName}'s $what for $buildDirectory, which this launch cannot attach to " +
            s"($why): ${outcome.map(_.toString).getOrElse("no record")}",
        )
        Right(())

  /** The session of another launch that holds the ownership record `record`, or None.
    *
    *   - RunOnHostSession.runtimeOwner looks in the live sessions, then in the condemned ones. The lookup is race-safe
    *     across the teardown rename, and ignores a record whose group is dead.
    *   - This method only reads the record. Only `takeOver` signals the group, under the retirement lock. */
  private def runtimeOwner(record: String): Option[Path] =
    RunOnHostSession.runtimeOwner(root, session.directory, record, processes)

  /** Whether `buildDirectory`'s portfile names the server that a launch with session `tmp/` `tmp` runs for it.
    *
    *   - The portfile must name the exact socket that sbt derives under that `tmp/`, connectable, with neither the
    *     socket entry nor its parent a symlink.
    *   - The symlink checks matter because the server profile grants the build write across `tmp/`. Without them,
    *     moving the socket directory aside and linking it to another warm directory's would redirect this client while
    *     the spelling stayed the same. */
  private def namesDerivedSocket(buildDirectory: Path, tmp: Path): Boolean =
    val derived = expectedServerSocket(tmp, buildDirectory)
    livePortfileServer(buildDirectory).contains(derived)
      && !Files.isSymbolicLink(derived) && !Files.isSymbolicLink(derived.getParent)

  private def lives(record: Path): Boolean = RunOnHostSession.leaderLives(record, processes)

  /** Ends the groups that the runtime's records name, the server or daemon first, then the proxy, and deletes the
    * records.
    *
    *   - The proxy log goes with the records, since a successor of the same name would read this proxy's ready line as
    *     its own.
    *   - The build file goes last, once no record of the hash remains. Another program's runtime for the same
    *     directory may still publish under it.
    *   - The answer says what became of the groups, and is Left when `discard` keeps a record for the next start to
    *     retry.
    *   - The proxy's record is discarded, or the discard is tried, even when the server's or daemon's record is
    *     kept. */
  private def discardRuntime(program: Program, hash: String, proxyLog: Path): Either[String, String] =
    val attached = program match
      case Program.Sbt  => Some(discard(program, hash, serverRecord(hash)).map(what => s"server $what"))
      case Program.Mill => Some(discard(program, hash, daemonRecord(hash)).map(what => s"daemon $what"))
      case _            => None
    val proxy = discard(program, hash, proxyRecord(program, hash)).map(what => s"proxy $what")
    try
      Files.deleteIfExists(proxyLog)
      Files.deleteIfExists(proxyProfileFile(proxyLog))
      Files.deleteIfExists(runtimeProfileFile(session, serverRecordName(hash)))
      Files.deleteIfExists(runtimeProfileFile(session, daemonRecordName(hash)))
      val recordsOfHash =
        Program.values.map(proxyRecord(_, hash)) ++ Seq(serverRecord(hash), daemonRecord(hash))
      if !recordsOfHash.exists(Files.exists(_)) then
        Files.deleteIfExists(RunOnHostSession.buildFile(session.directory, hash))
    catch case ex: IOException => log(s"discarding the runtime for hash $hash: ${ex.getMessage}")
    val outcomes = attached.toSeq :+ proxy
    outcomes.collectFirst { case Left(kept) => kept }
      .toLeft(outcomes.collect { case Right(what) => what }.mkString(", "))

  /** Ends the group that one record of the runtime of `program` and `hash` names, under its retirement lock, and
    * deletes the record and its exit file.
    *
    *   - The outcome may keep the record (`Collected.keeps`), as when a member is still listed or the lock is not free
    *     within the bound. Left then says so, so that the caller starts nothing whose leader would rename its record
    *     over the kept one.
    *   - The runtime's descriptor goes first, before any of its groups is ended, so that another launch attaches to
    *     nothing that is ending. The start that follows republishes the descriptor. */
  private def discard(program: Program, hash: String, record: Path): Either[String, String] =
    try Files.deleteIfExists(RunOnHostRuntimeDescriptor.file(session.directory, program, hash))
    catch
      case ex: IOException =>
        log(s"discarding the ${program.name} runtime descriptor for hash $hash: ${ex.getMessage}")
    val ended = if Files.exists(record) then RunOnHostSession.endRecordedGroup(root, record, processes) else None
    RunOnHostSession
      .forgetUnlessKept(record, ended, ex => log(s"discarding ${record.getFileName}: ${ex.getMessage}"))
      .left.map(kept => s"${record.getFileName} kept for the next start to retry: $kept")
      .map(_.map(_.toString).getOrElse("no record"))
