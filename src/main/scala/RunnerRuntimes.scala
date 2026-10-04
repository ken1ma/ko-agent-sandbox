// The runner's runtimes, kept for a launch's commands: per build directory and program, a proxy and
// the sbt server or mill daemon its clients attach to. One command's steps are RunOnHostSandbox.scala.

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
 * The runner's runtimes: one per build directory and program — a proxy, and the server or
 * daemon the program's clients attach to, sbt's server and mill's daemon — kept warm across the
 * launch's commands from that directory while its proxy lives. Visiting another build
 * directory leaves the runtimes already made alive (`live` is keyed by program and the build
 * directory's hash), so alternating between a root and a nested build keeps both warm. A
 * runtime is replaced whole only when its own proxy is gone. A server or daemon gone on its
 * own — `shutdown`, the program's idle exit — is replaced under the same proxy, the records and
 * build file deleted only when the last runtime of the hash is retired; so is a mill daemon
 * whose configuration changed, the one Mill's launcher restarts it on
 * (RunOnHostPrereqs.millDaemonConfig), assembled afresh since a changed version pin grants
 * another launcher. On a cancel the runner follows each program: a cancelled sbt command's server
 * is not retired, since stock sbt's disconnect cancels the exec and leaves the server, and a
 * cancelled mill command's daemon shuts itself down, as stock Mill's does on a disconnect
 * mid-command, so the next mill command starts one. Gradle's runtime is its proxy: the client
 * starts and matches the daemon in the launch's own registry, inside the profile, and the
 * runner records the registry's daemons after each command and ends them with its session
 * (RunOnHostGradleDaemons). Maven is never here: it runs once and exits, its proxy with the command.
 * The acceptance test's entry holds one of these over the command's own session for its one command, so
 * the one lifecycle has two callers and no second owner.
 *
 * When another launch owns the build directory's server or daemon (SECURITY.md "Run on host"),
 * this runner attaches its command to that runtime if it would start one under the same
 * confinement and environment (`attached`), and otherwise ends it by its owner's record under
 * the retirement lock and starts its own (`takeOver`) — the one case in which a runner signals
 * a live launch's group not its own; a dead launch's the scavenger collects.
 * `scavenge` runs before each preparation so a dead owner is collected by the exclusive
 * scavenger before a fresh server or daemon starts; one dying after it is taken over. Preparation and
 * the session's end share this object's monitor. Tests replace the second parameter list: they
 * register a stand-in leader where the proxy, server or daemon would be, and stub the scavenger.
 */
final class RunnerRuntimes(
  session: Session,
  project: Path,
  log: String => Unit,
  systemPaths: SeatbeltProfile.SystemPaths,
  forwards: Vector[(String, String)],
  fileRules: FileRules.Resolved,
  credentials: Vector[BrokeredCredential] = Vector.empty,
  // The launch's channel log, beside which each proxy's audit log is linked (RunOnHostProxy.linkAuditLog).
  channelLog: Option[Path] = None,
)(
  processes: RunOnHostSession.Processes = RunOnHostSession.HostProcesses,
  assemble: (Path, Program, Path) => Either[String, Assembled] =
    (project, program, buildDirectory) =>
      RunOnHostSandbox.assemble(project, program, name => Option(System.getenv(name)), buildDirectory),
  proxy: (Program, Vector[String], Path, Path) => Either[String, Int] =
    createProxy(systemPaths, credentials, channelLog),
  server: ServerStart => Either[String, Unit] =
    start => startSbtServer(session, systemPaths, forwards, fileRules, start),
  daemon: DaemonStart => Either[String, RunOnHostMillDaemons.Daemon] =
    start =>
      RunOnHostMillDaemons.start(
        session, systemPaths, forwards, fileRules, RunOnHostSession.HostProcesses, log, start,
      ),
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
    session.records.resolve(proxyRecordName(program, hash))
  private def serverRecord(hash: String): Path = session.records.resolve(serverRecordName(hash))
  private def daemonRecord(hash: String): Path = session.records.resolve(daemonRecordName(hash))

  /** The runtime a command in `buildDirectory` runs against, None for Maven's; `arguments` are
    * the request's, for a server this call starts. Called while the command's lock holder has the
    * build lock. A dead owner is collected first, so a stale portfile or record cannot block a
    * fresh start. */
  def prepare(program: Program, buildDirectory: Path, arguments: Seq[String]): Either[String, Option[Runtime]] =
    synchronized:
      // Scavenge before every dispatched command, Maven's included: a dead owner in any build
      // directory must be collected on the next launch's next command, not only when that
      // command needs a runtime of its own.
      scavenge()
      // The word this returns is what the lock holder execs the supervisor on (RunOnHostChannel.dispatch):
      // the executable's last check before that exec, Maven's included (RunOnHostSandbox.selfPresent has why).
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
        // and the record's group still lives. namesDerivedSocket checks the spelling
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
        // The client is confined to the daemon's port: reuse only the daemon identified at its
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
    val name = proxyRecordName(program, hash)
    val proxyLog = session.directory.resolve(s"$name.log")
    // An exception after a leader registered is a failed start like any other.
    val started =
      try
        for
          _ <- RunOnHostSession.publishBuildFile(session.directory, hash, buildDirectory)
          assembled <- assemble(project, program, buildDirectory)
          hosts <- readProgramRules(project, program)
          // A record a failed creation kept: discarded, or the leader that would rename over it refused.
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
        // A leader that registered, its proxy never reporting ready: left alone, its group would
        // outlive the record the next attempt's leader renames over, and its late ready line
        // would be read as that attempt's.
        Left(discardRuntime(program, hash, proxyLog).fold(kept => s"$reason; $kept", _ => reason))

  /** The server of a runtime whose proxy is up, no other launch owning the build directory's
    * server (foreignRuntime, decided by every caller first), once no foreign server holds its
    * portfile; up, it is described for other launches (publishDescriptor). A start that fails,
    * by refusal or exception, leaves no group behind its record. A record an earlier failure
    * kept is discarded first, or refuses the start while its group lives: the leader would
    * rename over it. */
  private def startServer(current: Live, arguments: Seq[String]): Either[String, Unit] =
    val record = serverRecord(current.hash)
    val started =
      try
        discard(Program.Sbt, current.hash, record).flatMap(_ => noForeignServer(current)).flatMap: _ =>
          // After any foreign server is gone, not before: RunOnHostSbtServer.shutdownForeignServer waits for the
          // user's build to finish, and sweeping its `target/` links mid-build would corrupt
          // it. Before the start: our server fails loading on a link into a denied store.
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
    * the user's own, once idle and after its start-time check (RunOnHostMillDaemons.start); up,
    * it is described for other
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
          runtime = current.runtime.copy(daemonPort = Some(found.port), daemonPid = Some(found.pid)),
          daemon = Some(found),
          daemonConfig = config,
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
      RunOnHostSession.readRecord(file).toRight(s"${file.getFileName} does not parse as a record")
    for
      proxy <- read(proxyRecord(program, current.hash))
      group <- read(record)
      inputs = runtimeInputs(
        current.assembled, session.tmp, current.runtime.proxyPort, current.runtime.trust, systemPaths, forwards,
        network, fileRules,
      )
      _ <- RunOnHostRuntimeDescriptor.publish(
        RunOnHostRuntimeDescriptor.file(session.directory, program, current.hash),
        RunOnHostRuntimeDescriptor(
          RunOnHostRuntimeDescriptor.fingerprint(inputs, egressRuleText(program, current.hosts)),
          current.runtime.proxyPort, proxy, group, daemon, daemonConfig.map(LogHelper.sha256Hex),
        ),
      )
    yield ()

  private def daemonLives(found: RunOnHostMillDaemons.Daemon): Boolean =
    processes.startOf(found.pid).contains(found.start)

  private def daemonConfig(buildDirectory: Path): Either[String, String] =
    try Right(millDaemonConfig(buildDirectory, readLines, millJavaHomeText(buildDirectory)))
    catch case ex: Unreadable => Left(wording(ex.refusal))

  /** The links a tree the user's own sbt built leaves under `target/` (RunOnHostSandbox.cleanForeignTargetLinks),
    * which our server would fail loading on. Run only when a server starts, after any foreign
    * server for the directory is shut down. */
  private def sweepTargetLinks(assembled: Assembled): Unit =
    val project = assembled.prereqs.project
    val swept = cleanForeignTargetLinks(project, project +: assembled.sbtCachesGranted)
    if swept.nonEmpty then
      log(s"removed ${swept.size} target/ links resolving outside the command's roots (first: ${swept.head})")

  /**
   * No server but this runner's may hold the build directory's portfile when its own starts
   * (SECURITY.md "Run on host", one server per build directory), another launch's ownership
   * decided before this (foreignRuntime): another launch's is attached to, or ended by its
   * record, never through the portfile. Beyond that:
   *
   *  - This launch's own derived socket, live while this launch has no record identifying
   *    that server, is a server it left
   *    unaccounted; refused, to be ended by hand — starting a second on the same socket would
   *    fail at the bind.
   *  - Any other live portfile socket is the user's own server, ended by protocol at the
   *    socket sbt derives (RunOnHostSbtServer.shutdownForeignServer); the portfile's own spelling is never
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
            s"$socket, while this launch has no record identifying this server; end it by hand and retry",
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
   * `server-sbt-<hash>` or `daemon-mill-<hash>` record whose group is not known to be gone
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
   * The runtime `owner`, another launch's runner session, holds for the build directory, for
   * this launch's command to run against, or why it cannot; Left is this launch's own failure
   * to assemble what it would start. Attached to when the server or daemon this launch would
   * start has the running one's confinement and environment
   * (RunOnHostRuntimeDescriptor.fingerprint has what that covers and leaves out): the owner is
   * live — locked under the root; one ending or dead is never attached to — its descriptor
   * (RunOnHostRuntimeDescriptor) carries the fingerprint of this launch's own would-be start,
   * derived with the owner's `tmp/` and proxy port and the rule file as read now, and is bound
   * to the owner's present records, whose proxy's leader lives; for sbt the server's leader lives and
   * the portfile names the socket derived under the owner's `tmp/`, unredirected; for mill the
   * daemon bears its start time and its configuration is the build directory's now —
   * `leaderLives` is no liveness for a mill runtime, whose starter has exited by design. The
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
            assembled <- assemble(project, program, buildDirectory)
            hosts <- readProgramRules(project, program)
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
   * The runtime `owner` holds for the build directory ended, for this launch's own to start in
   * its place — `why` is what kept this launch from attaching — or the refusal when its group is
   * not observed ended. One more holder of the record's retirement lock
   * (RunOnHostSession.retirementLockFile): under the build lock its command holds, the group
   * is ended by `endRecordedGroup`'s own steps — the record read only under the lock, the
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
          s"another launch's runner (${owner.getFileName}) owns the $what for $buildDirectory; this launch " +
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

  private def lives(record: Path): Boolean = RunOnHostSession.leaderLives(record, processes)

  /** End the groups the runtime's records name — the server or daemon, then the proxy — and delete
    * them with the proxy log, since a successor of the same name would read this proxy's ready
    * line as its own, and the build file last, once no record of the hash remains: another
    * program's runtime for the same directory still publishes under it. Answers what became
    * of the groups: Left when `discard` keeps a record for the next start to retry. The proxy's
    * record is discarded, or that tried, even when the server's or daemon's is kept. */
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

  /** End the group one record of the runtime `program` and `hash` names, under its
    * retirement lock, and delete the record and its exit file — unless the outcome keeps the
    * record (`Collected.keeps`), as when a member is still listed or the lock is not free within
    * the bound: then Left says so, for the caller to start nothing whose leader would rename its
    * record over the kept one.
    * The runtime's descriptor goes first, before any of its groups is ended, so another launch
    * attaches to nothing ending; the start that follows republishes it. */
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
