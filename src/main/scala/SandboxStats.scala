// --stats: a read-only report, because a size seen only while resetting is seen too late. The live
// section is answered first and skipped when the podman machine is stopped — a report starts
// nothing — and the directory walk is last: a real Coursier cache is millions of inodes, which is
// why this is an action and not a line printed at every launch.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{FileVisitResult, Files, Path, Paths, SimpleFileVisitor}
import java.nio.file.attribute.{BasicFileAttributes, FileTime}
import java.time.{Instant, ZoneId}
import java.time.format.DateTimeFormatter
import scala.jdk.CollectionConverters.*

import AgentSandboxLauncher.{
  logStateRoot, machineMemoryAvailable, machineMemoryLine, memoryTotal, persistentVolumes, rulesetStateRoot,
  projectsStateRoot, runContainerParts, stateRoot, buildMemoryHeadroom, tlsStateRoot,
}
import HostCommands.*
import RunOnHostPrereqs.Program

object SandboxStats:

  // -------------------------------------------------------------------------
  // Figures
  // -------------------------------------------------------------------------

  private val Units = Vector("", "K", "M", "G", "T", "P", "E")

  /**
   * A size as `df -h`, `du -h` and `ls -lh` print it, so a reader brings the rule with them:
   * bytes bare, otherwise the largest unit the size reaches, one decimal below 10 of it and none
   * from 10 up, rounded up, with 1023.6M carrying to 1.0G. That is two or three significant
   * figures; the four of `podman stats` are what make `16.67MB / 268.4MB` hard to read. Every
   * figure the launcher prints is this rule, and the entrypoint's `human` is its awk spelling.
   */
  def humanBytes(bytes: Long): String =
    val index = unitIndex(bytes)
    figure(bytes, index) + Units(index)

  /**
   * `0.3 / 11G` as (`0.3`, `11G`): a part beside its whole reads as a ratio when both are in
   * the whole's unit, so the part is rendered there — rounded as any figure, and the unit
   * written once, on the whole. The part is then known to a tenth of the whole's unit, a tenth
   * of a 1.0G limit at worst: the ratio's precision, on purpose, not the part's, so 30 MiB
   * under 6.7G reads 0.1.
   */
  def humanPair(part: Long, whole: Long): (String, String) =
    val index = unitIndex(whole)
    (figure(part, index), figure(whole, index) + Units(index))

  private def unitIndex(bytes: Long): Int =
    val reached = (1 until Units.size).count(index => bytes >= (1L << (10 * index)))
    if reached == Units.size - 1 || Math.ceilDiv(bytes, 1L << (10 * reached)) < 1024 then reached
    else reached + 1

  private def figure(bytes: Long, index: Int): String =
    if index == 0 then bytes.toString
    else
      val unit = 1L << (10 * index)
      // The remainder's tenths as fifths of half the unit: bytes * 10 overflows from 0.8 EiB.
      val tenths = (bytes / unit) * 10 + Math.ceilDiv((bytes % unit) * 5, unit / 2)
      if tenths < 100 then s"${tenths / 10}.${tenths % 10}" else Math.ceilDiv(bytes, unit).toString

  /**
   * `memory: 58% (4.2G) available`, `storage: 58% (937G) free`: the share first, for a
   * reader who knows the machine's size, and beside it the figure the limits and the
   * `--reset-run-on-host` flag act on, `tint` applied to just those. `whole` is positive; a
   * machine that cannot say its size gets no line.
   */
  def shareLine(label: String, part: Long, whole: Long, state: String, tint: String => String = identity): String =
    val figure = f"${part * 100.0 / whole}%.0f%% (${humanBytes(part)})"
    s"$label: ${tint(figure)} $state"

  /** `0 live sessions`, `1 project`, `3 projects`: the line over each table, and the whole
    * section when there is nothing to tabulate. */
  def counted(count: Int, noun: String, plural: String = ""): String =
    if count == 1 then s"1 $noun" else s"$count ${if plural.isEmpty then noun + "s" else plural}"

  // -------------------------------------------------------------------------
  // Live sessions
  // -------------------------------------------------------------------------

  /** One of this launcher's containers as `podman stats` sees it. */
  final case class LiveContainer(
    projectId: String,
    run: String,
    role: String,
    memoryBytes: Long,
    limitBytes: Long,
    cpuPercent: Double,
  )

  /**
   * Raw bytes and a full-precision percentage: the default `MemUsage` and `CPUPerc` are
   * podman's own rendering — decimal megabytes, two decimals — and the report renders every
   * figure itself so one unit and one rounding hold across it. The nested `ContainerStats` is
   * the one route to the usage in bytes, since `.MemUsage` at the top level is the rendered one.
   */
  val StatsFormat = "{{.Name}} {{.ContainerStats.MemUsage}} {{.MemLimit}} {{.CPU}}"

  /** Only this launcher's containers: another workload on the same machine is not the report's. */
  def liveContainers(lines: Vector[String]): Vector[LiveContainer] =
    lines.flatMap: line =>
      line.trim.split("\\s+") match
        case Array(name, usage, limit, cpu) =>
          for
            (kind, projectId, run) <- runContainerParts(name)
            usageBytes <- usage.toLongOption
            limitBytes <- limit.toLongOption
            cpuPercent <- cpu.toDoubleOption
          yield
            val role = if kind == "sandbox-run" then "sandbox" else "proxy"
            LiveContainer(projectId, run, role, usageBytes, limitBytes, cpuPercent)
        case _ => None

  /**
   * One row per session, largest combined memory first: the sandbox's memory, its proxy's, and
   * the cpu the two use together, the session's cost to the machine. A project is named as the
   * project table names it: by its recorded directory, or by its id where none is recorded.
   * Each memory column aligns on its slash, so used and limit each read down as a column; a
   * session missing one of its containers shows a dash there.
   */
  def liveTable(containers: Vector[LiveContainer], directories: Map[String, String]): String =
    if containers.isEmpty then counted(0, "live session") + "\n"
    else liveRows(containers, directories)

  private def liveRows(containers: Vector[LiveContainer], directories: Map[String, String]): String =
    val sessions = containers
      .groupBy(container => (container.projectId, container.run))
      .toVector
      .sortBy((session, group) => (-group.map(_.memoryBytes).sum, session))
    def memoryColumn(role: String): Vector[String] =
      val pairs = sessions.map: (_, group) =>
        group.find(_.role == role).map(container => humanPair(container.memoryBytes, container.limitBytes))
      val usedWidth = pairs.flatten.map(_._1.length).maxOption.getOrElse(0)
      pairs.map(_.fold("-")((used, limit) => s"${used.reverse.padTo(usedWidth, ' ').reverse} / $limit"))
    val sandbox = memoryColumn("sandbox")
    val proxy = memoryColumn("proxy")
    val rows = sessions.zipWithIndex.map:
      case (((projectId, run), group), index) =>
        Vector(
          run,
          sandbox(index),
          proxy(index),
          f"${group.map(_.cpuPercent).sum}%.1f%%",
          directories.getOrElse(projectId, projectId),
        )
    counted(sessions.size, "live session") + "\n" +
      table(Vector("run", "sandbox", "proxy", "cpu", "project"), rows, rightAligned = Set(3))

  // -------------------------------------------------------------------------
  // Run-on-host brokers
  // -------------------------------------------------------------------------

  /** One live broker: its launch's run suffix, its project, and for each build directory it has
    * served, the programs whose runtime it keeps there — a proxy and the server or daemon it
    * serves, which a `shutdown` or an idle exit leaves without the latter until the next command
    * (RunOnHostSandbox.BrokerRuntimes), so a runtime is not a process up this instant. */
  final case class Broker(run: String, project: String, warm: Vector[(String, Vector[String])])

  /**
   * The live brokers under the session root (`RunOnHostSession.root`): each a locked broker
   * session, its `run` file naming the launch's sandbox container, its build files the
   * directories served, and its proxy records the programs kept warm there — the proxy is the
   * runtime's constant part, a server or daemon gone on its own being replaced under it
   * (RunOnHostSandbox.BrokerRuntimes). A broker without a run file, one from a launch that
   * predates it, has a run the report cannot name. macOS only, like the brokers.
   */
  def brokers(root: Path): Vector[Broker] =
    // `except` names the caller's own session; the report has none, and the root is no child of itself.
    RunOnHostSession.liveBrokerSessions(root, except = root).map: session =>
      def file(name: String): Option[String] = readIfPresent(session.resolve(name)).map(_.trim).filter(_.nonEmpty)
      val run = file(RunOnHostSession.RunFile).flatMap(runContainerParts).map(_._3).getOrElse("?")
      val project = file(RunOnHostSession.ProjectFile).getOrElse("-")
      val programsByHash = childNames(session.resolve(RunOnHostSession.RecordsDir))
        .flatMap: name =>
          Program.values.iterator
            .find(program => name.startsWith(s"proxy-${program.name}-"))
            .map(program => name.stripPrefix(s"proxy-${program.name}-") -> program)
        .groupMap(_._1)(_._2)
      val warm = RunOnHostSession.buildDirectories(session).map: (hash, directory) =>
        directory.toString -> programsByHash.getOrElse(hash, Vector.empty).sortBy(_.ordinal).map(_.name)
      Broker(run, project, warm.sortBy(_._1))
    .sortBy(broker => (broker.run, broker.project))

  /** One row per directory a broker has served, by run, `runtime` the programs whose runtime
    * the broker keeps there. A broker that has served none yet has no row: its session is in the
    * live table, and a broker is one per session. */
  def brokerTable(brokers: Vector[Broker]): String =
    val rows = brokers.flatMap: broker =>
      broker.warm.map: (directory, programs) =>
        Vector(broker.run, if programs.isEmpty then "none" else programs.mkString(", "), directory)
    counted(rows.size, "run-on-host directory", "run-on-host directories") + "\n" +
      (if rows.isEmpty then "" else table(Vector("run", "runtime", "directory"), rows, rightAligned = Set.empty))

  // -------------------------------------------------------------------------
  // Volumes and storage
  // -------------------------------------------------------------------------

  /**
   * Each volume's bytes out of `podman system df -v`, whose "Local Volumes space usage" table is
   * the one route to a volume's size: `--format json` refuses `-v`, and `volume inspect` has no
   * size. The figures are podman's decimal rendering read back, four significant digits, which
   * keeps the size order and the total the column exists for.
   */
  def volumeSizes(dfVerbose: String): Map[String, Long] =
    dfVerbose.linesIterator
      .dropWhile(!_.startsWith("Local Volumes space usage"))
      .flatMap: line =>
        line.trim.split("\\s+") match
          case Array(name, _, size) => decimalSize(size).map(name -> _)
          case _                    => None
      .toMap

  private val DecimalUnits = Vector("B", "kB", "MB", "GB", "TB", "PB", "EB")
  private val DecimalSize = "([0-9]+(?:\\.[0-9]+)?)(B|kB|MB|GB|TB|PB|EB)".r

  /** `1.234GB` as podman prints sizes: powers of 1000, `kB` lower-case. */
  def decimalSize(text: String): Option[Long] =
    text match
      case DecimalSize(number, unit) =>
        Some(Math.round(number.toDouble * Math.pow(1000, DecimalUnits.indexOf(unit))))
      case _ => None

  /** Free and total bytes of the filesystem `df -P -k` reported, from the podman machine. */
  def dfSpace(text: String): Option[(Long, Long)] =
    text.linesIterator.toVector.lastOption.map(_.trim.split("\\s+")).flatMap:
      case Array(_, total, _, available, _*) =>
        for
          totalKiB <- total.toLongOption
          availableKiB <- available.toLongOption
        yield (availableKiB * 1024, totalKiB * 1024)
      case _ => None

  /**
   * One of the launcher's host roots and the filesystem holding it: `filesystem` is the same
   * string for two roots on one filesystem, so the report can say how many figures there are.
   */
  final case class HostRoot(path: Path, filesystem: String, freeBytes: Long, totalBytes: Long)

  /**
   * One line per filesystem, labelled by which machine holds it — the mount point alone would
   * not say whether `/home` is the host's or the VM's. The root's own path joins the label only
   * when the host's roots are split, the one case where it tells the lines apart.
   */
  def storageLines(os: Os, roots: Vector[HostRoot], machine: Option[(Long, Long)]): Vector[String] =
    val hostLabel = if os == Os.Linux then "storage" else "host storage"
    val filesystems = roots.map(_.filesystem).distinct
    val hostLines = filesystems.map: filesystem =>
      val group = roots.filter(_.filesystem == filesystem)
      val at = if filesystems.size > 1 then group.map(_.path).mkString(" at ", ", ", "") else ""
      shareLine(hostLabel, group.head.freeBytes, group.head.totalBytes, "free") + at
    hostLines ++ machine.map((free, total) => shareLine("podman machine storage", free, total, "free"))

  // -------------------------------------------------------------------------
  // Projects
  // -------------------------------------------------------------------------

  /**
   * One project's disk use: the launcher's state and build-cache roots, and its agents' volume —
   * None when podman was not there to size it. `directory` is the recorded one where it still
   * exists; None for a project last launched before the record existed, or whose directory is gone.
   */
  /** `lastWrite` is the newest modification under the project's state and cache trees — the
    * volume is in podman's store, out of the walk — and None where neither tree exists. */
  final case class ProjectUsage(
    id: String,
    directory: Option[String],
    stateBytes: Long,
    cacheBytes: Long,
    volumeBytes: Option[Long],
    lastWrite: Option[Instant],
  ):
    def totalBytes: Long = stateBytes + cacheBytes + volumeBytes.getOrElse(0L)

  /**
   * Each project's recorded directory, by id, where the directory still exists. When the recorded
   * directory is missing, the table prints the id instead: a missing directory may be on an
   * unmounted filesystem, and `--reset <id>` accepts the id without that directory.
   */
  def projectDirectories(projectsRoot: Path): Map[String, String] =
    childNames(projectsRoot).filter(SandboxProject.isProjectId).flatMap: id =>
      readIfPresent(projectsRoot.resolve(id)).map(_.trim).filter(_.nonEmpty)
        .filter(directory => Files.isDirectory(Paths.get(directory)))
        .map(id -> _)
    .toMap

  /** The roots holding one directory per project id, sized into the state column. */
  private def stateDirs(os: Os): Vector[Path] =
    Vector(tlsStateRoot(os), logStateRoot(os), rulesetStateRoot(os), projectsStateRoot(os))

  private def cacheDir(os: Os): Option[Path] =
    RunOnHostPrereqs.cacheRootOf(os, env).toOption.map(_.resolve("run-on-host"))

  private val VolumePrefix = "ko-agent-sandbox-persistent-"

  /** Project ids found under the state or cache roots, or extracted from persistent-volume names. */
  def projectIds(os: Os, volumeNames: Seq[String]): Vector[String] =
    projectIdsUnder(stateDirs(os) ++ cacheDir(os), volumeNames)

  /** Names matching the id's pattern only (SandboxProject.ProjectIdPattern): a stray file under a root is
    * not a project, and would be a row `--reset <id>` refuses. */
  def projectIdsUnder(roots: Seq[Path], volumeNames: Seq[String]): Vector[String] =
    val volumeIds = persistentVolumes(volumeNames).map(_.stripPrefix(VolumePrefix))
    (roots.flatMap(childNames) ++ volumeIds).filter(SandboxProject.isProjectId).distinct.sorted.toVector

  private val WriteFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")

  /**
   * Largest first, each project named by its directory — where `--reset-run-on-host` runs — and
   * by its id, which `--reset <id>` takes, where none is recorded or the recorded one is gone,
   * dated by its newest write in the reader's zone, to the minute. The flag threshold is 1% of
   * the cache filesystem's free space, so the report says which project to
   * `--reset-run-on-host` rather than leaving a column of numbers to compare by eye; it reads
   * only cache usage because `--reset-run-on-host` removes only that cache.
   */
  def projectTable(usages: Vector[ProjectUsage], cacheFreeBytes: Long, zone: ZoneId = ZoneId.systemDefault): String =
    if usages.isEmpty then counted(0, "project") + "\n"
    else
      val rows = usages.sortBy(usage => (-usage.totalBytes, usage.id)).map: usage =>
        val flag =
          if usage.cacheBytes * 100 > cacheFreeBytes then
            "  <- cache over 1% of free space; a --reset-run-on-host candidate"
          else ""
        Vector(
          humanBytes(usage.totalBytes),
          humanBytes(usage.stateBytes),
          humanBytes(usage.cacheBytes),
          usage.volumeBytes.fold("-")(humanBytes),
          usage.lastWrite.fold("-")(write => WriteFormat.format(write.atZone(zone))),
          usage.directory.getOrElse(usage.id) + flag,
        )
      counted(usages.size, "project") + "\n" +
        table(
          Vector("total", "state", "cache", "volume", "last write", "project"), rows, rightAligned = Set(0, 1, 2, 3),
        )

  /** Columns padded to their widest cell, the header included; rows indented two spaces. */
  private def table(header: Vector[String], rows: Vector[Vector[String]], rightAligned: Set[Int]): String =
    val all = header +: rows
    val widths = header.indices.map(column => all.map(_(column).length).max)
    all
      .map: cells =>
        cells.zipWithIndex
          .map: (cell, column) =>
            if rightAligned(column) then cell.reverse.padTo(widths(column), ' ').reverse
            else cell.padTo(widths(column), ' ')
          .mkString("  ", "  ", "")
          .stripTrailing
      .mkString("", "\n", "\n")

  // -------------------------------------------------------------------------
  // The action
  // -------------------------------------------------------------------------

  def stats(os: Os): Nothing =
    val directories = projectDirectories(projectsStateRoot(os))
    val service = podmanService(os)
    service match
      case Left(reason) => System.out.print(s"live sessions and volumes: not queried; $reason\n")
      case Right(podman) =>
        machineMemoryLine(
          os,
          memoryTotal(run(podman, "info", "--format", "{{.Host.MemTotal}}")),
          machineMemoryAvailable(
            os,
            readIfPresent(Paths.get("/proc/meminfo")).getOrElse(""),
            run(podman, "machine", "ssh", "cat /proc/meminfo"),
          ),
          color = colorStdout,
          scale = buildMemoryHeadroom,
        ).foreach(System.out.println)
        val answer = run(podman, "stats", "--no-stream", "--format", StatsFormat)
        if !answer.ok then System.out.print(s"live sessions: podman stats failed: ${firstLine(answer.err)}\n")
        else System.out.print(liveTable(liveContainers(answer.text.linesIterator.toVector), directories))
    if os == Os.Mac then
      val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
      System.out.print(brokerTable(brokers(RunOnHostSession.root(uid))))

    val volumes: Option[Map[String, Long]] = service.toOption.flatMap: podman =>
      val answer = run(podman, "system", "df", "-v")
      if answer.ok then Some(volumeSizes(answer.text))
      else
        System.out.print(s"volumes: podman system df failed: ${firstLine(answer.err)}\n")
        None

    val stateDirs = this.stateDirs(os)
    val cacheDir = this.cacheDir(os)

    // The volumes are in podman's store: a host path on native Linux, the VM's disk
    // elsewhere, which only the machine itself can size.
    val graphRoot = service.toOption.flatMap: podman =>
      val answer = run(podman, "info", "--format", "{{.Store.GraphRoot}}")
      Option.when(answer.ok)(answer.text.trim).filter(_.nonEmpty)
    val hostGraphRoot = graphRoot.filter(_ => os == Os.Linux).map(Paths.get(_))
    val hostRoots = (Vector(stateRoot(os)) ++ cacheDir ++ hostGraphRoot).flatMap(hostRoot)
    val machineSpace =
      for
        podman <- service.toOption
        root <- graphRoot
        if os != Os.Linux
        answer = run(podman, "machine", "ssh", s"df -P -k $root")
        if answer.ok
        space <- dfSpace(answer.text)
      yield space
    storageLines(os, hostRoots, machineSpace).foreach(System.out.println)

    val ids = projectIdsUnder(stateDirs ++ cacheDir, volumes.toVector.flatMap(_.keys))
    val usages = ids.map: id =>
      val state = stateDirs.map(dir => treeUsage(dir.resolve(id)))
      val cache = cacheDir.map(dir => treeUsage(dir.resolve(id)))
      ProjectUsage(
        id,
        directories.get(id),
        state.map(_.bytes).sum,
        cache.map(_.bytes).getOrElse(0L),
        volumes.map(_.getOrElse(VolumePrefix + id, 0L)),
        (state ++ cache).flatMap(_.newestWrite).maxOption,
      )
    val cacheFreeBytes = cacheDir.flatMap(hostRoot).map(_.freeBytes).getOrElse(0L)
    System.out.print(projectTable(usages, cacheFreeBytes))
    sys.exit(0)

  /** The podman to ask, or why the live figures are not queried: a missing podman or a stopped
    * machine is a note, never a start. */
  private def podmanService(os: Os): Either[String, String] =
    findOnPath("podman", env("PATH").getOrElse(""), os).map(_.toString) match
      case None => Left("podman is not on PATH")
      case Some(found) =>
        val machineDown = os != Os.Linux && {
          val machines = run(found, "machine", "list", "--format", "{{.Running}}")
          !machines.ok || !machines.text.linesIterator.map(_.trim).contains("true")
        }
        if machineDown then Left("the podman machine is not running") else Right(found)

  private def firstLine(text: String): String = text.linesIterator.nextOption().getOrElse("").trim

  /** Read at the nearest existing ancestor: the cache root does not exist before the first host
    * build. None when the filesystem will not answer. */
  private def hostRoot(path: Path): Option[HostRoot] =
    var probe = path.toAbsolutePath
    while !Files.exists(probe) && probe.getParent != null do probe = probe.getParent
    try
      val store = Files.getFileStore(probe)
      Some(HostRoot(path, store.toString, store.getUsableSpace, store.getTotalSpace)).filter(_.totalBytes > 0)
    catch case _: IOException => None

  /** A tree's regular-file bytes and its newest modification, of a file or of a directory
    * whose entries changed; None for a tree that does not exist. */
  final case class TreeUsage(bytes: Long, newestWrite: Option[Instant])

  /** Continues past races and permission holes: sizing must not fail on a tree a session is
    * changing. */
  def treeUsage(root: Path): TreeUsage =
    if !Files.exists(root) then TreeUsage(0L, None)
    else
      var total = 0L
      var newest: Option[FileTime] = None
      def noteWrite(attrs: BasicFileAttributes): Unit =
        val time = attrs.lastModifiedTime
        if newest.forall(_.compareTo(time) < 0) then newest = Some(time)
      Files.walkFileTree(
        root,
        new SimpleFileVisitor[Path]:
          override def preVisitDirectory(dir: Path, attrs: BasicFileAttributes) =
            noteWrite(attrs)
            FileVisitResult.CONTINUE
          override def visitFile(file: Path, attrs: BasicFileAttributes) =
            if attrs.isRegularFile then total += attrs.size()
            noteWrite(attrs)
            FileVisitResult.CONTINUE
          override def visitFileFailed(file: Path, exc: IOException) = FileVisitResult.CONTINUE,
      )
      TreeUsage(total, newest.map(_.toInstant))

  private def childNames(dir: Path): Vector[String] =
    if !Files.isDirectory(dir) then Vector.empty
    else
      val stream = Files.list(dir)
      try stream.iterator().asScala.map(_.getFileName.toString).toVector
      finally stream.close()
