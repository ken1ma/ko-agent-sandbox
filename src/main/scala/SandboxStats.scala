// --stats: a read-only report, because a size seen only while resetting is seen too late. The live
// section is answered first and skipped when the podman machine is stopped — a report starts
// nothing — and the directory walk is last: a real Coursier cache is millions of inodes, which is
// why this is a verb and not a line printed at every launch.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{FileVisitResult, Files, Path, Paths, SimpleFileVisitor}
import java.nio.file.attribute.BasicFileAttributes
import scala.jdk.CollectionConverters.*

import AgentSandboxLauncher.{
  logStateRoot, machineMemoryAvailable, machineMemoryLine, memoryTotal, persistentVolumes, policyStateRoot,
  projectsStateRoot, runContainerParts, stateRoot, tlsStateRoot,
}
import HostCommands.*

object SandboxStats:

  // -------------------------------------------------------------------------
  // Figures
  // -------------------------------------------------------------------------

  /**
   * Sizes from bytes to TiB in one column: a Coursier cache is gigabytes while a policy cache is
   * kilobytes, and one fixed unit would flatten one of them. Whole numbers up to MiB and one
   * decimal from GiB: no figure under 10 MiB changes what the reader does, and the decimal then
   * marks the gigabyte rows. A figure that rounds to 1024 of its unit takes the next one, so
   * 1023.6 MiB reads 1.0 GiB.
   */
  def humanBytes(bytes: Long): String =
    val units = Vector("B", "KiB", "MiB", "GiB", "TiB")
    val wholeUnits = 3
    def rounded(index: Int): Double =
      val value = bytes.toDouble / (1L << (10 * index))
      if index < wholeUnits then Math.round(value).toDouble else Math.round(value * 10) / 10.0
    val index = units.indices.find(i => i == units.size - 1 || rounded(i) < 1024).get
    val figure = if index < wholeUnits then rounded(index).toLong.toString else f"${rounded(index)}%.1f"
    s"$figure ${units(index)}"

  /**
   * `memory: 58% (4.2 GiB) available`, `storage: 58% (936.7 GiB) free`: the share first, for a
   * reader who knows the machine's size, and beside it the figure the ceilings and the
   * `--reset-cache` flag act on. `whole` is positive; a machine that cannot say its size gets no
   * line.
   */
  def shareLine(label: String, part: Long, whole: Long, state: String): String =
    f"$label: ${part * 100.0 / whole}%.0f%% (${humanBytes(part)}) $state"

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
   * Sessions by their combined memory, largest first, and within a session the sandbox before
   * its proxy: the one the reader acts on, whatever an idle sandbox happens to use. A project
   * is named as the project table names it: by its recorded directory, or by its id where none
   * is recorded.
   */
  def liveTable(containers: Vector[LiveContainer], directories: Map[String, String]): String =
    val sessions = containers
      .groupBy(container => (container.projectId, container.run))
      .toVector
      .sortBy((session, group) => (-group.map(_.memoryBytes).sum, session))
    val ordered = sessions.flatMap((_, group) => group.sortBy(container => container.role != "sandbox"))
    val usedWidth = ordered.map(container => humanBytes(container.memoryBytes).length).max
    val rows = ordered.map: container =>
      val used = humanBytes(container.memoryBytes).reverse.padTo(usedWidth, ' ').reverse
      Vector(
        container.run,
        container.role,
        s"$used / ${humanBytes(container.limitBytes)}",
        f"${container.cpuPercent}%.1f%%",
        directories.getOrElse(container.projectId, container.projectId),
      )
    table(Vector("run", "role", "memory", "cpu", "project"), rows, rightAligned = Set(2, 3))

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
   * None when podman was not there to size it. `directory` is the recorded one; None for a
   * project last launched before the record existed.
   */
  final case class ProjectUsage(
    id: String,
    directory: Option[String],
    stateBytes: Long,
    cacheBytes: Long,
    volumeBytes: Option[Long],
  ):
    def totalBytes: Long = stateBytes + cacheBytes + volumeBytes.getOrElse(0L)

  /** Each project's recorded directory, by id. */
  def projectDirectories(projectsRoot: Path): Map[String, String] =
    childNames(projectsRoot).flatMap: id =>
      readIfPresent(projectsRoot.resolve(id)).map(_.trim).filter(_.nonEmpty).map(id -> _)
    .toMap

  /**
   * Largest first, each project named by its directory — where `--reset-cache` runs — and by its
   * id where none is recorded. The flag threshold is 1% of the cache filesystem's free space, so
   * the report says which project to `--reset-cache` rather than leaving a column of numbers to
   * compare by eye; it reads the cache column alone, the one `--reset-cache` removes.
   */
  def projectTable(usages: Vector[ProjectUsage], cacheFreeBytes: Long): String =
    if usages.isEmpty then "projects: none\n"
    else
      val rows = usages.sortBy(usage => (-usage.totalBytes, usage.id)).map: usage =>
        val flag =
          if usage.cacheBytes * 100 > cacheFreeBytes then
            "  <- cache over 1% of free space; a --reset-cache candidate"
          else ""
        Vector(
          humanBytes(usage.totalBytes),
          humanBytes(usage.stateBytes),
          humanBytes(usage.cacheBytes),
          usage.volumeBytes.fold("-")(humanBytes),
          usage.directory.getOrElse(usage.id) + flag,
        )
      table(Vector("total", "state", "cache", "volume", "project"), rows, rightAligned = Set(0, 1, 2, 3))

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
  // The verb
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
        ).foreach(System.out.println)
        val answer = run(podman, "stats", "--no-stream", "--format", StatsFormat)
        if !answer.ok then System.out.print(s"live sessions: podman stats failed: ${firstLine(answer.err)}\n")
        else
          liveContainers(answer.text.linesIterator.toVector) match
            case Vector() => System.out.print("live sessions: none\n")
            case found    => System.out.print("live sessions:\n" + liveTable(found, directories))

    val volumes: Option[Map[String, Long]] = service.toOption.flatMap: podman =>
      val answer = run(podman, "system", "df", "-v")
      if answer.ok then Some(volumeSizes(answer.text))
      else
        System.out.print(s"volumes: podman system df failed: ${firstLine(answer.err)}\n")
        None

    val stateDirs = Vector(tlsStateRoot(os), logStateRoot(os), policyStateRoot(os), projectsStateRoot(os))
    val cacheDir = RunOnHostPolicy.cacheRootOf(os, env).toOption.map(_.resolve("cache"))

    // Where the volumes live is podman's store: a host path on native Linux, the VM's disk
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

    val volumePrefix = "ko-agent-sandbox-persistent-"
    val volumeIds =
      volumes.toVector.flatMap(sizes => persistentVolumes(sizes.keys.toSeq)).map(_.stripPrefix(volumePrefix))
    val ids = ((stateDirs ++ cacheDir.toVector).flatMap(childNames) ++ volumeIds).distinct.sorted
    val usages = ids.map: id =>
      ProjectUsage(
        id,
        directories.get(id),
        stateDirs.map(dir => directoryBytes(dir.resolve(id))).sum,
        cacheDir.map(dir => directoryBytes(dir.resolve(id))).getOrElse(0L),
        volumes.map(_.getOrElse(volumePrefix + id, 0L)),
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

  /** Continues past races and permission holes: sizing must not fail on a tree a session is
    * changing. */
  def directoryBytes(root: Path): Long =
    if !Files.exists(root) then 0L
    else
      var total = 0L
      Files.walkFileTree(
        root,
        new SimpleFileVisitor[Path]:
          override def visitFile(file: Path, attrs: BasicFileAttributes) =
            if attrs.isRegularFile then total += attrs.size()
            FileVisitResult.CONTINUE
          override def visitFileFailed(file: Path, exc: IOException) = FileVisitResult.CONTINUE,
      )
      total

  private def childNames(dir: Path): Vector[String] =
    if !Files.isDirectory(dir) then Vector.empty
    else
      val stream = Files.list(dir)
      try stream.iterator().asScala.map(_.getFileName.toString).toVector
      finally stream.close()
