#!/usr/bin/env -S scala shebang
//> using scala 3.10.0

/*
  Measures whether the podman machine gives a build's memory back to the host, on macOS and on Windows. The section
  "Memory" of doc/run-on-host-evidence.md records the answers. Run this probe after a podman, libkrun, WSL, macOS or
  Windows upgrade, and update that section.

  Run the probe on the HOST, from the repository root, on a freshly started machine with no session on it.

  On macOS:

      podman machine restart
      src/probe/PodmanMachineMemoryReclaim.scala

  On Windows, in PowerShell, where no shebang runs:

      wsl --shutdown
      podman machine start
      scala shebang src\probe\PodmanMachineMemoryReclaim.scala

  Options, before an optional `--` and the build command:

      [--baseline SECONDS] [--after SECONDS] [--interval SECONDS] [--no-pressure] [-- COMMAND...]

  - The default command is the build that the macOS measurement used:
    java -jar target/dist/ko-agent-sandbox.jar --no-options-file --session-start=immediate sbt test
  - The probe refuses a machine that has been up for more than ten minutes, and a machine with a running container.
    The uptime shows a recent start, not that nothing ran since.
  - On Windows, start no other WSL distribution: every distribution shares one VM, so another distribution's memory
    shows in the same process. The probe warns when one is running.

  What the probe does:

  1. It prints what decides the answer: the OS, podman, the machine's provider and memory, and per host:
     - macOS: the libkrun that krunkit loads. libkrun frees reported guest pages with MADV_FREE from v1.19.0
       (containers/libkrun pull 703, merged 2026-06-03, on the stable-1.19.x branch); v1.18 and older use
       MADV_DONTNEED, which does nothing on macOS. The machine kernel binds virtio_balloon with the
       free-page-reporting feature negotiated (read from sysfs in a session, 2026-09-22).
     - Windows: the WSL version, and `autoMemoryReclaim` in %UserProfile%\.wslconfig. Microsoft documents that setting
       under `[experimental]` with the default `dropCache`, which reclaims cached memory immediately; `gradual`
       reclaims it slowly, and `disabled` turns reclamation off
       (https://learn.microsoft.com/en-us/windows/wsl/wsl-config).
  2. It samples the VM process every 5 s through these phases, and reads the guest's /proc/meminfo at the end of each:
       baseline  60 s before the build
       build     the command, run on this host so that the sampler sees the machine grow
       after     600 s once the command has exited
       pressure  macOS only: 60 s under `memory_pressure -l warn`, then 60 s more as "released"
     The VM process is krunkit on macOS, and vmmemWSL or vmmem on Windows; the probe samples every such process.
  3. It writes the samples to a CSV, prints its path, and summarizes the first, peak and last sample of each phase.
     Keep the CSV with the result.

  Read the summary per host.

  macOS: pages freed with MADV_FREE stay in the process's resident size until macOS needs them, so a return shows in
  the pressure phase, not in "after". Per-process counters alone do not decide the answer either way: the pull
  request above reports reclamation that Activity Monitor's per-process figure did not show, and macOS can compress
  a process's pages, which lowers its resident size without discarding them. Read the columns together, as evidence
  rather than proof:
  - The resident size falls under pressure while CMPRS, the compressor's stored pages and swap stay put: consistent
    with the pages being discarded.
  - The resident size falls by about what CMPRS, stored pages or swap gain: consistent with the pages being
    compressed or swapped out, still held.
  - Anything else, a flat resident size included: inconclusive, with the host's free pages and pressure level during
    the pressure phase as the remaining evidence.
  The probe reports a pressure phase as invalid when memory_pressure exits before its 60 s. The resident size can
  exceed the machine's memory (13.4 GiB for a 12 GiB machine after a build, 2026-09-22), so read the columns as
  differences between phases.

  Windows: WSL documents its reclaim as happening without host pressure, so "after" decides.
  - The working set falls back toward its baseline during "after": WSL returned the build's memory.
  - The working set stays near its build peak through "after": WSL kept the memory.
  - The guest's Cached falls while its MemFree rises, with no matching fall in the working set: the guest freed the
    memory, and Windows did not get it back.
  A control run makes the reading a measurement of the setting. Run it with reclamation disabled:

      Add-Content -Path "$env:USERPROFILE\.wslconfig" -Value "`r`n[experimental]`r`nautoMemoryReclaim=disabled"
      wsl --shutdown
      podman machine start
      scala shebang src\probe\PodmanMachineMemoryReclaim.scala

  If .wslconfig already has an [experimental] section, add `autoMemoryReclaim=disabled` under it instead. Remove the
  added lines afterwards, and run `wsl --shutdown` again, to return to the default.

  A machine that has run sessions is already fully resident at baseline. The build phase then shows no growth, and
  a later fall undoes whatever the guest freed earlier, not the build. On a freshly started machine, the guest's
  untouched memory is not resident on the host, so the build's growth shows.
*/

import scala.jdk.CollectionConverters.*
import scala.util.Properties

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

enum Host:
  case Mac, Windows

/** One sample of one VM process. A column the host does not have is None, and the CSV leaves it empty. */
case class Sample(
    epoch: Long,
    phase: String,
    pid: Long,
    vmResidentKb: Long,
    vmCompressedKb: Option[Long],
    vmPrivateKb: Option[Long],
    hostFreeKb: Long,
    compressorStoredKb: Option[Long],
    compressorOccupiedKb: Option[Long],
    swapUsedKb: Option[Long],
    pressureLevel: Option[String],
):
  def csvLine: String =
    def cell(value: Option[Any]) = value.map(_.toString).getOrElse("")
    Seq(
      epoch.toString, phase, pid.toString, vmResidentKb.toString, cell(vmCompressedKb), cell(vmPrivateKb),
      hostFreeKb.toString, cell(compressorStoredKb), cell(compressorOccupiedKb), cell(swapUsedKb), cell(pressureLevel),
    ).mkString(",")

object Sample:
  val CsvHeader = "epoch,phase,pid,vm_resident_kb,vm_compressed_kb,vm_private_kb,host_free_kb," +
    "host_compressor_stored_kb,host_compressor_occupied_kb,host_swap_used_kb,host_pressure_level"

case class Options(
    baselineSeconds: Int = 60,
    afterSeconds: Int = 600,
    intervalSeconds: Int = 5,
    pressure: Boolean = true,
    command: Seq[String] = Nil,
)

val DefaultCommand =
  Seq("java", "-jar", "target/dist/ko-agent-sandbox.jar", "--no-options-file", "--session-start=immediate", "sbt",
    "test")

def fail(message: String): Nothing =
  System.err.println(message)
  sys.exit(2)

def say(label: String, value: String): Unit = println(f"$label%-28s $value")

/** A command's output, both streams merged and decoded as UTF-8, and its exit status. */
def run(command: Seq[String], environment: Map[String, String] = Map.empty): (Int, String) =
  val builder = ProcessBuilder(command*).redirectErrorStream(true)
  environment.foreach((name, value) => builder.environment.put(name, value))
  val process =
    try builder.start()
    catch case ex: java.io.IOException => return (-1, s"${command.head}: ${ex.getMessage}")
  process.getOutputStream.close()
  val text = String(process.getInputStream.readAllBytes(), UTF_8)
  (process.waitFor(), text)

def output(command: String*): String = run(command)._2.trim

// wsl.exe writes UTF-16 unless WSL_UTF8 is set.
def wsl(arguments: String*): Seq[String] =
  run("wsl.exe" +: arguments, Map("WSL_UTF8" -> "1"))._2.linesIterator.map(_.trim).filter(_.nonEmpty).toSeq

def parseOptions(arguments: List[String], options: Options = Options()): Options = arguments match
  case Nil => options
  case "--" :: command => options.copy(command = command)
  case "--baseline" :: seconds :: rest => parseOptions(rest, options.copy(baselineSeconds = seconds.toInt))
  case "--after" :: seconds :: rest => parseOptions(rest, options.copy(afterSeconds = seconds.toInt))
  case "--interval" :: seconds :: rest => parseOptions(rest, options.copy(intervalSeconds = seconds.toInt))
  case "--no-pressure" :: rest => parseOptions(rest, options.copy(pressure = false))
  case other :: _ => fail(s"Unknown option $other. See the header of src/probe/PodmanMachineMemoryReclaim.scala.")

def reclaimSetting: String =
  val path = Path.of(sys.env.getOrElse("USERPROFILE", ""), ".wslconfig")
  val default = "(documented default: dropCache)"
  if !Files.isRegularFile(path) then s"unset, no .wslconfig $default"
  else
    val Section = """\[(.+)\]""".r
    val Setting = """(?i)automemoryreclaim\s*=\s*(\S+)""".r
    // Each line paired with the section it is in.
    val sectioned = Files.readAllLines(path).asScala.map(_.trim).scanLeft(("", "")) {
      case (_, line @ Section(name)) => (name.toLowerCase, line)
      case ((section, _), line) => (section, line)
    }
    sectioned.collectFirst { case ("experimental", Setting(value)) => value }.getOrElse(s"unset $default")

def guestMemInfo: String =
  val Line = """(MemTotal|MemFree|MemAvailable|Buffers|Cached):\s+(\d+) kB""".r
  output("podman", "machine", "ssh", "--", "cat", "/proc/meminfo").linesIterator.collect {
    case Line(name, kb) => s"$name ${kb.toLong / 1024}"
  }.mkString(", ")

/** top and vm_stat print sizes such as 1024K, 512M or 2G, sometimes with a trailing + or -. */
def sizeKb(text: String): Option[Long] =
  val Size = """(\d+(?:\.\d+)?)([BKMG]?)[+-]?""".r
  text.trim match
    case Size(number, unit) =>
      val value = number.toDouble
      Some(unit match
        case "B" => (value / 1024).toLong
        case "M" => (value * 1024).toLong
        case "G" => (value * 1024 * 1024).toLong
        case _ => value.toLong)
    case _ => None

def macVmPids: Seq[Long] =
  output("pgrep", "-x", "krunkit").linesIterator.flatMap(_.trim.toLongOption).toSeq

def macSamples(phase: String, pids: Seq[Long]): Seq[Sample] =
  val vmStat = output("vm_stat")
  val pageBytes = """page size of (\d+) bytes""".r.findFirstMatchIn(vmStat).map(_.group(1).toLong).getOrElse(4096L)
  def pagesKb(label: String) =
    s"""$label:\\s+(\\d+)""".r.findFirstMatchIn(vmStat).map(_.group(1).toLong * pageBytes / 1024)
  val swap = """used = (\S+)""".r.findFirstMatchIn(output("sysctl", "-n", "vm.swapusage"))
    .flatMap(found => sizeKb(found.group(1)))
  val level = Some(output("sysctl", "-n", "kern.memorystatus_vm_pressure_level")).filter(_.nonEmpty)
  val now = Instant.now.getEpochSecond
  pids.flatMap { pid =>
    output("ps", "-o", "rss=", "-p", pid.toString).toLongOption.map { rss =>
      val top = output("top", "-l", "1", "-pid", pid.toString, "-stats", "pid,mem,cmprs").linesIterator
        .map(_.trim.split("\\s+")).find(_.headOption.contains(pid.toString))
      Sample(now, phase, pid, rss, top.flatMap(fields => fields.lift(2).flatMap(sizeKb)), None,
        pagesKb("Pages free").getOrElse(0L), pagesKb("Pages stored in compressor"),
        pagesKb("Pages occupied by compressor"), swap, level)
    }
  }

// One PowerShell line reads both processes and the free memory, so a sample costs one process start. Get-Process
// exposes the VM process's working set and private bytes, which Java's ProcessHandle does not.
val WindowsSampleScript =
  "Get-Process -Name vmmemWSL, vmmem -ErrorAction SilentlyContinue | ForEach-Object { 'vm {0} {1} {2}' -f " +
    "$_.Id, $_.WorkingSet64, $_.PrivateMemorySize64 }; " +
    "'free {0}' -f (Get-CimInstance -ClassName Win32_OperatingSystem).FreePhysicalMemory"

def windowsSamples(phase: String): Seq[Sample] =
  val lines = output("powershell", "-NoProfile", "-NonInteractive", "-Command", WindowsSampleScript).linesIterator
    .map(_.trim.split("\\s+").toSeq).toSeq
  val freeKb = lines.collectFirst { case Seq("free", kb) => kb.toLong }.getOrElse(0L)
  val now = Instant.now.getEpochSecond
  lines.collect { case Seq("vm", pid, workingSet, privateBytes) =>
    Sample(now, phase, pid.toLong, workingSet.toLong / 1024, None, Some(privateBytes.toLong / 1024), freeKb, None,
      None, None, None)
  }

@main def podmanMachineMemoryReclaim(arguments: String*): Unit =
  val options = parseOptions(arguments.toList)
  val host =
    if Properties.isMac then Host.Mac
    else if Properties.isWin then Host.Windows
    else fail(s"This probe measures a podman machine on macOS or Windows; this is ${Properties.osName}.")
  if sys.env.contains("KO_AGENT_SANDBOX_EGRESS_RULESET") || Files.isDirectory(Path.of("/etc/ko-agent-sandbox")) then
    fail("This looks like a sandbox session. Run the probe on the host instead.")
  val command =
    if options.command.nonEmpty then options.command
    else if Files.isRegularFile(Path.of("target/dist/ko-agent-sandbox.jar")) then DefaultCommand
    else fail("target/dist/ko-agent-sandbox.jar is missing: run 'sbt dist' first, or pass a build command after --.")

  println("== What decides the answer")
  say("OS", s"${Properties.osName} ${System.getProperty("os.version")} ${System.getProperty("os.arch")}")
  say("podman", output("podman", "--version"))
  say("machine provider", output("podman", "machine", "info", "--format", "{{.Host.VMType}}"))
  say("machine memory (MiB)", output("podman", "machine", "inspect", "--format", "{{.Resources.Memory}}"))
  host match
    case Host.Mac =>
      val krunkit = output("which", "krunkit")
      if krunkit.isEmpty then say("krunkit", "MISSING (the provider above is not libkrun, or krunkit is not on PATH)")
      else
        say("krunkit", krunkit)
        // The dylib's install name carries the version that Homebrew built; 1.19.0 or later means MADV_FREE.
        output("otool", "-L", krunkit).linesIterator.filter(_.toLowerCase.contains("libkrun"))
          .foreach(line => println(s"    ${line.trim}"))
        val brew = output("brew", "list", "--versions", "libkrun", "krunkit")
        if brew.nonEmpty then say("brew versions", brew.linesIterator.mkString(" "))
    case Host.Windows =>
      wsl("--version").foreach(line => println(s"    $line"))
      say("autoMemoryReclaim", reclaimSetting)
      val running = wsl("--list", "--running", "--quiet")
      say("running WSL distributions", running.mkString(", "))
      if running.size > 1 then
        System.err.println("warning: another WSL distribution is running, and its memory shows in the same VM.")
  val uptime = output("podman", "machine", "ssh", "--", "cut", "-d.", "-f1", "/proc/uptime")
  uptime.toLongOption match
    case None => fail(s"Cannot read the machine's uptime over podman machine ssh: $uptime")
    case Some(seconds) =>
      say("machine uptime (s)", seconds.toString)
      if seconds > 600 then
        fail("The machine has been up longer than ten minutes: restart it as the header shows, then run this probe.")
  val containers = output("podman", "ps", "-q")
  if containers.nonEmpty then fail(s"Containers are running on the machine; end those sessions first:\n$containers")
  val macPids = if host == Host.Mac then macVmPids else Nil
  val firstSample = host match
    case Host.Mac => macSamples("check", macPids)
    case Host.Windows => windowsSamples("check")
  if firstSample.isEmpty then
    fail("No VM process (krunkit on macOS, vmmemWSL or vmmem on Windows): start the machine and run again.")
  say("VM process(es)", firstSample.map(_.pid).mkString(" "))
  println()

  // The directory stays after the run, because the summary names it.
  val samplesDir = Files.createTempDirectory("podman-machine-memory-reclaim")
  val csv = samplesDir.resolve("samples.csv")
  Files.writeString(csv, Sample.CsvHeader + "\n")
  val phase = AtomicReference("baseline")
  val samples = java.util.concurrent.ConcurrentLinkedQueue[Sample]()
  val guest = scala.collection.mutable.LinkedHashMap[String, String]()
  val sampler = Thread(() =>
    try
      while true do
        val taken = host match
          case Host.Mac => macSamples(phase.get, macPids)
          case Host.Windows => windowsSamples(phase.get)
        taken.foreach { sample =>
          samples.add(sample)
          Files.writeString(csv, sample.csvLine + "\n", java.nio.file.StandardOpenOption.APPEND)
        }
        Thread.sleep(options.intervalSeconds * 1000L)
    catch case _: InterruptedException => ()
  )
  sampler.setDaemon(true)
  sampler.start()

  def hold(name: String, seconds: Int): Unit =
    phase.set(name)
    Thread.sleep(seconds * 1000L)

  println(s"== baseline: ${options.baselineSeconds} s")
  hold("baseline", options.baselineSeconds)
  guest("baseline") = guestMemInfo
  println(s"== build: ${command.mkString(" ")}")
  phase.set("build")
  val started = System.nanoTime
  // The launcher's start prompt would otherwise wait for a user who reads the sampler's output, so the default command
  // passes --session-start=immediate.
  val status = ProcessBuilder(command*).inheritIO().start().waitFor()
  println(s"command exited $status after ${(System.nanoTime - started) / 1_000_000_000L} s")
  guest("build") = guestMemInfo
  println(s"== after: ${options.afterSeconds} s")
  hold("after", options.afterSeconds)
  guest("after") = guestMemInfo
  var pressureNote = ""
  if host == Host.Mac && options.pressure then
    println("== pressure: memory_pressure -l warn for 60 s, then 60 s more")
    phase.set("pressure")
    val pressureLog = samplesDir.resolve("memory_pressure.log")
    val pressure = ProcessBuilder("memory_pressure", "-l", "warn").redirectErrorStream(true)
      .redirectOutput(pressureLog.toFile).start()
    // memory_pressure holds its level in a loop and does not watch its parent, so a probe that ended without
    // destroying it would leave the host under pressure. The hook covers SIGINT and SIGTERM, which end the JVM
    // without reaching the finally below.
    val endPressure = Thread(() => pressure.destroy())
    Runtime.getRuntime.addShutdownHook(endPressure)
    try
      if pressure.waitFor(60, java.util.concurrent.TimeUnit.SECONDS) then
        pressureNote =
          s"pressure phase INVALID: memory_pressure exited with status ${pressure.exitValue} before its 60 s; " +
            s"see $pressureLog"
        System.err.println(pressureNote)
      else
        pressure.destroy()
        pressure.waitFor()
        hold("released", 60)
    finally
      pressure.destroy()
      Runtime.getRuntime.removeShutdownHook(endPressure)
    guest("pressure") = guestMemInfo
  sampler.interrupt()
  sampler.join()

  println()
  println(s"== summary (MiB): first, peak and last sample of each phase; samples in $csv")
  val columns: Seq[(String, Sample => Option[Long])] = host match
    case Host.Mac => Seq(
        "VM RSS" -> (sample => Some(sample.vmResidentKb)),
        "VM CMPRS" -> (_.vmCompressedKb),
        "host free" -> (sample => Some(sample.hostFreeKb)),
        "compressor stored" -> (_.compressorStoredKb),
        "host swap used" -> (_.swapUsedKb),
      )
    case Host.Windows => Seq(
        "VM working set" -> (sample => Some(sample.vmResidentKb)),
        "VM private" -> (_.vmPrivateKb),
        "host free" -> (sample => Some(sample.hostFreeKb)),
      )
  val levelHeader = if host == Host.Mac then (" | pressure level", " | last") else ("", "")
  println(f"${"phase"}%-9s ${"pid"}%-6s" + columns.map((name, _) => f" | $name%-20s").mkString + levelHeader._1)
  println(f"${""}%-9s ${""}%-6s" + columns.map(_ => f" | ${"first  peak  last"}%-20s").mkString + levelHeader._2)
  val all = samples.asScala.toSeq
  for
    (name, inPhase) <- all.groupBy(sample => (sample.phase, sample.pid)).toSeq
      .sortBy((key, group) => group.map(_.epoch).min)
  do
    val cells = columns.map { (_, column) =>
      val values = inPhase.sortBy(_.epoch).flatMap(column(_)).map(_ / 1024)
      if values.isEmpty then f"${"-"}%20s" else f"${values.head}%6d ${values.max}%6d ${values.last}%6d"
    }
    val level = if host == Host.Mac then inPhase.maxBy(_.epoch).pressureLevel.map(" | " + _).getOrElse("") else ""
    println(f"${name._1}%-9s ${name._2}%-6d" + cells.map(" | " + _).mkString + level)
  println()
  println("== guest /proc/meminfo (MiB) at the end of each phase")
  guest.foreach((name, values) => say(name, values))
  if pressureNote.nonEmpty then println(pressureNote)
