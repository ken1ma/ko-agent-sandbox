// The recorders that MicRelayTest gives the relays, one mode per scenario.
//
// A real recorder is one process: `rec` delivers 1280- and 640-byte pieces alternating every 30 ms, which averages
// 640 bytes per 20 ms (doc/mic.md, "macOS, measured"). So the fake is one process that writes every period the clock
// has made due. A shell loop that starts processes per period falls behind under load: during a full `testWithPodman`
// run on 2026-11-04, the POSIX relay's supervisor ended such a loop as a recorder that delivered no audio for 5 s.
//
// Every mode counts its starts in `<host>/starts-<mode>`.

package agentsandbox.launcher

import java.nio.file.{Files, Path, StandardCopyOption}

object FakeMicRecorder:

  /** The number of distinct indexed periods. Period `i` holds 320 samples of `i % Periods`, so a capture reads
    * as a sequence of indices, and period 0 is zeros. */
  val Periods = 1000

  val PeriodBytes = 640
  private val PeriodNanos = 20_000_000L

  /** The periods of zeros that `late` writes before its indexed periods. */
  val LateZeroPeriods = 100

  private val Zeros = new Array[Byte](PeriodBytes)

  private def indexed(index: Int): Array[Byte] =
    Array.fill(PeriodBytes / 2)(Array((index & 0xff).toByte, (index >> 8).toByte)).flatten

  /**
   * - `good` writes the indexed periods, and before each one writes its count to `<host>/at`.
   * - `late` writes LateZeroPeriods periods of zeros, then writes as `good` does, without `at`.
   * - `silent` writes zeros.
   * - `failing` exits immediately at startup, with SoX's warning and then its failure on stderr.
   * - `mute` never writes.
   * - `stalling` writes the probe's periods and 30 more at once, then nothing.
   */
  def main(args: Array[String]): Unit =
    val Array(mode, hostPath) = args
    val host = Path.of(hostPath)
    val starts = host.resolve(s"starts-$mode")
    val started = if Files.exists(starts) then Files.readString(starts).trim.toInt else 0
    Files.writeString(starts, s"${started + 1}\n")
    val out = java.io.FileOutputStream(java.io.FileDescriptor.out)
    def write(bytes: Array[Byte]): Unit =
      try out.write(bytes)
      catch case _: java.io.IOException => sys.exit(1)
    mode match
      case "good"   => paced(index => { recordAt(host, index); write(indexed((index % Periods).toInt)) })
      case "late"   =>
        paced: index =>
          write(if index < LateZeroPeriods then Zeros else indexed(((index - LateZeroPeriods) % Periods).toInt))
      case "silent" => paced(_ => write(Zeros))
      case "failing" =>
        // A recorder that fails immediately at startup would lose these lines here: the Windows relay destroys it
        // before reading its stderr, and on Linux and macOS, unlike Windows, the JDK's destroy closes the process's
        // streams. This JVM starts slowly enough that the relay's reader is already waiting.
        System.err.println("rec WARN formats: can't set sample rate 16000; using 48000")
        System.err.println("rec FAIL formats: can't open input")
        sys.exit(2)
      case "mute"     => sleepForever()
      case "stalling" =>
        (0 until MicRelay.ProbeReads + 30).foreach(index => write(indexed(index)))
        sleepForever()
      case other => throw IllegalArgumentException(s"unknown mode $other")

  /** Calls `period` with each period's index once the clock has made it due, period 0 at once. */
  private def paced(period: Long => Unit): Unit =
    val start = System.nanoTime()
    var next = 0L
    while true do
      val due = (System.nanoTime() - start) / PeriodNanos + 1
      while next < due do
        period(next)
        next += 1
      val untilNext = start + next * PeriodNanos - System.nanoTime()
      if untilNext > 0 then Thread.sleep(untilNext / 1_000_000, (untilNext % 1_000_000).toInt)

  /** Replaces `<host>/at` whole, so a reader never finds it empty. */
  private def recordAt(host: Path, index: Long): Unit =
    val partial = host.resolve("at.partial")
    Files.writeString(partial, s"$index\n")
    Files.move(partial, host.resolve("at"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)

  private def sleepForever(): Unit =
    while true do Thread.sleep(3_600_000)
