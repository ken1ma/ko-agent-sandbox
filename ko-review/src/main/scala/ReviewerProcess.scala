package koreview

import io.circe.JsonObject
import java.io.{BufferedInputStream, ByteArrayOutputStream, OutputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.util.concurrent.{CountDownLatch, TimeUnit}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicReference}
import scala.collection.mutable
import scala.util.control.NonFatal

/** What a reviewer's run left: its events, the first thread id it named, the first line that is not JSON, whether the
  * timeout ended it, and its exit status. */
final case class Streamed(
    events: Vector[JsonObject],
    threadId: Option[String],
    badLine: Option[String],
    timedOut: Boolean,
    exitStatus: Int,
)

/** A timer that runs an action once, unless cancelled first. `join` waits for an action already running. */
trait TurnTimer:
  def cancel(): Unit
  def join(): Unit

/** Runs one reviewer turn's processes. The constructor's functions are for the tests, which pause a timer or fail a
  * reap at a chosen moment.
  *
  * A process of the helper's own leads the reviewer's process group, and lives until the group has been killed, so
  * the group's id stays taken until then. A reviewer leading its own group would free the id the moment it is reaped,
  * and an unrelated process could take the id before the kill. The leader reads the helper's pipe, so the leader
  * exits with the helper at the latest.
  */
class ReviewerProcess(
    javaCommand: Seq[String],
    signalGroup: Long => Unit = pgid => Posix.killGroup(pgid, Posix.SIGKILL): Unit,
    startTimer: (Long, () => Unit) => TurnTimer = ReviewerProcess.sleepingTimer,
    reapProcess: Process => Unit = ReviewerProcess.reapUninterruptibly,
):

  /** Starts the group's leader, `cat` in a group of its own, and waits until it leads that group. */
  def startLeader(): Process =
    val stderr = Files.createTempFile("ko-review-leader-", ".err")
    try
      val leader = ProcessBuilder((javaCommand ++ Seq("koreview.JoinGroup", "0", "cat"))*)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(stderr.toFile).start()
      val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
      while !Posix.getpgid(leader.pid()).contains(leader.pid()) do
        if !leader.isAlive || System.nanoTime() > deadline then
          leader.destroyForcibly()
          throw IllegalStateException(
            s"the reviewer's process group leader did not start: ${Files.readString(stderr).trim}")
        Thread.sleep(10)
      leader
    finally Files.deleteIfExists(stderr): Unit

  /** Starts `command` in the leader's group, with the reviewer's stdout piped and its stderr in `stderr`. */
  def startReviewer(leader: Process, command: Seq[String], cwd: Path, env: Map[String, String], stderr: Path): Process =
    val builder = ProcessBuilder((javaCommand ++ Seq("koreview.JoinGroup", leader.pid().toString) ++ command)*)
      .directory(cwd.toFile).redirectError(stderr.toFile)
    builder.environment().clear()
    env.foreach((name, value) => builder.environment().put(name, value))
    builder.start()

  /** Feeds the prompt, copies the reviewer's stdout to `eventsPath`, and parses its JSON lines as they arrive.
    *
    * - `onThread` runs the moment the reviewer names its thread. Whatever ends the turn after that, the thread holds
    *   the request, and a retry resumes it.
    * - The turn ends with the reviewer's exit, not with the output's end: a process that the reviewer left holding
    *   its stdout decides when the output ends.
    * - A failure in the reading thread ends the turn too, and propagates once the cleanup is through.
    * - Once the turn ends, or at once on any exception, the cleanup kills the reviewer's group, reaps the reviewer and
    *   the leader, then kills and reaps the orphans that the helper adopted. All of this happens before the method
    *   returns or the exception propagates, so no process of the group, nor on Linux any descendant of the reviewer,
    *   outlives the lock that serialized the turn.
    */
  def stream(
      process: Process,
      leader: Process,
      prompt: Array[Byte],
      timeoutSeconds: Long,
      eventsPath: Path,
      threadIdOf: JsonObject => Option[String],
      onThread: String => Unit,
  ): Streamed =
    val timedOut = AtomicBoolean(false)
    val signalled = AtomicBoolean(false)
    val turnOver = CountDownLatch(1)
    val readerFailure = AtomicReference[Throwable]()
    val events = mutable.ArrayBuffer.empty[JsonObject]
    val threadId = AtomicReference[Option[String]](None)
    val badLine = AtomicReference[Option[String]](None)
    var timer: Option[TurnTimer] = None
    var reader: Option[Thread] = None
    var eventsStream: Option[OutputStream] = None

    def signalOnce(): Unit = signalled.synchronized:
      // A group signalled once is not signalled again: after the leader is reaped, its id is free for another group.
      if !signalled.get then
        signalGroup(leader.pid())
        signalled.set(true)

    // Repeatable, so that a failure inside it can run it again. A timer action that started before `cancel` runs to
    // its end, and must find the leader unreaped.
    def endGroup(): Unit =
      timer.foreach: running =>
        running.cancel()
        running.join()
      signalOnce()
      reapProcess(process)
      reapProcess(leader)
      Posix.killAndReapChildren() // once the reviewer and the leader are reaped, every child is an adopted orphan
      // At the output's end: on Linux, every process that held the stdout is dead.
      reader.foreach(ReviewerProcess.joinUninterruptibly)
      eventsStream.foreach(_.close())

    var cleanedUp = false
    try
      Thread.ofVirtual().start: () =>
        try
          process.getOutputStream.write(prompt)
          process.getOutputStream.close()
        catch case _: java.io.IOException => () // the reviewer stopped reading
      timer = Some(startTimer(timeoutSeconds, () =>
        timedOut.set(true)
        signalOnce()
      ))
      val stream = Files.newOutputStream(eventsPath)
      eventsStream = Some(stream)
      reader = Some(Thread.ofPlatform().daemon().start: () =>
        try
          val input = BufferedInputStream(process.getInputStream)
          var line = readLine(input)
          while line.isDefined do
            stream.write(line.get)
            stream.flush()
            val text = String(line.get, UTF_8).trim
            if text.nonEmpty then
              io.circe.parser.parse(text) match
                case Left(_) => if badLine.get.isEmpty then badLine.set(Some(text.take(200)))
                case Right(json) =>
                  json.asObject.foreach: event =>
                    events.synchronized(events += event)
                    if threadId.get.isEmpty then
                      threadIdOf(event).foreach: id =>
                        threadId.set(Some(id))
                        onThread(id)
            line = readLine(input)
        catch
          case NonFatal(ex) =>
            readerFailure.set(ex)
            turnOver.countDown()
      )
      Thread.ofVirtual().start: () =>
        reapProcess(process)
        turnOver.countDown()
      turnOver.await()
      endGroup()
      cleanedUp = true
      Option(readerFailure.get).foreach(ex => throw ex)
    finally if !cleanedUp then endGroup()
    Streamed(events.synchronized(events.toVector), threadId.get, badLine.get, timedOut.get, process.exitValue())

  /** The next line with its newline, or None at the end of the output. */
  private def readLine(input: BufferedInputStream): Option[Array[Byte]] =
    val line = ByteArrayOutputStream()
    var byte = input.read()
    while byte >= 0 && byte != '\n' do
      line.write(byte)
      byte = input.read()
    if byte < 0 && line.size == 0 then None
    else
      if byte >= 0 then line.write(byte)
      Some(line.toByteArray)

object ReviewerProcess:

  def sleepingTimer(seconds: Long, action: () => Unit): TurnTimer =
    val cancelled = AtomicBoolean(false)
    val thread = Thread.ofVirtual().start: () =>
      try
        Thread.sleep(TimeUnit.SECONDS.toMillis(seconds))
        if !cancelled.get then action()
      catch case _: InterruptedException => ()
    new TurnTimer:
      def cancel(): Unit =
        cancelled.set(true)
        thread.interrupt()
      def join(): Unit = joinUninterruptibly(thread)

  /** Waits for `process` to end. An interrupt meanwhile waits on, and stays pending for the caller. */
  def reapUninterruptibly(process: Process): Unit =
    var interrupted = false
    var done = false
    while !done do
      try
        process.waitFor()
        done = true
      catch case _: InterruptedException => interrupted = true
    if interrupted then Thread.currentThread().interrupt()

  def joinUninterruptibly(thread: Thread): Unit =
    var interrupted = false
    var done = false
    while !done do
      try
        thread.join()
        done = true
      catch case _: InterruptedException => interrupted = true
    if interrupted then Thread.currentThread().interrupt()
