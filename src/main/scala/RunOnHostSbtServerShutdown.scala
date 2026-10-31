// Speaks sbt's local-socket shutdown: the tokenless `initialize` that the pinned client sends, then
// `sbt/exec shutdown`.
//
// - sbt v2.0.4's NetworkClient and Serialization implement this sequence, and src/probe/session-recovery.sh M4
//   measured it.
// - The framing follows ServerConnection.sendString: the length counts the body plus its trailing CRLF.
// - Local-mode servers authenticate nothing (Defaults.serverAuthentication is TCP-only), so there is no token to
//   pass.
//
// This file never runs sbt's own client. Faced with a dead socket, sbt's client deletes the portfile and starts its
// own server (measured). Started from a scavenger, that server would be unconfined.

package agentsandbox.launcher

import java.io.IOException
import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import java.util.UUID

import RunOnHostSession.ServerAnswer

object RunOnHostSbtServerShutdown:

  def frame(json: String): Array[Byte] =
    val body = json.getBytes(UTF_8)
    s"Content-Length: ${body.length + 2}\r\n\r\n".getBytes(UTF_8) ++ body ++ "\r\n".getBytes(UTF_8)

  def initializeMessage(execId: String): String =
    s"""{ "jsonrpc": "2.0", "id": "$execId", "method": "initialize", "params": """ +
      """{ "initializationOptions": {"skipAnalysis":true,"canWork":true,"subscribeToAll":false} } }"""

  def execMessage(execId: String, commandLine: String): String =
    s"""{ "jsonrpc": "2.0", "id": "$execId", "method": "sbt/exec", """ +
      s""""params": { "commandLine": "$commandLine" } }"""

  private enum Awaited:
    case BytesArrived, Eof, TimedOut
  import Awaited.*

  /**
   * Connects, initializes, waits for the server's first bytes, sends the shutdown exec, and waits for the server to
   * close the socket. The steps follow the measured sequence of a successful shutdown.
   *
   *   - A deadline bounds every step, the connect included.
   *   - A definitive answer that no listener exists is Unreachable.
   *   - Everything else is Unanswered, for the caller to retry, such as an unanswered protocol or a transient
   *     connect failure. The caller never guesses a verdict by pid.
   *   - The default bound is minutes, not seconds. A server in the middle of an exec runs `shutdown` after its
   *     current command, so the bound covers a queued exec, not only a dead socket.
   */
  def shutdown(socket: Path, deadlineMillis: Long = 120_000): ServerAnswer =
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    // notExists, not !exists: both are false when the status cannot be determined, for example under an
    // unreadable parent. Only proven absence is definitive.
    if java.nio.file.Files.notExists(socket) then ServerAnswer.Unreachable(s"$socket does not exist")
    else
      connect(socket, deadline) match
        case Left(answer) => answer
        case Right(channel) =>
          try
            writeAll(channel, frame(initializeMessage(UUID.randomUUID.toString)))
            awaitBytes(channel, deadline) match
              case Eof =>
                ServerAnswer.Unanswered("the server closed the socket before answering initialize")
              case TimedOut => ServerAnswer.Unanswered("no answer to initialize before the deadline")
              case BytesArrived =>
                writeAll(channel, frame(execMessage(UUID.randomUUID.toString, "shutdown")))
                if drainToEof(channel, deadline) then ServerAnswer.ShutDown
                else
                  ServerAnswer.Unanswered("the server did not close the socket before the deadline")
          catch case ex: IOException => ServerAnswer.Unanswered(ex.getMessage)
          finally channel.close()

  /**
   * Connects without blocking, under the deadline. A blocking Unix-domain connect can wait on a full backlog, and a
   * full backlog means a live and busy server.
   *
   *   - Only a definitive refusal is Unreachable. The notExists check in `shutdown` answers proven absence.
   *   - Anything else, such as EACCES or exhausted descriptors, may hide a live listener and stays retryable.
   *   - The measured mapping: no listener raises a ConnectException, an absent path a generic SocketException, and
   *     EACCES a BindException.
   */
  private def connect(socket: Path, deadline: Long): Either[ServerAnswer, SocketChannel] =
    try
      val channel = SocketChannel.open(StandardProtocolFamily.UNIX)
      try
        channel.configureBlocking(false)
        var connected = channel.connect(UnixDomainSocketAddress.of(socket))
        while !connected && System.nanoTime < deadline do
          connected = channel.finishConnect()
          if !connected then Thread.sleep(10)
        if connected then Right(channel)
        else
          channel.close()
          Left(ServerAnswer.Unanswered("no connect before the deadline"))
      catch
        case ex: java.net.ConnectException =>
          channel.close()
          Left(ServerAnswer.Unreachable(ex.getMessage))
        case ex: IOException =>
          channel.close()
          Left(ServerAnswer.Unanswered(ex.getMessage))
    catch case ex: IOException => Left(ServerAnswer.Unanswered(ex.getMessage))

  private def awaitBytes(channel: SocketChannel, deadline: Long): Awaited =
    val buffer = ByteBuffer.allocate(4096)
    var result: Option[Awaited] = None
    while result.isEmpty do
      buffer.clear()
      channel.read(buffer) match
        case -1            => result = Some(Eof)
        case n if n > 0    => result = Some(BytesArrived)
        case _ =>
          if System.nanoTime > deadline then result = Some(TimedOut)
          else Thread.sleep(10)
    result.get

  private def writeAll(channel: SocketChannel, bytes: Array[Byte]): Unit =
    val buffer = ByteBuffer.wrap(bytes)
    while buffer.hasRemaining do if channel.write(buffer) == 0 then Thread.sleep(1)

  /** A reset here means that the peer exited while closing, which is the awaited outcome, not a failure. */
  private def drainToEof(channel: SocketChannel, deadline: Long): Boolean =
    var outcome: Option[Boolean] = None
    while outcome.isEmpty do
      try
        awaitBytes(channel, deadline) match
          case Eof          => outcome = Some(true)
          case TimedOut     => outcome = Some(false)
          case BytesArrived => ()
      catch case _: IOException => outcome = Some(true)
    outcome.get
