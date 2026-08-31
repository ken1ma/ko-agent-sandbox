// Speaks sbt's local-socket shutdown: the tokenless `initialize` the pinned client sends, then
// `sbt/exec shutdown` — the sequence sbt v2.0.4's NetworkClient/Serialization implement and
// probe/session-recovery.sh M4 measured, framing per ServerConnection.sendString (the length
// counts the body plus its trailing CRLF). Local-mode servers authenticate nothing
// (Defaults.serverAuthentication is TCP-only), so there is no token to carry.
//
// Never sbt's own client here: its measured answer to a dead socket is to delete the portfile and
// start its own server — from a scavenger, an unconfined one.

package agentsandbox.launcher

import java.io.IOException
import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import java.util.UUID

import RunOnHostSession.ServerAnswer

object SbtServerShutdown:

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
   * Connect, initialize, wait for the server's first bytes, send the shutdown exec, and wait for
   * the server to close the socket — the measured shape of a successful shutdown. Bounded
   * throughout, the connect included; a definitive no-listener answer is Unreachable, and
   * everything else — an unanswered protocol, a transient connect failure — is Unanswered, for
   * the caller to retry, never something to guess at by pid. The default bound is minutes, not
   * seconds: a server mid-exec runs `shutdown` after the command it is on, so the bound covers a
   * queued exec, not only a dead socket.
   */
  def shutdown(socket: Path, deadlineMillis: Long = 120_000): ServerAnswer =
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    // notExists, not !exists: both are false when the status cannot be determined (an unreadable
    // parent, say), and only proven absence is definitive.
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
   * Non-blocking, and under the deadline: a blocking Unix-domain connect can wait on a full
   * backlog, which is a live and busy server. Only a definitive refusal is Unreachable — proven
   * absence is answered by the notExists check above; anything else (EACCES, exhausted
   * descriptors) may hide a live listener and stays retryable. Measured mapping: no listener is a
   * ConnectException, an absent path a generic SocketException, EACCES a BindException.
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

  /** A reset here is the peer exiting mid-close — the outcome being waited for, not a failure. */
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
