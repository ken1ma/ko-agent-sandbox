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
   * throughout; a server that neither answers nor closes is a Left for the caller to report,
   * never something to guess at by pid. The default bound is minutes, not seconds: a server
   * mid-exec runs `shutdown` after the command it is on, so the bound covers a queued exec, not
   * only a dead socket.
   */
  def shutdown(socket: Path, deadlineMillis: Long = 120_000): Either[String, Unit] =
    val deadline = System.nanoTime + deadlineMillis * 1_000_000
    try
      val channel = SocketChannel.open(StandardProtocolFamily.UNIX)
      try
        channel.connect(UnixDomainSocketAddress.of(socket))
        channel.configureBlocking(false)
        writeAll(channel, frame(initializeMessage(UUID.randomUUID.toString)))
        awaitBytes(channel, deadline) match
          case Eof          => Left("the server closed the socket before answering initialize")
          case TimedOut     => Left("no answer to initialize before the deadline")
          case BytesArrived =>
            writeAll(channel, frame(execMessage(UUID.randomUUID.toString, "shutdown")))
            drainToEof(channel, deadline) match
              case true  => Right(())
              case false => Left("the server did not close the socket before the deadline")
      finally channel.close()
    catch case ex: IOException => Left(ex.getMessage)

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
