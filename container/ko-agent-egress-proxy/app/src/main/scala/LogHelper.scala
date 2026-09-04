// The audit log's form: the line grammar, the per-line UTC stamp, the tee into the host file, and
// the digest naming the enforced policy. What is logged when is the proxy's (AgentEgressProxy).

package agentsandbox.egress

import java.io.OutputStream
import java.time.Instant
import java.time.format.DateTimeFormatter

object LogHelper:
  /**
   * One connection event of the audit log: `verb host method [target] tail` — the grammar
   * SECURITY.md ("The audit line grammar") declares stable through field 3. A `-` fills a field
   * the connection ended before revealing; the target appears exactly when a parsed inspected
   * request exists; the tail is human text with no field structure.
   */
  def auditLine(verb: String, host: String, method: String, target: String, tail: String): String =
    (Vector(verb, host, method) ++ Vector(target, tail).filter(_.nonEmpty)).mkString(" ")

  /**
   * Every line the proxy reports, prefixed with the instant it was written, as
   * `2026-08-26T11:59:38Z `. UTC, per SECURITY.md "The audit line grammar".
   * Prefixing at the byte level, on the first byte after a newline, so a line
   * printed in pieces is stamped once.
   */
  def stampLines(out: OutputStream, now: () => Instant): OutputStream = new OutputStream:
    private var lineStart = true
    private def stamp(): Unit =
      out.write(DateTimeFormatter.ISO_INSTANT.format(now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)).getBytes)
      out.write(' ')
      lineStart = false
    override def write(byte: Int): Unit =
      if lineStart then stamp()
      out.write(byte)
      lineStart = byte == '\n'
    override def write(bytes: Array[Byte], offset: Int, length: Int): Unit =
      var from = offset
      val end = offset + length
      while from < end do
        if lineStart then stamp()
        val newline = bytes.indexOf('\n'.toByte, from)
        val to = if newline < 0 || newline >= end then end else newline + 1
        out.write(bytes, from, to - from)
        lineStart = bytes(to - 1) == '\n'
        from = to
    override def flush(): Unit = out.flush()

  /**
   * Both sinks, flushes included: every line must reach the file as it is written,
   * because the reaper removes this container the moment its sandbox exits.
   */
  def teeOutput(a: OutputStream, b: OutputStream): OutputStream = new OutputStream:
    override def write(byte: Int): Unit =
      a.write(byte)
      b.write(byte)
    override def write(bytes: Array[Byte], offset: Int, length: Int): Unit =
      a.write(bytes, offset, length)
      b.write(bytes, offset, length)
    override def flush(): Unit =
      a.flush()
      b.flush()

  def sha256Hex(text: String): String =
    java.security.MessageDigest
      .getInstance("SHA-256")
      .digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8))
      .map(byte => f"$byte%02x")
      .mkString
