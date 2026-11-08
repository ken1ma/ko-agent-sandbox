// The audit log's form. This file holds:
//
// - the line grammar and the per-line UTC stamp;
// - the tee into the host file;
// - the SHA-256 digest that names the enforced ruleset and the launcher's records.
//
// The proxy decides what it logs and when (AgentEgressProxy).

package agentsandbox.egress

import java.io.{IOException, OutputStream}
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference
import java.time.format.DateTimeFormatter

object LogHelper:
  /**
   * One connection event of the audit log: `action host method [target] tail`. SECURITY.md declares this grammar
   * stable through field 3 ("The audit line grammar").
   *
   * - A `-` fills a field that the connection ended before revealing.
   * - The target appears exactly when a parsed inspected request exists.
   * - The tail is human text with no field structure.
   *
   * The target is the request's, and the tail may quote the origin. So every field writes these characters as a
   * Java/Scala string literal spells them:
   *
   *   - C0 and C1 controls and DEL (`\t`, `\u001b`). A tab would break the field grammar that tooling greps. On
   *     the terminal that reads the log, an escape sequence would let a request or an origin choose how its own
   *     record reads.
   *   - U+2028 and U+2029 (`\u2028`). Tools that split lines on them would end the line early.
   *   - Format characters (`Character.FORMAT`: the bidi controls, zero-width characters, U+00AD, the tag
   *     characters; `\u202e`, `\u200b`, `\udb40\udc41`). Terminals and editors show them as nothing or reorder
   *     the rest of the line by them, so the line would read other than what was sent. Any request target can
   *     carry U+00AD.
   *   - `"`, `\` and unpaired surrogates (`\"`, `\\`, `\ud800`). A field then reads back exactly as the content
   *     of a string literal: a `\u001b` in the log is always an escape, and a lone surrogate does not become the
   *     `?` that UTF-8 encoding would write.
   */
  def auditLine(action: String, host: String, method: String, target: String, tail: String): String =
    (Vector(action, host, method) ++ Vector(target, tail).filter(_.nonEmpty)).map(escapeForLogLine).mkString(" ")

  /** An audit line read back past the stamp that stampLines puts first. `rest` is the target and the tail, or the
    * tail alone, as auditLine wrote them. */
  final case class AuditFields(action: String, host: String, method: String, rest: String)

  /** None for a line without a stamp, action, host and method. */
  def auditFields(line: String): Option[AuditFields] =
    unstamped(line).flatMap:
      _.split(" ", 4) match
        case Array(action, host, method, rest) => Some(AuditFields(action, host, method, rest))
        case Array(action, host, method)       => Some(AuditFields(action, host, method, ""))
        case _                                 => None

  private val Stamped = """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z (.*)""".r

  /** A line that stampLines wrote, without its stamp. None for a line another writer put in the same file, such as
    * a host proxy's sandbox-exec. */
  def unstamped(line: String): Option[String] = line match
    case Stamped(rest) => Some(rest)
    case _             => None

  /** @return the content between the quotes of a Java/Scala string literal whose value is `text`.
    * The result's `\u` escapes never stand for a quote, a backslash or a line break, which Java translates
    * before it reads the literal. */
  def escapeForLogLine(text: String): String =
    def isControl(char: Char) = char < 0x20 || (char >= 0x7f && char <= 0x9f)
    def unicodeEscape(char: Char) = f"\\u${char.toInt}%04x"

    val result = StringBuilder(text.length)
    var i = 0
    while i < text.length do
      text.charAt(i) match
        case '"'                            => result ++= "\\\""
        case '\\'                           => result ++= "\\\\"
        case '\b'                           => result ++= "\\b"
        case '\t'                           => result ++= "\\t"
        case '\n'                           => result ++= "\\n"
        case '\f'                           => result ++= "\\f"
        case '\r'                           => result ++= "\\r"
        case char @ ('\u2028' | '\u2029')   => result ++= unicodeEscape(char)
        case char if isControl(char)        => result ++= unicodeEscape(char)
        case char if Character.isHighSurrogate(char) =>
          if i + 1 < text.length && Character.isLowSurrogate(text.charAt(i + 1)) then
            val low = text.charAt(i + 1)
            if Character.getType(Character.toCodePoint(char, low)) == Character.FORMAT then
              result ++= unicodeEscape(char)
              result ++= unicodeEscape(low)
            else
              result += char
              result += low
            i += 1
          else result ++= unicodeEscape(char)
        case char if Character.isLowSurrogate(char)              => result ++= unicodeEscape(char)
        case char if Character.getType(char) == Character.FORMAT => result ++= unicodeEscape(char)
        case char                                                => result += char
      i += 1
    result.result()

  /**
   * Every line the proxy reports, prefixed with the instant it was written, as `2026-08-26T11:59:38Z `. The stamp
   * is in UTC (SECURITY.md, "The audit line grammar").
   * The prefix goes in at the byte level, on the first byte after a newline, so a line printed in pieces is stamped
   * once.
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
   * Both sinks, flushes included. Every line must reach the file as the proxy writes it, because the reaper removes
   * this container the moment its sandbox exits.
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

  /**
   * `out`, keeping the first write or flush that failed in `first` instead of throwing it.
   *
   * - `out` is never a PrintStream. The System.err that these sinks sit under is a PrintStream, which catches the
   *   IOException anyway and keeps a flag without the reason (checkError).
   * - A thrown failure would also end the write of a stamped line halfway and keep the rest from the tee's other
   *   sink. That other sink is where the failure is then reported.
   */
  def keepingFirstFailure(out: OutputStream, first: AtomicReference[IOException]): OutputStream = new OutputStream:
    require(!out.isInstanceOf[java.io.PrintStream], "a PrintStream throws no IOException to keep")
    private def keeping(write: => Unit): Unit =
      try write
      catch case ex: IOException => first.compareAndSet(null, ex)
    override def write(byte: Int): Unit = keeping(out.write(byte))
    override def write(bytes: Array[Byte], offset: Int, length: Int): Unit = keeping(out.write(bytes, offset, length))
    override def flush(): Unit = keeping(out.flush())

  /** The launcher compiles this file, and also names a workspace's id and volumes, a build directory's records and a
    * runtime's fingerprint by this digest. */
  def sha256Hex(text: String): String =
    java.util.HexFormat.of().formatHex(
      java.security.MessageDigest.getInstance("SHA-256").digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
    )
