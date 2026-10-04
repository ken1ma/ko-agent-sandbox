// A rule's path and the spelling a request path must have to be compared with one: the grammar a
// rule file's path, a `--egress-cred` prefix and a request under either share (doc/egress-proxy.md,
// "The rule file"). The proxy compares paths literally and decodes nothing it forwards: a spelling
// is validated, never rewritten into the one a rule accepts.
//
// The grammar keeps a path from naming another place under another HTTP or URI reading of it:
// percent-decoding, dot segments, backslashes, path parameters, empty segments, and Unicode
// normalization. It does not model an application that reads a segment as something else — an NTFS
// stream after `:`, an archive entry after `!`, form data where `+` is a space.
//
// A POST, PUT, PATCH or DELETE path is stricter still, at every scope: no `%` and no dot segment, since a
// forge decodes those before routing (requireUnambiguousPath).

package agentsandbox.egress

import java.nio.ByteBuffer
import java.nio.charset.{CharacterCodingException, CodingErrorAction, StandardCharsets}
import java.text.Normalizer

/** A rule's path: `/` the root, a trailing `/` a tree, none one exact path. */
object RulePath:
  val Root = "/"

  def contains(path: String, request: String): Boolean =
    if path.endsWith("/") then request.startsWith(path) else request == path

  /** The longest of `scopes` containing `path`, a request's or a rule's. */
  def longestMatch(scopes: Iterable[String], path: String): Option[String] =
    scopes.filter(scope => contains(scope, path)).maxByOption(_.length)

  /** Characters that separate, rename or end a path under some server's reading of it. */
  private val Delimiters = "/\\.;%?#"

  /**
   * Why `path` cannot be compared literally to a rule's path, or None: the one rule for a rule's path
   * and an `--egress-cred` prefix at launch, and for a request under either. One spelling per path:
   *
   * - printable ASCII alone, as RFC 3986 spells a URI: a server reading raw bytes above `0x7E` as text
   *   decides for itself what they become;
   * - no backslash, which a Windows-hosted or lenient server reads as `/`; no `;`, which servlet
   *   containers strip as a path parameter, `/a/..;/b` included; no empty segment, which many collapse;
   *   no `.` or `..` segment; no `#`, which ends a URI's path and no request target carries, though an
   *   origin's parser may cut the path there;
   * - `%` only in an escape of UTF-8 text above ASCII, or of a space: a character that has a raw
   *   spelling has no second one. Hex case is the writer's, compared byte for byte as letter case is:
   *   a request spelled in the other case falls under the enclosing rule's path, which grants no
   *   more, and is not under a prefix;
   * - escapes that decode as strict UTF-8, so no overlong form spells `.` or `/` (`%C0%AE`), and whose
   *   decoded text gains no delimiter under NFKC, the widest normalization a server or library may
   *   apply: U+FF0F becomes `/`, and U+037E `;` under NFC already.
   */
  def literalPathProblem(path: String): Option[String] =
    if path.exists(char => char < 0x21 || char > 0x7e) then Some("a character outside printable ASCII")
    else if path.contains('\\') then Some("a backslash")
    else if path.contains(';') then Some("a semicolon")
    else if path.contains('#') then Some("a number sign")
    else if path.contains("//") then Some("an empty segment")
    else if path.split("/", -1).exists(isDotSegment) then Some("a dot segment")
    else escapeProblem(path)

  /**
   * `.` or `..`, with or without a path parameter: Tomcat and other servlet containers remove a
   * segment's `;` parameter before they resolve dot segments, so `/allowed/..;/other` is served as
   * `/other`.
   */
  private def isDotSegment(segment: String): Boolean =
    val name = segment.takeWhile(_ != ';')
    name == "." || name == ".."

  private def escapeProblem(path: String): Option[String] =
    val decoded = StringBuilder()
    val pending = java.io.ByteArrayOutputStream()
    var problem: Option[String] = None
    def flush(): Unit =
      if pending.size > 0 then
        val decoder = StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
        try decoded.append(decoder.decode(ByteBuffer.wrap(pending.toByteArray)))
        catch case _: CharacterCodingException => problem = problem.orElse(Some("an escape that is not UTF-8"))
        pending.reset()
    var index = 0
    while problem.isEmpty && index < path.length do
      val char = path.charAt(index)
      if char != '%' then
        flush()
        decoded.append(char)
        index += 1
      else
        val hex = path.slice(index + 1, index + 3)
        if hex.length < 2 || !hex.forall(digit => Character.digit(digit, 16) >= 0) then
          problem = Some("a malformed escape")
        else
          val byte = Integer.parseInt(hex, 16)
          if byte < 0x80 && byte != 0x20 then problem = Some("an escaped ASCII character other than a space")
          else pending.write(byte)
        index += 3
    if problem.isEmpty then flush()
    problem.orElse:
      val text = decoded.toString
      def delimiters(spelled: String) = spelled.count(Delimiters.contains(_))
      Option.when(delimiters(Normalizer.normalize(text, Normalizer.Form.NFKC)) != delimiters(text))(
        "an escape whose Unicode normalization spells a delimiter",
      )

  /** Spellings a forge decodes before routing: percent-encoding, and a dot segment. */
  private def decodedSpelling(path: String): Option[String] =
    if path.contains('%') then Some("percent-encoding")
    else if path.split("/", -1).exists(isDotSegment) then Some("a dot segment")
    else None

  /** A POST, PUT, PATCH or DELETE path, refused rather than normalized when a forge would decode it
    * first. Forge names never need escaping, so neither is a request git would make. */
  def requireUnambiguousPath(path: String): Unit =
    decodedSpelling(path).foreach(problem => throw Refusal(s"$problem in the path", RefusalAdvice.ambiguousPath))

  /** A path whose longest match is a line other than the root, on every method: refused for any
    * spelling literalPathProblem names. */
  def requireLiteralPath(path: String): Unit =
    literalPathProblem(path).foreach(problem => throw Refusal(s"$problem in the path", RefusalAdvice.ambiguousPath))
