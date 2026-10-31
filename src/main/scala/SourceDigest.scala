// What of a source file a digest covers: its code, comments aside, so that a comment edit changes no
// digest and any change to code does. The launcher's source ids (LauncherImages.bundleSourceId), which
// decide when --build must rebuild, and the source digests the BPF backend's evidence names
// (bpf/ko-agent-bpf/doc/evidence.md, "Suites") both take it. Self-contained, with no dependency on the
// launcher, so that it can leave the project as it is.
//
// What counts as a comment, by file name:
//   - `.c`, `.h`: `//` to the line's end and `/* */`, outside string and character literals, read after
//     the line splicing C does first, so a backslash at a line's end joins it to the next;
//   - `.scala`: `//` to the line's end and nesting `/* */`, outside plain, triple-quoted and
//     interpolated strings (an interpolation's `${...}` is code again) and character literals;
//   - `.rs`: `//` to the line's end and nesting `/* */`, outside plain, byte and raw strings and
//     character literals, except what rustdoc may compile: a `///` or `//!` line inside a fenced block
//     (``` or ~~~) not marked `text`, or indented as a code block, and every `/** */` or `/*! */` block;
//   - `Containerfile`, `Dockerfile`: a line whose first non-blank character is `#`, except the parser
//     directives at the top and the lines of every heredoc;
//   - any other file, or one of those that is not valid UTF-8: nothing, its bytes count as they are.
// Where the scanner cannot tell, it keeps the text: a misread can only make a digest stricter. A block
// comment stands as one space, as in C, so `a/**/b` stays two tokens; a line left blank by removing
// comments is dropped, with the blanks before a comment that ends its line. Line endings count as `\n`,
// so a checkout with CRLF digests as one with LF.

package agentsandbox.launcher

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.security.MessageDigest

object SourceDigest:

  /** The digest of `files`, each a name, which selects its comment syntax, and its bytes, in order. */
  def digest(files: Seq[(String, Array[Byte])]): String =
    val sha = MessageDigest.getInstance("SHA-256")
    files.foreach: (name, bytes) =>
      val kept = content(name, bytes)
      sha.update(ByteBuffer.allocate(8).putLong(kept.length.toLong).array)
      sha.update(kept)
    sha.digest.map(byte => f"$byte%02x").mkString

  /** The digest of the files a list names, one path a line relative to the list's directory, in its order. */
  def ofList(list: Path): String =
    val names = Files.readString(list).linesIterator.filter(_.nonEmpty).toSeq
    digest(names.map(name => name -> Files.readAllBytes(list.resolveSibling(name))))

  /** What of a file's bytes a digest covers: its code for a syntax this knows, its bytes otherwise. */
  def content(name: String, bytes: Array[Byte]): Array[Byte] =
    syntax(name) match
      case None => bytes
      case Some(known) =>
        try code(known, UTF_8.newDecoder.decode(ByteBuffer.wrap(bytes)).toString).getBytes(UTF_8)
        catch case _: CharacterCodingException => bytes

  /** What of a file's text a digest covers. */
  def code(name: String, text: String): String =
    syntax(name).fold(text.replace("\r\n", "\n"))(code(_, text))

  private enum Syntax:
    case C, Scala, Rust, Container

  private def syntax(name: String): Option[Syntax] =
    val base = name.split('/').last
    if base.endsWith(".c") || base.endsWith(".h") then Some(Syntax.C)
    else if base.endsWith(".scala") then Some(Syntax.Scala)
    else if base.endsWith(".rs") then Some(Syntax.Rust)
    else if base == "Containerfile" || base == "Dockerfile" then Some(Syntax.Container)
    else None

  private def code(known: Syntax, text: String): String =
    val unix = text.replace("\r\n", "\n")
    known match
      case Syntax.Container => containerCode(unix)
      // C splices a backslash and the newline after it before it recognizes any comment or token.
      case Syntax.C => withoutComments(unix.replace("\\\n", ""), known)
      case _ => withoutComments(unix, known)

  // Placeholders the scanner leaves where it removed a comment, resolved per line afterwards.
  private val LineComment = '\u0000'
  private val BlockComment = '\u0001'
  private val RawStringOpening = raw"b?r(#*)\"".r
  private val FenceMark = raw"(`{3,}|~{3,})(.*)".r

  private enum Mode:
    /** Code; `nested` is code inside an interpolation's `${`, which ends at its unmatched `}`. */
    case Code(nested: Boolean, braces: Int)
    case Quoted(interpolated: Boolean)
    case TripleQuoted(interpolated: Boolean)
    /** A Rust raw string, which ends at a quote followed by `hashes` of `#`. */
    case Raw(hashes: Int)

  private def withoutComments(text: String, syntax: Syntax): String =
    import Mode.*
    val scala = syntax == Syntax.Scala
    val rust = syntax == Syntax.Rust
    val out = StringBuilder()
    var modes: List[Mode] = List(Code(nested = false, braces = 0))
    // A Rust doc comment's open fenced block: its fence's character and length, and whether rustdoc may
    // compile it, which it may unless the block is marked `text`.
    var fence: Option[(Char, Int, Boolean)] = None
    var i = 0
    def at(literal: String): Boolean = text.startsWith(literal, i)
    def identifierBefore(index: Int): Boolean =
      index > 0 && (text(index - 1).isLetterOrDigit || text(index - 1) == '_')
    def copy(count: Int): Unit =
      out ++= text.substring(i, (i + count).min(text.length))
      i += count
    def lineEnd: Int = text.indexOf('\n', i) match
      case -1 => text.length
      case end => end
    while i < text.length do
      val c = text(i)
      modes.head match
        case Code(nested, braces) =>
          val rawOpening =
            if rust && (c == 'r' || c == 'b') && !identifierBefore(i) then
              RawStringOpening.findPrefixMatchOf(text.subSequence(i, (i + 260).min(text.length)))
            else None
          if at("//") then
            val docLine = rust && (at("//!") || (at("///") && !at("////")))
            val raw = if docLine then text.substring(i + 3, lineEnd) else ""
            val doc = raw.trim
            val fenceMark = FenceMark.findPrefixMatchOf(doc)
            val kept = fence match
              case Some((mark, length, compiled)) if docLine =>
                val closes = fenceMark.exists: m =>
                  m.group(1).head == mark && m.group(1).length >= length && m.group(2).trim.isEmpty
                if closes then fence = None
                compiled
              case _ if fenceMark.isDefined =>
                val compiled = fenceMark.get.group(2).trim != "text"
                fence = Some((fenceMark.get.group(1).head, fenceMark.get.group(1).length, compiled))
                compiled
              case _ =>
                if !docLine then fence = None
                // An indented code block, which rustdoc compiles too; a list's indented paragraph is kept with it.
                docLine && (raw.startsWith("    ") || raw.startsWith("\t") || raw.startsWith(" \t"))
            if kept then copy(lineEnd - i)
            else
              while out.nonEmpty && (out.last == ' ' || out.last == '\t') do out.setLength(out.length - 1)
              out.append(LineComment)
              i = lineEnd
          else if at("/*") then
            val start = i
            val kept = rust && ((at("/**") && !at("/**/") && !at("/***")) || at("/*!"))
            i += 2
            var depth = 1
            while i < text.length && depth > 0 do
              if (scala || rust) && at("/*") then { depth += 1; i += 2 }
              else if at("*/") then { depth -= 1; i += 2 }
              else i += 1
            if kept then out ++= text.substring(start, i) else out.append(BlockComment)
          else if rawOpening.isDefined then
            copy(rawOpening.get.end)
            modes = Raw(rawOpening.get.group(1).length) :: modes
          else if c == '"' then
            val interpolated = scala && identifierBefore(i)
            if scala && at("\"\"\"") then
              copy(3)
              modes = TripleQuoted(interpolated) :: modes
            else
              copy(1)
              modes = Quoted(interpolated) :: modes
          else if c == '\'' then copy(characterLiteral(text, i, alwaysLiteral = syntax == Syntax.C))
          else if nested && c == '}' && braces == 0 then
            copy(1)
            modes = modes.tail
          else
            if nested && c == '{' then modes = Code(nested, braces + 1) :: modes.tail
            if nested && c == '}' then modes = Code(nested, braces - 1) :: modes.tail
            copy(1)
        case Quoted(interpolated) =>
          if c == '\\' then copy(2)
          else if interpolated && (at("$$") || at("$\"")) then copy(2)
          else if interpolated && at("${") then
            copy(2)
            modes = Code(nested = true, braces = 0) :: modes
          else if c == '"' || (c == '\n' && !rust) then
            copy(1)
            modes = modes.tail
          else copy(1)
        case TripleQuoted(interpolated) =>
          if at("\"\"\"") then
            var end = i
            while end < text.length && text(end) == '"' do end += 1
            copy(end - i)
            modes = modes.tail
          else if interpolated && (at("$$") || at("$\"")) then copy(2)
          else if interpolated && at("${") then
            copy(2)
            modes = Code(nested = true, braces = 0) :: modes
          else copy(1)
        case Raw(hashes) =>
          if at("\"" + "#" * hashes) then
            copy(1 + hashes)
            modes = modes.tail
          else copy(1)
    resolvePlaceholders(out.toString)

  /** The length of the character literal starting at `start`. Where `'` starts none, as before a Scala
    * quoted expression or a Rust lifetime, it is 1, or with `alwaysLiteral`, as in C, the rest of the line. */
  private def characterLiteral(text: String, start: Int, alwaysLiteral: Boolean): Int =
    val closing =
      if start + 1 < text.length && text(start + 1) == '\\' then
        (start + 2 until (start + 12).min(text.length)).find(j => text(j) == '\'' || text(j) == '\n')
      else Option.when(start + 2 < text.length && text(start + 1) != '\n' && text(start + 2) == '\'')(start + 2)
    closing.filter(text(_) == '\'') match
      case Some(end) => end - start + 1
      case None if !alwaysLiteral => 1
      case None => text.indexOf('\n', start + 1) match
          case -1 => text.length - start
          case end => end - start

  /** A line holding only removed comments goes; one with code keeps it, a block comment as a space. */
  private def resolvePlaceholders(text: String): String =
    val trailing = raw"[ \t]*[\u0000\u0001][ \t]*$$".r
    text.split("\n", -1).toSeq.flatMap: line =>
      if !line.exists(ch => ch == LineComment || ch == BlockComment) then Some(line)
      else
        val resolved = trailing.replaceAllIn(line, "").replace(LineComment.toString, "")
          .replace(BlockComment.toString, " ")
        Option.when(resolved.exists(ch => ch != ' ' && ch != '\t'))(resolved)
    .mkString("\n")

  private def containerCode(text: String): String =
    val directive = raw"#\s*[A-Za-z]+\s*=.*".r
    val heredocStart = raw"<<(-?)\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?".r
    var directives = true
    // The heredocs an instruction opened whose bodies are still to come, in order.
    var heredocs: List[(String, Boolean)] = Nil
    text.split("\n", -1).toSeq.filter: line =>
      heredocs match
        case (delimiter, stripTabs) :: rest =>
          if (if stripTabs then line.dropWhile(_ == '\t') else line) == delimiter then heredocs = rest
          true
        case Nil =>
          val trimmed = line.trim
          if directives && directive.matches(trimmed) then true
          else
            directives = false
            if trimmed.startsWith("#") then false
            else
              heredocs = heredocStart.findAllMatchIn(line).map(m => (m.group(2), m.group(1) == "-")).toList
              true
    .mkString("\n")
