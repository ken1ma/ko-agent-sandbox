// A JSON reader for the files the launcher only reads, such as a plugin manifest: the launcher has
// no JSON library, and what it writes is literal text.

package agentsandbox.launcher

object JsonText:

  enum Json:
    case Obj(fields: Vector[(String, Json)])
    case Arr(items: Vector[Json])
    case Str(value: String)
    case Num(text: String)
    case Bool(value: Boolean)
    case Null

    /** The object's field, if this is an object that has it: the last of a repeated key, which is
      * the value JavaScript's JSON.parse keeps (ECMA-262, ParseJSON), so the one Claude Code reads. */
    def field(key: String): Option[Json] = this match
      case Obj(fields) => fields.reverse.collectFirst { case (name, value) if name == key => value }
      case _           => None

  /** The document's one value, or what made the text not JSON, with the offset it was found at. */
  def parse(text: String): Either[String, Json] =
    val parser = Parser(text)
    try
      parser.skipSpace()
      val value = parser.value()
      parser.skipSpace()
      if parser.at < text.length then Left(parser.error("text after the value")) else Right(value)
    catch case ex: Malformed => Left(ex.getMessage)

  private class Malformed(message: String) extends Exception(message)

  private val NumberText = raw"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?".r

  private class Parser(text: String):
    var at = 0

    def error(what: String): String = s"not JSON at offset $at: $what"
    private def fail(what: String): Nothing = throw Malformed(error(what))

    def skipSpace(): Unit =
      while at < text.length && " \t\r\n".indexOf(text.charAt(at)) >= 0 do at += 1

    private def peek: Char = if at < text.length then text.charAt(at) else fail("the text ends")

    private def expect(char: Char): Unit =
      if peek != char then fail(s"expected '$char'") else at += 1

    def value(): Json = peek match
      case '{' => obj()
      case '[' => arr()
      case '"' => Json.Str(string())
      case 't' => literal("true", Json.Bool(true))
      case 'f' => literal("false", Json.Bool(false))
      case 'n' => literal("null", Json.Null)
      case _   => number()

    private def literal(word: String, json: Json): Json =
      if text.startsWith(word, at) then
        at += word.length
        json
      else fail(s"expected $word")

    private def number(): Json =
      NumberText.findPrefixOf(text.substring(at)) match
        case Some(digits) =>
          at += digits.length
          Json.Num(digits)
        case None => fail("expected a value")

    private def obj(): Json =
      expect('{')
      skipSpace()
      if peek == '}' then
        at += 1
        Json.Obj(Vector.empty)
      else
        val fields = Vector.newBuilder[(String, Json)]
        var more = true
        while more do
          skipSpace()
          val key = string()
          skipSpace()
          expect(':')
          skipSpace()
          fields += key -> value()
          skipSpace()
          if peek == ',' then at += 1
          else
            expect('}')
            more = false
        Json.Obj(fields.result())

    private def arr(): Json =
      expect('[')
      skipSpace()
      if peek == ']' then
        at += 1
        Json.Arr(Vector.empty)
      else
        val items = Vector.newBuilder[Json]
        var more = true
        while more do
          skipSpace()
          items += value()
          skipSpace()
          if peek == ',' then at += 1
          else
            expect(']')
            more = false
        Json.Arr(items.result())

    private def string(): String =
      expect('"')
      val out = StringBuilder()
      while peek != '"' do
        val char = peek
        at += 1
        if char == '\\' then
          val escaped = peek
          at += 1
          escaped match
            case '"' | '\\' | '/' => out += escaped
            case 'b'              => out += '\b'
            case 'f'              => out += '\f'
            case 'n'              => out += '\n'
            case 'r'              => out += '\r'
            case 't'              => out += '\t'
            case 'u' =>
              if at + 4 > text.length then fail("the text ends inside a \\u escape")
              val hex = text.substring(at, at + 4)
              val code =
                try Integer.parseInt(hex, 16)
                catch case _: NumberFormatException => fail(s"bad escape \\u$hex")
              out += code.toChar
              at += 4
            case other => fail(s"bad escape \\$other")
        else if char < ' ' then fail("a control character inside a string")
        else out += char
      at += 1
      out.result()
