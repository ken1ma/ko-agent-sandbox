// The JSON reader the launcher uses on files it only reads.

package agentsandbox.launcher

import JsonText.Json.*

class JsonTextTest extends munit.FunSuite:

  test("objects, arrays, strings with escapes, numbers and literals are read, in document order"):
    val text =
      """ { "name": "a\"b""" + "\\u00e9" + """\n", "n": [1, -2.5e3, true, false, null], "o": {} } """
    assertEquals(
      JsonText.parse(text),
      Right(Obj(Vector(
        "name" -> Str("a\"bé\n"),
        "n" -> Arr(Vector(Num("1"), Num("-2.5e3"), Bool(true), Bool(false), Null)),
        "o" -> Obj(Vector.empty),
      ))),
    )
    assertEquals(JsonText.parse("[]"), Right(Arr(Vector.empty)))
    assertEquals(JsonText.parse("\"\""), Right(Str("")))

  test("a field is found at the top level only, and a nested same-named field does not stand in"):
    val manifest = JsonText.parse("""{ "author": { "name": "me" }, "name": "band" }""").toOption.get
    assertEquals(manifest.field("name"), Some(Str("band")))
    assertEquals(manifest.field("version"), None)
    // A repeated key: the last value, as JSON.parse keeps it.
    val repeated = JsonText.parse("""{ "name": "safe", "name": "ko-review" }""").toOption.get
    assertEquals(repeated.field("name"), Some(Str("ko-review")))
    assertEquals(Str("x").field("name"), None)

  test("what is not JSON is named with its offset"):
    def failure(text: String): String = JsonText.parse(text).swap.getOrElse("parsed")
    assert(failure("""{ "name": "a", }""").contains("offset 15: expected '\""), failure("""{ "name": "a", }"""))
    assert(failure("""{ "name": "a" } x""").contains("text after the value"))
    assert(failure("""{ "name": "a""").contains("the text ends"))
    assert(failure("""{ "name": tru }""").contains("expected true"))
    assert(failure("""{ "name": "a\x" }""").contains("bad escape"), failure("""{ "name": "a\x" }"""))
    assert(failure("{ \"name\": \"a\tb\" }").contains("control character"))
    assert(failure("").contains("the text ends"))
