package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Files

class SourceDigestTest extends munit.FunSuite:

  private def digestOf(files: (String, String)*): String =
    SourceDigest.digest(files.map((name, text) => name -> text.getBytes(UTF_8)))

  private def sameCode(name: String, left: String, right: String)(using munit.Location): Unit =
    assertEquals(SourceDigest.code(name, left), SourceDigest.code(name, right))

  private def otherCode(name: String, left: String, right: String)(using munit.Location): Unit =
    assertNotEquals(SourceDigest.code(name, left), SourceDigest.code(name, right))

  test("a C comment's text, its lines and its position after code do not count"):
    sameCode("a.c", "int x; // one\n// two\nint y;\n", "int x; // other words\n/* a\n * block\n */\nint y;\n")
    sameCode("a.c", "int x;\nint y;\n", "int x; /* trailing */\nint y;   // and here\n")

  test("C code counts, a block comment between tokens standing as a space"):
    otherCode("a.c", "int x = 1;\n", "int x = 2;\n")
    otherCode("a.c", "a/**/b\n", "ab\n")
    sameCode("a.c", "a/* one */b\n", "a/* two */b\n")

  test("a backslash at the end of a C line comment joins the next line to it"):
    otherCode("a.c", "// note\nreturn 0;\n", "// note \\\nreturn 0;\n")
    sameCode("a.c", "// a \\\nb\nint x;\n", "// c \\\nd\nint x;\n")

  test("C splices lines before comments: a block comment's end split by a backslash still ends it"):
    otherCode("a.c", "int f(void) { /* note *\\\n/ return 0; /* tail */ return 1; }\n",
      "int f(void) { /* note *\\\n/ return 2; /* tail */ return 1; }\n")
    otherCode("a.c", "int x; /\\\n/ a\nint y;\n", "int x; /\\\n/ a\nint z;\n")
    sameCode("a.c", "int x; /\\\n/ a\nint y;\n", "int x; // b\nint y;\n")

  test("comment markers inside C string and character literals are code"):
    otherCode("a.c", "puts(\"// kept\");\n", "puts(\"// changed\");\n")
    otherCode("a.c", "puts(\"/* kept */\");\n", "puts(\"/* changed */\");\n")
    otherCode("a.c", "char q = '\"'; int a; // c\n", "char q = '\"'; int b; // c\n")
    otherCode("a.c", "puts(\"\\\" // kept\");\n", "puts(\"\\\" // changed\");\n")

  test("Scala block comments nest"):
    sameCode("a.scala", "/* a /* b */ c */ val x = 1\n", "/* other */ val x = 1\n")
    otherCode("a.scala", "/* a /* b */ c */ val x = 1\n", "/* a /* b */ c */ val x = 2\n")

  test("Scala strings keep what looks like a comment, trailing blanks and blank lines"):
    otherCode("a.scala", "val s = \"// a\"\n", "val s = \"// b\"\n")
    otherCode("a.scala", "val s = \"\"\"a // b\n\n# c  \n\"\"\"\n", "val s = \"\"\"a // b\n# c\n\"\"\"\n")
    otherCode("a.scala", "val c = '\"'; val a = 1 // x\n", "val c = '\"'; val a = 2 // x\n")

  test("an interpolation's expression is code, its strings and comments as anywhere else"):
    otherCode("a.scala", "s\"${f(\"// a\")} rest\"\n", "s\"${f(\"// b\")} rest\"\n")
    sameCode("a.scala", "s\"${f(1) /* a */} rest\"\n", "s\"${f(1) /* b */} rest\"\n")
    otherCode("a.scala", "s\"$$ // a\"\n", "s\"$$ // b\"\n")
    otherCode("a.scala", "s\"\"\"${m(Map(1 -> 2))} // a\"\"\"\n", "s\"\"\"${m(Map(1 -> 2))} // b\"\"\"\n")

  test("Containerfile comment lines do not count; directives, inline text and heredocs do"):
    sameCode("Containerfile", "# one\nFROM a\n# two\nRUN b\n", "FROM a\n# other\n# lines\nRUN b\n")
    otherCode("Containerfile", "# syntax=docker/dockerfile:1\nFROM a\n", "# syntax=docker/dockerfile:2\nFROM a\n")
    otherCode("Containerfile", "RUN a # one\n", "RUN a # two\n")
    otherCode("Containerfile", "RUN cat <<EOF > f\n# one\nEOF\n", "RUN cat <<EOF > f\n# two\nEOF\n")
    otherCode("Containerfile", "RUN sh <<A /dev/stdin <<B\na\nA\n# one\nB\n",
      "RUN sh <<A /dev/stdin <<B\na\nA\n# two\nB\n")

  test("Rust comments nest, and lifetimes, byte and raw strings are read as such"):
    sameCode("a.rs", "/* a /* b */ c */ fn f() {} // x\n", "/* other */ fn f() {}\n")
    otherCode("a.rs", "fn f<'a>(s: &'a str) -> &'a str { \"// a\" }\n",
      "fn f<'a>(s: &'a str) -> &'a str { \"// b\" }\n")
    otherCode("a.rs", "let s = r#\"\" // a \"#;\n", "let s = r#\"\" // b \"#;\n")
    otherCode("a.rs", "let s = br\"// a\";\n", "let s = br\"// b\";\n")
    otherCode("a.rs", "let c = '\"'; let a = 1; // x\n", "let c = '\"'; let a = 2; // x\n")
    otherCode("a.rs", "let s = \"one\n// a\";\n", "let s = \"one\n// b\";\n")

  test("a Rust doc comment counts where rustdoc may compile it, and only there"):
    sameCode("a.rs", "/// Adds.\nfn f() {}\n", "/// Adds two numbers.\nfn f() {}\n")
    sameCode("a.rs", "//! ```text\n//! a\n//! ```\nfn f() {}\n", "//! ```text\n//! b\n//! ```\nfn f() {}\n")
    otherCode("a.rs", "/// ```\n/// f(1);\n/// ```\nfn f() {}\n", "/// ```\n/// f(2);\n/// ```\nfn f() {}\n")
    otherCode("a.rs", "/** a */ fn f() {}\n", "/** b */ fn f() {}\n")
    otherCode("a.rs", "/// ~~~\n/// f(1);\n/// ~~~\nfn f() {}\n", "/// ~~~\n/// f(2);\n/// ~~~\nfn f() {}\n")
    sameCode("a.rs", "/// ~~~text\n/// a\n/// ~~~\nfn f() {}\n", "/// ~~~text\n/// b\n/// ~~~\nfn f() {}\n")
    otherCode("a.rs", "/// Use:\n///\n///     f(1);\nfn f() {}\n", "/// Use:\n///\n///     f(2);\nfn f() {}\n")
    otherCode("a.rs", "/// ````\n/// ```\n/// f(1);\n/// ````\nfn f() {}\n",
      "/// ````\n/// ```\n/// f(2);\n/// ````\nfn f() {}\n")
    sameCode("a.rs", "/// ```\n/// f(1);\n/// ```\n/// a\nfn f() {}\n",
      "/// ```\n/// f(1);\n/// ```\n/// b\nfn f() {}\n")

  test("another file's whole text counts"):
    otherCode("sources.txt", "a\n# b\n", "a\n# c\n")

  test("content is the code where the syntax is known and valid UTF-8, the bytes otherwise"):
    val invalid = Array[Byte](0x69, 0x6e, 0x74, 0x20, 0xff.toByte, 0x3b, 0x20, 0x2f, 0x2f, 0x20, 0x61, 0x0a)
    assertEquals(SourceDigest.content("a.c", invalid).toSeq, invalid.toSeq)
    assertEquals(String(SourceDigest.content("a.c", "int x; // a\n".getBytes(UTF_8)), UTF_8), "int x;\n")
    assertEquals(String(SourceDigest.content("a.txt", "a\r\n".getBytes(UTF_8)), UTF_8), "a\r\n")

  test("CRLF line endings digest as LF"):
    sameCode("a.c", "int x;\r\n// c\r\n", "int x;\n// c\n")

  test("a list's digest is its files' in its order, each found beside the list"):
    val dir = Files.createTempDirectory("source-digest")
    Files.writeString(dir.resolve("a.c"), "int x; // a\n")
    Files.createDirectories(dir.resolve("sub"))
    Files.writeString(dir.resolve("sub/b.scala"), "val y = 1\n")
    Files.writeString(dir.resolve("sources.txt"), "sub/b.scala\na.c\n\n")
    val expected = digestOf("b.scala" -> "val y = 1\n", "a.c" -> "int x;\n")
    assertEquals(SourceDigest.ofList(dir.resolve("sources.txt")), expected)

  test("the digest follows the files' order and boundaries, not their names"):
    assertEquals(digestOf("a.c" -> "int x;\n"), digestOf("b.c" -> "int x; // b\n"))
    assertNotEquals(digestOf("a.c" -> "x", "b.c" -> "y"), digestOf("b.c" -> "y", "a.c" -> "x"))
    assertNotEquals(digestOf("a.txt" -> "ab", "b.txt" -> "c"), digestOf("a.txt" -> "a", "b.txt" -> "bc"))
