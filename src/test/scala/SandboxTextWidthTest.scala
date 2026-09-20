// ko-sandbox-text-width, run as the Python script it is. It needs wcwidth, which the image has in
// /opt/ko-sandbox/python and the script looks for there; elsewhere, PYTHONPATH supplies it:
//
//   uv pip install --target ~/wcwidth wcwidth==$WCWIDTH_VERSION   # the Containerfile's
//   PYTHONPATH=~/wcwidth sbt 'testOnly *SandboxTextWidthTest'
//
// A host with neither skips.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.text.Normalizer

import HostCommands.*
import FileHelper.*

class SandboxTextWidthTest extends munit.FunSuite:

  private val script = Path.of("container/ko-agent-sandbox/ko-sandbox-text-width").toAbsolutePath

  private lazy val measurable: Boolean =
    try run("python3", "-c", "import sys; sys.path.insert(0, '/opt/ko-sandbox/python'); from wcwidth import width").ok
    catch case _: java.io.IOException => false

  private val directory = FunFixture[Path](
    setup = _ =>
      assume(measurable, "needs python3 with wcwidth")
      Files.createTempDirectory("ko-sandbox-text-width")
    ,
    teardown = deleteRecursively,
  )

  private def textWidth(args: String*): Run = run(("python3" +: script.toString +: args)*)

  private def file(directory: Path, name: String, content: String): String =
    Files.writeString(directory.resolve(name), content).toString

  /** The width of `line` alone in a file. */
  private def width(directory: Path, line: String): Int =
    val path = file(directory, "line.txt", line + "\n")
    val measured = textWidth(path)
    assertEquals(measured.exit, 0, measured.err)
    assert(measured.text.startsWith(s"$path:1:"), measured.text)
    measured.text.stripPrefix(s"$path:1:").toInt

  directory.test("display width counts wide and ambiguous characters and emoji sequences as 2"): directory =>
    assertEquals(width(directory, "abc"), 3)
    assertEquals(width(directory, "全角ab"), 6)
    assertEquals(width(directory, "ｱｲｳ"), 3, "halfwidth katakana")
    val composed = "がぎ é"
    val decomposed = Normalizer.normalize(composed, Normalizer.Form.NFD)
    assertNotEquals(decomposed, composed)
    // é is East Asian Ambiguous, as many accented Latin letters are: 2 + 2 + 1 + 2.
    assertEquals(width(directory, composed), 7)
    assertEquals(width(directory, decomposed), 7)
    // x with a combining macron below has no composed form, so NFC leaves the mark in place.
    assertEquals(width(directory, "x̱"), 1)
    assertEquals(width(directory, "— “x” …"), 11, "East Asian Ambiguous characters take 2")
    assertEquals(width(directory, "→α§"), 6)
    assertEquals(width(directory, "👨‍👩‍👧"), 2, "ZWJ sequence")
    assertEquals(width(directory, "❤️"), 2, "variation selector")
    assertEquals(width(directory, "🇯🇵"), 2, "flag")
    assertEquals(width(directory, "👍🏽"), 2, "skin tone")

  directory.test("neither line ending is measured"): directory =>
    val path = file(directory, "endings.txt", "ab\r\nabcd\nabc")
    assertEquals(textWidth("--over", "0", path).text, s"$path:1:2\n$path:2:4\n$path:3:3")

  directory.test("without --over, each file's widest line is printed: the first of that width"): directory =>
    val twice = file(directory, "twice.txt", "ab\nabcd\nabc\nwxyz\n")
    val empty = file(directory, "empty.txt", "")
    val measured = textWidth(twice, empty)
    assertEquals(measured.exit, 0, measured.err)
    assertEquals(measured.text, s"$twice:2:4\n$empty:0:0")

  directory.test("--over prints every wider line and exits 1, or nothing and exits 0"): directory =>
    val path = file(directory, "lines.txt", "ab\nabcd\nabc\nwxyz\n")
    val over = textWidth("--over", "3", path)
    assertEquals(over.exit, 1, over.err)
    assertEquals(over.text, s"$path:2:4\n$path:4:4")
    val within = textWidth("--over", "4", path)
    assertEquals(within.exit, 0, within.err)
    assertEquals(within.text, "")

  directory.test("--show-text preserves the source while filtering by normalized display width"): directory =>
    val decomposed = Normalizer.normalize("é", Normalizer.Form.NFD)
    val path = file(directory, "source.txt", s"a\r\n  $decomposed:全角  \r\n\tx\n")
    val shown = textWidth("--show-text", "--tab-width", "4", "--over", "4", path)
    assertEquals(shown.exit, 1, shown.err)
    assertEquals(shown.text, s"$path:2:11:   $decomposed:全角  \n$path:3:5: \tx")
    val within = textWidth("--show-text", "--tab-width", "4", "--over", "11", path)
    assertEquals(within.exit, 0, within.err)
    assertEquals(within.text, "")

  directory.test("--show-text includes the first widest line and omits text only for an empty file"): directory =>
    val path = file(directory, "tied.txt", "a\nwide\nalso\n")
    val empty = file(directory, "empty.txt", "")
    val blank = file(directory, "blank.txt", "\n")
    val shown = textWidth("--show-text", path, empty, blank)
    assertEquals(shown.exit, 0, shown.err)
    assertEquals(shown.text, s"$path:2:4: wide\n$empty:0:0\n$blank:1:0: ")
    val filtered = textWidth("--show-text", "--over", "0", empty, blank)
    assertEquals(filtered.exit, 0, filtered.err)
    assertEquals(filtered.text, "")

  directory.test("--show-text prints no partial results for a file that fails to measure"): directory =>
    val tabbed = file(directory, "tabbed.txt", "abcd\n\tx\n")
    val invalid = directory.resolve("invalid.txt")
    Files.write(invalid, "abcd\n".getBytes(UTF_8) ++ Array(0xff.toByte))
    val plain = file(directory, "plain.txt", "wide\n")
    for options <- Seq(Seq("--show-text"), Seq("--show-text", "--over", "3")) do
      val shown = textWidth((options ++ Seq(tabbed, invalid.toString, plain))*)
      assertEquals(shown.exit, 2)
      assert(shown.err.contains(s"$tabbed: line 2 has a tab"), shown.err)
      assert(shown.err.contains(s"$invalid: "), shown.err)
      assertEquals(shown.text, s"$plain:1:4: wide")

  directory.test("the image's wcwidth takes precedence over PYTHONPATH and virtual-environment packages"): directory =>
    assume(Files.isDirectory(Path.of("/opt/ko-sandbox/python/wcwidth")), "needs the image's bundled wcwidth")
    val shadow = Files.createDirectory(directory.resolve("shadow"))
    file(shadow, "wcwidth.py", "raise RuntimeError('project wcwidth was imported')\n")
    val plain = file(directory, "plain.txt", "全角\n")
    val environment = directory.resolve("venv")
    val created = run("python3", "-m", "venv", "--without-pip", environment.toString)
    assertEquals(created.exit, 0, created.err)
    val python = environment.resolve("bin/python3").toString
    val packages = run(python, "-c", "import sysconfig; print(sysconfig.get_path('purelib'))")
    assertEquals(packages.exit, 0, packages.err)
    Files.copy(shadow.resolve("wcwidth.py"), Path.of(packages.text).resolve("wcwidth.py"))
    for interpreter <- Seq("python3", python) do
      val builder = ProcessBuilder(interpreter, script.toString, plain).redirectErrorStream(true)
      builder.environment().put("PYTHONPATH", shadow.toString)
      val process = builder.start()
      val output = String(process.getInputStream.readAllBytes(), UTF_8)
      assertEquals(process.waitFor(), 0, output)
      assertEquals(output.stripLineEnd, s"$plain:1:4")

  directory.test("a tab is an error naming --tab-width, and with it advances to the next stop"): directory =>
    val tabbed = file(directory, "tabbed.txt", "ab\n\tx\nabc\tx\n")
    val plain = file(directory, "plain.txt", "abcdefghijkl\n")
    val refused = textWidth("--over", "10", tabbed, plain)
    assertEquals(refused.exit, 2)
    assert(refused.err.contains(s"$tabbed: line 2 has a tab"), refused.err)
    assert(refused.err.contains("--tab-width"), refused.err)
    assertEquals(refused.text, s"$plain:1:12", "the file with the tab is not measured; the other is")
    assertEquals(textWidth("--tab-width", "8", "--over", "0", tabbed).text, s"$tabbed:1:2\n$tabbed:2:9\n$tabbed:3:9")
    assertEquals(textWidth("--tab-width", "4", "--over", "0", tabbed).text, s"$tabbed:1:2\n$tabbed:2:5\n$tabbed:3:5")
    assertEquals(textWidth("--tab-width", "0", plain).exit, 2)

  directory.test("a file that is missing or not UTF-8 exits 2 and the others are still measured"): directory =>
    val invalid = directory.resolve("invalid.txt")
    Files.write(invalid, Array(0xff.toByte, 0xfe.toByte))
    val missing = directory.resolve("missing.txt").toString
    val plain = file(directory, "plain.txt", "abc\n")
    val measured = textWidth(invalid.toString, missing, plain)
    assertEquals(measured.exit, 2)
    assert(measured.err.contains(s"$invalid: "), measured.err)
    assert(measured.err.contains(s"$missing: "), measured.err)
    assertEquals(measured.text, s"$plain:1:3")
