// ko-sandbox-markdown-link-check on one set of fixture files, run two ways:
//
// - directly, as the Python script in this repository. It needs lychee on PATH (the version is the
//   Containerfile's LYCHEE_VERSION), and a machine without it skips.
// - in the image, under `sbt "testWithPodman *SandboxMarkdownLinkCheckTest"` (WithPodman has the condition).
//   Nothing there is assumed: an image without lychee or the script fails the run.
//
// Only the second run shows that the image's lychee and script work together.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import FileHelper.*
import WithPodman.*

class SandboxMarkdownLinkCheckTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val script = Path.of("container/ko-agent-sandbox/ko-sandbox-markdown-link-check").toAbsolutePath

  private val Fixtures = Vector(
    "target.md" ->
      """# Setup
        |## Setup
        |## The `--over` option: what's it for?
        |## 日本語 の見出し
        |<a id="custom"></a>
        |```
        |## Inside a fence
        |```
        |""".stripMargin,
    "page.html" -> """<h1 id="top">Top</h1>""",
    // One file of each type the program counts a fragment as checked in (FRAGMENT_CHECKED_SUFFIXES).
    "types/a.md" -> "# Setup\n",
    "types/b.MD" -> "# Setup\n",
    "types/c.markdown" -> "# Setup\n",
    "types/d.html" -> """<h1 id="top">Top</h1>""",
    "types/e.htm" -> """<h1 id="top">Top</h1>""",
    "types/links.md" -> "[a](a.md#gone) [b](b.MD#gone) [c](c.markdown#gone) [d](d.html#gone) [e](e.htm#gone)\n",
    "notes.txt" -> "# Setup\n",
    "sub/rule" -> "allow\n",
    "valid.md" ->
      """[heading](target.md#setup) [repeated heading](target.md#setup-1)
        |[punctuation](target.md#the---over-option-whats-it-for) [unicode](target.md#日本語-の見出し)
        |[explicit anchor](target.md#custom) [html](page.html#top) [own heading](#own)
        |[another file type](sub/rule) [from the root](/sub/rule) [reference-style][defined]
        |[external](https://example.com/) `[in a code span](gone.md)`
        |```
        |[in a fence](gone.md)
        |```
        |## Own
        |
        |[defined]: target.md#setup
        |""".stripMargin,
    "broken.md" ->
      """[file](gone.md) and [the same file again](gone.md)
        |[another file type](sub/gone)
        |[one repeat too many](target.md#setup-2)
        |[heading in a fence](target.md#inside-a-fence)
        |[html](page.html#bottom)
        |[own heading](#gone)
        |<a href="gone.html">html link</a> ![image](gone.png)
        |[reference-style][undefined target]
        |[valid](target.md#setup)
        |[escaped](gone%20with%20space.md)
        |
        |[undefined target]: target.md#gone
        |""".stripMargin,
    "unchecked.md" -> "[line](sub/rule#L1) [text file](notes.txt#gone) [valid](target.md#setup)\n",
    "name with space.md" -> "[file](gone.md)\n",
    "ignored.md" -> "[file](gone.md)\n",
    ".gitignore" -> "ignored.md\n",
    // Either would hide broken.md's findings from a lychee run in this directory.
    "lychee.toml" -> "exclude_path = [\"broken.md\"]\n",
    ".lycheeignore" -> "gone\n",
  )

  private val BrokenFindings =
    """broken.md:1: missing-file: gone.md
      |broken.md:1: missing-file: gone.md
      |broken.md:2: missing-file: sub/gone
      |broken.md:3: missing-anchor: target.md#setup-2
      |broken.md:4: missing-anchor: target.md#inside-a-fence
      |broken.md:5: missing-anchor: page.html#bottom
      |broken.md:6: missing-anchor: broken.md#gone
      |broken.md:7: missing-file: gone.html
      |broken.md:7: missing-file: gone.png
      |broken.md:8: missing-anchor: target.md#gone
      |broken.md:10: missing-file: gone with space.md
      |""".stripMargin

  private val TypesFindings =
    """types/links.md:1: missing-anchor: types/a.md#gone
      |types/links.md:1: missing-anchor: types/b.MD#gone
      |types/links.md:1: missing-anchor: types/c.markdown#gone
      |types/links.md:1: missing-anchor: types/d.html#gone
      |types/links.md:1: missing-anchor: types/e.htm#gone
      |""".stripMargin

  private val UncheckedFindings =
    """unchecked.md:1: unchecked-fragment: sub/rule#L1
      |unchecked.md:1: unchecked-fragment: notes.txt#gone
      |""".stripMargin

  private def writeFixtures(directory: Path): Unit =
    assert(run("git", "init", "--quiet", directory.toString).ok, s"could not create a repository in $directory")
    for (name, content) <- Fixtures do
      val file = directory.resolve(name)
      Files.createDirectories(file.getParent)
      Files.writeString(file, content)

  /** `program` and its arguments, run by `sh` in `directory`. */
  private def runIn(directory: String, program: Seq[String]): Vector[String] =
    Vector("sh", "-c", """cd "$1" && shift && exec "$@"""", "sh", directory) ++ program

  /** Every case, against the program as `linkCheck` runs it: in a directory given relative to the fixtures', with
    * arguments. */
  private def assertReports(linkCheck: (String, Seq[String]) => Run): Unit =
    def assertRun(args: Seq[String], exit: Int, output: String): Unit =
      val ran = linkCheck(".", args)
      assertEquals(ran.text, output.stripLineEnd, s"output for ${args.mkString(" ")}; stderr: ${ran.err}")
      assertEquals(ran.exit, exit, s"exit for ${args.mkString(" ")}; stderr: ${ran.err}")

    assertRun(
      Vector("valid.md"), 0,
      "summary: files 1; local references 10: valid 10, broken 0, unchecked 0; external excluded 1",
    )
    assertRun(
      Vector("broken.md"), 1,
      BrokenFindings + "summary: files 1; local references 12: valid 1, broken 11, unchecked 0; external excluded 0",
    )
    assertRun(
      Vector("unchecked.md"), 0,
      UncheckedFindings + "summary: files 1; local references 3: valid 1, broken 0, unchecked 2; external excluded 0",
    )
    assertRun(
      Vector("types/links.md"), 1,
      TypesFindings + "summary: files 1; local references 5: valid 0, broken 5, unchecked 0; external excluded 0",
    )
    // Without FILE: the untracked files, the one with a space in its name included, but not the ignored one.
    val wholeRepository = "summary: files 7; local references 31: valid 12, broken 17, unchecked 2; external excluded 1"
    assertRun(
      Vector.empty, 1,
      BrokenFindings + "name with space.md:1: missing-file: gone.md\n" + TypesFindings + UncheckedFindings +
        wholeRepository,
    )
    val fromSubdirectory = linkCheck("sub", Vector.empty)
    assertEquals(
      (fromSubdirectory.text.linesIterator.next(), fromSubdirectory.text.linesIterator.toVector.last),
      ("../broken.md:1: missing-file: ../gone.md", wholeRepository),
      "without FILE in a subdirectory: the whole repository, named from that directory",
    )
    val absent = linkCheck(".", Vector("absent.md"))
    assertEquals(absent.exit, 2, absent.err)
    assert(absent.err.contains("not a file: absent.md"), absent.err)

  test("run directly: each broken reference by position, unchecked fragments apart, and a summary"):
    val lycheeOnPath = sys.env.getOrElse("PATH", "").split(java.io.File.pathSeparator)
      .exists(directory => Files.isExecutable(Path.of(directory, "lychee")))
    assume(lycheeOnPath, "needs lychee on PATH; `sbt testWithPodman` runs the image's")
    val fixtures = Files.createTempDirectory("ko-sandbox-markdown-link-check").toRealPath()
    try
      writeFixtures(fixtures)
      assertReports: (directory, args) =>
        run(runIn(fixtures.resolve(directory).toString, Vector("python3", script.toString) ++ args)*)
    finally deleteRecursively(fixtures)

  test("run in the image: the same reports from the installed program and lychee"):
    requireTestWithPodman()
    val project = scratchProject()
    try
      writeFixtures(project)
      val session = launch(project, project.resolve("session.log"))
      try assertReports((directory, args) => exec(session, runIn(directory, "ko-sandbox-markdown-link-check" +: args)*))
      finally stop(session)
    finally discard(project)
