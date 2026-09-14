// The clipboard protocol, end to end on one host: the reaper's real shell functions against the
// image's real shim, with podman and the host clipboard programs replaced by scripts. What it holds
// is the contract between the three parties, which no unit of either side can hold alone.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions

import scala.jdk.CollectionConverters.*
import scala.util.Using

class ClipboardBrokerTest extends munit.FunSuite:

  // The shim runs in the Debian image, so its programs are the image's; a macOS host has neither.
  private val programs = Vector("sh", "flock", "timeout", "setsid", "mkfifo")
  private def onPath(program: String): Boolean =
    sys.env.getOrElse("PATH", "").split(":").exists(dir => Files.isExecutable(Paths.get(dir, program)))

  private val Image = "PNG binary".getBytes(UTF_8)

  /**
   * Never the production path. A suite is run inside a sandbox session as readily as outside one,
   * and there `/tmp/ko-agent-sandbox/clipboard` holds the FIFOs that session's broker is reading:
   * removing them leaves its reader blocked on an unlinked inode, and nothing inside the container can
   * restore the channel. Both sides are pointed here instead — the broker's shell functions by
   * their argument, the shim by the one line rewritten below.
   */
  private val FifoDir = Files.createTempDirectory("clipboard-fifos")

  /** The image's shim with its directory line rewritten and nothing else. A spelling this no
    * longer finds fails the suite rather than testing a script the image does not ship. Made on
    * first use, so a platform whose tests all skip never sets POSIX permissions — not at cleanup
    * either, which is why the copy is tracked rather than the value forced. */
  private var shimCopy: Option[Path] = None
  private def Shim: Path = shimCopy.getOrElse:
    val source = Paths.get("container/ko-agent-sandbox/ko-agent-clipboard").toAbsolutePath
    val text = Files.readString(source)
    val line = s"dir=${ClipboardBroker.SandboxDir}"
    require(text.linesIterator.count(_ == line) == 1, s"$source no longer spells `$line`")
    val copy = Files.createTempFile("ko-agent-clipboard", "")
    Files.writeString(copy, text.replace(line, s"dir=$FifoDir"))
    Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rwxr-xr-x"))
    shimCopy = Some(copy)
    copy

  override def afterAll(): Unit =
    deleteRecursively(FifoDir)
    shimCopy.foreach(Files.deleteIfExists)
    ()

  private def executable(path: Path, body: String): Unit =
    Files.writeString(path, body)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"))

  // The shim by its symlink name, as Claude Code invokes it; ProcessBuilder resolves through the
  // parent's PATH, so the name is spelled absolute here.
  private def sandboxCall(sandboxBin: Path, stdin: Array[Byte], command: String*): (Int, Array[Byte]) =
    val builder = ProcessBuilder((sandboxBin.resolve(command.head).toString +: command.tail)*)
    builder.redirectError(ProcessBuilder.Redirect.DISCARD)
    val process = builder.start()
    process.getOutputStream.write(stdin)
    process.getOutputStream.close()
    val out = process.getInputStream.readAllBytes()
    (process.waitFor(), out)

  // `wayland`: the host has only wl-clipboard, so the broker's xclip-first chain must fall through.
  // `blockingCopy`: the host's copy never returns, as a clipboard program waiting on its display
  // may not. The broker's temporary files go under `host/tmp`.
  private def exchange(mode: String, wayland: Boolean = false, blockingCopy: Boolean = false)(
    check: (Path, Path) => Unit,
  ): Unit =
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    val dir = Files.createTempDirectory("clipboard")
    val host = Files.createDirectory(dir.resolve("host"))
    val sandboxBin = Files.createDirectory(dir.resolve("sandbox"))
    Files.write(host.resolve("image.bin"), Image)
    // "podman exec -i C sh -c S" runs S here; the container is always running.
    executable(
      host.resolve("podman"),
      """#!/bin/sh
        |case "$1 $2" in
        |  "container inspect") echo true ;;
        |  "exec -i") shift 3; exec "$@" ;;
        |esac
        |""".stripMargin
    )
    // The host's real clipboard programs, answering the three calls the broker makes, by absolute
    // path as the launcher resolves them; the host's PATH is deliberately not offered.
    executable(
      host.resolve("xclip"),
      s"""#!/bin/sh
         |case "$$*" in
         |  "-selection clipboard -t TARGETS -o") printf 'text/plain\\nimage/png\\n' ;;
         |  "-selection clipboard -t image/png -o") cat "$host/image.bin" ;;
         |  "-selection clipboard -i") ${if blockingCopy then "sleep 60" else s"""cat > "$host/copied.txt""""} ;;
         |esac
         |""".stripMargin
    )
    executable(
      host.resolve("wl-paste"),
      s"""#!/bin/sh
         |case "$$*" in
         |  "-l") printf 'text/plain\\nimage/png\\n' ;;
         |  "--type image/png") cat "$host/image.bin" ;;
         |esac
         |""".stripMargin
    )
    executable(host.resolve("wl-copy"), s"#!/bin/sh\ncat > \"$host/copied.txt\"\n")
    Vector("xclip", "xsel", "wl-paste", "wl-copy").foreach: name =>
      Files.createSymbolicLink(sandboxBin.resolve(name), Shim)
    deleteRecursively(FifoDir)
    val hostPrograms =
      if wayland then s"'' $host/wl-paste $host/wl-copy" else s"$host/xclip '' ''"
    val broker = ProcessBuilder(
      "setsid", "sh", "-c",
      s"${ClipboardBroker.hostShellFunctions(FifoDir.toString)}\n" +
        s"clipboard_broker $host/podman C $mode $hostPrograms",
    )
    broker.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD)
    broker.environment().put("TMPDIR", Files.createDirectory(host.resolve("tmp")).toString)
    val process = broker.start()
    try
      Thread.sleep(500)
      check(sandboxBin, host)
    finally
      // The fake exec's `cat` on the FIFO is what a stopped container would have ended; it ignores
      // TERM by design, so forcibly.
      process.descendants().forEach(_.destroyForcibly())
      process.destroyForcibly()
      deleteRecursively(FifoDir)

  private def deleteRecursively(path: Path): Unit =
    if Files.exists(path) then
      Using.resource(Files.walk(path)): entries =>
        entries.iterator().asScala.toVector.reverse.foreach(Files.deleteIfExists)

  test("paste serves the image under every name Claude Code asks by, and drops a set"):
    exchange("paste"): (sandboxBin, host) =>
      val (rc, types) = sandboxCall(sandboxBin, Array.empty, "xclip", "-selection", "clipboard", "-t", "TARGETS", "-o")
      assertEquals(rc, 0)
      assertEquals(String(types, UTF_8), "image/png\n")
      assertEquals(String(sandboxCall(sandboxBin, Array.empty, "wl-paste", "-l")._2, UTF_8), "image/png\n")
      val (_, png) = sandboxCall(sandboxBin, Array.empty, "xclip", "-selection", "clipboard", "-t", "image/png", "-o")
      assertEquals(png.toVector, Image.toVector)
      assertEquals(sandboxCall(sandboxBin, Array.empty, "wl-paste", "--type", "image/png")._2.toVector, Image.toVector)
      // Answered in order after a drop: the paste-mode broker drained the body it refused.
      assertEquals(sandboxCall(sandboxBin, "secret".getBytes(UTF_8), "wl-copy")._1, 0)
      Thread.sleep(300)
      assert(!Files.exists(host.resolve("copied.txt")), "paste mode set the host clipboard")
      assertEquals(String(sandboxCall(sandboxBin, Array.empty, "wl-paste", "-l")._2, UTF_8), "image/png\n")

  test("bidirectional sets the host clipboard from every copy spelling"):
    exchange("bidirectional"): (sandboxBin, host) =>
      def copied(): String =
        Thread.sleep(300)
        Files.readString(host.resolve("copied.txt"))
      assertEquals(sandboxCall(sandboxBin, "via wl-copy".getBytes(UTF_8), "wl-copy")._1, 0)
      assertEquals(copied(), "via wl-copy")
      sandboxCall(sandboxBin, "via xsel".getBytes(UTF_8), "xsel", "--clipboard", "--input")
      assertEquals(copied(), "via xsel")
      sandboxCall(sandboxBin, "via xclip\n".getBytes(UTF_8), "xclip", "-selection", "clipboard")
      assertEquals(copied(), "via xclip\n")
      // Copilot's /copy spelling, under the WAYLAND_DISPLAY the launcher exports in this mode.
      assertEquals(sandboxCall(sandboxBin, "via copilot".getBytes(UTF_8), "wl-copy", "--type", "text/plain")._1, 0)
      assertEquals(copied(), "via copilot")

  /** A write to the request FIFO that is not the shim's: what any process in the sandbox can do. */
  private def rawRequest(bytes: Array[Byte]): Int =
    val writer = ProcessBuilder("timeout", "5", "sh", "-c", s"cat > $FifoDir/req").start()
    writer.getOutputStream.write(bytes)
    writer.getOutputStream.close()
    writer.waitFor()

  /** One response, read as the shim reads it. */
  private def rawResponse(): Array[Byte] =
    val reader = ProcessBuilder("timeout", "10", "cat", s"$FifoDir/rsp").start()
    val out = reader.getInputStream.readAllBytes()
    reader.waitFor()
    out

  test("a request the grammar or the cap refuses is dropped whole, and the next is served"):
    exchange("bidirectional"): (sandboxBin, host) =>
      def copied(): Option[String] =
        Thread.sleep(300)
        Option.when(Files.exists(host.resolve("copied.txt")))(Files.readString(host.resolve("copied.txt")))
      // A line outside the grammar, with a request behind it: the reading ends at the line, so
      // the `get` is never read as a request — a PNG answered to nobody would hold the broker for
      // the response writer's ten seconds, past the shim's own wait.
      assertEquals(rawRequest("junk\nget image/png\n".getBytes(UTF_8)), 0)
      assertEquals(String(sandboxCall(sandboxBin, Array.empty, "wl-paste", "-l")._2, UTF_8), "image/png\n")
      // Two requests in one stream — a writer opening before the reader saw the last one's end —
      // are both served, in order: the boundary is the line and its count, not the exec.
      assertEquals(rawRequest("types\nget image/png\n".getBytes(UTF_8)), 0)
      assertEquals(String(rawResponse(), UTF_8), "image/png\n")
      assertEquals(rawResponse().toVector, Image.toVector)
      // A `set` past the cap, and one whose count `[` could not compare: nothing copied, the
      // writer's end read as for a served request.
      assertEquals(rawRequest(s"set ${ClipboardBroker.MaxRequestBytes + 1}\nabc".getBytes(UTF_8)), 0)
      assertEquals(rawRequest("set 99999999999999999999\nabc".getBytes(UTF_8)), 0)
      assertEquals(copied(), None)
      // A body the writer cut short, and a count with a leading zero: nothing copied.
      assertEquals(rawRequest("set 6\nabc".getBytes(UTF_8)), 0)
      assertEquals(rawRequest("set 03\nabc".getBytes(UTF_8)), 0)
      assertEquals(copied(), None)
      // The count's bytes and no more, as the Windows twin reads them (`requests`).
      assertEquals(rawRequest("set 3\nabcdef".getBytes(UTF_8)), 0)
      assertEquals(copied(), Some("abc"))
      assertEquals(sandboxCall(sandboxBin, "after".getBytes(UTF_8), "wl-copy")._1, 0)
      assertEquals(copied(), Some("after"))

  test("a copy blocked in the clipboard program leaves no body file for the session's end"):
    exchange("bidirectional", blockingCopy = true): (sandboxBin, host) =>
      assertEquals(sandboxCall(sandboxBin, "held".getBytes(UTF_8), "wl-copy")._1, 0)
      Thread.sleep(500)
      // The broker is inside the copy now, which the session's end will KILL: the body has no name.
      assertEquals(Files.list(host.resolve("tmp")).count(), 0L)

  test("the Windows twin's stream grammar is the shell twin's"):
    import ClipboardBroker.{MaxRequestBytes, Request, requests}
    def stream(text: String): Array[Byte] = text.getBytes(UTF_8)
    def bodies(text: String): Vector[String] =
      requests(stream(text)).map:
        case Request.Set(body) => String(body, UTF_8)
        case other             => other.toString
    assertEquals(requests(stream("types\n")), Vector(Request.Types))
    assertEquals(requests(stream("get image/png\n")), Vector(Request.Get("image/png")))
    assertEquals(requests(stream("get text/plain\n")), Vector(Request.Get("text/plain")))
    assertEquals(bodies("set 3\nabc"), Vector("abc"))
    assertEquals(bodies("set 0\n"), Vector(""))
    // In order, to the first request that cannot be read: the counted body frames the next line.
    assertEquals(bodies("types\nget image/png\n"), Vector("Types", "Get(image/png)"))
    assertEquals(bodies("set 5\nhe\nlotypes\n"), Vector("he\nlo", "Types"))
    assertEquals(bodies("set 3\nabcdef"), Vector("abc"))
    assertEquals(bodies("types\njunk\ntypes\n"), Vector("Types"))
    // A body the stream does not hold whole — the writer stopped, or the cut did — is refused.
    Vector(
      "types", "junk\nget image/png\n", "set\n", "set -1\nx", "set +1\nx", "set 1 2\nx", "set 6\nabc",
      "set 03\nabc", "set 00\n",
      s"set ${MaxRequestBytes + 1}\nx", "set 99999999999999999999\nx",
    ).foreach(text => assertEquals(requests(stream(text)), Vector.empty, text))
    val cut = stream(s"set ${MaxRequestBytes - 8}\n") ++ Array.fill[Byte](MaxRequestBytes - 13)(0)
    assertEquals(cut.length, MaxRequestBytes, "a stream cut at the cap")
    assertEquals(requests(cut), Vector.empty, "the body the cut shortened")

  test("a Wayland-only host serves both directions"):
    exchange("bidirectional", wayland = true): (sandboxBin, host) =>
      val (_, png) = sandboxCall(sandboxBin, Array.empty, "xclip", "-selection", "clipboard", "-t", "image/png", "-o")
      assertEquals(png.toVector, Image.toVector)
      assertEquals(sandboxCall(sandboxBin, "via wl-copy".getBytes(UTF_8), "wl-copy")._1, 0)
      Thread.sleep(300)
      assertEquals(Files.readString(host.resolve("copied.txt")), "via wl-copy")

  test("without a broker the shim fails at once, and an unknown argument pattern is a usage error"):
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    val sandboxBin = Files.createTempDirectory("clipboard-none")
    Files.createSymbolicLink(sandboxBin.resolve("xclip"), Shim)
    deleteRecursively(FifoDir)
    assertEquals(sandboxCall(sandboxBin, Array.empty, "xclip", "-selection", "clipboard", "-t", "TARGETS", "-o")._1, 1)
    // A broker present, an argument pattern the shim does not answer: refused before any FIFO is touched.
    Files.createDirectories(FifoDir)
    try
      ProcessBuilder("mkfifo", FifoDir.resolve("req").toString).start().waitFor()
      assertEquals(sandboxCall(sandboxBin, Array.empty, "xclip", "-o")._1, 64)
    finally deleteRecursively(FifoDir)
