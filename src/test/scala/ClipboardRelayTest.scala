// Tests the clipboard protocol end to end on one host: the reaper's real shell functions against the
// image's real shim, with scripts in place of podman and the host clipboard programs. The suite holds
// the contract between the three parties, which no unit test of either side can hold alone.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions

import scala.jdk.CollectionConverters.*
import scala.util.Using

class ClipboardRelayTest extends munit.FunSuite:

  // The shim runs in the Debian image, so its programs are the image's; a macOS host lacks them.
  private val programs = Vector("sh", "flock", "timeout", "setsid", "mkfifo")
  private def onPath(program: String): Boolean =
    sys.env.getOrElse("PATH", "").split(":").exists(dir => Files.isExecutable(Paths.get(dir, program)))

  private val Image = "PNG binary".getBytes(UTF_8)

  /**
   * The suite never uses the production path. A suite runs inside a sandbox session as readily as
   * outside one, and there `/tmp/ko-agent-sandbox/clipboard` holds the FIFOs that the session's relay
   * is reading. Removing them leaves the relay's reader blocked on an unlinked inode, and nothing inside
   * the container can restore the channel. The suite points both sides here instead: the relay's shell
   * functions by their argument, and the shim by the one line rewritten below.
   */
  private val FifoDir = Files.createTempDirectory("clipboard-fifos")

  /** The image's shim with its directory line rewritten and nothing else. When the rewrite no longer
    * finds that line's spelling, the suite fails rather than test a script that the image does not ship.
    * The copy is made on first use, so a platform whose tests all skip never sets POSIX permissions, not
    * at cleanup either. The suite therefore tracks the copy rather than forcing the value. */
  private var shimCopy: Option[Path] = None
  private def Shim: Path = shimCopy.getOrElse:
    val source = Paths.get("container/ko-agent-sandbox/ko-sandbox-clipboard").toAbsolutePath
    val text = Files.readString(source)
    val line = s"dir=${ClipboardRelay.SandboxDir}"
    require(text.linesIterator.count(_ == line) == 1, s"$source no longer spells `$line`")
    val copy = Files.createTempFile("ko-sandbox-clipboard", "")
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

  // Calls the shim by its symlink name, as Claude Code invokes it. ProcessBuilder resolves a bare name
  // through the parent's PATH, so this method spells the name absolute.
  private def sandboxCall(sandboxBin: Path, stdin: Array[Byte], command: String*): (Int, Array[Byte]) =
    val builder = ProcessBuilder((sandboxBin.resolve(command.head).toString +: command.tail)*)
    builder.redirectError(ProcessBuilder.Redirect.DISCARD)
    val process = builder.start()
    process.getOutputStream.write(stdin)
    process.getOutputStream.close()
    val out = process.getInputStream.readAllBytes()
    (process.waitFor(), out)

  // - `wayland`: the host has only wl-clipboard, so the relay's xclip-first chain must fall through.
  // - `blockingCopy`: the host's copy never returns, as a clipboard program that waits on its display
  //   may not.
  // - `failingCopy`: the host's copy exits nonzero, as a copy with no display does.
  //
  // The relay's temporary files go under `host/tmp`.
  private def exchange(
    mode: String,
    wayland: Boolean = false,
    blockingCopy: Boolean = false,
    failingCopy: Boolean = false,
  )(
    check: (Path, Path) => Unit,
  ): Unit =
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    val dir = Files.createTempDirectory("clipboard")
    val host = Files.createDirectory(dir.resolve("host"))
    val sandboxBin = Files.createDirectory(dir.resolve("sandbox"))
    Files.write(host.resolve("image.bin"), Image)
    // The fake podman runs S here for "podman exec -i --detach-keys= C sh -c S", and fails an exec -i that
    // leaves the detach keys on. The container is always running.
    executable(
      host.resolve("podman"),
      """#!/bin/sh
        |case "$1 $2" in
        |  "container inspect") echo true ;;
        |  "exec -i")
        |    [ "$3" = --detach-keys= ] || { echo "exec -i with the detach keys on" >&2; exit 125; }
        |    shift 4; exec "$@" ;;
        |esac
        |""".stripMargin
    )
    // Stand-ins for the host's real clipboard programs answer the three calls that the relay makes. The
    // relay calls them by absolute path, as the launcher resolves them; the test deliberately offers no
    // host PATH. xclip's copy leaves a child behind that holds stdout, as xclip's selection owner does
    // (wl-copy's child has stdout on /dev/null). On the response pipe, that child would hold the shim
    // past `ok` until the writer's timeout.
    val copyAction =
      if blockingCopy then "sleep 60"
      else if failingCopy then "cat >/dev/null; exit 1"
      else s"""cat > "$host/copied.txt"; sleep 60 &"""
    executable(
      host.resolve("xclip"),
      s"""#!/bin/sh
         |case "$$*" in
         |  "-selection clipboard -t TARGETS -o") printf 'text/plain\\nimage/png\\n' ;;
         |  "-selection clipboard -t image/png -o") cat "$host/image.bin" ;;
         |  "-selection clipboard -i") $copyAction ;;
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
    val relay = ProcessBuilder(
      "setsid", "sh", "-c",
      s"${ClipboardRelay.hostShellFunctions(FifoDir.toString)}\n" +
        s"clipboard_relay $host/podman C $mode $hostPrograms",
    )
    relay.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD)
    relay.environment().put("TMPDIR", Files.createDirectory(host.resolve("tmp")).toString)
    val process = relay.start()
    try
      Thread.sleep(500)
      check(sandboxBin, host)
    finally
      // A stopped container would have ended the fake exec's `cat` on the FIFO. That `cat` ignores
      // TERM by design, so the teardown kills it forcibly.
      // - The relay forks a new reader on every pass of its loop. A reader forked after a snapshot of
      //   the tree outlives the teardown, and blocks on a FIFO at the path that the next test reuses.
      //   That reader can take the next test's request, which then gets no answer.
      // - So the teardown first stops the relay's process group, which setsid made the relay's pid.
      //   The stopped relay forks nothing, and its tree stays whole for the snapshot, the
      //   response writers that `timeout` moved into groups of their own included.
      signalGroup(process, "STOP")
      process.descendants().forEach(_.destroyForcibly())
      signalGroup(process, "KILL")
      process.destroyForcibly()
      deleteRecursively(FifoDir)

  private def signalGroup(leader: Process, signal: String): Unit =
    ProcessBuilder("kill", s"-$signal", "--", s"-${leader.pid}").start().waitFor()
    ()

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
      // Paste mode acknowledges the drop without changing the host clipboard.
      assertEquals(sandboxCall(sandboxBin, "secret".getBytes(UTF_8), "wl-copy")._1, 0)
      Thread.sleep(300)
      assert(!Files.exists(host.resolve("copied.txt")), "paste mode set the host clipboard")
      assertEquals(String(sandboxCall(sandboxBin, Array.empty, "wl-paste", "-l")._2, UTF_8), "image/png\n")

  /** Returns the call's exit status, and asserts that the call returned on the relay's answer rather
    * than on the response writer's ten-second timeout. That timeout is what a copy's child that holds
    * the pipe costs. */
  private def promptly(call: => (Int, Array[Byte])): Int =
    val started = System.nanoTime()
    val (rc, _) = call
    val seconds = (System.nanoTime() - started) / 1e9
    assert(seconds < 5, s"the shim returned after $seconds s, on a timeout rather than an answer")
    rc

  test("bidirectional sets the host clipboard from every copy spelling"):
    exchange("bidirectional"): (sandboxBin, host) =>
      def copied(): String =
        Thread.sleep(300)
        Files.readString(host.resolve("copied.txt"))
      assertEquals(promptly(sandboxCall(sandboxBin, "via wl-copy".getBytes(UTF_8), "wl-copy")), 0)
      assertEquals(copied(), "via wl-copy")
      sandboxCall(sandboxBin, "via xsel".getBytes(UTF_8), "xsel", "--clipboard", "--input")
      assertEquals(copied(), "via xsel")
      sandboxCall(sandboxBin, "via xclip\n".getBytes(UTF_8), "xclip", "-selection", "clipboard")
      assertEquals(copied(), "via xclip\n")
      // Copilot's /copy spelling, under the WAYLAND_DISPLAY the launcher exports in this mode.
      assertEquals(sandboxCall(sandboxBin, "via copilot".getBytes(UTF_8), "wl-copy", "--type", "text/plain")._1, 0)
      assertEquals(copied(), "via copilot")

  /** Writes to the request FIFO without the shim, as any process in the sandbox can. */
  private def rawRequest(bytes: Array[Byte]): Int =
    val writer = ProcessBuilder("timeout", "5", "sh", "-c", s"cat > $FifoDir/req").start()
    writer.getOutputStream.write(bytes)
    writer.getOutputStream.close()
    writer.waitFor()

  /** Reads one response to EOF, and keeps the newline that the shim's command substitution removes. */
  private def rawResponse(): Array[Byte] =
    val reader = ProcessBuilder("timeout", "10", "cat", s"$FifoDir/rsp").start()
    val out = reader.getInputStream.readAllBytes()
    assertEquals(reader.waitFor(), 0, "the response reader failed or timed out")
    out

  for
    mode <- Vector("paste", "bidirectional")
    wayland <- Vector(false, true)
  do
    test(s"$mode consumes a set body before the next request in the same stream (wayland=$wayland)"):
      exchange(mode, wayland = wayland): (sandboxBin, host) =>
        // An undrained body is an invalid request line, so the following types request goes unanswered.
        for body <- Vector("junk\n", "") do
          assertEquals(rawRequest(s"set ${body.getBytes(UTF_8).length}\n${body}types\n".getBytes(UTF_8)), 0)
          assertEquals(String(rawResponse(), UTF_8), "ok\n")
          assertEquals(String(rawResponse(), UTF_8), "image/png\n")
          if mode == "bidirectional" then assertEquals(Files.readString(host.resolve("copied.txt")), body)
          else assert(!Files.exists(host.resolve("copied.txt")), "paste mode set the host clipboard")
          val (status, types) = sandboxCall(sandboxBin, Array.empty, "wl-paste", "-l")
          assertEquals(status, 0)
          assertEquals(String(types, UTF_8), "image/png\n")

  test("a request the grammar or the cap refuses is dropped whole, and the next is served"):
    exchange("bidirectional"): (sandboxBin, host) =>
      def copied(): Option[String] =
        Thread.sleep(300)
        Option.when(Files.exists(host.resolve("copied.txt")))(Files.readString(host.resolve("copied.txt")))
      // A line outside the grammar, with a request behind it: the reading ends at the line, so the
      // relay never reads the `get` as a request. A PNG answered to nobody would hold the relay for
      // the response writer's ten seconds, past the shim's own wait.
      // A `types` with an argument and a `get` without one are outside the grammar too, as the
      // Windows relay reads them.
      Vector("junk\nget image/png\n", "types x\nget image/png\n", "get\nget image/png\n").foreach: refused =>
        assertEquals(rawRequest(refused.getBytes(UTF_8)), 0, refused)
        val (_, types) = sandboxCall(sandboxBin, Array.empty, "wl-paste", "-l")
        assertEquals(String(types, UTF_8), "image/png\n", refused)
      // Two requests in one stream, from a writer that opened before the reader saw the last request's
      // end, are both served in order: the line and its count form the boundary, not the exec.
      assertEquals(rawRequest("types\nget image/png\n".getBytes(UTF_8)), 0)
      assertEquals(String(rawResponse(), UTF_8), "image/png\n")
      assertEquals(rawResponse().toVector, Image.toVector)
      // A `set` past the cap, and a `set` whose count `[` could not compare, copy nothing. The relay
      // reads the writer's end as it does for a served request.
      assertEquals(rawRequest(s"set ${ClipboardRelay.MaxRequestBytes + 1}\nabc".getBytes(UTF_8)), 0)
      assertEquals(rawRequest("set 99999999999999999999\nabc".getBytes(UTF_8)), 0)
      assertEquals(copied(), None)
      // A body that the writer cut short, and a count with a leading zero, copy nothing.
      assertEquals(rawRequest("set 6\nabc".getBytes(UTF_8)), 0)
      assertEquals(rawRequest("set 03\nabc".getBytes(UTF_8)), 0)
      assertEquals(copied(), None)
      // The relay reads the count's bytes and no more, as the Windows relay reads them (`requests`). Without
      // a response reader, the relay waits for the response writer's timeout before it serves the next request.
      assertEquals(rawRequest("set 3\nabcdef".getBytes(UTF_8)), 0)
      assertEquals(String(rawResponse(), UTF_8), "ok\n")
      assertEquals(copied(), Some("abc"))
      assertEquals(sandboxCall(sandboxBin, "after".getBytes(UTF_8), "wl-copy")._1, 0)
      assertEquals(copied(), Some("after"))

  test("a copy blocked in the clipboard program leaves no body file for the session's end"):
    exchange("bidirectional", blockingCopy = true): (sandboxBin, host) =>
      // The copy never returns, so the shim waits out its own timeout for the `ok` that never comes. The
      // test checks the body file during that wait, in a thread that the exchange's teardown abandons.
      val call = Thread(() => { sandboxCall(sandboxBin, "held".getBytes(UTF_8), "wl-copy"); () })
      call.setDaemon(true)
      call.start()
      Thread.sleep(500)
      // The body must have no name while the copy is blocked, because a session that ends here KILLs the
      // relay's tree.
      assertEquals(Files.list(host.resolve("tmp")).count(), 0L)

  test("a copy the host program fails is reported to the caller, not answered ok"):
    exchange("bidirectional", failingCopy = true): (sandboxBin, _) =>
      // xclip exits nonzero, so the relay answers nothing, and the shim fails the copy rather than
      // report success on a write that never reached the host.
      assertEquals(sandboxCall(sandboxBin, "lost".getBytes(UTF_8), "wl-copy")._1, 1)

  test("the Windows relay's stream grammar is the POSIX relay's"):
    import ClipboardRelay.{MaxRequestBytes, Request, requests}
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
    // The parser reads requests in order, up to the first request that cannot be read: the counted body
    // frames the next line.
    assertEquals(bodies("types\nget image/png\n"), Vector("Types", "Get(image/png)"))
    assertEquals(bodies("set 5\nhe\nlotypes\n"), Vector("he\nlo", "Types"))
    assertEquals(bodies("set 3\nabcdef"), Vector("abc"))
    assertEquals(bodies("types\njunk\ntypes\n"), Vector("Types"))
    // A body that the stream does not hold whole, because the writer stopped or the cut did, is refused.
    Vector(
      "types", "junk\nget image/png\n", "types x\n", "types \n", "get\n",
      "set\n", "set -1\nx", "set +1\nx", "set 1 2\nx", "set 6\nabc",
      "set 03\nabc", "set 00\n", "set ٣\nabc",
      s"set ${MaxRequestBytes + 1}\nx", "set 99999999999999999999\nx",
    ).foreach(text => assertEquals(requests(stream(text)), Vector.empty, text))
    val cut = stream(s"set ${MaxRequestBytes - 8}\n") ++ Array.fill[Byte](MaxRequestBytes - 13)(0)
    assertEquals(cut.length, MaxRequestBytes, "a stream cut at the cap")
    assertEquals(requests(cut), Vector.empty, "the body the cut shortened")

  test("a Wayland-only host serves both directions"):
    exchange("bidirectional", wayland = true): (sandboxBin, host) =>
      val (_, png) = sandboxCall(sandboxBin, Array.empty, "xclip", "-selection", "clipboard", "-t", "image/png", "-o")
      assertEquals(png.toVector, Image.toVector)
      assertEquals(promptly(sandboxCall(sandboxBin, "via wl-copy".getBytes(UTF_8), "wl-copy")), 0)
      Thread.sleep(300)
      assertEquals(Files.readString(host.resolve("copied.txt")), "via wl-copy")

  test("without a relay the shim fails at once, and an unknown argument pattern is a usage error"):
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    val sandboxBin = Files.createTempDirectory("clipboard-none")
    Files.createSymbolicLink(sandboxBin.resolve("xclip"), Shim)
    deleteRecursively(FifoDir)
    assertEquals(sandboxCall(sandboxBin, Array.empty, "xclip", "-selection", "clipboard", "-t", "TARGETS", "-o")._1, 1)
    // With a relay present, an argument pattern that the shim does not answer is refused before any FIFO
    // is touched.
    Files.createDirectories(FifoDir)
    try
      ProcessBuilder("mkfifo", FifoDir.resolve("req").toString).start().waitFor()
      assertEquals(sandboxCall(sandboxBin, Array.empty, "xclip", "-o")._1, 64)
    finally deleteRecursively(FifoDir)
