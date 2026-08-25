// The clipboard protocol, end to end on one host: the reaper's real shell functions against the
// image's real shim, with podman and the host clipboard tools replaced by scripts. What it holds
// is the contract between the three parties, which no unit of either side can hold alone.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions

import scala.jdk.CollectionConverters.*

class ClipboardBrokerTest extends munit.FunSuite:

  // The shim runs in the Debian image, so its tools are the image's; a macOS host has neither.
  private val tools = Vector("sh", "flock", "timeout", "setsid", "mkfifo")
  private def onPath(tool: String): Boolean =
    sys.env.getOrElse("PATH", "").split(":").exists(dir => Files.isExecutable(Paths.get(dir, tool)))

  private val Shim = Paths.get("container/ko-agent-sandbox/ko-agent-clipboard").toAbsolutePath
  private val Image = "PNG binary".getBytes(UTF_8)
  private val FifoDir = Paths.get(ClipboardBroker.SandboxDir)

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

  private def exchange(mode: String)(check: (Path, Path) => Unit): Unit =
    assume(tools.forall(onPath), s"needs ${tools.mkString(", ")} on PATH")
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
    // The host's real clipboard tool, answering the three calls the broker makes.
    executable(
      host.resolve("xclip"),
      s"""#!/bin/sh
         |case "$$*" in
         |  "-selection clipboard -t TARGETS -o") printf 'text/plain\\nimage/png\\n' ;;
         |  "-selection clipboard -t image/png -o") cat "$host/image.bin" ;;
         |  "-selection clipboard -i") cat > "$host/copied.txt" ;;
         |esac
         |""".stripMargin
    )
    Vector("xclip", "xsel", "wl-paste", "wl-copy").foreach: name =>
      Files.createSymbolicLink(sandboxBin.resolve(name), Shim)
    deleteRecursively(FifoDir)
    val broker = ProcessBuilder(
      "setsid", "sh", "-c", s"${ClipboardBroker.HostShellFunctions}\nclipboard_broker podman C $mode"
    )
    broker.environment().put("PATH", s"$host:${sys.env("PATH")}")
    broker.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD)
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
      Files.walk(path).iterator().asScala.toVector.reverse.foreach(Files.deleteIfExists)

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

  test("without a broker the shim fails at once, and an unknown shape is a usage error"):
    assume(tools.forall(onPath), s"needs ${tools.mkString(", ")} on PATH")
    val sandboxBin = Files.createTempDirectory("clipboard-none")
    Files.createSymbolicLink(sandboxBin.resolve("xclip"), Shim)
    deleteRecursively(FifoDir)
    assertEquals(sandboxCall(sandboxBin, Array.empty, "xclip", "-selection", "clipboard", "-t", "TARGETS", "-o")._1, 1)
    // A broker present, an argument shape the shim does not speak: refused before any FIFO is touched.
    Files.createDirectories(FifoDir)
    try
      ProcessBuilder("mkfifo", FifoDir.resolve("req").toString).start().waitFor()
      assertEquals(sandboxCall(sandboxBin, Array.empty, "xclip", "-o")._1, 64)
    finally deleteRecursively(FifoDir)
