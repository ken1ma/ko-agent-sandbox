// The host clipboard, offered to the sandbox on request: the protocol both twins speak, the POSIX
// twin's shell (a job of the reaper, SandboxLifecycle), and the Windows twin (a thread of the
// resident launcher). SECURITY.md "Clipboard" has what the channel grants and withholds.

package agentsandbox.launcher

import java.io.{ByteArrayOutputStream, IOException, InputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path

import HostCommands.{Os, findOnPath, run}

object ClipboardBroker:

  /**
   * Two FIFOs under the sandbox's /tmp, both made by the broker's first exec so that a session
   * without a broker has neither and the shim fails at once. The shim writes one request line to
   * `req` — `types`, `get image/png`, or `set <bytes>` followed by that many bytes — and, for the
   * first two, reads `rsp` to EOF: the MIME type (or nothing), the PNG (or nothing). `set` has no
   * response. The broker reads `req` through one long-lived exec, and answers each request through
   * a short one, so the sandbox opens nothing outward and the host runs nothing it did not start.
   *
   * The response writer is bounded from inside the sandbox — the host may have no `timeout` — so
   * a shim that gave up waiting cannot hold the broker on a FIFO nobody reads.
   */
  val SandboxDir = "/tmp/ko-agent-sandbox/clipboard"

  val SandboxRequestReader: String =
    s"trap \"\" INT HUP TERM; d=$SandboxDir; mkdir -p -m 700 $$d; " +
      s"for f in req rsp; do [ -p $$d/$$f ] || mkfifo -m 600 $$d/$$f; done; while :; do cat $$d/req; done"

  val SandboxResponseWriter: String = s"timeout 10 sh -c \"cat > $SandboxDir/rsp\""

  /**
   * The POSIX twin: `clipboard_broker <podman> <sandbox> <mode> <read tool> <copy tool>`, for the
   * reaper to run as a job. The tools are [[hostBackend]]'s, absolute — the reaper's PATH is
   * [[HostCommands.ScriptPath]], not the one they were found on — and empty on macOS, whose
   * osascript and pbcopy are in /usr/bin. One request at a time, which the shim's lock guarantees;
   * a request the mode refuses (`set` under paste) is read and dropped. Restarted while the
   * sandbox runs, because a signal the terminal sends the foreground group can end the exec.
   */
  val HostShellFunctions: String =
    """# The host clipboard as three commands: is there an image, print it as PNG, set the clipboard
      |# from stdin. macOS prints the PNG as AppleScript hex («data PNGf…»).
      |clipboard_broker() {
      |  clipboard_read=$4
      |  clipboard_copy=$5
      |  case "$(uname -s)" in
      |    Darwin)
      |      has_image() { osascript -e 'clipboard info' 2>/dev/null | grep -q PNGf; }
      |      png() {
      |        osascript -e 'the clipboard as «class PNGf»' | LC_ALL=C sed 's/^«data PNGf//; s/»$//' | xxd -r -p
      |      }
      |      copy() { pbcopy; }
      |      ;;
      |    *)
      |      case "$clipboard_read" in
      |        */xclip)
      |          has_image() { "$clipboard_read" -selection clipboard -t TARGETS -o 2>/dev/null | grep -qx image/png; }
      |          png() { "$clipboard_read" -selection clipboard -t image/png -o 2>/dev/null; }
      |          ;;
      |        *)
      |          has_image() { "$clipboard_read" -l 2>/dev/null | grep -qx image/png; }
      |          png() { "$clipboard_read" --type image/png 2>/dev/null; }
      |          ;;
      |      esac
      |      case "$clipboard_copy" in
      |        */xclip) copy() { "$clipboard_copy" -selection clipboard -i; } ;;
      |        *) copy() { "$clipboard_copy"; } ;;
      |      esac
      |      ;;
      |  esac
      |  reply() { "$1" exec -i "$2" sh -c '""".stripMargin + SandboxResponseWriter + """'; }
      |  while [ "$("$1" container inspect --format '{{.State.Running}}' "$2" 2>/dev/null)" = true ]; do
      |    "$1" exec -i "$2" sh -c '""".stripMargin + SandboxRequestReader + """' |
      |      while read -r verb arg; do
      |        case "$verb" in
      |          set) if [ "$3" = bidirectional ]; then head -c "$arg" | copy; else head -c "$arg" >/dev/null; fi ;;
      |          types) { has_image && echo image/png; } | reply "$1" "$2" ;;
      |          get) { [ "$arg" = image/png ] && png; } | reply "$1" "$2" ;;
      |        esac
      |      done
      |    sleep 1
      |  done
      |}
      |
      |""".stripMargin

  // -------------------------------------------------------------------------
  // The Windows twin
  // -------------------------------------------------------------------------
  //
  // Windows has no reaper — the launcher stays resident — so the broker is a daemon thread here,
  // ending with the exec it reads, which ends with the sandbox. Windows PowerShell rather than
  // pwsh: it is always present, and its default STA apartment is what the clipboard API demands.

  private val PowerShellArgs = Vector("-NoProfile", "-NonInteractive", "-Sta", "-Command")

  /**
   * What the host runs for the mode: PowerShell for the resident twin, or the tools the shell twin
   * calls, each as [[findOnPath]] resolved it (a bare name would be searched for in the checkout,
   * DESIGN.md "No PATH-resolved host executables"). `read` and `copy` are empty where the twin
   * needs nothing, macOS.
   */
  final case class HostBackend(powershell: Option[Path] = None, read: String = "", copy: String = "")

  /**
   * Resolved before the launch makes anything, because a tool missing at request time would read
   * as an empty clipboard or a successful copy. On Linux xclip serves both directions, and failing
   * that wl-paste, with wl-copy only when the mode writes. macOS always has osascript and pbcopy.
   */
  def hostBackend(mode: String, os: Os, pathValue: String): Either[String, HostBackend] =
    def tool(name: String): Option[Path] = findOnPath(name, pathValue, os)
    if mode == "off" then Right(HostBackend())
    else os match
      case Os.Windows =>
        tool("powershell").map(path => HostBackend(powershell = Some(path)))
          .toRight(s"error: $ClipboardVariable=$mode needs powershell.exe on PATH")
      case Os.Linux =>
        val needs = s"error: $ClipboardVariable=$mode needs xclip or wl-clipboard installed on this host"
        tool("xclip") match
          case Some(xclip) => Right(HostBackend(read = xclip.toString, copy = xclip.toString))
          case None =>
            (tool("wl-paste"), tool("wl-copy")) match
              case (Some(read), Some(copy)) => Right(HostBackend(read = read.toString, copy = copy.toString))
              case (Some(read), None) if mode == "paste" => Right(HostBackend(read = read.toString))
              case _ => Left(needs)
      case _ => Right(HostBackend())

  private def ClipboardVariable = AgentSandboxLauncher.ClipboardVariable

  private val HasImage =
    "Add-Type -AssemblyName System.Windows.Forms; " +
      "if ([System.Windows.Forms.Clipboard]::ContainsImage()) { 'image/png' }"

  private val Png =
    "Add-Type -AssemblyName System.Windows.Forms; " +
      "$i = [System.Windows.Forms.Clipboard]::GetImage(); if ($i) { " +
      "$m = New-Object System.IO.MemoryStream; $i.Save($m, [System.Drawing.Imaging.ImageFormat]::Png); " +
      "$o = [System.Console]::OpenStandardOutput(); $m.WriteTo($o); $o.Flush() }"

  private val Copy =
    "[System.Console]::InputEncoding = [System.Text.Encoding]::UTF8; " +
      "Set-Clipboard -Value ([System.Console]::In.ReadToEnd())"

  /** Started once the sandbox runs; returns at once. Nothing to start when the mode is off. */
  def startResident(powershell: Path, podman: String, sandboxContainer: String, mode: String): Unit =
    if mode != "off" then
      val thread = Thread(() => serve(powershell, podman, sandboxContainer, mode), "ko-agent-sandbox-clipboard")
      thread.setDaemon(true)
      thread.start()

  /**
   * The shell twin's loop: wait for the sandbox to run, serve until the exec ends, and go round
   * while the sandbox still runs. The first wait is bounded like the reaper's, for a launcher that
   * never reaches the start.
   */
  private def serve(powershell: Path, podman: String, sandboxContainer: String, mode: String): Unit =
    def running(): Boolean =
      try run(podman, "container", "inspect", "--format", "{{.State.Running}}", sandboxContainer).text == "true"
      catch case _: IOException => false
    var waited = 0
    while !running() && waited < 600 do
      Thread.sleep(1000)
      waited += 1
    while running() do
      try serveOnce(powershell, podman, sandboxContainer, mode)
      catch case _: IOException | _: NumberFormatException => ()
      Thread.sleep(1000)

  private def serveOnce(powershell: Path, podman: String, sandboxContainer: String, mode: String): Unit =
    val reader = ProcessBuilder(podman, "exec", "-i", sandboxContainer, "sh", "-c", SandboxRequestReader)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    reader.getOutputStream.close()
    val in = reader.getInputStream
    Iterator.continually(readLine(in)).takeWhile(_.isDefined).flatten.foreach: line =>
      line.split(" ", 2) match
        case Array("set", size) =>
          val body = readExactly(in, size.trim.toInt)
          if mode == "bidirectional" then host(powershell, Copy, body)
        case Array("types") => respond(podman, sandboxContainer, host(powershell, HasImage, Array.empty))
        case Array("get", "image/png") => respond(podman, sandboxContainer, host(powershell, Png, Array.empty))
        case _ => respond(podman, sandboxContainer, Array.empty)

  private def host(powershell: Path, command: String, stdin: Array[Byte]): Array[Byte] =
    val process = ProcessBuilder((powershell.toString +: PowerShellArgs :+ command)*)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    val feeder = Thread(() =>
      try
        process.getOutputStream.write(stdin)
        process.getOutputStream.close()
      catch case _: IOException => ()
    )
    feeder.start()
    val out = process.getInputStream.readAllBytes()
    process.waitFor()
    out

  private def respond(podman: String, sandboxContainer: String, body: Array[Byte]): Unit =
    val writer = ProcessBuilder(podman, "exec", "-i", sandboxContainer, "sh", "-c", SandboxResponseWriter)
      .redirectOutput(ProcessBuilder.Redirect.DISCARD)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    try
      writer.getOutputStream.write(body)
      writer.getOutputStream.close()
    catch case _: IOException => ()
    writer.waitFor()

  private def readLine(in: InputStream): Option[String] =
    val buffer = ByteArrayOutputStream()
    var byte = in.read()
    while byte != -1 && byte != '\n' do
      buffer.write(byte)
      byte = in.read()
    if byte == -1 && buffer.size == 0 then None else Some(String(buffer.toByteArray, UTF_8))

  private def readExactly(in: InputStream, count: Int): Array[Byte] =
    val bytes = in.readNBytes(count)
    if bytes.length < count then throw IOException("request body cut short") else bytes
