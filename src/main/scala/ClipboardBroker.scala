// The host clipboard, offered to the sandbox on request: the protocol both twins speak, the POSIX
// twin's shell (a job of the reaper, SandboxLifecycle), and the Windows twin (a thread of the
// resident launcher). SECURITY.md "Clipboard" has what the channel grants and withholds.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path

import HostCommands.{Os, findOnPath, run}

object ClipboardBroker:

  /**
   * Two FIFOs under the sandbox's /tmp, both made by the broker's first exec so that a session
   * without a broker has neither and the shim fails at once. The shim opens `req` once per
   * request and writes one line — `types`, `get image/png`, or `set <bytes>` followed by that
   * many bytes — then reads `rsp` to EOF: the MIME type (or nothing), the PNG (or nothing), or for
   * `set` the word `ok` once the host clipboard is set (or paste mode has dropped the body) and
   * nothing when the copy failed, so the shim reports a write that did not reach the host. The
   * broker reads requests through an exec that ends with the FIFO's writers — one open of it, or
   * several that overlap — parsing them by line and count, and answers each through an exec of its
   * own, so the sandbox opens nothing outward and the host runs nothing it did not start.
   *
   * The response writer is bounded from inside the sandbox — the host may have no `timeout` — so
   * a shim that gave up waiting cannot hold the broker on a FIFO nobody reads.
   */
  val SandboxDir = "/tmp/ko-agent-sandbox/clipboard"

  /**
   * What the host reads of one exec's stream, lines and bodies together, and no more: anything in
   * the sandbox can write the FIFO, and what the host holds — the resident launcher's heap on
   * Windows, the clipboard program's memory on POSIX — is bounded by this, not by the writer: the
   * stream is cut here whatever a request declares. A `set` whose count passes it is refused, and
   * a body is copied only whole, so neither the cut nor a writer that stopped short puts part of
   * one on the clipboard; the largest copy a TUI makes is a transcript, well under a megabyte. A
   * request the grammar refuses ends the stream's reading, the rest of it unread.
   */
  val MaxRequestBytes = 16 * 1024 * 1024

  // Each takes the directory rather than reading the constant, so a test can serve a channel of
  // its own: a suite on the live one would delete the FIFOs this session's broker is holding.
  def sandboxRequestReader(sandboxDir: String = SandboxDir): String =
    s"trap \"\" INT HUP TERM; d=$sandboxDir; mkdir -p -m 700 $$d; " +
      s"for f in req rsp; do [ -p $$d/$$f ] || mkfifo -m 600 $$d/$$f; done; cat $$d/req"

  def sandboxResponseWriter(sandboxDir: String = SandboxDir): String =
    s"timeout 10 sh -c \"cat > $sandboxDir/rsp\""

  /**
   * The POSIX twin: `clipboard_broker <podman> <sandbox> <mode> <xclip> <wl-paste> <wl-copy>`, for
   * the reaper to run as a job. The programs are [[hostBackend]]'s, absolute — the reaper's PATH is
   * [[HostCommands.ScriptPath]], not the one they were found on — and empty where absent, or
   * everywhere on macOS, whose osascript and pbcopy are in /usr/bin. xclip is tried first and the
   * Wayland program answers when it fails, as on a Wayland session without XWayland. One request at a
   * time, which the shim's lock guarantees. An exec's stream, cut at [[MaxRequestBytes]], is parsed
   * in a subshell as the requests it carries ([[requests]] is the same grammar in Scala); a `set`
   * paste mode will not copy is read by its count and dropped, then answered `ok` like one copied,
   * since the drop is the mode working as asked. A stream with no request in it — an exec that
   * failed, or a writer that wrote nothing — pauses the loop a second, so a container that is gone
   * or a writer opening and closing the FIFO costs one exec a second, not a spin.
   */
  def hostShellFunctions(sandboxDir: String = SandboxDir): String =
    """# The host clipboard as three commands: is there an image, print it as PNG, set the clipboard
      |# from stdin. macOS prints the PNG as AppleScript hex («data PNGf…»).
      |clipboard_broker() {
      |  clipboard_xclip=$4
      |  clipboard_wl_paste=$5
      |  clipboard_wl_copy=$6
      |  case "$(uname -s)" in
      |    Darwin)
      |      has_image() { osascript -e 'clipboard info' 2>/dev/null | grep -q PNGf; }
      |      png() {
      |        osascript -e 'the clipboard as «class PNGf»' | LC_ALL=C sed 's/^«data PNGf//; s/»$//' | xxd -r -p
      |      }
      |      copy() { pbcopy; }
      |      ;;
      |    *)
      |      has_image() {
      |        { { [ -n "$clipboard_xclip" ] && "$clipboard_xclip" -selection clipboard -t TARGETS -o 2>/dev/null; } ||
      |          { [ -n "$clipboard_wl_paste" ] && "$clipboard_wl_paste" -l 2>/dev/null; }; } | grep -qx image/png
      |      }
      |      png() {
      |        { [ -n "$clipboard_xclip" ] && "$clipboard_xclip" -selection clipboard -t image/png -o 2>/dev/null; } ||
      |          { [ -n "$clipboard_wl_paste" ] && "$clipboard_wl_paste" --type image/png; }
      |      }
      |      copy() {
      |        { [ -n "$clipboard_xclip" ] && "$clipboard_xclip" -selection clipboard -i 2>/dev/null; } ||
      |          { [ -n "$clipboard_wl_copy" ] && "$clipboard_wl_copy"; }
      |      }
      |      ;;
      |  esac
      |  reply() { "$1" exec -i "$2" sh -c '""".stripMargin + sandboxResponseWriter(sandboxDir) + """'; }
      |  while [ "$("$1" container inspect --format '{{.State.Running}}' "$2" 2>/dev/null)" = true ]; do
      |    "$1" exec -i "$2" sh -c '""".stripMargin + sandboxRequestReader(sandboxDir) + s"""' |
      |      head -c $MaxRequestBytes | {
      |        # A line the grammar refuses ends the reading, the rest of the stream unread. The
      |        # status is 1 until a request is served; `|| sleep 1` reads it.
      |        status=1
      |        while IFS= read -r line; do
      |          case "$$line" in *" "*) action=$${line%% *}; arg=$${line#* } ;; *) action=$$line; arg= ;; esac
      |          case "$$action" in
      |            set)
      |              # Digits, no leading zero — octal to the shell, decimal to head — within the cap's
      |              # width before `[` compares: a longer number is undefined there.
      |              case "$$arg" in ''|*[!0-9]*|0?*) exit $$status ;; esac
      |              [ "$${#arg}" -le ${MaxRequestBytes.toString.length} ] || exit $$status
      |              [ "$$arg" -le $MaxRequestBytes ] || exit $$status
      |              if [ "$$3" = bidirectional ]; then
      |                # Copied only whole: head -c stops without a word at the writer's end or the cut.
      |                # The file is unlinked before a byte reaches it and read through descriptors
      |                # opened first: the reaper KILLs this tree at the session's end, a copy blocked
      |                # in the clipboard program included, and a named file would outlive that.
      |                body=$$(mktemp) || exit $$status
      |                exec 3<> "$$body" 4< "$$body" 5< "$$body"
      |                rm -f "$$body" || exit $$status
      |                head -c "$$arg" >&3
      |                # Answered only for a whole body: a short one — which only a raw writer,
      |                # never the shim, sends — is dropped unanswered, so a FIFO that writer never
      |                # reads does not hold the broker. The copy's stdout is not the response pipe:
      |                # xclip forks a child that serves the selection and inherits stdout, and on
      |                # the pipe it would hold the shim's read past `ok` until the response
      |                # writer's timeout (wl-copy's child has stdout on /dev/null already).
      |                [ "$$(wc -c <&4 | tr -d ' ')" -eq "$$arg" ] &&
      |                  { copy <&5 >/dev/null && echo ok; } | reply "$$1" "$$2"
      |                exec 3<&- 4<&- 5<&-
      |              else head -c "$$arg" >/dev/null; echo ok | reply "$$1" "$$2"; fi ;;
      |            types) { has_image && echo image/png; } | reply "$$1" "$$2" ;;
      |            get) { [ "$$arg" = image/png ] && png; } | reply "$$1" "$$2" ;;
      |            *) exit $$status ;;
      |          esac
      |          status=0
      |        done
      |        exit $$status
      |      } || sleep 1
      |  done
      |}
      |
      |""".stripMargin

  // -------------------------------------------------------------------------
  // The Windows twin
  // -------------------------------------------------------------------------
  //
  // Windows has no reaper — the launcher stays resident — so the broker is a daemon thread here,
  // ending when its loop finds the sandbox stopped. Windows PowerShell rather than pwsh: it is
  // always present, and its default STA apartment is what the clipboard API demands.

  private val PowerShellArgs = Vector("-NoProfile", "-NonInteractive", "-Sta", "-Command")

  /**
   * What the host runs for the mode: PowerShell for the resident twin, or the programs the shell twin
   * calls, each as [[findOnPath]] resolved it (a bare name would be searched for in the project directory,
   * design.md "No repository-controlled host executable resolution"). Each program is its own field rather than a name
   * the shell would classify: findOnPath canonicalizes, so the file need not be called `xclip`.
   * Empty where absent, and everywhere on macOS.
   */
  final case class HostBackend(
    powershell: Option[Path] = None,
    xclip: String = "",
    wlPaste: String = "",
    wlCopy: String = "",
    /** The `ps` the reaper ends the broker's process tree with; empty on Windows and under off. */
    ps: String = "",
  )

  /**
   * Resolved before the launch makes anything, because a program missing at request time would read
   * as an empty clipboard or a successful copy. On Linux, xclip serves both directions; without it
   * wl-paste, and wl-copy when the mode writes. macOS always has osascript and pbcopy. Both need
   * the `ps` the reaper's cleanup rests on (probedPs).
   */
  def hostBackend(mode: String, os: Os, pathValue: String): Either[String, HostBackend] =
    def program(name: String): String = findOnPath(name, pathValue, os).map(_.toString).getOrElse("")
    if mode == "off" then Right(HostBackend())
    else os match
      case Os.Windows =>
        findOnPath("powershell", pathValue, os).map(path => HostBackend(powershell = Some(path)))
          .toRight(s"error: $ClipboardVariable=$mode needs powershell.exe on PATH")
      case Os.Linux =>
        probedPs(mode, os, pathValue).flatMap: ps =>
          val found =
            HostBackend(xclip = program("xclip"), wlPaste = program("wl-paste"), wlCopy = program("wl-copy"), ps = ps)
          val reads = found.xclip.nonEmpty || found.wlPaste.nonEmpty
          val writes = found.xclip.nonEmpty || (found.wlPaste.nonEmpty && found.wlCopy.nonEmpty)
          if reads && (mode == "paste" || writes) then Right(found)
          else Left(s"error: $ClipboardVariable=$mode needs xclip or wl-clipboard installed on this host")
      case _ => probedPs(mode, os, pathValue).map(ps => HostBackend(ps = ps))

  /**
   * The `ps` the reaper enumerates the broker's process tree with, proven on this host before an
   * enabled mode is accepted: an absent `ps`, or one that answers `ps -A -o pid=,ppid=` with
   * nothing (BusyBox's prints another format), would leave a blocked clipboard program alive after the
   * session while the cleanup silently ended the job alone. The proof is this launcher's own row —
   * its pid, and its parent's when the JVM knows one — in exactly the output the reaper parses.
   */
  def probedPs(mode: String, os: Os, pathValue: String): Either[String, String] =
    findOnPath("ps", pathValue, os).map(_.toString)
      .toRight(s"error: $ClipboardVariable=$mode needs ps on PATH; the reaper ends the broker's processes with it")
      .flatMap: ps =>
        val me = ProcessHandle.current
        val listed =
          try Some(run(ps, "-A", "-o", "pid=,ppid="))
          catch case _: IOException => None
        val own = listed.filter(_.ok).toVector.flatMap(_.text.linesIterator).map(_.trim.split("\\s+")).exists: row =>
          row.length == 2 && row(0) == me.pid.toString
            && me.parent.map[Boolean](parent => row(1) == parent.pid.toString).orElse(row(1).forall(_.isDigit))
        if own then Right(ps)
        else Left(s"error: $ClipboardVariable=$mode needs a ps answering `ps -A -o pid=,ppid=`, which $ps did not")

  private def ClipboardVariable = AgentSandboxLauncher.ClipboardVariable

  private val HasImage =
    "Add-Type -AssemblyName System.Windows.Forms; " +
      "if ([System.Windows.Forms.Clipboard]::ContainsImage()) { 'image/png' }"

  private val Png =
    "Add-Type -AssemblyName System.Windows.Forms; " +
      "$i = [System.Windows.Forms.Clipboard]::GetImage(); if ($i) { " +
      "$m = New-Object System.IO.MemoryStream; $i.Save($m, [System.Drawing.Imaging.ImageFormat]::Png); " +
      "$o = [System.Console]::OpenStandardOutput(); $m.WriteTo($o); $o.Flush() }"

  // Stop turns a Set-Clipboard failure into a nonzero exit the caller reads as a copy that did not
  // reach the host; without it the cmdlet's error is non-terminating and PowerShell still exits 0.
  private val Copy =
    "$ErrorActionPreference = 'Stop'; " +
      "[System.Console]::InputEncoding = [System.Text.Encoding]::UTF8; " +
      "try { Set-Clipboard -Value ([System.Console]::In.ReadToEnd()) } catch { exit 1 }"

  private val Ok = "ok".getBytes(UTF_8)

  def startResident(powershell: Path, podman: String, sandboxContainer: String, mode: String): Unit =
    if mode != "off" then
      val thread = Thread(() => serve(powershell, podman, sandboxContainer, mode), "ko-agent-sandbox-clipboard")
      thread.setDaemon(true)
      thread.start()

  /**
   * The resident twin's loop, the shell twin's `while` in Java: wait for the sandbox to run, then
   * an exec at a time while it runs, pausing a second after a stream with no request in it. The
   * first wait is bounded like the reaper's, for a launcher that never reaches the start.
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
      val served =
        try serveOnce(powershell, podman, sandboxContainer, mode)
        catch case _: IOException => false
      if !served then Thread.sleep(1000)

  /** What one request asks. */
  enum Request:
    case Types
    case Get(mime: String)
    case Set(body: Array[Byte])

  /**
   * The requests one stream carries — one exec's output, at most [[MaxRequestBytes]] — in order,
   * up to the first it cannot read: a line without its newline, a line outside the grammar, or
   * a `set` whose count is not digits without a leading zero within the cap's width, or whose
   * body the stream does not hold whole, whether the writer stopped short or the cut did.
   * Nothing past that is read. The shell twin keeps this grammar in `hostShellFunctions`.
   */
  def requests(stream: Array[Byte]): Vector[Request] =
    val found = Vector.newBuilder[Request]
    var offset = 0
    var reading = true
    while reading do
      val newline = stream.indexOf('\n'.toByte, offset)
      if newline < 0 then reading = false
      else
        String(stream, offset, newline - offset, UTF_8).split(" ", 2) match
          case Array("set", count)
              if count.nonEmpty && count.length <= MaxRequestBytes.toString.length && count.forall(_.isDigit)
                && (count == "0" || !count.startsWith("0")) && newline + 1 + count.toInt <= stream.length =>
            found += Request.Set(stream.slice(newline + 1, newline + 1 + count.toInt))
            offset = newline + 1 + count.toInt
          case Array("types") =>
            found += Request.Types
            offset = newline + 1
          case Array("get", mime) =>
            found += Request.Get(mime)
            offset = newline + 1
          case _ => reading = false
    found.result()

  /** One exec's stream, its requests served in order: whether there was one. A stream that
    * reaches the cap is cut there, the exec ended under it. */
  private def serveOnce(powershell: Path, podman: String, sandboxContainer: String, mode: String): Boolean =
    val reader = ProcessBuilder(podman, "exec", "-i", sandboxContainer, "sh", "-c", sandboxRequestReader())
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    reader.getOutputStream.close()
    val stream = reader.getInputStream.readNBytes(MaxRequestBytes)
    if stream.length == MaxRequestBytes then reader.destroy()
    val found = requests(stream)
    found.foreach:
      case Request.Set(body) =>
        val copied = mode != "bidirectional" || host(powershell, Copy, body)._2 == 0
        respond(podman, sandboxContainer, if copied then Ok else Array.empty[Byte])
      case Request.Types => respond(podman, sandboxContainer, host(powershell, HasImage, Array.empty)._1)
      case Request.Get(mime) =>
        val png = if mime == "image/png" then host(powershell, Png, Array.empty)._1 else Array.empty[Byte]
        respond(podman, sandboxContainer, png)
    found.nonEmpty

  /** The command's stdout and its exit status: Types and Get read the bytes, Set the status. */
  private def host(powershell: Path, command: String, stdin: Array[Byte]): (Array[Byte], Int) =
    val process = ProcessBuilder((powershell.toString +: PowerShellArgs :+ command)*)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    val feeder = Thread(() =>
      try
        process.getOutputStream.write(stdin)
        process.getOutputStream.close()
      catch case _: IOException => (),
    )
    feeder.start()
    val out = process.getInputStream.readAllBytes()
    (out, process.waitFor())

  private def respond(podman: String, sandboxContainer: String, body: Array[Byte]): Unit =
    val writer = ProcessBuilder(podman, "exec", "-i", sandboxContainer, "sh", "-c", sandboxResponseWriter())
      .redirectOutput(ProcessBuilder.Redirect.DISCARD)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    try
      writer.getOutputStream.write(body)
      writer.getOutputStream.close()
    catch case _: IOException => ()
    writer.waitFor()
