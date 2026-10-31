// The relays offer the host clipboard to the sandbox on request. This file holds:
//
// - the protocol that both relays speak;
// - the POSIX relay's shell, which runs as a job of the reaper (SandboxLifecycle);
// - the Windows relay, which runs as a thread of the resident launcher.
//
// SECURITY.md, "Clipboard", has what the channel grants and withholds.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path

import HostCommands.{containerRunning, ExecWithInput, Os, findOnPath, quoteFreeSh, run}

object ClipboardRelay:

  /**
   * The directory of two FIFOs under the sandbox's /tmp. The relay's first exec makes both FIFOs, so a
   * session without a relay has neither and the shim fails at once.
   *
   * - The shim opens `req` once per request and writes one line: `types`, `get image/png`, or
   *   `set <bytes>` followed by that many bytes.
   * - The shim then reads `rsp` to EOF. For `types`, the response is the MIME type or nothing. For
   *   `get`, the response is the PNG or nothing.
   * - For `set`, the response is the word `ok` once the host clipboard is set or paste mode has dropped
   *   the body. The response is empty when the copy failed, so the shim reports a write that did not
   *   reach the host.
   * - The relay reads requests through an exec that ends with the FIFO's writers, whether one open of
   *   the FIFO or several that overlap. The relay parses the requests by line and count, and answers
   *   each request through an exec of its own.
   * - The sandbox therefore opens nothing outward, and the host runs nothing it did not start.
   * - The response writer is bounded from inside the sandbox, because the host may have no `timeout`.
   *   A shim that gave up waiting therefore cannot hold the relay on a FIFO that nobody reads.
   */
  val SandboxDir = "/tmp/ko-agent-sandbox/clipboard"

  /**
   * The most that the host reads of one exec's stream, lines and bodies together.
   *
   * - Anything in the sandbox can write the FIFO. This limit, not the writer, bounds what the host
   *   holds: the resident launcher's heap on Windows, and the clipboard program's memory on POSIX.
   * - The stream is cut here, whatever a request declares.
   * - The relay refuses a `set` whose count passes this limit. The largest copy a TUI makes is a
   *   transcript, well under a megabyte.
   * - The relay copies a body only whole, so neither the cut nor a writer that stopped short puts part
   *   of a body on the clipboard.
   * - A request that the grammar refuses ends the reading of the stream, and the rest of the stream
   *   stays unread.
   */
  val MaxRequestBytes = 16 * 1024 * 1024

  // Both functions take the directory rather than read the constant, so a test can serve a channel of
  // its own. A suite on the live channel would delete the FIFOs that this session's relay holds.
  def sandboxRequestReader(sandboxDir: String = SandboxDir): String =
    s"trap \"\" INT HUP TERM; d=$sandboxDir; mkdir -p -m 700 $$d; " +
      s"for f in req rsp; do [ -p $$d/$$f ] || mkfifo -m 600 $$d/$$f; done; cat $$d/req"

  def sandboxResponseWriter(sandboxDir: String = SandboxDir): String =
    s"timeout 10 sh -c \"cat > $sandboxDir/rsp\""

  /**
   * The POSIX relay, `clipboard_relay <podman> <sandbox> <mode> <xclip> <wl-paste> <wl-copy>`, for the
   * reaper to run as a job.
   *
   * - The programs are [[hostBackend]]'s, as absolute paths, because the reaper's PATH is
   *   [[HostCommands.ScriptPath]], not the PATH the programs were found on.
   * - A program is empty where it is absent. All three are empty on macOS, whose osascript and pbcopy
   *   are in /usr/bin.
   * - The relay tries xclip first, and the Wayland program answers when xclip fails, as on a Wayland
   *   session without XWayland.
   * - The relay serves one request at a time, which the shim's lock guarantees.
   * - A subshell parses an exec's stream, cut at [[MaxRequestBytes]], as the requests the stream
   *   carries ([[requests]] is the same grammar in Scala).
   * - The relay reads a `set` that paste mode will not copy by its count, drops the body, and answers
   *   `ok` as for a copied body, because the drop is the mode working as asked.
   * - A stream with no request in it pauses the loop for a second: an exec that failed, or a writer
   *   that wrote nothing. A container that is gone, or a writer that opens and closes the FIFO, then
   *   costs one exec a second rather than a spin.
   */
  def hostShellFunctions(sandboxDir: String = SandboxDir): String =
    """# The host clipboard as three commands: is there an image, print it as PNG, set the clipboard
      |# from stdin. macOS prints the PNG as AppleScript hex («data PNGf...»).
      |clipboard_relay() {
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
      |  reply() { "$1" """.stripMargin + ExecWithInput.mkString(" ") + """ "$2" sh -c '""" +
      sandboxResponseWriter(sandboxDir) + """'; }
      |  while [ "$("$1" container inspect --format '{{.State.Running}}' "$2" 2>/dev/null)" = true ]; do
      |    "$1" """.stripMargin + ExecWithInput.mkString(" ") + """ "$2" sh -c '""" +
      sandboxRequestReader(sandboxDir) + s"""' |
      |      head -c $MaxRequestBytes | {
      |        # A line the grammar refuses ends the reading, the rest of the stream unread. The
      |        # status is 1 until a request is served; `|| sleep 1` reads it.
      |        status=1
      |        while IFS= read -r line; do
      |          case "$$line" in *" "*) action=$${line%% *}; arg=$${line#* } ;; *) action=$$line; arg= ;; esac
      |          case "$$action" in
      |            set)
      |              # Digits, no leading zero (octal to the shell, decimal to head), within the cap's
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
      |                # Answered only for a whole body: a short one (which only a raw writer,
      |                # never the shim, sends) is dropped unanswered, so a FIFO that writer never
      |                # reads does not hold the relay. The copy's stdout is not the response pipe:
      |                # xclip forks a child that serves the selection and inherits stdout, and on
      |                # the pipe it would hold the shim's read past `ok` until the response
      |                # writer's timeout (wl-copy's child has stdout on /dev/null already).
      |                [ "$$(wc -c <&4 | tr -d ' ')" -eq "$$arg" ] &&
      |                  { copy <&5 >/dev/null && echo ok; } | reply "$$1" "$$2"
      |                exec 3<&- 4<&- 5<&-
      |              else head -c "$$arg" >/dev/null; echo ok | reply "$$1" "$$2"; fi ;;
      |            types) [ "$$line" = types ] || exit $$status; { has_image && echo image/png; } | reply "$$1" "$$2" ;;
      |            get) [ "$$line" != get ] || exit $$status; { [ "$$arg" = image/png ] && png; } | reply "$$1" "$$2" ;;
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
  // The Windows relay
  // -------------------------------------------------------------------------
  //
  // Windows has no reaper, because the launcher stays resident there. The relay is therefore a daemon
  // thread here, and the thread ends when its loop finds the sandbox stopped. The relay runs Windows
  // PowerShell rather than pwsh: Windows PowerShell is always present, and the clipboard API demands
  // its default STA apartment.

  private val PowerShellArgs = Vector("-NoProfile", "-NonInteractive", "-Sta", "-Command")

  /**
   * What the host runs for the mode: PowerShell for the Windows relay, or the programs that the POSIX
   * relay calls.
   *
   * - Each program is the path that [[findOnPath]] resolved. A bare name would be searched for in the
   *   workspace root (design.md, "No repository-controlled host executable resolution").
   * - Each program has its own field rather than a name that the shell would classify. findOnPath
   *   canonicalizes, so the file need not be called `xclip`.
   * - The xclip, wl-paste and wl-copy fields are empty where the program is absent, and always on
   *   macOS.
   */
  final case class HostBackend(
    powershell: Option[Path] = None,
    xclip: String = "",
    wlPaste: String = "",
    wlCopy: String = "",
    /** The `ps` with which the reaper ends the relay's process tree. The field is empty on Windows and
      * under off. */
    ps: String = "",
  )

  /**
   * The launcher resolves the backend before the launch makes anything, because a program missing at
   * request time would read as an empty clipboard or a successful copy.
   *
   * - On Linux, xclip serves both directions. Without xclip, the relay needs wl-paste, and wl-copy when
   *   the mode writes.
   * - macOS always has osascript and pbcopy.
   * - Linux and macOS both need the `ps` that the reaper's cleanup rests on (probedPs).
   */
  def hostBackend(mode: String, os: Os, pathValue: String): Either[String, HostBackend] =
    def program(name: String): String = findOnPath(name, pathValue, os).map(_.toString).getOrElse("")
    if mode == "off" then Right(HostBackend())
    else os match
      case Os.Windows =>
        findOnPath("powershell", pathValue, os).map(path => HostBackend(powershell = Some(path)))
          .toRight(s"error: --clipboard=$mode needs powershell.exe on PATH")
      case Os.Linux =>
        probedPs(s"--clipboard=$mode", os, pathValue).flatMap: ps =>
          val found =
            HostBackend(xclip = program("xclip"), wlPaste = program("wl-paste"), wlCopy = program("wl-copy"), ps = ps)
          val reads = found.xclip.nonEmpty || found.wlPaste.nonEmpty
          val writes = found.xclip.nonEmpty || (found.wlPaste.nonEmpty && found.wlCopy.nonEmpty)
          if reads && (mode == "paste" || writes) then Right(found)
          else Left(s"error: --clipboard=$mode needs xclip or wl-clipboard installed on this host")
      case _ => probedPs(s"--clipboard=$mode", os, pathValue).map(ps => HostBackend(ps = ps))

  /**
   * The `ps` with which the reaper enumerates a relay's process tree. The launcher proves the `ps` on
   * this host before it accepts the `option` that needs a relay.
   *
   * - An absent `ps`, or a `ps` that answers `ps -A -o pid=,ppid=` with nothing, would leave a blocked
   *   clipboard program or a recorder alive after the session. The cleanup would silently end the job
   *   alone. BusyBox's `ps` prints another format.
   * - The proof is this launcher's own row in exactly the output that the reaper parses: the launcher's
   *   pid, and its parent's pid when the JVM knows the parent.
   */
  def probedPs(option: String, os: Os, pathValue: String): Either[String, String] =
    findOnPath("ps", pathValue, os).map(_.toString)
      .toRight(s"error: $option needs ps on PATH; the reaper ends the relay's processes with it")
      .flatMap: ps =>
        val me = ProcessHandle.current
        val listed =
          try Some(run(ps, "-A", "-o", "pid=,ppid="))
          catch case _: IOException => None
        val own = listed.filter(_.ok).toVector.flatMap(_.text.linesIterator).map(_.trim.split("\\s+")).exists: row =>
          row.length == 2 && row(0) == me.pid.toString
            && me.parent.map[Boolean](parent => row(1) == parent.pid.toString).orElse(row(1).forall(_.isDigit))
        if own then Right(ps)
        else Left(s"error: $option needs a ps answering `ps -A -o pid=,ppid=`, which $ps did not")

  private val HasImage =
    "Add-Type -AssemblyName System.Windows.Forms; " +
      "if ([System.Windows.Forms.Clipboard]::ContainsImage()) { 'image/png' }"

  private val Png =
    "Add-Type -AssemblyName System.Windows.Forms; " +
      "$i = [System.Windows.Forms.Clipboard]::GetImage(); if ($i) { " +
      "$m = New-Object System.IO.MemoryStream; $i.Save($m, [System.Drawing.Imaging.ImageFormat]::Png); " +
      "$o = [System.Console]::OpenStandardOutput(); $m.WriteTo($o); $o.Flush() }"

  // `Stop` turns a Set-Clipboard failure into a nonzero exit, which the caller reads as a copy that did
  // not reach the host. Without `Stop`, the cmdlet's error is non-terminating, and PowerShell still exits 0.
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
   * The Windows relay's loop, which is the POSIX relay's `while` in Java. The loop waits for the
   * sandbox to run, then runs one exec at a time while the sandbox runs. After a stream with no request
   * in it, the loop pauses for a second. The first wait is bounded like the reaper's, for a launcher
   * that never reaches the start.
   */
  private def serve(powershell: Path, podman: String, sandboxContainer: String, mode: String): Unit =
    def running(): Boolean = containerRunning(podman, sandboxContainer)
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
   * The requests that one stream carries, in order. A stream is one exec's output, at most
   * [[MaxRequestBytes]]. The method stops at the first request that it cannot read, and reads nothing
   * past that request:
   *
   * - a line without its newline;
   * - a line outside the grammar;
   * - a `set` whose count is not digits without a leading zero, within the cap's width;
   * - a `set` whose body the stream does not hold whole, whether the writer stopped short or the cut
   *   did.
   *
   * The POSIX relay keeps this grammar in `hostShellFunctions`.
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
              if agentsandbox.egress.HTTPHelper.isDecimal(count) && count.length <= MaxRequestBytes.toString.length
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

  /** Serves the requests of one exec's stream in order, and returns whether the stream held a request.
    * A stream that reaches the cap is cut there, and the method ends the exec under it. */
  private def serveOnce(powershell: Path, podman: String, sandboxContainer: String, mode: String): Boolean =
    val command = (podman +: ExecWithInput :+ sandboxContainer) ++ quoteFreeSh(sandboxRequestReader())
    val reader = ProcessBuilder(command*)
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
    val command = (podman +: ExecWithInput :+ sandboxContainer) ++ quoteFreeSh(sandboxResponseWriter())
    val writer = ProcessBuilder(command*)
      .redirectOutput(ProcessBuilder.Redirect.DISCARD)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    try
      writer.getOutputStream.write(body)
      writer.getOutputStream.close()
    catch case _: IOException => ()
    writer.waitFor()
