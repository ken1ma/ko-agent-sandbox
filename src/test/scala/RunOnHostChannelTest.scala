// The build channel, end to end on one host: the real broker against the image's real shim, with
// `podman exec` replaced by a script and the wrapper by scripts the tests choose — the transport
// and the build stubbed, never the protocol. What it holds is §6.2's contract: framing under
// bounds, the working-directory boundary, streamed output carried whole with the build's own exit
// code, and teardown by descriptor lifetime — a dead shim ends the running build, a handshake
// whose requester died is stillborn with no build started, and a competing shim waits its turn
// rather than attaching to a predecessor's streams. The macOS gate re-runs the protocol against
// real sbt; these rows hold everywhere.

package agentsandbox.launcher

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicBoolean

import scala.jdk.CollectionConverters.*

import HostCommands.Os
import RunOnHostChannel.*

class RunOnHostChannelTest extends munit.FunSuite:

  private val tools = Vector("sh", "flock", "mkfifo", "timeout")
  private def onPath(tool: String): Boolean =
    sys.env.getOrElse("PATH", "").split(":").exists(dir => Files.isExecutable(Paths.get(dir, tool)))

  private val Shim = Paths.get("container/ko-agent-sandbox/sandbox-run-on-host").toAbsolutePath
  private val FifoDir = Paths.get(RunOnHostChannel.SandboxDir)

  // ---------------------------------------------------------------------------
  // Framing
  // ---------------------------------------------------------------------------

  /** The request bytes exactly as the shim's printf pair produces them. */
  private def framed(tool: String, cwd: String, args: String*): Array[Byte] =
    (s"$tool ${args.size}\n" + (cwd +: args).map(_ + "\u0000").mkString).getBytes(UTF_8)

  test("a request round-trips, empty and awkward arguments included"):
    val bytes = framed("sbt", "/workspace/sub dir", "test", "", "set x := \"a\nb\"", "λ")
    assertEquals(
      readRequest(ByteArrayInputStream(bytes)),
      Right(Some(Request("sbt", "/workspace/sub dir", Vector("test", "", "set x := \"a\nb\"", "λ")))),
    )

  test("no arguments is a request; end of stream at a boundary is None"):
    val in = ByteArrayInputStream(framed("mill", "/workspace"))
    assertEquals(readRequest(in), Right(Some(Request("mill", "/workspace", Vector.empty))))
    assertEquals(readRequest(in), Right(None))

  test("a stream that cannot frame a request is refused whole"):
    def refused(bytes: Array[Byte]): Unit =
      assert(readRequest(ByteArrayInputStream(bytes)).isLeft, String(bytes, UTF_8))
    refused("sbt\n".getBytes(UTF_8)) // no argument count
    refused("sbt one\n".getBytes(UTF_8)) // a count that is no number
    refused(s"sbt ${MaxArguments + 1}\n".getBytes(UTF_8)) // over the bound
    refused("sbt 0\n".getBytes(UTF_8) ++ Array.fill(MaxRequestBytes + 1)('a'.toByte)) // too big
    refused(Array.fill(MaxLineBytes + 1)('a'.toByte)) // a header that never ends
    refused("sbt 2\n/workspace\u0000only-one\u0000".getBytes(UTF_8)) // ends inside the request

  test("a NUL-dense frame is bounded by bytes, not by its claimed field count"):
    // The drain must charge the NUL delimiters too: with an argument count near Int.MaxValue and
    // an endless all-NUL stream, only the byte budget ends this read — returning at all is the
    // assertion, and the overflow of argc + 1 must not end it early either.
    val endlessNuls = new java.io.InputStream:
      def read(): Int = 0
    val in = java.io.SequenceInputStream(
      ByteArrayInputStream(s"sbt ${Int.MaxValue}\n".getBytes(UTF_8)),
      endlessNuls,
    )
    assert(readRequest(in).isLeft)

  // ---------------------------------------------------------------------------
  // The boundary
  // ---------------------------------------------------------------------------

  private def service(project: Path, mount: String = WorkspaceMount, deadline: Long = 30_000): Service =
    Service(
      project, Set("sbt"), (_, _, _) => Seq("true"), Os.Mac,
      mount = mount, requestDeadlineMillis = deadline,
    )

  test("the working directory is translated, and proven inside the project"):
    val project = Files.createTempDirectory("channel-project").toRealPath()
    val sub = Files.createDirectory(project.resolve("sub"))
    val outside = Files.createTempDirectory("channel-outside").toRealPath()
    val svc = service(project)
    assertEquals(validated(svc, Request("sbt", "/workspace", Vector.empty)), Right(project))
    assertEquals(validated(svc, Request("sbt", "/workspace/sub", Vector.empty)), Right(sub))
    def refused(workingDirectory: String): Unit =
      val answer = validated(svc, Request("sbt", workingDirectory, Vector.empty))
      assert(answer.left.exists(_.startsWith("CHANNEL_UNAVAILABLE")), s"$workingDirectory: $answer")
    refused(outside.toString) // an unrelated host path
    refused("/workspace/../escape") // climbing out
    refused("/workspace/absent") // nothing to canonicalize
    Files.createSymbolicLink(project.resolve("link"), outside)
    refused("/workspace/link") // a symlink leaving the project

  test("a tool the launch did not name is refused, not run"):
    val project = Files.createTempDirectory("channel-project").toRealPath()
    val answer = validated(service(project), Request("mill", "/workspace", Vector.empty))
    assert(answer.left.exists(_.contains("does not name mill")), answer.toString)

  // ---------------------------------------------------------------------------
  // End to end: the real shim against the real broker over a stubbed transport
  // ---------------------------------------------------------------------------

  private def executable(path: Path, body: String): Unit =
    Files.writeString(path, body)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"))

  private def deleteRecursively(path: Path): Unit =
    if Files.exists(path) then
      Files.walk(path).iterator().asScala.toVector.reverse.foreach(Files.deleteIfExists)

  /**
   * The broker served like production — same exec argument shape, `podman` a script running the
   * exec locally — with the shim's mount spelled as the project itself, so the shim's own $PWD is
   * a request every host can make.
   */
  private def channel(
    buildCommand: (String, Path, Seq[String]) => Seq[String],
    deadline: Long = 30_000,
  )(check: (Path, Path, () => String) => Unit): Unit =
    assume(tools.forall(onPath), s"needs ${tools.mkString(", ")} on PATH")
    val dir = Files.createTempDirectory("channel")
    val host = Files.createDirectory(dir.resolve("host"))
    val project = Files.createDirectory(dir.resolve("project")).toRealPath()
    executable(
      host.resolve("podman"),
      """#!/bin/sh
        |case "$1 $2" in
        |  "exec -i") shift 3; exec "$@" ;;
        |esac
        |""".stripMargin,
    )
    deleteRecursively(FifoDir)
    val running = AtomicBoolean(true)
    val endpoint = Endpoint(Seq(host.resolve("podman").toString, "exec", "-i", "C"), () => running.get)
    val log = StringBuilder()
    val broker = Thread(() =>
      serve(
        endpoint,
        service(project, mount = project.toString, deadline = deadline)
          .copy(buildCommand = buildCommand),
        line => log.synchronized { log.append(line).append('\n'); () },
      ),
    )
    broker.start()
    var waited = 0
    while !Files.exists(FifoDir.resolve("req")) && waited < 100 do
      Thread.sleep(100)
      waited += 1
    try check(project, host, () => log.synchronized(log.toString))
    finally
      running.set(false)
      // A handshake that is no transaction id ends the cycle empty and, with running now false,
      // the loop — the clean lever this side of the FIFO has. Bounded: with the reader already
      // gone the open would block forever.
      val poison = ProcessBuilder("sh", "-c", s"echo poison > $FifoDir/req").start()
      if !poison.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) then poison.destroyForcibly()
      broker.join(10_000)
      deleteRecursively(FifoDir)
      deleteRecursively(dir)

  /** The shim as the agent runs it, from `cwd`; answers (exit, stdout, stderr). */
  private def shimCall(cwd: Path, command: String*): (Int, String, String) =
    val builder = ProcessBuilder((Shim.toString +: command)*)
    builder.directory(cwd.toFile)
    val process = builder.start()
    process.getOutputStream.close()
    val out = process.getInputStream.readAllBytes()
    val err = process.getErrorStream.readAllBytes()
    (process.waitFor(), String(out, UTF_8), String(err, UTF_8))

  test("a build streams both channels back and returns its own exit code"):
    channel((tool, cwd, args) =>
      Seq("sh", "-c", s"echo ran $tool ${args.mkString(" ")} in $cwd; echo complaint >&2; exit 7"),
    ): (project, _, _) =>
      val (exit, out, err) = shimCall(project, "sbt", "test", "-v")
      assertEquals(exit, 7)
      assertEquals(out, s"ran sbt test -v in $project\n")
      assertEquals(err, "complaint\n")

  test("a refused request answers on stderr with exit 2, and the channel keeps serving"):
    channel((_, cwd, _) => Seq("sh", "-c", s"echo built in $cwd")): (project, _, _) =>
      val (exit, _, err) = shimCall(project, "mill", "build")
      assertEquals(exit, 2)
      assert(err.contains("CHANNEL_UNAVAILABLE"), err)
      val (again, out, _) = shimCall(project, "sbt")
      assertEquals(again, 0)
      assertEquals(out, s"built in $project\n")

  test("a dead shim ends the running build: teardown follows the descriptor"):
    channel((_, cwd, _) =>
      // The validated working directory arrives as an argument, so the markers spell it out; the
      // child's own cwd is the broker's and carries nothing.
      Seq(
        "sh", "-c",
        s"echo started > $cwd/started; trap 'echo 143 > $cwd/ended; exit 143' TERM; " +
          "while :; do sleep 0.1; done",
      ),
    ): (project, _, _) =>
      val shim = ProcessBuilder(Shim.toString, "sbt", "test")
        .directory(project.toFile)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .start()
      var waited = 0
      while !Files.exists(project.resolve("started")) && waited < 100 do
        Thread.sleep(100)
        waited += 1
      assert(Files.exists(project.resolve("started")), "the build never started")
      shim.destroyForcibly()
      waited = 0
      while !Files.exists(project.resolve("ended")) && waited < 100 do
        Thread.sleep(100)
        waited += 1
      assert(Files.exists(project.resolve("ended")), "the shim died and the build kept running")

  test("a request the broker cannot frame is answered, not left hanging"):
    channel((_, cwd, _) => Seq("sh", "-c", s"echo built in $cwd")): (project, _, _) =>
      // Over the argument bound — reachable with a legitimate shim, since ARG_MAX allows it —
      // and past the FIFO-plus-pipe capacity, so without the drain the shim would still be
      // blocked writing, never reaching the streams the refusal answers on.
      val (exit, _, err) = shimCall(project, ("sbt" +: Seq.fill(MaxArguments + 1)("x" * 100))*)
      assertEquals(exit, 2)
      assert(err.contains("could not be read"), err)
      val (again, out, _) = shimCall(project, "sbt")
      assertEquals(again, 0)
      assertEquals(out, s"built in $project\n")

  test("a handshake queued behind a dying predecessor's is consumed, never discarded"):
    channel((_, cwd, _) => Seq("sh", "-c", s"echo built in $cwd")): (project, _, brokerLog) =>
      // Both ids through one writer connection — the same cat — as when a shim dies right after
      // its handshake and the next one connects before that reader sees EOF.
      ProcessBuilder("sh", "-c", s"printf '9998\\n9999\\n' > $FifoDir/req").start().waitFor()
      val (exit, out, _) = shimCall(project, "sbt")
      assertEquals(exit, 0)
      assertEquals(out, s"built in $project\n")
      val logged = brokerLog()
      assert(logged.contains("9998"), logged)
      assert(logged.contains("9999"), logged)

  test("a requester dead before speaking is stillborn: no build, and the channel keeps serving"):
    channel((_, cwd, _) => Seq("sh", "-c", s"echo built in $cwd"), deadline = 1500): (project, _, _) =>
      // A handshake whose ctl exists but is never opened — the shim died between its two steps —
      // and one whose ctl never existed at all. Neither may start a build or wedge the broker.
      ProcessBuilder("sh", "-c", s"mkfifo -m 600 $FifoDir/ctl.4242; echo 4242 > $FifoDir/req")
        .start().waitFor()
      ProcessBuilder("sh", "-c", s"echo 4243 > $FifoDir/req").start().waitFor()
      // Serving this proves the broker declared both stagings stillborn and moved on: cycles
      // are serial, so a wedged one would leave this handshake blocked.
      val (exit, out, _) = shimCall(project, "sbt")
      assertEquals(exit, 0)
      assertEquals(out, s"built in $project\n")

  test("a competing shim waits its turn, and is served after the first one's death"):
    channel((_, cwd, args) =>
      if args.contains("quick") then Seq("sh", "-c", s"echo done in $cwd")
      else
        Seq(
          "sh", "-c",
          s"echo started > $cwd/started; trap 'exit 143' TERM; while :; do sleep 0.1; done",
        ),
    ): (project, _, _) =>
      val first = ProcessBuilder(Shim.toString, "sbt", "slow")
        .directory(project.toFile)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .start()
      var waited = 0
      while !Files.exists(project.resolve("started")) && waited < 100 do
        Thread.sleep(100)
        waited += 1
      assert(Files.exists(project.resolve("started")), "the first build never started")
      val second = ProcessBuilder(Shim.toString, "sbt", "quick").directory(project.toFile).start()
      second.getOutputStream.close()
      Thread.sleep(500)
      assert(second.isAlive, "the second shim did not wait for the first")
      first.destroyForcibly()
      val out = String(second.getInputStream.readAllBytes(), UTF_8)
      assertEquals(second.waitFor(), 0)
      assertEquals(out, s"done in $project\n")

  test("output arrives whole, however large"):
    val payload = 1 << 20
    channel((_, _, _) =>
      Seq("sh", "-c", s"i=0; while [ $$i -lt ${payload / 1024} ]; do printf '%01024d' $$i; i=$$((i+1)); done"),
    ): (project, _, _) =>
      val (exit, out, _) = shimCall(project, "sbt")
      assertEquals(exit, 0)
      assertEquals(out.length, payload)

  test("a slow reader is never truncated: writers die only with their requester"):
    val payload = 1 << 20
    channel((_, _, _) =>
      Seq(
        "sh", "-c",
        s"i=0; while [ $$i -lt ${payload / 1024} ]; do printf '%01024d' $$i; i=$$((i+1)); done; exit 5",
      ),
    ): (project, host, _) =>
      // A hand-rolled requester that opens its readers only after fifteen seconds — past the
      // ten-second writer bound a truncating implementation had — with output past the pipes'
      // capacity, so the broker's pumps are genuinely blocked while it sleeps.
      val script = host.resolve("slow-shim.sh")
      executable(
        script,
        s"""#!/bin/sh
           |set -eu
           |d=${RunOnHostChannel.SandboxDir}
           |id=$$$$
           |rm -f "$$d/ctl.$$id" "$$d/out.$$id" "$$d/err.$$id" "$$d/exit.$$id"
           |mkfifo -m 600 "$$d/ctl.$$id" "$$d/out.$$id" "$$d/err.$$id" "$$d/exit.$$id"
           |printf '%s\\n' "$$id" > "$$d/req"
           |exec 8> "$$d/ctl.$$id"
           |{ printf 'sbt 0\\n'; printf '%s\\0' "$project"; } >&8
           |sleep 15
           |cat "$$d/out.$$id" > "$host/slow.out" 8>&-
           |cat "$$d/err.$$id" > /dev/null 8>&-
           |code=$$(cat "$$d/exit.$$id" 8>&-)
           |printf '%s' "$$code" > "$host/slow.code"
           |""".stripMargin,
      )
      val slow = ProcessBuilder(script.toString).start()
      assertEquals(slow.waitFor(), 0)
      assertEquals(Files.size(host.resolve("slow.out")), payload.toLong)
      assertEquals(Files.readString(host.resolve("slow.code")), "5")

  test("without a broker the shim fails at once, naming the launch option"):
    assume(tools.forall(onPath), s"needs ${tools.mkString(", ")} on PATH")
    deleteRecursively(FifoDir)
    val project = Files.createTempDirectory("channel-none")
    val (exit, _, err) = shimCall(project, "sbt", "test")
    assertEquals(exit, 1)
    assert(err.contains("--run-on-host"), err)
    // An unknown tool is a usage error before the channel is consulted.
    assertEquals(shimCall(project, "gradle", "build")._1, 64)
