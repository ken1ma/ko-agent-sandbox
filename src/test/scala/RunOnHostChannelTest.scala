// The command channel, end to end on one host: the real broker against the image's real shim,
// with `podman exec` replaced by a script, the shim's FIFO directory rewritten, and the wrapper
// by scripts the tests choose — the transport and the command stubbed, never the protocol. What
// it holds is the channel's contract: framing under bounds, the working-directory boundary,
// streamed output carried whole with the command's own exit code, and teardown by descriptor
// lifetime — a dead shim ends the running command, a handshake whose requester died expires
// with no command started, and a competing shim waits its turn rather than attaching to a
// predecessor's streams. The acceptance test re-runs the protocol against real sbt; these rows hold
// everywhere.

package agentsandbox.launcher

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicBoolean

import scala.jdk.CollectionConverters.*
import scala.util.Using

import HostCommands.Os
import RunOnHostChannel.*

class RunOnHostChannelTest extends munit.FunSuite:

  private val programs = Vector("sh", "flock", "mkfifo", "timeout")
  private def onPath(program: String): Boolean =
    sys.env.getOrElse("PATH", "").split(":").exists(dir => Files.isExecutable(Paths.get(dir, program)))

  /** Never the production path, for the reason ClipboardBrokerTest's own gives: both sides are
    * pointed here instead — the broker by its transport, the shim by the line rewritten below. */
  private val FifoDir = Files.createTempDirectory("channel-fifos")

  /** The seconds the shim copy waits on the broker, in place of the image's: what a dead broker
    * costs each of the tests below. */
  private val ShimBound = 5

  /** The image's shim with its directory and bound lines rewritten and nothing else. A spelling
    * this no longer finds fails the suite rather than testing a script the image does not ship.
    * Made on first use, so a platform whose tests all skip never sets POSIX permissions — not at
    * cleanup either, which is why the copy is tracked rather than the value forced. */
  private var shimCopy: Option[Path] = None
  private def Shim: Path = shimCopy.getOrElse:
    val source = Paths.get("container/ko-agent-sandbox/ko-sandbox-run-on-host").toAbsolutePath
    val text = Files.readString(source)
    val rewritten = Map(s"dir=${RunOnHostChannel.SandboxDir}" -> s"dir=$FifoDir", "bound=30" -> s"bound=$ShimBound")
    rewritten.keys.foreach: line =>
      require(text.linesIterator.count(_ == line) == 1, s"$source no longer spells `$line`")
    val copy = Files.createTempFile("ko-sandbox-run-on-host", "")
    Files.writeString(copy, rewritten.foldLeft(text)((text, entry) => text.replace(entry._1, entry._2)))
    Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rwxr-xr-x"))
    shimCopy = Some(copy)
    copy

  override def afterAll(): Unit =
    deleteRecursively(FifoDir)
    shimCopy.foreach(Files.deleteIfExists)
    ()

  // ---------------------------------------------------------------------------
  // Framing
  // ---------------------------------------------------------------------------

  /** The request bytes exactly as the shim's printf pair produces them. */
  private def framed(program: String, cwd: String, args: String*): Array[Byte] =
    (s"$program ${args.size}\n" + (cwd +: args).map(_ + "\u0000").mkString).getBytes(UTF_8)

  test("a request round-trips, empty and awkward arguments included"):
    val bytes = framed("sbt", "/Users/me/app/sub dir", "test", "", "set x := \"a\nb\"", "λ")
    assertEquals(
      readRequest(ByteArrayInputStream(bytes)),
      Right(Some(Request("sbt", "/Users/me/app/sub dir", Vector("test", "", "set x := \"a\nb\"", "λ")))),
    )

  test("no arguments is a request; end of stream at a boundary is None"):
    val in = ByteArrayInputStream(framed("mill", "/Users/me/app"))
    assertEquals(readRequest(in), Right(Some(Request("mill", "/Users/me/app", Vector.empty))))
    assertEquals(readRequest(in), Right(None))

  test("a stream that cannot frame a request is refused whole"):
    def refused(bytes: Array[Byte]): Unit =
      assert(readRequest(ByteArrayInputStream(bytes)).isLeft, String(bytes, UTF_8))
    refused("sbt\n".getBytes(UTF_8)) // no argument count
    refused("sbt one\n".getBytes(UTF_8)) // a count that is no number
    refused(s"sbt ${MaxArguments + 1}\n".getBytes(UTF_8)) // over the bound
    refused("sbt 0\n".getBytes(UTF_8) ++ Array.fill(MaxRequestBytes + 1)('a'.toByte)) // too big
    refused(Array.fill(MaxLineBytes + 1)('a'.toByte)) // a header that never ends
    refused("sbt 2\n/Users/me/app\u0000only-one\u0000".getBytes(UTF_8)) // ends inside the request

  test("the request bound charges the NUL delimiters, as the drain does"):
    // An empty argument is its delimiter alone, so MaxArguments of them put into the frame the most
    // NULs an accepted request can hold.
    def withCwdOf(bytes: Int): Array[Byte] =
      framed("sbt", "a" * bytes, Vector.fill(MaxArguments)("")*)
    val fits = withCwdOf(MaxRequestBytes - MaxArguments - 1)
    assertEquals(fits.length - s"sbt $MaxArguments\n".length, MaxRequestBytes, "fields and NULs fill the bound")
    assert(readRequest(ByteArrayInputStream(fits)).isRight, "a request at the bound")
    val over = ByteArrayInputStream(withCwdOf(MaxRequestBytes - MaxArguments))
    assert(readRequest(over).isLeft, "one byte past it")
    assertEquals(over.available(), 0, "the refused frame is drained whole")

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

  /** The project mounted at its own path, as a launch has it. */
  private def service(project: Path, deadline: Long = 30_000): Service =
    Service(
      project, Set("sbt"), (_, _, _, _) => Seq("true"), Os.Mac,
      buildLock = (_, _) => Right(Path.of("/unused")),
      runtime = (_, _, _) => Right(Seq.empty),
      mount = project.toString, requestDeadlineMillis = deadline,
    )

  test("the working directory is translated, and proven inside the project"):
    val project = Files.createTempDirectory("channel-project").toRealPath()
    val sub = Files.createDirectory(project.resolve("sub"))
    val outside = Files.createTempDirectory("channel-outside").toRealPath()
    val svc = service(project)
    assertEquals(validated(svc, Request("sbt", project.toString, Vector.empty)), Right(project))
    assertEquals(validated(svc, Request("sbt", s"$project/sub", Vector.empty)), Right(sub))
    def refused(workingDirectory: String): Unit =
      val answer = validated(svc, Request("sbt", workingDirectory, Vector.empty))
      assert(answer.left.exists(_.startsWith("CHANNEL_UNAVAILABLE")), s"$workingDirectory: $answer")
    refused(outside.toString) // an unrelated host path
    refused(s"$project/../escape") // climbing out
    refused(s"$project/absent") // nothing to canonicalize
    Files.createSymbolicLink(project.resolve("link"), outside)
    refused(s"$project/link") // a symlink leaving the project

  test("a program the launch did not name is refused, not run"):
    val project = Files.createTempDirectory("channel-project").toRealPath()
    val answer = validated(service(project), Request("mill", project.toString, Vector.empty))
    assert(answer.left.exists(_.contains("does not name mill")), answer.toString)

  // ---------------------------------------------------------------------------
  // End to end: the real shim against the real broker over a stubbed transport
  // ---------------------------------------------------------------------------

  private def executable(path: Path, body: String): Unit =
    Files.writeString(path, body)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"))

  private def deleteRecursively(path: Path): Unit =
    if Files.exists(path) then
      Using.resource(Files.walk(path)): entries =>
        entries.iterator().asScala.toVector.reverse.foreach(Files.deleteIfExists)

  /**
   * The broker served like production — same exec argument pattern, `podman` a script running the
   * exec locally — with the shim's mount spelled as the project itself, so the shim's own $PWD is
   * a request every host can make. The wrapper command is the test's, under the real locked
   * spawn, since dispatch speaks its protocol; `runtime` is what the broker's word carries.
   */
  private def channel(
    wrapperCommand: (String, Path, Seq[String]) => Seq[String],
    deadline: Long = 30_000,
    runtime: (String, Path, Seq[String]) => Either[String, Seq[String]] = (_, _, _) => Right(Seq.empty),
    ended: String => Unit = _ => (),
  )(check: (Path, Path, () => String) => Unit): Unit =
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    val dir = Files.createTempDirectory("channel")
    val host = Files.createDirectory(dir.resolve("host"))
    val project = Files.createDirectory(dir.resolve("project")).toRealPath()
    val lockFile = host.resolve("build-lock")
    // On the host `podman exec` returns tens of milliseconds after the container-side process
    // ends (measured in a session's channel log). The exit writer's lateness is the one the
    // protocol can observe — the shim's ctl closes before the broker sees that writer end — so
    // the stub delays that exec alone.
    executable(
      host.resolve("podman"),
      """#!/bin/sh
        |case "$1 $2" in
        |  "exec -i") shift 3
        |    case "$*" in
        |      *"/exit."*) "$@"; sleep 0.3 ;;
        |      *) exec "$@" ;;
        |    esac ;;
        |esac
        |""".stripMargin,
    )
    deleteRecursively(FifoDir)
    val running = AtomicBoolean(true)
    val transport =
      Transport(Seq(host.resolve("podman").toString, "exec", "-i", "C"), () => running.get, FifoDir.toString)
    val log = StringBuilder()
    val broker = Thread(() =>
      serve(
        transport,
        service(project, deadline = deadline).copy(
          buildLock = (_, _) => Right(lockFile),
          wrapperCommand = (program, directory, _, arguments) =>
            RunOnHostSession.lockedSpawn(lockFile, wrapperCommand(program, directory, arguments), underBroker = true),
          runtime = runtime,
          ended = ended,
        ),
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
      // the loop — the one way this side of the FIFO can end it. Bounded: with the reader already
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

  test("a command streams both channels back and returns its own exit code"):
    val endedPrograms = java.util.concurrent.CopyOnWriteArrayList[String]()
    channel(
      (program, cwd, args) =>
        Seq("sh", "-c", s"echo ran $program ${args.mkString(" ")} in $cwd; echo complaint >&2; exit 7"),
      ended = endedPrograms.add(_),
    ): (project, _, brokerLog) =>
      val (exit, out, err) = shimCall(project, "sbt", "test", "-v")
      assertEquals(exit, 7)
      assertEquals(out, s"ran sbt test -v in $project\n")
      assertEquals(err, "complaint\n")
      // The service hears of the command's end with its program, once the spawn is gone.
      assertEquals(endedPrograms.asScala.toList, List("sbt"))
      // The shim leaves as soon as it has its exit code, and the log records that as the
      // answer's end, never as a requester lost mid-command. The exit line lands after the
      // shim's own return, by the exit writer's end, so it is awaited.
      var waited = 0
      while !brokerLog().contains("exit 7") && waited < 100 do
        Thread.sleep(100)
        waited += 1
      val logged = brokerLog()
      assert(logged.contains("exit 7"), logged)
      assert(!logged.contains("requester is gone"), logged)

  test("small stdout and stderr writes arrive before the command can finish"):
    channel((_, cwd, _) =>
      Seq("sh", "-c", s"printf ready; printf 'waiting\\n' >&2; while [ ! -f '$cwd/release' ]; do sleep 0.1; done"),
    ): (project, host, _) =>
      val out = host.resolve("stdout")
      val err = host.resolve("stderr")
      val process = ProcessBuilder(Shim.toString, "sbt")
        .directory(project.toFile)
        .redirectOutput(out.toFile)
        .redirectError(err.toFile)
        .start()
      process.getOutputStream.close()
      try
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
        while process.isAlive && System.nanoTime() < deadline &&
            (Files.readString(out) != "ready" || Files.readString(err) != "waiting\n") do
          Thread.sleep(20)
        assert(process.isAlive, "the command must still be waiting for release")
        assertEquals(Files.readString(out), "ready")
        assertEquals(Files.readString(err), "waiting\n")
      finally
        Files.writeString(project.resolve("release"), "")
        if !process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS) then process.destroyForcibly()

  test("the banner the injected _JAVA_OPTIONS causes is dropped, and nothing else is"):
    val banner = "Picked up _JAVA_OPTIONS: -Djava.io.tmpdir=/x"
    channel((_, _, _) =>
      Seq(
        "sh", "-c",
        s"echo '$banner' >&2; echo complaint >&2; echo 'Picked up JAVA_TOOL_OPTIONS: -Dx=1' >&2; " +
          s"echo '[warn] $banner' >&2; echo '$banner'",
      ),
    ): (project, _, _) =>
      val (exit, out, err) = shimCall(project, "sbt")
      assertEquals(exit, 0)
      // Only what the wrapper's own injection causes is hidden: another VM-options variable is the
      // host environment's to explain, a line that merely quotes the banner is the command's, and
      // stdout is not the stream the announcement is written to.
      assertEquals(err, s"complaint\nPicked up JAVA_TOOL_OPTIONS: -Dx=1\n[warn] $banner\n")
      assertEquals(out, s"$banner\n")

  test("a refused request answers on stderr with exit 2, and the channel keeps serving"):
    channel((_, cwd, _) => Seq("sh", "-c", s"echo built in $cwd")): (project, _, _) =>
      val (exit, _, err) = shimCall(project, "mill", "build")
      assertEquals(exit, 2)
      assert(err.contains("CHANNEL_UNAVAILABLE"), err)
      val (again, out, _) = shimCall(project, "sbt")
      assertEquals(again, 0)
      assertEquals(out, s"built in $project\n")

  test("an end asked for during preparation waits for the word, so the build lock is held throughout"):
    // The runtime's preparation, slow enough to be interrupted: it records whether the build
    // lock is still held halfway through, which a spawn ended early would have freed.
    val runtime = (_: String, buildDirectory: Path, _: Seq[String]) =>
      Files.writeString(buildDirectory.resolve("preparing"), "")
      Thread.sleep(1500)
      val lockFile = buildDirectory.getParent.resolve("host").resolve("build-lock")
      val held = ProcessBuilder("flock", "-n", lockFile.toString, "true").start().waitFor() != 0
      Files.writeString(buildDirectory.resolve(if held then "held" else "free"), "")
      Right(Seq.empty)
    channel((_, cwd, _) => Seq("sh", "-c", s"echo built in $cwd"), runtime = runtime): (project, host, brokerLog) =>
      def await(what: String)(condition: => Boolean): Unit =
        var waited = 0
        while !condition && waited < 100 do
          Thread.sleep(100)
          waited += 1
        assert(condition, what)
      def lockFree = ProcessBuilder("flock", "-n", host.resolve("build-lock").toString, "true").start().waitFor() == 0
      // The requester leaves mid-preparation.
      val shim = ProcessBuilder(Shim.toString, "sbt", "test")
        .directory(project.toFile)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .start()
      await("preparation started")(Files.exists(project.resolve("preparing")))
      shim.destroyForcibly()
      await("preparation finished")(Files.exists(project.resolve("held")) || Files.exists(project.resolve("free")))
      assert(Files.exists(project.resolve("held")), "the lock was freed while the runtime was prepared")
      await("the transaction ended")(brokerLog().contains("for a requester already gone"))
      assert(lockFree, "the lock is freed once the word is out")
      assert(!brokerLog().contains("exit 0"), "the wrapper never ran: the word was the refusal")
      // The broker's own end mid-preparation, as its TERM hook asks for it: it returns after
      // the preparation, and the requester gets the refusal.
      Files.delete(project.resolve("preparing"))
      Files.delete(project.resolve("held"))
      val second = ProcessBuilder(Shim.toString, "sbt", "test").directory(project.toFile).start()
      second.getOutputStream.close()
      await("preparation started again")(Files.exists(project.resolve("preparing")))
      endCurrentCommand()
      assert(Files.exists(project.resolve("held")), "the end returned before the preparation finished")
      val err = String(second.getErrorStream.readAllBytes(), UTF_8)
      assertEquals(second.waitFor(), 2)
      assertEquals(err, "refused: the command was ended before it started\n")
      assert(lockFree)

  test("the runtime reaches the wrapper as options; a refusal or an exception preparing it is the command's"):
    val prepared = java.util.concurrent.atomic.AtomicReference[(String, Path, Seq[String])]()
    channel(
      (_, _, args) => Seq("sh", "-c", "printf '%s\\n' \"$@\"", "sh", "--") ++ args,
      runtime = (program, buildDirectory, arguments) =>
        prepared.set((program, buildDirectory, arguments))
        buildDirectory.getFileName.toString match
          case "sub"    => Left("no runtime for sub")
          case "broken" => throw java.nio.charset.MalformedInputException(1)
          case _        => Right(Seq("--proxy-port=1")),
    ): (project, host, brokerLog) =>
      val (exit, out, _) = shimCall(project, "sbt", "compile")
      assertEquals(exit, 0)
      assertEquals(out, "--proxy-port=1\n--\ncompile\n")
      assertEquals(prepared.get, ("sbt", project, Seq("compile")))
      val sub = Files.createDirectory(project.resolve("sub"))
      val (refused, _, err) = shimCall(sub, "sbt", "compile")
      assertEquals(refused, 2)
      assertEquals(err, "refused: no runtime for sub\n")
      assert(brokerLog().contains("refused: no runtime for sub"), brokerLog())
      // An exception is answered the same way, and the spawn ends with the lock released.
      val broken = Files.createDirectory(project.resolve("broken"))
      val (thrown, _, thrownErr) = shimCall(broken, "sbt", "compile")
      assertEquals(thrown, 2)
      assertEquals(thrownErr, "refused: preparing the runtime: MalformedInputException: Input length = 1\n")
      assertEquals(ProcessBuilder("flock", "-n", host.resolve("build-lock").toString, "true").start().waitFor(), 0)

  test("a dead shim ends the running command: teardown follows the descriptor"):
    channel((_, cwd, _) =>
      // The validated working directory arrives as an argument, so the markers spell it out;
      // the child's own cwd is the broker's and says nothing.
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
      assert(Files.exists(project.resolve("started")), "the command never started")
      shim.destroyForcibly()
      waited = 0
      while !Files.exists(project.resolve("ended")) && waited < 100 do
        Thread.sleep(100)
        waited += 1
      assert(Files.exists(project.resolve("ended")), "the shim died and the command kept running")

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

  test("a transaction whose requester died without a request expires: no command, and the channel keeps serving"):
    channel((_, cwd, _) => Seq("sh", "-c", s"echo built in $cwd"), deadline = 1500): (project, _, _) =>
      // A handshake whose ctl exists but is never opened — the shim died between its two steps —
      // and one whose ctl never existed at all. Neither may start a command or leave the broker blocked on a FIFO.
      ProcessBuilder("sh", "-c", s"mkfifo -m 600 $FifoDir/ctl.4242; echo 4242 > $FifoDir/req")
        .start().waitFor()
      ProcessBuilder("sh", "-c", s"echo 4243 > $FifoDir/req").start().waitFor()
      // Serving the next transaction proves both incomplete transactions expired; cycles are serial,
      // so a transaction still blocked on its FIFO would prevent it.
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
      assert(Files.exists(project.resolve("started")), "the first command never started")
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
           |d=$FifoDir
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

  test("a broker gone before the streams open leaves no shim hanging"):
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    deleteRecursively(FifoDir)
    Files.createDirectories(FifoDir)
    val project = Files.createTempDirectory("channel-gone")
    def unanswered(standIn: Option[String]): Unit =
      ProcessBuilder("sh", "-c", s"rm -f $FifoDir/req; mkfifo -m 600 $FifoDir/req").start().waitFor()
      val broker = standIn.map(script => ProcessBuilder("sh", "-c", script).start())
      val (exit, _, err) = shimCall(project, "sbt", "test")
      assertEquals(exit, 70, err)
      assert(err.contains("did not answer"), err)
      // The stand-in ends with the shim: its ctl closed, so nothing of the transaction is held.
      broker.foreach: process =>
        assert(process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS), "the stand-in outlived the shim")
      val left = FileHelper.directoryEntries(FifoDir).map(_.getFileName.toString).toSet
      assertEquals(left, Set("req", "lock"))
    // A req nobody reads: the broker died, its FIFO staying on the container's tmpfs.
    unanswered(None)
    // A broker that took the handshake and the request, then died before opening the streams.
    unanswered(Some(s"id=$$(head -n 1 $FifoDir/req); cat $FifoDir/ctl.$$id > /dev/null"))

  for (ending, expectedExit) <- Vector(
    "HUP" -> 129,
    "INT" -> 130,
    "TERM" -> 143,
    "PIPE" -> 141,
    "open failure" -> 2,
    "broken request pipe" -> 141,
  ) do
    test(s"$ending during startup retires the watchdog before cleanup"):
      assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
      deleteRecursively(FifoDir)
      Files.createDirectories(FifoDir)
      assertEquals(ProcessBuilder("mkfifo", FifoDir.resolve("req").toString).start().waitFor(), 0)
      val argument = if ending == "broken request pipe" then "x" * (100 * 1024) else "test"
      val shim = ProcessBuilder(Shim.toString, "sbt", argument)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .start()
      val descendants = scala.collection.mutable.ArrayBuffer.empty[ProcessHandle]
      var handshake: Option[Process] = None
      try
        val deadline = System.nanoTime() + 2_000_000_000L
        while descendants.isEmpty && System.nanoTime() < deadline do
          val children = shim.toHandle.descendants()
          try descendants ++= children.iterator.asScala.filter(_.info().command().orElse("").endsWith("/sleep"))
          finally children.close()
          if descendants.isEmpty then Thread.sleep(10)
        assert(descendants.nonEmpty, s"$ending: the watchdog never started")
        // Keep the watchdog's handle too, so a failing regression test can clean up its timer.
        descendants.head.parent().ifPresent(parent => { descendants += parent; () })
        if ending == "open failure" then
          val ctl = FifoDir.resolve(s"ctl.${shim.pid()}")
          Files.delete(ctl)
          // Opening the directory fails, but cleanup can unlink this symlink successfully.
          Files.createSymbolicLink(ctl, FifoDir)
          handshake = Some(ProcessBuilder("head", "-n", "1", FifoDir.resolve("req").toString).start())
        else if ending == "broken request pipe" then
          // More than a FIFO buffer: closing the reader interrupts a real request write.
          handshake = Some(ProcessBuilder("sh", "-c",
            s"read -r transaction < $FifoDir/req; exec 6< $FifoDir/ctl.$$transaction; exec 6<&-",
          ).start())
        else
          assertEquals(ProcessBuilder("kill", s"-$ending", shim.pid().toString).start().waitFor(), 0)
        handshake.foreach: process =>
          assert(process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS), "handshake did not finish")
        assert(shim.waitFor(2, java.util.concurrent.TimeUnit.SECONDS), s"$ending: shim did not exit promptly")
        assertEquals(shim.exitValue(), expectedExit, ending)
        Thread.sleep((ShimBound + 1) * 1000L)
        val entries = FileHelper.directoryEntries(FifoDir).map(_.getFileName.toString).toSet
        assertEquals(entries, Set("req", "lock"), ending)
      finally
        handshake.foreach(_.destroyForcibly())
        descendants.reverseIterator.foreach(_.destroyForcibly())
        shim.destroyForcibly()
        shim.waitFor()

  test("opening the streams disarms the startup deadline for a longer running command"):
    channel((_, _, _) => Seq("sh", "-c", s"sleep ${ShimBound + 1}; echo completed; exit 7")):
      (project, _, _) =>
        val (exit, out, _) = shimCall(project, "sbt", "test")
        assertEquals(exit, 7)
        assertEquals(out, "completed\n")
        val entries = FileHelper.directoryEntries(FifoDir).map(_.getFileName.toString).toSet
        assertEquals(entries, Set("req", "lock"))

  test("without a broker the shim fails at once, naming the launch option"):
    assume(programs.forall(onPath), s"needs ${programs.mkString(", ")} on PATH")
    deleteRecursively(FifoDir)
    val project = Files.createTempDirectory("channel-none")
    val (exit, _, err) = shimCall(project, "sbt", "test")
    assertEquals(exit, 1)
    assert(err.contains("--run-on-host"), err)
    // An unknown program is a usage error before the channel is consulted.
    assertEquals(shimCall(project, "ant", "build")._1, 64)
