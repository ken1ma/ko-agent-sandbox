package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.util.concurrent.TimeUnit

/** project/KoAgentSandboxHelper.scala in a build of its own, under an sbt 2 server that the variable marks as a
  * launch's run-on-host server, as a terminal's `sbt` meets one. No launch is needed: the variable alone selects the
  * refusal. */
class KoAgentSandboxHelperTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(5, "min")

  private val sbt = sys.env.getOrElse("PATH", "").split(java.io.File.pathSeparator).map(Path.of(_, "sbt"))
    .find(Files.isExecutable)

  /** Runs sbt in `build`, with the output in a file (KoReviewTest.runIn gives the reason). */
  private def runSbt(build: Path, environment: Map[String, String], arguments: String*): (Int, String) =
    val output = Files.createTempFile("ko-agent-sandbox-helper", ".log")
    val builder = ProcessBuilder((sbt.get.toString +: arguments)*).directory(build.toFile)
      .redirectErrorStream(true).redirectOutput(output.toFile)
    builder.environment().remove(KoAgentSandboxHelperTest.HostCommandVariable)
    environment.foreach((name, value) => builder.environment().put(name, value))
    val process = builder.start()
    try
      assert(process.waitFor(240, TimeUnit.SECONDS), s"sbt ${arguments.mkString(" ")} exceeded 240 seconds")
      (process.exitValue(), Files.readString(output))
    finally
      process.destroyForcibly()
      Files.deleteIfExists(output)

  /** Whether the server deleted its portfile within 10 seconds. The server deletes it after the client that stopped
    * the server has returned, so a deletion of the build before then can race the server's own. */
  private def serverEnded(build: Path): Boolean =
    val portfile = build.resolve("project/target/active.json")
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while Files.exists(portfile) && System.nanoTime() < deadline do Thread.sleep(100)
    !Files.exists(portfile)

  // sbt 1's plain `sbt` runs a JVM of its own, so only its thin client meets a launch's server; sbt 2's `sbt` is a thin
  // client already. Both take --client.
  for sbtVersion <- Seq("2.1.0", "1.13.1") do
    test(s"under sbt $sbtVersion, a refused task beside a slower one reaches the client before the server ends"):
      assume(sbt.isDefined, "needs sbt on PATH")
      // A server started from a host command would be confined as the launch's own, which refuses another server.
      assume(!sys.env.contains(KoAgentSandboxHelperTest.HostCommandVariable), "runs outside a run-on-host command")
      val build = Files.createTempDirectory("ko-agent-sandbox-helper")
      try
        Files.createDirectories(build.resolve("project"))
        Files.copy(Path.of("project/KoAgentSandboxHelper.scala"), build.resolve("project/KoAgentSandboxHelper.scala"))
        Files.writeString(build.resolve("project/build.properties"), s"sbt.version=$sbtVersion\n")
        Files.writeString(build.resolve("build.sbt"),
          """lazy val slow = taskKey[Unit]("sleeps longer than the refusal's delay")
            |slow := Thread.sleep(5000)
            |lazy val dist = taskKey[Unit]("refused in a run-on-host server")
            |dist := KoAgentSandboxHelper.outsideHostCommand("dist", KoAgentSandboxHelper.BuildsWhatYouRun)(
            |  Def.task(println("built"))
            |).value
            |""".stripMargin)
        // The first client starts the server, which inherits the variable; the second, as a terminal's, does not.
        val marked = Map(KoAgentSandboxHelperTest.HostCommandVariable -> "1")
        val (started, startOutput) = runSbt(build, marked, "--client", "show name")
        assertEquals(started, 0, startOutput)
        val (refused, output) = runSbt(build, Map.empty, "--client", "all dist slow")
        assertEquals(refused, 1, output)
        val refusal = "dist: your sbt command reached an sbt server that ko-agent-sandbox's run-on-host started"
        assert(output.contains(refusal), output)
        assert(output.contains("Stopping that server: run your sbt command again in a host terminal."), output)
        assert(serverEnded(build), "the server left its portfile")
        val (built, builtOutput) = runSbt(build, Map.empty, "--client", "dist")
        assertEquals(built, 0, builtOutput)
        assert(builtOutput.contains("built"), builtOutput)
      finally
        runSbt(build, Map.empty, "--client", "shutdown")
        serverEnded(build)
        FileHelper.deleteRecursively(build)

object KoAgentSandboxHelperTest:
  val HostCommandVariable = "KO_AGENT_SANDBOX_RUN_ON_HOST_COMMAND"
