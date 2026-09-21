package agentsandbox.launcher

import java.nio.file.{Files, Path}

import RunOnHostPrereqs.Program
import RunOnHostSession.Record

class RunOnHostRuntimeDescriptorTest extends munit.FunSuite:

  private val daemon = RunOnHostMillDaemons.Daemon(42, "Mon Sep 14 10:00:00 2026", 40_001)
  private val proxy = Record(7, "Mon Sep 14 09:59:00 2026")
  private val group = Record(9, "Mon Sep 14 09:59:30 2026")

  test("a descriptor renders and parses back, with and without a daemon; another format is none"):
    val server = RunOnHostRuntimeDescriptor("ab" * 32, 7001, proxy, group, None, None)
    val mill = RunOnHostRuntimeDescriptor("cd" * 32, 7002, proxy, group, Some(daemon), Some("ef" * 32))
    assertEquals(RunOnHostRuntimeDescriptor.parse(RunOnHostRuntimeDescriptor.render(server)), Some(server))
    assertEquals(RunOnHostRuntimeDescriptor.parse(RunOnHostRuntimeDescriptor.render(mill)), Some(mill))
    val rendered = RunOnHostRuntimeDescriptor.render(mill)
    assertEquals(RunOnHostRuntimeDescriptor.parse(rendered.replace("ko-agent-runtime 1", "x 2")), None)
    assertEquals(RunOnHostRuntimeDescriptor.parse(rendered.replace("proxy-port 7002\n", "")), None)
    val dir = Files.createTempDirectory("descriptor")
    val file = RunOnHostRuntimeDescriptor.file(dir, Program.Mill, "0123456789abcdef")
    assertEquals(file.getFileName.toString, "runtime-mill-0123456789abcdef")
    assertEquals(RunOnHostRuntimeDescriptor.read(file), None, "absent")
    assertEquals(RunOnHostRuntimeDescriptor.publish(file, mill), Right(()))
    assertEquals(RunOnHostRuntimeDescriptor.read(file), Some(mill))
    assert(!Files.exists(file.resolveSibling(s"${file.getFileName}.pending")))

  test("the fingerprint follows every start input, the rules and the forwards, and no ordering"):
    def assembled(jdk: String, program: Program = Program.Sbt) =
      RunOnHostSandbox.Assembled(
        RunOnHostPrereqs.CommandPrereqs(Path.of("/p"), Path.of(jdk), Path.of("/v1"), program, Path.of("/exe")),
        Some(Path.of("/dist")), Path.of("/g"), Path.of("/i"), Path.of("/gradle"), Path.of("/m"), None, None,
      )
    val systemPaths = SeatbeltProfile.SystemPaths(Seq(Path.of("/usr/lib")), Seq(Path.of("/bin/sh")))
    def inputs(
      jdk: String = "/jdk", tmp: String = "/t", port: Int = 7001, forwards: Vector[(String, String)] = Vector.empty,
      reads: Seq[Path] = systemPaths.reads, network: SeatbeltProfile.Network = SeatbeltProfile.Network.ProxyOnly,
      home: String = "/home/u", trust: String = "/b/proxy.trust",
    ) =
      RunOnHostSandbox.runtimeInputs(
        assembled(jdk), Path.of(tmp), port, Path.of(trust), systemPaths.copy(reads = reads), forwards, network,
        host = name => Option.when(name == "HOME")(home), userName = "u",
      )
    def fingerprint(in: RunOnHostSandbox.RuntimeInputs, rules: String = "deny defaults") =
      RunOnHostRuntimeDescriptor.fingerprint(in, rules)
    val base = fingerprint(inputs())
    assertEquals(fingerprint(inputs()), base, "deterministic")
    assertEquals(
      fingerprint(inputs(forwards = Vector("A" -> "1", "B" -> "2"))),
      fingerprint(inputs(forwards = Vector("B" -> "2", "A" -> "1"))),
      "the environment is a set",
    )
    val differing = Map(
      "jdk" -> fingerprint(inputs(jdk = "/jdk2")),
      "tmp" -> fingerprint(inputs(tmp = "/t2")),
      "port" -> fingerprint(inputs(port = 7002)),
      "trust" -> fingerprint(inputs(trust = "/b/proxy2.trust")),
      "forward" -> fingerprint(inputs(forwards = Vector("TOKEN" -> "t"))),
      "forwarded value" -> fingerprint(inputs(forwards = Vector("TOKEN" -> "u"))),
      "systemPaths" -> fingerprint(inputs(reads = Seq.empty)),
      "network" -> fingerprint(inputs(network = SeatbeltProfile.Network.MillDaemon)),
      "passed-through HOME" -> fingerprint(inputs(home = "/home/v")),
      "rules" -> fingerprint(inputs(), rules = "deny defaults\nallow https://example.org/ read"),
    )
    differing.foreach((what, other) => assertNotEquals(other, base, what))
    assertEquals(differing.values.toSet.size, differing.size, "each difference its own fingerprint")
    // Framing: a field boundary moved leaves a different rendering.
    assertNotEquals(
      fingerprint(inputs(forwards = Vector("AB" -> "C"))),
      fingerprint(inputs(forwards = Vector("A" -> "BC"))),
    )
