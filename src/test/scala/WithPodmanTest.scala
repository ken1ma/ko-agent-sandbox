// Tests the pure parts of the container suites' setup: the sweep's selection over the scratch registry
// (what the suites delete from an earlier run, and what they leave to another JVM that may still use
// the registry), and the check for a command on PATH that runs before the launcher looks the command up.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import WithPodman.{Scratch, commandMissing, orphanScratch}

class WithPodmanTest extends munit.FunSuite:

  test("a sweep deletes scratch workspaces owned here or by exited JVMs, never by another running JVM"):
    val mine = Scratch("mine-0123456789ab", 100L, 1L, Paths.get("/tmp/mine"))
    val dead = Scratch("dead-0123456789ab", 200L, 2L, Paths.get("/tmp/dead"))
    val other = Scratch("other-0123456789ab", 300L, 3L, Paths.get("/tmp/other"))
    val alive: Scratch => Boolean = entry => entry.ownerPid == 300L
    assertEquals(orphanScratch(Vector(mine, dead, other), selfPid = 100L, alive), Vector(mine, dead))

  test("the container suites fail on a PATH without podman, and pass the check on one with podman"):
    assume(!scala.util.Properties.isWin, "the fake executable is a POSIX file without an extension")
    val empty = Files.createTempDirectory("no-podman").toRealPath()
    val withPodman = Files.createTempDirectory("with-podman").toRealPath()
    try
      val executable = Files.writeString(withPodman.resolve("podman"), "#!/bin/sh\n")
      executable.toFile.setExecutable(true)
      assert(commandMissing("podman", empty.toString).exists(_.contains("needs podman on the PATH")))
      assertEquals(commandMissing("podman", s"$empty:$withPodman"), None)
    finally
      Files.deleteIfExists(withPodman.resolve("podman"))
      Files.delete(withPodman)
      Files.delete(empty)
