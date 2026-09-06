// The sweep's selection over the scratch registry, pure: what the container suites delete from an
// earlier run, and what they leave to another JVM that may still be using it.

package agentsandbox.launcher

import java.nio.file.Paths

import WithPodman.{Scratch, orphanScratch}

class WithPodmanTest extends munit.FunSuite:

  test("a sweep deletes scratch projects owned here or by exited JVMs, never by another running JVM"):
    val mine = Scratch("mine-0123456789ab", 100L, 1L, Paths.get("/tmp/mine"))
    val dead = Scratch("dead-0123456789ab", 200L, 2L, Paths.get("/tmp/dead"))
    val other = Scratch("other-0123456789ab", 300L, 3L, Paths.get("/tmp/other"))
    val alive: Scratch => Boolean = entry => entry.ownerPid == 300L
    assertEquals(orphanScratch(Vector(mine, dead, other), selfPid = 100L, alive), Vector(mine, dead))
