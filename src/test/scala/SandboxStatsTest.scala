package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import HostCommands.Os
import SandboxStats.*

class SandboxStatsTest extends munit.FunSuite:

  test("sizes are whole up to MiB, one decimal from GiB, and carry into the next unit at 1024"):
    assertEquals(humanBytes(0), "0 B")
    assertEquals(humanBytes(1023), "1023 B")
    assertEquals(humanBytes(1024), "1 KiB")
    assertEquals(humanBytes(1536), "2 KiB")
    assertEquals(humanBytes(937L * 1024), "937 KiB")
    assertEquals(humanBytes((15L << 20) / 10), "2 MiB")
    assertEquals(humanBytes(2L << 30), "2.0 GiB")
    assertEquals(humanBytes((72L << 30) / 10), "7.2 GiB")
    assertEquals(humanBytes((10236L << 20) / 10), "1.0 GiB")
    assertEquals(humanBytes((102396L << 30) / 100), "1.0 TiB")
    assertEquals(humanBytes(3L << 40), "3.0 TiB")

  test("a share line says the percentage first and the figure the thresholds act on beside it"):
    assertEquals(shareLine("storage", (9367L << 30) / 10, (16L << 40) / 10, "free"), "storage: 57% (936.7 GiB) free")
    assertEquals(shareLine("memory", 6L << 30, 8L << 30, "available"), "memory: 75% (6.0 GiB) available")

  test("the live rows are this launcher's containers only, read as raw figures"):
    val id = "app-0123456789ab"
    val rows = liveContainers(
      Vector(
        s"ko-agent-sandbox-run-$id-1a2b3c4d 342800000 7213000000 8.0123",
        s"ko-agent-egress-proxy-$id-1a2b3c4d 46180000 268435456 1.2e-01",
        "some-other-container 1000000 8000000000 0",
        s"ko-agent-sandbox-run-$id-1a2b3c4d not numbers 0",
      ),
    )
    assertEquals(
      rows,
      Vector(
        LiveContainer(id, "1a2b3c4d", "sandbox", 342800000L, 7213000000L, 8.0123),
        LiveContainer(id, "1a2b3c4d", "proxy", 46180000L, 268435456L, 0.12),
      ),
    )

  test("live sessions order by their combined memory, the sandbox before its proxy, named by directory"):
    val small = "small-0123456789ab"
    val big = "big-0123456789ab"
    // An idle sandbox under its own proxy still leads: the order names roles, not sizes.
    val rendered = liveTable(
      Vector(
        LiveContainer(small, "1a2b3c4d", "proxy", 40L << 20, 256L << 20, 0.12),
        LiveContainer(small, "1a2b3c4d", "sandbox", 30L << 20, (67L << 30) / 10, 8.04),
        LiveContainer(big, "5e6f7a8b", "proxy", 50L << 20, 256L << 20, 0.0),
        LiveContainer(big, "5e6f7a8b", "sandbox", 2L << 30, (67L << 30) / 10, 42.54),
      ),
      Map(big -> "/home/me/big"),
    )
    assertEquals(
      rendered,
      """  run       role                memory    cpu  project
        |  5e6f7a8b  sandbox  2.0 GiB / 6.7 GiB  42.5%  /home/me/big
        |  5e6f7a8b  proxy     50 MiB / 256 MiB   0.0%  /home/me/big
        |  1a2b3c4d  sandbox   30 MiB / 6.7 GiB   8.0%  small-0123456789ab
        |  1a2b3c4d  proxy     40 MiB / 256 MiB   0.1%  small-0123456789ab
        |""".stripMargin,
    )

  test("volume sizes are read back from the verbose df table, in podman's decimal units"):
    val df =
      """Images space usage:
        |
        |REPOSITORY   TAG   IMAGE ID   CREATED   SIZE   SHARED SIZE   UNIQUE SIZE   CONTAINERS
        |localhost/x  1     abc        1 day     1.2GB  0B            1.2GB         1
        |
        |Containers space usage:
        |
        |CONTAINER ID  IMAGE  COMMAND  LOCAL VOLUMES  SIZE   CREATED  STATUS  NAMES
        |
        |Local Volumes space usage:
        |
        |VOLUME NAME                                LINKS  SIZE
        |ko-agent-sandbox-persistent-app-0123456789ab  1      1.234GB
        |my-shared-volume                           0      937kB
        |empty                                      0      0B
        |""".stripMargin
    assertEquals(
      volumeSizes(df),
      Map(
        "ko-agent-sandbox-persistent-app-0123456789ab" -> 1234000000L,
        "my-shared-volume" -> 937000L,
        "empty" -> 0L,
      ),
    )
    assertEquals(decimalSize("446.2MB"), Some(446200000L))
    assertEquals(decimalSize("1.2GiB"), None)
    assertEquals(decimalSize("12"), None)

  test("the machine's df answers free and total bytes from its 1024-blocks"):
    val df =
      """Filesystem     1024-blocks     Used Available Capacity Mounted on
        |/dev/vda4        100000000 20000000  75000000      22% /
        |""".stripMargin
    assertEquals(dfSpace(df), Some((75000000L * 1024, 100000000L * 1024)))
    assertEquals(dfSpace(""), None)
    assertEquals(dfSpace("df: /nowhere: No such file or directory"), None)

  test("storage says which machine holds each filesystem, and a root's path only when the host's are split"):
    val state = HostRoot(Paths.get("/home/me/.local/state/x"), "/home (/dev/sda2)", 936L << 30, 1610L << 30)
    val cache = HostRoot(Paths.get("/home/me/.cache/x"), "/home (/dev/sda2)", 936L << 30, 1610L << 30)
    val store = HostRoot(Paths.get("/var/lib/containers"), "/var (/dev/sda3)", 30L << 30, 250L << 30)
    assertEquals(storageLines(Os.Linux, Vector(state, cache), None), Vector("storage: 58% (936.0 GiB) free"))
    assertEquals(
      storageLines(Os.Linux, Vector(state, cache, store), None),
      Vector(
        "storage: 58% (936.0 GiB) free at /home/me/.local/state/x, /home/me/.cache/x",
        "storage: 12% (30.0 GiB) free at /var/lib/containers",
      ),
    )
    assertEquals(
      storageLines(Os.Mac, Vector(state, cache), Some((71L << 30, 100L << 30))),
      Vector("host storage: 58% (936.0 GiB) free", "podman machine storage: 71% (71.0 GiB) free"),
    )
    assertEquals(storageLines(Os.Windows, Vector.empty, None), Vector.empty)

  test("projects order largest first by total, volumes included, and flag only a cache over 1% of free space"):
    val rendered = projectTable(
      Vector(
        ProjectUsage("small-000000000000", Some("/home/me/small"), 1024, 10 * 1024, Some(0)),
        ProjectUsage("big-000000000000", None, 0, 2L << 30, Some(0)),
        ProjectUsage(
          "agents-000000000000",
          Some("/home/me/agents"),
          (15L << 20) / 10,
          445L << 20,
          Some((12L << 30) / 10),
        ),
      ),
      100L << 30,
    )
    // A project with no record, last launched before records existed, is named by its id.
    assertEquals(
      rendered,
      """    total  state    cache   volume  project
        |  2.0 GiB    0 B  2.0 GiB      0 B  big-000000000000  <- cache over 1% of free space; a --reset-cache candidate
        |  1.6 GiB  2 MiB  445 MiB  1.2 GiB  /home/me/agents
        |   11 KiB  1 KiB   10 KiB      0 B  /home/me/small
        |""".stripMargin,
    )
    // At exactly 1% nothing is flagged, and an unsized volume reads as unknown, not as empty.
    val edge = projectTable(Vector(ProjectUsage("p-0", None, 0, 1L << 30, None)), 100L << 30)
    assert(!edge.contains("--reset-cache"), edge)
    assert(edge.contains("  -  p-0"), edge)
    assertEquals(projectTable(Vector.empty, 5L << 30), "projects: none\n")

  test("a run container's name reads back as kind, project id and run suffix"):
    assertEquals(
      AgentSandboxLauncher.runContainerParts("ko-agent-sandbox-run-app-0123456789ab-1a2b3c4d"),
      Some(("sandbox-run", "app-0123456789ab", "1a2b3c4d")),
    )
    assertEquals(
      AgentSandboxLauncher.runContainerParts("ko-agent-egress-proxy-my.app_2-0123456789ab-1a2b3c4d"),
      Some(("egress-proxy", "my.app_2-0123456789ab", "1a2b3c4d")),
    )
    assertEquals(AgentSandboxLauncher.runContainerParts("ko-agent-sandbox-run-app-0123456789ab"), None)
    assertEquals(AgentSandboxLauncher.runContainerParts("ko-agent-self-test-app-0123456789ab-1a2b3c4d"), None)

  test("the directory behind an id is what the launch recorded, and nothing where it did not"):
    val root = Files.createTempDirectory("projects")
    val project = Paths.get("/home/me/app")
    AgentSandboxLauncher.recordProjectDirectory(root, "app-0123456789ab", project)
    Files.createDirectories(root.resolve("odd-0123456789ab"))
    Files.writeString(root.resolve("blank-0123456789ab"), "\n")
    assertEquals(projectDirectories(root), Map("app-0123456789ab" -> project.toString))
    if HostCommands.posixPermissions(root) then
      assertEquals(Files.getPosixFilePermissions(root.resolve("app-0123456789ab")).size, 2)
    assertEquals(projectDirectories(root.resolve("absent")), Map.empty)

  test("a volume probe answers present on 0, absent on 1, and nothing on any other exit"):
    assertEquals(AgentSandboxLauncher.volumeExistsAnswer(0), Some(true))
    assertEquals(AgentSandboxLauncher.volumeExistsAnswer(1), Some(false))
    assertEquals(AgentSandboxLauncher.volumeExistsAnswer(125), None)
    assertEquals(AgentSandboxLauncher.volumeExistsAnswer(-1), None)

  test("a reset drops the record once nothing it names remains, and keeps it while something does"):
    val root = Files.createTempDirectory("projects")
    val id = "app-0123456789ab"
    val kept = Files.createTempDirectory("cache")
    val absent = kept.resolve("absent")
    AgentSandboxLauncher.recordProjectDirectory(root, id, Paths.get("/home/me/app"))
    AgentSandboxLauncher.dropRecordUnless(root, id, Vector(absent, kept), volumeKept = false)
    assert(Files.exists(root.resolve(id)), "kept: one of the named directories exists")
    AgentSandboxLauncher.dropRecordUnless(root, id, Vector(absent), volumeKept = true)
    assert(Files.exists(root.resolve(id)), "kept: the generated volume remains")
    AgentSandboxLauncher.dropRecordUnless(root, id, Vector(absent), volumeKept = false)
    assert(!Files.exists(root.resolve(id)), "dropped: nothing named remains")
    AgentSandboxLauncher.dropRecordUnless(root, id, Vector.empty, volumeKept = false)
    AgentSandboxLauncher.dropRecordUnless(root.resolve("never"), id, Vector(absent), volumeKept = false)
