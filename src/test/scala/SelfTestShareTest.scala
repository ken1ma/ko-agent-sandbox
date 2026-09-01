// The share rows' pure half: the probe command carrying a session's own flags, the line protocol
// both sides speak, and the names that keep a killed run inside the reset sweep's reach.

package agentsandbox.launcher

import munit.FunSuite

import KoAgentFs.*
import SelfTestShare.*

class SelfTestShareTest extends FunSuite:

  test("the probe container runs with a session's own mapping, disposable and offline"):
    val mountpoint = "/home/core/.local/share/ko-agent-sandbox/mounts/self-test-share-1a2b3c4d/workspace"
    val command = probeRunCommand("podman", mountpoint, probeContainerName("1a2b3c4d"))
    assert(command.contains("--rm"))
    assert(command.contains("--network=none"))
    assert(command.contains("--entrypoint="))
    assert(command.contains("--userns=keep-id:uid=65532,gid=65532"))
    assert(command.contains("--user=65532:65532"))
    assert(command.contains(s"--volume=$mountpoint:/workspace:rw"))
    // No image build and no volume creation: the probe reuses the sandbox image as it stands, so
    // a second run rebuilds nothing and leaves no second container or volume behind.
    assertEquals(command.takeRight(3), Vector("ko-agent-sandbox:latest", "python3", "-"))

  test("a killed run's mount and container land inside the sweeps every reset already makes"):
    assert(koAgentFsMountDir(shareMountId("1a2b3c4d")).startsWith(s"$KoAgentFsInstallDir/mounts/"))
    assertEquals(
      probeContainers(
        Seq(probeContainerName("1a2b3c4d"), "ko-agent-self-test-share-mine", "ko-agent-sandbox-run-x"),
      ),
      Seq(probeContainerName("1a2b3c4d")),
    )
    // The minted name itself, so the sweep and the builder cannot drift apart.
    assert(probeContainers(Seq(probeContainerName(AgentSandboxLauncher.newRunSuffix()))).nonEmpty)

  test("the probe programs speak exactly the protocol the orchestrator reads"):
    assertEquals(interpret("stack filtered"), ProbeEvent.Stack(true))
    assertEquals(interpret("stack unfiltered"), ProbeEvent.Stack(false))
    assertEquals(interpret("READY"), ProbeEvent.ReadySeen)
    assertEquals(interpret("read-visible"), ProbeEvent.ReadSeen(true))
    assertEquals(interpret("read-visible never"), ProbeEvent.ReadSeen(false))
    assertEquals(interpret("mmap-visible 42"), ProbeEvent.MmapSeen(Some(42L)))
    assertEquals(interpret("mmap-visible never"), ProbeEvent.MmapSeen(None))
    assertEquals(interpret("mmap-visible ??"), ProbeEvent.Noise("mmap-visible ??"))
    assertEquals(interpret("HELD"), ProbeEvent.HeldSeen)
    assertEquals(interpret("abort: the seed reads b'CCCC'"), ProbeEvent.Aborted("the seed reads b'CCCC'"))
    assertEquals(interpret("WARNING: something"), ProbeEvent.Noise("WARNING: something"))
    // The programs interpolate the same constants interpret reads; their presence is the drift
    // guard for the python side.
    for marker <- Seq("READY", "read-visible", "mmap-visible", "stack ", SeedName, OldBytes, NewBytes) do
      assert(PosixSessionProbe.contains(marker), marker)
    for marker <- Seq("READY", "read-visible", "HELD", "stack ", SeedName, OldBytes, NewBytes, ReleaseName) do
      assert(WindowsSessionProbe.contains(marker), marker)
    // No mmap row on Windows: the write it measures is refused while the mapping holds
    // (verification-log.md, "coherency on Windows"); the HELD refusal row stands in its place.
    assert(!WindowsSessionProbe.contains("mmap-visible"))

  test("the machine venue script asks about the backing path without splicing it"):
    val script = machineVenueScript("/Users/x/proj/self-test-share.1")
    assert(!script.contains("/Users/x/proj"))
    assert(script.contains("base64 -d"))
    assert(script.contains("uname -r"))
    // findmnt, not stat: virtiofs registers under FUSE's statfs magic, and the venue line exists
    // to tell the share from the filter's own mounts.
    assert(script.contains("findmnt"))
