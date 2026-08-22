// The workspace FUSE filter as the launcher drives it: source identity, install and consent
// commands, the mount and reap scripts, and the opt-out that fails closed.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}
import java.nio.file.attribute.{FileTime, PosixFilePermissions}
import java.time.Instant

import HostCommands.{deleteRecursively, Os}
import KoAgentFs.*

class KoAgentFsTest extends munit.FunSuite:

  private val isWindows = System.getProperty("os.name").toLowerCase.contains("win")

  /** A bundled build-context entry, as the resourceGenerators task in build.sbt wrote it into the
    * jar. Duplicated from AgentSandboxLauncherTest, where the bundle-shape tests keep the other
    * copy. */
  private def buildContextResource(name: String): String =
    val stream = getClass.getResourceAsStream(s"/sandbox-build/$name")
    assert(stream != null, name)
    try String(stream.readAllBytes(), "UTF-8")
    finally stream.close()

  test("ko-agent-fs installs on the VM side of the boundary on podman machine, host-side on Linux"):
    // On podman machine both the image storage and the daemon live inside the VM, so the extraction
    // must run there — a host-side `podman cp` would land the binary on the wrong side.
    val vm = koAgentFsInstallCommands("podman", Os.Mac, "/Users/me")
    assertEquals(vm.length, 1)
    assertEquals(vm.head.take(3), Vector("podman", "machine", "ssh"))
    val script = vm.head(3)
    assert(script.startsWith("set -eu"), script)
    Vector("mkdir -p", "podman create --replace", "podman cp", "podman rm").foreach: step =>
      assert(script.contains(step), s"script missing '$step':\n$script")
    // /etc/fuse.conf is the user's configuration: the install script itself must not touch it —
    // that change goes through the consent prompt (ensureUserAllowOther), never silently.
    assert(!script.contains("sudo"), script)
    // The host home must not leak into a script that runs in the VM user's home.
    assert(!script.contains("/Users/me"), script)
    assertEquals(koAgentFsInstallCommands("podman", Os.Windows, "C:\\Users\\me"), vm)

    val linux = koAgentFsInstallCommands("podman", Os.Linux, "/home/me")
    assertEquals(linux.map(_.head).distinct, Vector("podman"))
    assert(linux.exists(_.contains("ko-agent-fs-extract:/ko-agent-fs")))
    assert(linux.exists(_.contains(s"/home/me/$KoAgentFsBinary")))
    assert(!linux.exists(_.contains("machine")), "native Linux has no VM to ssh into")
    // A native Linux host is not the launcher's to reconfigure.
    assert(!linux.exists(_.exists(_.contains("sudo"))), "the launcher must never sudo on the host")

  test("the installed ko-agent-fs is asked for its version and self-test where it runs"):
    assertEquals(
      koAgentFsVersionCommand("podman", Os.Linux, "/home/me"),
      Vector(s"/home/me/$KoAgentFsBinary", "--version")
    )
    assertEquals(
      koAgentFsVersionCommand("podman", Os.Mac, "/Users/me"),
      Vector("podman", "machine", "ssh", s"./$KoAgentFsBinary --version")
    )
    assertEquals(
      koAgentFsSelfTestCommand("podman", Os.Linux, "/home/me"),
      Vector(s"/home/me/$KoAgentFsBinary", "--self-test")
    )
    assertEquals(
      koAgentFsSelfTestCommand("podman", Os.Windows, "C:\\Users\\me"),
      Vector("podman", "machine", "ssh", s"./$KoAgentFsBinary --self-test")
    )

  test("the fuse.conf consent flow checks idempotently and enables exactly what it explained"):
    assertEquals(
      koAgentFsFuseConfCheckCommand("podman"),
      Vector("podman", "machine", "ssh", "grep -qx user_allow_other /etc/fuse.conf")
    )
    // The script run on consent is the same text shown to the user — no surprise delta.
    assertEquals(
      koAgentFsFuseConfEnableCommand("podman"),
      Vector("podman", "machine", "ssh", KoAgentFsFuseConfEnable)
    )
    assert(KoAgentFsFuseConfEnable.contains("user_allow_other >> /etc/fuse.conf"))
    // The original is saved first — and only if no backup exists yet, so a re-run after machine
    // recreation cannot overwrite the true original with an already-modified copy.
    assert(KoAgentFsFuseConfEnable.contains(s"test -e $KoAgentFsFuseConfBackup ||"))
    assert(KoAgentFsFuseConfEnable.contains(s"sudo cp /etc/fuse.conf $KoAgentFsFuseConfBackup"))
    // A missing fuse.conf must not make the backup step fail the script.
    assert(KoAgentFsFuseConfEnable.startsWith("test ! -f /etc/fuse.conf ||"))

  test("the mount script carries the backing path only base64-encoded, and every lifecycle step"):
    val backing = "/Users/some one's ~dir/proj; rm -rf $HOME"
    val script = koAgentFsMountScript(backing, "app-abc123def456", "d" * 64, "run-container-1")
    // A user-controlled path must never be spliced into shell text.
    assert(!script.contains(backing))
    assert(!script.contains("rm -rf $HOME"))
    val encoded = java.util.Base64.getEncoder.encodeToString(backing.getBytes("UTF-8"))
    assert(script.contains(s"printf %s $encoded | base64 -d"))

    // Adopt a healthy same-version mount; unmount a stale one; refuse a non-empty mountpoint;
    // start detached; wait until statfs says FUSE (fuse or fuseblk, hence the prefix match).
    Vector(
      "mountpoint -q",
      "fusermount3 -uz",
      "is not empty; refusing",
      "--source \"$backing\" --mount \"$mnt\" --foreground",
      "fuse*) echo \"workspace FUSE filter: mounted\"; exit 0",
      "mounts/app-abc123def456",
      "d" * 64,
      // The user must not have to infer "reused" from silence.
      "echo \"workspace FUSE filter: reusing the existing mount\"",
      // The previous daemon's log is the post-mortem after a crash: rotated, never deleted.
      "mv -f \"$dir/daemon.log\" \"$dir/daemon.log.1\""
    ).foreach(step => assert(script.contains(step), s"script missing '$step':\n$script"))
    // The session marker is the teardown's reference count, written *before* the adopt/mount
    // branches: that ordering is what closes the race with a concurrent last-session reap.
    val marker = script.indexOf(": > \"$dir/sessions/run-container-1\"")
    assert(marker >= 0, script)
    assert(marker < script.indexOf("if mountpoint -q"), "marker written after the adopt check")
    // Then the project lock, so the reuse decision cannot straddle a concurrent reap's unmount —
    // and the marker stays outside it, which is what keeps the ordering meaningful where the
    // machine has no flock.
    val lock = script.indexOf("flock 9")
    assert(script.contains("exec 9>\"$dir/lock\""), script)
    assert(marker < lock && lock < script.indexOf("if mountpoint -q"), script)
    // The daemon outlives this shell, so it must not inherit the lock and hold it for the
    // session's whole life.
    assert(script.contains("9>&- >>\"$dir/daemon.log\""), script)
    // PATH first (see below), then fail-fast before anything that can fail.
    assertEquals(script.linesIterator.drop(1).next(), "set -eu")

  test("the backing path crosses into the machine in the daemon's own spelling"):
    // The one host path podman does not translate for us. Windows drives live at /mnt/<drive>
    // inside the WSL machine; POSIX paths pass as they are — the macOS machine mounts host
    // shares at their host paths.
    def backing(os: Os, path: String): Either[String, String] =
      koAgentFsBackingPath(os, Paths.get(path))
    assertEquals(backing(Os.Windows, """C:\work\ko-agent-sandbox"""), Right("/mnt/c/work/ko-agent-sandbox"))
    assertEquals(backing(Os.Windows, """D:\a b\proj"""), Right("/mnt/d/a b/proj"))
    // A UNC path has no /mnt spelling: refused with the reason, never guessed at.
    assert(backing(Os.Windows, """\\server\share\proj""").isLeft)
    // POSIX paths pass through as the runner's Path type spells them — a POSIX host is the only
    // one that produces them for real, and a Windows runner respells them with its own separator.
    assertEquals(backing(Os.Mac, "/Users/me/proj"), Right(Paths.get("/Users/me/proj").toString))
    assertEquals(backing(Os.Linux, "/home/me/proj"), Right(Paths.get("/home/me/proj").toString))

  test("lifecycle scripts run in the VM on podman machine and locally on Linux"):
    // The VM path carries the script base64-encoded, so no argument holds a double quote —
    // Windows argument encoding passes an embedded one through unescaped, mangling the command
    // line the VM receives.
    val script = "if mountpoint -q \"$mnt\"; then exit 0; fi"
    val vm = koAgentFsScriptCommand("podman", Os.Mac, script)
    assertEquals(vm.take(3), Vector("podman", "machine", "ssh"))
    assert(!vm(3).contains('"'), vm(3))
    val encoded = vm(3).stripPrefix("printf %s ").stripSuffix(" | base64 -d | sh")
    assertEquals(String(java.util.Base64.getDecoder.decode(encoded), "UTF-8"), script)
    assertEquals(koAgentFsScriptCommand("podman", Os.Windows, script), vm)
    // /bin/sh, never a PATH-resolved `sh`: the launcher's working directory is the repository being
    // sandboxed (findOnPath).
    assertEquals(
      koAgentFsScriptCommand("podman", Os.Linux, "script"),
      Vector("/bin/sh", "-c", "script")
    )

  test("the reap script counts sessions by marker, prunes dead ones, and unmounts only at zero"):
    val script = koAgentFsReapScript("/usr/bin/podman", "app-abc123def456", "run-container-1")
    assert(script.contains("rm -f \"$dir/sessions/run-container-1\""))
    // A crashed launcher leaks its marker; pruning by container existence self-heals it.
    assert(script.contains("\"/usr/bin/podman\" container exists \"$(basename \"$marker\")\""))
    assert(script.contains("mounts/app-abc123def456"))
    // The age gate comes first, so a marker whose container does not exist *yet* — a launch
    // between its mount and its `podman create` — is never reached by the prune.
    val age = script.indexOf("[ -z \"$(find \"$marker\" -mmin +10 2>/dev/null)\" ] && continue")
    assert(age >= 0, script)
    assert(age < script.indexOf("container exists"), "the prune runs before the age gate")
    // Unmount only when no markers remain, and lazily: a straggler bind keeps a working mount.
    assert(script.contains("if [ -z \"$(ls -A \"$dir/sessions\" 2>/dev/null)\" ]"))
    assert(script.contains("fusermount3 -uz \"$dir/workspace\""))
    // Counting and unmounting happen under the same lock the mount script takes, so a launch
    // cannot decide to reuse a mount this script is about to remove.
    val lock = script.indexOf("flock 9")
    assert(script.contains("exec 9>\"$dir/lock\""), script)
    assert(lock >= 0 && lock < script.indexOf("if [ -z \"$(ls -A"), script)

  /**
   * Runs the reap script the way the reaper does — /bin/sh, `HOME` pointing at a scratch tree —
   * and answers which markers survived. Nothing here needs podman, a container or a mount: the
   * script takes its podman as an argument, so a stub exiting with `podmanExit` decides what
   * `container exists` reports for every marker. Markers arrive as (name, age in seconds).
   */
  private def survivingMarkers(podmanExit: Int, markers: Seq[(String, Long)]): Set[String] =
    val home = Files.createTempDirectory("ko-agent-fs-reap")
    try
      val sessions = home.resolve(koAgentFsMountDir("app-abc123def456")).resolve("sessions")
      Files.createDirectories(sessions)
      markers.foreach: (name, age) =>
        val marker = Files.writeString(sessions.resolve(name), "")
        Files.setLastModifiedTime(marker, FileTime.from(Instant.now.minusSeconds(age)))
      val stub = Files.writeString(home.resolve("podman-stub"), s"#!/bin/sh\nexit $podmanExit\n")
      Files.setPosixFilePermissions(stub, PosixFilePermissions.fromString("rwx------"))

      val builder =
        ProcessBuilder("/bin/sh", "-c", koAgentFsReapScript(stub.toString, "app-abc123def456", "run-1"))
      builder.environment().put("HOME", home.toString)
      builder.redirectErrorStream(true)
      assertEquals(builder.start().waitFor(), 0, "the reap script failed")

      Option(sessions.toFile.list()).map(_.toSet).getOrElse(Set.empty)
    finally deleteRecursively(home)

  test("a reap leaves a launch that has mounted but has no container yet"):
    // The defect this closes: a marker is written at the mount, its container exists only once
    // the proxy is up, and a concurrent session's reap in between would prune the marker, find
    // none left and unmount under the launch. Deterministic because the stub podman answers "no
    // such container" for every marker — the state a launch in flight is indistinguishable from.
    assume(!isWindows)
    assertEquals(
      survivingMarkers(podmanExit = 1, Seq("launching" -> 5L, "crashed" -> 3600L)),
      Set("launching")
    )
    // Its own marker goes by name whatever its age, and a live container's is never touched.
    assertEquals(
      survivingMarkers(podmanExit = 0, Seq("run-1" -> 5L, "live" -> 3600L)),
      Set("live")
    )

  test("a reap prunes only on podman's own not-exists answer, never on a broken podman"):
    // `container exists` answers 1 for a gone container and 125 when podman itself fails; the
    // resolved-path fix closed the 127 miss, and this is the rest of the class — any non-1
    // failure is unknown liveness, and pruning on unknown unmounts under a live session.
    assume(!isWindows)
    assertEquals(
      survivingMarkers(podmanExit = 125, Seq("crashed" -> 3600L, "fresh" -> 5L)),
      Set("crashed", "fresh")
    )
    assertEquals(
      survivingMarkers(podmanExit = 127, Seq("crashed" -> 3600L)),
      Set("crashed")
    )

  test("the reap script runs in the VM on podman machine and on this host on Linux"):
    assertEquals(koAgentFsTeardownMode(Os.Mac), "machine")
    assertEquals(koAgentFsTeardownMode(Os.Linux), "local")

  test("the reap script's podman is resolved on the host and bare only inside the VM"):
    // ScriptPath closed the PATH-substitution hole this first answered; what remains is that a
    // host's podman need not be in ScriptPath at all, and only the resolved path is the podman
    // that created these containers and can answer for them (the exit-code gate above is the
    // backstop for one that fails rather than answers). Inside the VM the bare name is the only
    // one that reaches the machine's own podman, which owns those containers.
    assertEquals(koAgentFsReapPodman("/usr/bin/podman", Os.Linux), "/usr/bin/podman")
    assertEquals(koAgentFsReapPodman("/usr/bin/podman", Os.Mac), "podman")
    assertEquals(koAgentFsReapPodman("C:\\podman.exe", Os.Windows), "podman")

    val onHost = koAgentFsReapScript(
      koAgentFsReapPodman("/usr/bin/podman", Os.Linux), "app-abc123def456", "run-container-1"
    )
    // With the resolved path struck out, no executable line may mention podman; comments may.
    assert(
      onHost.replace("/usr/bin/podman", "").linesIterator.forall: line =>
        line.trim.startsWith("#") || !line.contains("podman")
      ,
      s"a bare podman invocation crept in:\n$onHost"
    )

  test("the unmount scripts release the mount lazily and remove only launcher-owned state"):
    val one = koAgentFsUnmountScript("app-abc123def456")
    assert(one.contains("fusermount3 -uz"))
    assert(one.contains("mounts/app-abc123def456"))
    assert(!one.contains("rm -rf /"), one)
    val all = koAgentFsUnmountAllScript
    assert(all.contains("fusermount3 -uz"))
    assert(all.contains(s"""rm -rf "$$HOME/$KoAgentFsInstallDir/mounts""""))

  test("the bundled ko-agent-fs source id is computable from this classpath and well-formed"):
    // The per-session gate compares the installed binary's --version against this digest; it must
    // agree with what --build stamps, which hashes the same entries under the same relative paths.
    val id = bundledKoAgentFsSourceId()
    assertEquals(id.length, 64)
    assert(id.forall(c => c.isDigit || ('a' to 'f').contains(c)))
    assertEquals(bundledKoAgentFsSourceId(), id)

    // The decisive property: the jar-side digest equals the unpacked-context digest --build stamps.
    // A skew here would fail every launch with "Run --build first" no matter how often it is run.
    val context = Files.createTempDirectory("bundled-id-check")
    try
      buildContextResource("INDEX").linesIterator
        .filter(_.startsWith("ko-agent-fs/"))
        .foreach: entry =>
          val target = context.resolve(entry)
          Files.createDirectories(target.getParent)
          val stream = getClass.getResourceAsStream(s"/sandbox-build/$entry")
          try Files.copy(stream, target)
          finally stream.close()
      assertEquals(koAgentFsSourceId(context), id)
    finally deleteRecursively(context)

  test("the consent prompt's diff is the file's actual content plus the one addition"):
    assertEquals(
      fuseConfDiff("# mount_max = 1000\n#user_allow_other"),
      """  # mount_max = 1000
        |  #user_allow_other
        |+ user_allow_other""".stripMargin
    )
    // The commented-out line above is context, never a match: the check greps whole lines.
    assertEquals(
      fuseConfDiff(""),
      """  (/etc/fuse.conf does not exist yet; it will be created)
        |+ user_allow_other""".stripMargin
    )

  test("the --version line parses to its source id, and to nothing on any other shape"):
    assertEquals(koAgentFsReportedSourceId("ko-agent-fs 0.1.0 source probe"), Some("probe"))
    assertEquals(koAgentFsReportedSourceId("ko-agent-fs 1.2.3 source " + "a" * 64), Some("a" * 64))
    assertEquals(koAgentFsReportedSourceId("ko-agent-fs 0.1.0 source unstamped"), Some("unstamped"))
    assertEquals(koAgentFsReportedSourceId(""), None)
    assertEquals(koAgentFsReportedSourceId("bash: ./ko-agent-fs: No such file or directory"), None)
    assertEquals(koAgentFsReportedSourceId("ko-agent-fs 0.1.0"), None)

  test("the ko-agent-fs source id keys on content, name and file set — nothing else"):
    def bytes(text: String) = text.getBytes("UTF-8")
    val base = Seq("src/lib.rs" -> bytes("pub mod policy;"), "Cargo.toml" -> bytes("[package]"))
    val id = bundleSourceId(base)
    assertEquals(id.length, 64)
    assert(id.forall(c => c.isDigit || ('a' to 'f').contains(c)))

    // Bundling order is not identity.
    assertEquals(bundleSourceId(base.reverse), id)
    // Content, a rename, and an added file each are.
    assertNotEquals(bundleSourceId(Seq(base(0), "Cargo.toml" -> bytes("[patch]"))), id)
    assertNotEquals(bundleSourceId(Seq(base(0), "Cargo.lock" -> bytes("[package]"))), id)
    assertNotEquals(bundleSourceId(base :+ ("deny.toml" -> bytes(""))), id)
    // File boundaries cannot shift: a name eating into its content is a different identity.
    assertNotEquals(
      bundleSourceId(Seq("ab" -> bytes("c"))),
      bundleSourceId(Seq("a" -> bytes("bc")))
    )

  test("the ko-agent-fs source id of a build context digests exactly its files"):
    // The Path overload must agree with the pure function, because the pure one is what the tests
    // above pin and the Path one is what --build actually runs.
    val context = Files.createTempDirectory("ko-agent-fs-id-test")
    try
      val root = context.resolve("ko-agent-fs")
      Files.createDirectories(root.resolve("src"))
      Files.write(root.resolve("src/lib.rs"), "pub mod policy;".getBytes("UTF-8"))
      Files.write(root.resolve("Cargo.toml"), "[package]".getBytes("UTF-8"))
      // A sibling image's files are not part of this identity.
      Files.createDirectories(context.resolve("ko-agent-sandbox"))
      Files.write(context.resolve("ko-agent-sandbox/Containerfile"), "FROM scratch".getBytes("UTF-8"))

      assertEquals(
        koAgentFsSourceId(context),
        bundleSourceId(Seq(
          "src/lib.rs" -> "pub mod policy;".getBytes("UTF-8"),
          "Cargo.toml" -> "[package]".getBytes("UTF-8")
        ))
      )
    finally deleteRecursively(context)

  test("the workspace guard fails closed on anything it does not recognize"):
    // A variable that can weaken the boundary (NESTING is the other), so an unclear value
    // must not be read as the weaker option (DESIGN.md, "Security configuration must fail closed").
    // Exactly fuse and none, case-sensitive: every accepted spelling is surface that must stay
    // correct everywhere it is parsed.
    assertEquals(workspaceGuard(None), Right("fuse"))
    assertEquals(workspaceGuard(Some("")), Right("fuse"))
    assertEquals(workspaceGuard(Some("fuse")), Right("fuse"))
    assertEquals(workspaceGuard(Some("none")), Right("none"))
    Vector("on", "off", "1", "0", "None", "Fuse", "FUSE", "true", "no", " none ").foreach: value =>
      assert(workspaceGuard(Some(value)).isLeft, s"'$value' was not refused")
    // The refusal says what to do instead.
    val refused = workspaceGuard(Some("on")).swap.getOrElse("")
    assert(refused.contains("the only values are fuse and none, exactly"), refused)
    assert(refused.contains("Unset it (or set it to fuse) to keep the workspace filter"), refused)

  test("the venue exit code means the same thing in the filter and in the launcher"):
    // Only the code that performed the mount can say whether a self-test failure was the venue's,
    // so the filter grades its own exit and the launcher reads the verdict. Two spellings of one
    // number: drift makes the launcher retry a defect as root, or report a bad venue as a bug.
    val declared = """(?m)^const SELF_TEST_VENUE_EXIT: u8 = (\d+);$""".r
      .findFirstMatchIn(Files.readString(Paths.get("fuse/ko-agent-fs/src/main.rs")))
      .map(_.group(1).toInt)
      .getOrElse(fail("src/main.rs declares no SELF_TEST_VENUE_EXIT"))
    assertEquals(declared, AgentSandboxLauncher.SelfTestVenueExit)

  test("everything that compiles the filter derives its toolchain instead of repeating it"):
    // The privileged rig, the self-test image and the image build have to be the same compiler, or
    // one of them is exercising a compiler that does not ship — and nothing else would notice a bump
    // to only one of them. probe/rig.sh reads the pin out of the Containerfile and the self-test
    // image takes it as an ARG with no default (AgentSandboxLauncher.pinnedRustVersion supplies it);
    // this is what keeps both reading rather than copying. rig.sh is read from the checkout, since
    // it is not bundled into the jar (as the README test does, and for the same reason).
    val pinned = """(?m)^ARG RUST_VERSION=(\S+)$""".r
      .findFirstMatchIn(Files.readString(Paths.get("fuse/ko-agent-fs/Containerfile")))
      .map(_.group(1))
      .getOrElse(fail("ko-agent-fs's Containerfile pins no RUST_VERSION"))
    val rig = Files.readString(Paths.get("fuse/ko-agent-fs/probe/rig.sh"))
    assert(rig.contains("ARG RUST_VERSION="), "probe/rig.sh does not read the Containerfile's pin")
    assert(rig.contains("docker.io/library/rust:"), "probe/rig.sh names no rust image")
    assert(
      !rig.contains(pinned),
      s"probe/rig.sh hardcodes rust $pinned rather than reading the pin"
    )

    val selfTest = Files.readString(Paths.get("container/ko-agent-self-test/Containerfile"))
    assert(
      selfTest.contains("ARG RUST_VERSION\n") || selfTest.contains("ARG RUST_VERSION\r\n"),
      "the self-test image declares no bare ARG RUST_VERSION for the launcher to supply"
    )
    assert(
      !selfTest.contains(pinned),
      s"container/ko-agent-self-test/Containerfile hardcodes rust $pinned rather than taking the pin"
    )
