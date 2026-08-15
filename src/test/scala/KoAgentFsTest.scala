// The workspace FUSE filter as the launcher drives it: source identity, install and consent
// commands, the mount and reap scripts, and the opt-out that fails closed.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import HostCommands.{deleteRecursively, Os}
import KoAgentFs.*

class KoAgentFsTest extends munit.FunSuite:

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
    // PATH first (see below), then fail-fast before anything that can fail.
    assertEquals(script.linesIterator.drop(1).next(), "set -eu")

  test("lifecycle scripts run in the VM on podman machine and locally on Linux"):
    assertEquals(
      koAgentFsScriptCommand("podman", Os.Mac, "script"),
      Vector("podman", "machine", "ssh", "script")
    )
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
    // Unmount only when no markers remain, and lazily: a straggler bind keeps a working mount.
    assert(script.contains("if [ -z \"$(ls -A \"$dir/sessions\" 2>/dev/null)\" ]"))
    assert(script.contains("fusermount3 -uz \"$dir/workspace\""))

  test("the reap script runs in the VM on podman machine and on this host on Linux"):
    assertEquals(koAgentFsTeardownMode(Os.Mac), "machine")
    assertEquals(koAgentFsTeardownMode(Os.Linux), "local")

  test("the reap script's podman is resolved on the host and bare only inside the VM"):
    // ScriptPath closed the PATH-substitution hole this first answered; what remains is that a
    // host's podman need not be in ScriptPath at all. A bare-name miss returns 127, which the reap
    // script reads as "the container is gone" and prunes every session marker — unmounting a live
    // concurrent session. Inside the VM the bare name is the only one that reaches the machine's
    // own podman, which owns those containers.
    assertEquals(koAgentFsReapPodman("/usr/bin/podman", Os.Linux), "/usr/bin/podman")
    assertEquals(koAgentFsReapPodman("/usr/bin/podman", Os.Mac), "podman")
    assertEquals(koAgentFsReapPodman("C:\\podman.exe", Os.Windows), "podman")

    val onHost = koAgentFsReapScript(
      koAgentFsReapPodman("/usr/bin/podman", Os.Linux), "app-abc123def456", "run-container-1"
    )
    // With the resolved path struck out, no mention of podman may remain.
    assert(
      !onHost.replace("/usr/bin/podman", "").contains("podman"),
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

  /** A bundled build-context entry, as the resourceGenerators task in build.sbt wrote it into the jar. */

  test("the workspace guard fails closed on anything it does not recognize"):
    // A variable that can weaken the boundary (NESTING is the other), so an unclear value
    // must not be read as the weaker option (DESIGN.md, "Security configuration must fail closed").
    // Exactly fuse and none, case-sensitive: every accepted spelling is surface that must stay
    // correct everywhere it is parsed — and the old on/off values are refused, not remapped.
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

  test("the ko-agent-fs dev rig runs the Rust its image build pins"):
    // docs/testing.md's privileged-rig container and the image build have to be the same toolchain,
    // or the rig is exercising a different compiler than the one that ships. Nothing else would
    // notice a bump to one of them. testing.md is not bundled into the jar, so both are read from
    // the checkout — as the README test does, and for the same reason.
    val pinned = """(?m)^ARG RUST_VERSION=(\S+)$""".r
      .findFirstMatchIn(Files.readString(Paths.get("fuse/ko-agent-fs/Containerfile")))
      .map(_.group(1))
      .getOrElse(fail("ko-agent-fs's Containerfile pins no RUST_VERSION"))
    val rig = Files.readString(Paths.get("fuse/ko-agent-fs/docs/testing.md"))
    assert(
      rig.contains(s"docker.io/library/rust:$pinned-slim-trixie"),
      s"docs/testing.md does not run the rig on rust:$pinned-slim-trixie"
    )
