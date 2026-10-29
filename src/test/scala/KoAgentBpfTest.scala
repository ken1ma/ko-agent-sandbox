// The BPF backend as the launcher drives it: the scripts' fixed text and transport, the probe's
// verdicts, the labels and the comparison with the live sessions, and the launch script's parse.

package agentsandbox.launcher

import java.nio.file.Files

import CommandLine.{parseWorkspace, WorkspaceSettings}
import HostCommands.Os
import KoAgentBpf.*

class KoAgentBpfTest extends munit.FunSuite:

  private def settings(value: String): WorkspaceSettings = parseWorkspace(value).fold(fail(_), identity)

  test("the hooks are the eight of every session, and the ninth under unix-socket"):
    assertEquals(hooks(unixSocket = false).size, 8)
    assertEquals(hooks(unixSocket = true), Hooks :+ "file_receive")
    assert(!Hooks.contains("file_receive"))

  test("the build runs from the bundle's root against the machine's kernel, the cache stage first"):
    val commands = buildCommands("podman", "7.2.5-200.fc44.aarch64", "abc")
    assertEquals(commands.size, 2)
    assert(commands.head.contains("--target") && commands.head.contains("build"))
    commands.foreach: command =>
      assertEquals(command.last, ".")
      assert(command.containsSlice(Vector("-f", "bpf/ko-agent-bpf/Containerfile")), command.mkString(" "))
      assert(command.contains("BUILD_KERNEL=7.2.5-200.fc44.aarch64"))
      assert(command.contains("KO_AGENT_BPF_SOURCE_ID=abc"))
      assert(command.contains(ImageBuilds.NoRegistryLookup))
    assertEquals(commands.last(commands.last.indexOf("-t") + 1), LauncherImages.KoAgentBpfImage)

  test("the install extracts the image, checks the source id, records the tags and prepares the preloaded set"):
    val script = installScript("abc")
    Vector(
      "podman create --replace", "podman cp ko-agent-bpf-extract:/out/.", "podman rm", "expected abc",
      "readback\" tags policy.bpf.o", "preload /sys/fs/bpf/ko-agent-bpf/preloaded", "mount -t bpf",
    ).foreach(step => assert(script.contains(step), s"missing '$step':\n$script"))
    // Root only through the machine's sudo, for the controller and the read-back.
    assert(script.linesIterator.filter(_.contains("sudo")).forall(line => line.contains("sudo -n")), script)
    val installed =
      "tags object=policy.bpf.o programs=9 kernel=x out=y ms=500.1\npreloaded pindir=p programs=9 load_ms=410"
    assertEquals(
      installedLine(installed),
      "ko-agent-bpf installed: 9 programs verified; a program set for the next launch loaded in 410 ms",
    )

  /** The retired unit's text as a839d14 and ee8793c wrote it, the home as `@HOME@`: what RetiredUnitSha256
    * stands for. */
  private val retiredUnitText = Vector(
    "[Unit]",
    "Description=ko-agent-sandbox: load and verify the workspace policy's BPF programs ahead of the first launch",
    "# Written by ko-agent-sandbox --build with your consent (KoAgentBpf.scala); remove with",
    "# `sudo systemctl disable --now ko-agent-bpf-spare.service && " +
      "sudo rm /etc/systemd/system/ko-agent-bpf-spare.service`.",
    "",
    "[Service]",
    "Type=oneshot",
    "ExecStartPre=/bin/sh -c 'findmnt -n /sys/kernel/security >/dev/null \\",
    "  || mount -t securityfs securityfs /sys/kernel/security'",
    "ExecStartPre=/bin/sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'",
    "ExecStart=@HOME@/.local/share/ko-agent-sandbox/bpf/controller prepare-spare /sys/fs/bpf/ko-agent-bpf/spare",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
  ).mkString("", "\n", "\n")

  test("the retired boot unit is removed while its text is the one written, and kept once changed"):
    assume(!System.getProperty("os.name").toLowerCase.contains("win"), "the stubs are /bin/sh scripts")
    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(retiredUnitText.getBytes("UTF-8"))
    assertEquals(digest.map("%02x".format(_)).mkString, RetiredUnitSha256)
    val dir = Files.createTempDirectory("retired-unit").toRealPath()
    try
      val log = dir.resolve("systemctl.log")
      def stub(name: String, body: String): Unit =
        Files.writeString(dir.resolve(name), s"#!/bin/sh\n$body\n")
        dir.resolve(name).toFile.setExecutable(true)
      stub("sudo", "[ \"$1\" = -n ] && shift\nexec \"$@\"")
      stub("systemctl", s"echo \"$$*\" >> $log")
      // macOS, where the host's suite runs, has shasum where the machine has sha256sum.
      if HostCommands.findOnPath("sha256sum", Os.Linux).isEmpty then stub("sha256sum", "exec shasum -a 256")
      val unit = dir.resolve("ko-agent-bpf-spare.service")
      def answer(): String =
        val builder = ProcessBuilder("/bin/sh", "-c", retiredUnitScript(unit.toString)).redirectErrorStream(true)
        builder.environment().put("HOME", dir.toString)
        builder.environment().put("PATH", s"$dir:${System.getenv("PATH")}")
        val process = builder.start()
        val text = String(process.getInputStream.readAllBytes()).trim
        process.waitFor()
        text
      assertEquals(answer(), "", "no unit")
      Files.writeString(unit, retiredUnitText.replace("@HOME@", dir.toString) + "# edited\n")
      assertEquals(answer(), "changed")
      assert(Files.exists(unit) && !Files.exists(log), "a changed unit is left alone")
      Files.writeString(unit, retiredUnitText.replace("@HOME@", dir.toString))
      assertEquals(answer(), "removed")
      assert(!Files.exists(unit))
      assertEquals(
        Files.readAllLines(log).toArray.toVector,
        Vector[Object](s"disable --now $RetiredUnit", "daemon-reload"),
      )
    finally FileHelper.deleteRecursively(dir)

  test("a build skips the backend on a machine without its kernel prerequisites, and builds it otherwise"):
    val capable = parseFacts("sudo=1\nlsm=lockdown,capability,bpf\ncgroup2=cgroup2fs\nmounted=1\nbtf=1")
    // What a launch needs beyond the kernel, the install among it, is not the build's to require.
    assertEquals(buildFailures(capable, Os.Mac), Vector.empty)
    val noLsm = parseFacts("sudo=1\nlsm=lockdown,capability\ncgroup2=cgroup2fs\nmounted=1\nbtf=1")
    assert(buildFailures(noLsm, Os.Windows).exists(_.contains("wsl --update")), buildFailures(noLsm, Os.Windows))
    val noBtf = parseFacts("sudo=1\nlsm=bpf\ncgroup2=cgroup2fs\nmounted=1\nbtf=0")
    assert(buildFailures(noBtf, Os.Mac).exists(_.contains("/sys/kernel/btf/vmlinux")), buildFailures(noBtf, Os.Mac))
    assert(buildSkippedNote(buildFailures(noBtf, Os.Mac)).contains("refused until"), "the note says what follows")
    assert(checksScript("/").contains("btf="), "the probe reports the kernel's BTF")
    // A kernel that passes these checks and still lacks a feature the program uses fails the backend's
    // own build or install; the build warns, names the upgrade, and completes the rest.
    val failed = buildFailedNote("build failed: podman build -f bpf/ko-agent-bpf/Containerfile .", Os.Windows)
    assert(failed.contains("rest of the build is complete") && failed.contains("wsl --update"), failed)
    assert(failed.endsWith("The backend's build failed: podman build -f bpf/ko-agent-bpf/Containerfile ."), failed)

  test("the probe reads every requirement, and each failure names what to do"):
    val answer =
      """home=/var/home/core
        |uid=501
        |kernel=7.2.5-200.fc44.aarch64
        |manager=systemd
        |cgroup2=cgroup2fs
        |user_manager=running
        |sudo=1
        |mounted=1
        |lsm=lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm
        |share_type=virtiofs
        |installed_source=bpf-id
        |binaries=1
        |tags_kernel=7.2.5-200.fc44.aarch64
        |fs_version=ko-agent-fs 0.1.0 source fs-id
        |""".stripMargin
    val facts = parseFacts(answer)
    assertEquals(facts.home, "/var/home/core")
    assertEquals(facts.manager, "systemd")
    assertEquals(requirementFailures(facts, Os.Mac, "bpf-id", "fs-id"), Vector.empty)
    def failing(key: String, value: String): Vector[String] =
      requirementFailures(parseFacts(answer.replaceAll(s"(?m)^$key=.*$$", s"$key=$value")), Os.Mac, "bpf-id", "fs-id")
    assert(failing("lsm", "capability,yama").exists(_.contains("podman machine os upgrade --restart")))
    val windowsFacts = parseFacts(answer.replace("lsm=lockdown,capability,yama,selinux,bpf", "lsm=capability"))
    assertEquals(requirementFailures(windowsFacts, Os.Windows, "bpf-id", "fs-id").count(_.contains("wsl --update")), 1)
    assert(failing("cgroup2", "tmpfs").exists(_.contains("not cgroup v2")))
    assert(failing("user_manager", "none").exists(_.contains("systemd manager")))
    assert(failing("sudo", "0").exists(_.contains("sudo -n")))
    assert(failing("mounted", "0").exists(_.contains("bpffs")))
    assert(failing("share_type", "nfs").exists(_.contains("not one the policy was measured on")))
    assert(failing("installed_source", "other").exists(_.contains("run --build")))
    assert(failing("binaries", "0").exists(_.contains("run --build")))
    assert(failing("tags_kernel", "7.1.8-300.fc44.aarch64").exists(_.contains("recorded under kernel 7.1.8")))
    assert(failing("fs_version", "ko-agent-fs 0.1.0 source other").exists(_.contains("ko-agent-fs")))
    assertEquals(requirementFailures(parseFacts(""), Os.Mac, "bpf-id", "fs-id").size, 9)
    // The probe reads the share's type of the backing path, which travels encoded.
    val script = checksScript("/Users/me/My Project")
    assert(!script.contains("My Project") && script.contains("base64 -d"), script)
    assert(script.contains("findmnt -n -o FSTYPE -T"), script)

  test("under cgroupfs a proof whose scope or join fails ends the launch script before the container's steps"):
    assume(!System.getProperty("os.name").toLowerCase.contains("win"), "the stubs are /bin/sh scripts")
    val dir = Files.createTempDirectory("launch-script").toRealPath()
    try
      val bin = Files.createDirectories(dir.resolve("bin"))
      val home = dir.resolve("home")
      val install = Files.createDirectories(home.resolve(InstallDir))
      def stub(file: java.nio.file.Path, body: String): Unit =
        Files.writeString(file, s"#!/bin/sh\n$body\n")
        file.toFile.setExecutable(true)
      Files.writeString(install.resolve("source-id"), "bpf-id")
      stub(home.resolve(KoAgentFs.KoAgentFsBinary), "case $1 in --version) echo 'ko-agent-fs source fs-id' ;; esac")
      stub(install.resolve("controller"), "[ \"$1\" = attach ] && echo 'attach preloaded=0 hooks=8 load_ms=1'; true")
      stub(install.resolve("readback"), "[ \"$1\" = verify ] && echo 'verify ok=1'; true")
      // The proof's two ways to fail on WSL: the user manager's scope, and the move into the leaf.
      stub(install.resolve("fixture"),
        """case $1 in
          |  join) [ -n "$STUB_JOIN_FAILS" ] && { echo 'join: Permission denied' >&2; exit 2; }; shift 2; exec "$@" ;;
          |  run) echo 'fixture ops=68 mismatches=0 share_answered=0 ms=1.0' ;;
          |esac""".stripMargin)
      stub(bin.resolve("systemd-run"),
        """[ -n "$STUB_SCOPE_FAILS" ] && { echo 'Failed to start transient scope unit' >&2; exit 1; }
          |while [ "$1" != -q ]; do shift; done; shift; exec "$@"""".stripMargin)
      stub(bin.resolve("sudo"), "[ \"$1\" = -n ] && shift\nexec \"$@\"")
      stub(bin.resolve("podman"),
        "case \"$1 $2\" in 'volume inspect') echo /vol ;; inspect*) echo 'initialized 1' ;; esac")
      stub(bin.resolve("stat"), "echo 1")
      if HostCommands.findOnPath("sha256sum", Os.Linux).isEmpty then
        stub(bin.resolve("sha256sum"), "exec shasum -a 256")
      val cgroupRoot = dir.resolve("cgroup").toString
      val script = launchScript(
        "s1", settings("live,bpf"), parseFacts("manager=cgroupfs\nuid=1000"), dir.toString,
        dir.resolve("proof").toString, dir.resolve("placement").toString, "", "vol", None, Vector.empty, "fs-id",
        "bpf-id", Os.Windows,
      ).linesIterator.drop(1).mkString("\n").replace("/sys/fs/cgroup", cgroupRoot)
      def ran(failure: Option[String]): (Int, String) =
        val builder = ProcessBuilder("/bin/sh", "-c", script).redirectErrorStream(true)
        builder.environment().put("HOME", home.toString)
        builder.environment().put("PATH", s"$bin:${System.getenv("PATH")}")
        failure.foreach(name => builder.environment().put(name, "1"))
        val process = builder.start()
        val output = String(process.getInputStream.readAllBytes())
        (process.waitFor(), output)
      val (passed, passedOutput) = ran(None)
      assertEquals(passed, 0, passedOutput)
      assert(passedOutput.contains("step=done"), passedOutput)
      for failure <- Vector("STUB_SCOPE_FAILS", "STUB_JOIN_FAILS") do
        val (status, output) = ran(Some(failure))
        assertEquals(status, 4, s"$failure:\n$output")
        assert(output.contains("step=proof") && !output.contains("step=placement"), s"$failure:\n$output")
    finally FileHelper.deleteRecursively(dir)

  test("the attach cgroup is a slice under systemd and a directory under the user's delegated subtree under cgroupfs"):
    val systemd = parseFacts("manager=systemd\nuid=501")
    val cgroupfs = parseFacts("manager=cgroupfs\nuid=1000")
    assertEquals(cgroupParent(systemd, "ko-agent-sandbox-run-app-0123456789ab-deadbeef"),
      "ko-agent-bpf-ko-agent-sandbox-run-app-0123456789ab-deadbeef.slice")
    assertEquals(
      cgroupParent(cgroupfs, "s1"), "/user.slice/user-1000.slice/user@1000.service/app.slice/ko-agent-bpf-s1",
    )

  test("the launch script runs the steps in order, with every user value encoded and root through sudo -n alone"):
    val facts = parseFacts("manager=systemd\nuid=501")
    val script = launchScript(
      "s1", settings("live,bpf"), facts, "/Users/me/My Project",
      "/Users/me/.local/state/ko-agent-sandbox/bpf/proof/id",
      "/Users/me/.local/state/ko-agent-sandbox/bpf/placement/s1",
      "host-view /Users\nread-only .vscode\n", "ko-agent-sandbox-persistent-id", Some("/Users/me/main/.git"),
      Vector("/Users/me/other"), "fs-id", "bpf-id", Os.Mac,
    )
    val steps = script.linesIterator.filter(_.startsWith("echo \"step="))
      .map(_.stripPrefix("echo \"step=").stripSuffix("\"")).toVector
    assertEquals(
      steps, Vector("checks", "records", "fixture", "cgroup", "attach", "verify", "proof", "placement", "done"),
    )
    // The watcher waits for this session's container, started once the proof passed.
    assert(
      script.contains("(nohup sh \"$sess/watch-placement\" \"$placement\" s1 >/dev/null 2>&1 &)"), script,
    )
    Vector("My Project", "read-only .vscode", "/Users/me/other").foreach: value =>
      assert(!script.contains(value), s"'$value' travels in clear:\n$script")
    assert(script.linesIterator.filter(_.contains("sudo")).forall(_.contains("sudo -n")), script)
    assert(script.contains("--resolve --file-rules") && script.contains("--bpf-records"), "the guard writes them")
    assert(script.contains("systemd-run --user --unit=ko-agent-bpf-hold-s1 --slice=ko-agent-bpf-s1.slice"), script)
    assert(
      script.contains("check-preloaded /sys/fs/bpf/ko-agent-bpf/preloaded"),
      "the preloaded set is checked before it is taken",
    )
    assert(script.contains("--bind-source \"$backing\""), "a mount under the bind source refuses the launch")
    assert(script.contains("--preloaded $PreloadedPinDir") || script.contains("$preloaded"), script)
    assert(script.contains("systemd-run --user --scope --slice=ko-agent-bpf-s1.slice -q"), "the proof below the slice")
    assert(!script.contains("--no-root") && !script.contains("unix-socket"), script)
    assert(script.contains(Hooks.mkString(" ")), script)
    assert(script.contains(FileRules.ResolvedMarker))
    assert(
      script.contains(s"controller\" preload $PreloadedPinDir"),
      "the next preloaded set is prepared after a launch took one",
    )
    assert(script.contains("pins=/sys/fs/bpf/ko-agent-bpf/s1\n"), script)
    assert(script.contains("stamp=\"$({ echo bpf-id; cat \"$sess/rules\" "), "a backend upgrade lays the fixture again")

  test("a read-only session's launch records no root, writes no records, and proves every write refused"):
    val facts = parseFacts("manager=cgroupfs\nuid=1000")
    val script = launchScript(
      "s2", settings("read-only,bpf,unix-socket"), facts, "/mnt/c/work/app", "/mnt/c/Users/me/AppData/proof",
      "/mnt/c/Users/me/AppData/placement/s2", "host-view /mnt/c\n", "vol", None, Vector.empty, "fs-id", "bpf-id",
      Os.Windows,
    )
    assert(script.contains("--no-root"), script)
    assert(!script.contains("--bpf-records"), "a no-root policy needs no records")
    // On Windows the share is NTFS: the short-name form is refused, in the attach and the read-back.
    assertEquals(script.linesIterator.count(_.contains("--flags short-names,unix-socket")), 2, script)
    assert(script.contains("run \"$fixture\" \"$sess/proof-rules\" --unix-socket --no-root"), script)
    assertEquals(policyFlags(settings("live,bpf"), Os.Mac), "")
    assertEquals(policyFlags(settings("live,bpf"), Os.Windows), "--flags short-names")
    assertEquals(policyFlags(settings("live,bpf,unix-socket"), Os.Mac), "--flags unix-socket")
    assert(script.contains(": > \"$sess/proof-rules\""), "an empty rule file lays out the fixed entries alone")
    assert(script.contains(" file_receive"), "the ninth hook")
    assert(script.contains("mkdir -p \"$cg/proof\"") && script.contains("fixture\" join \"$cg/proof\""), "a leaf")
    assert(script.contains("cg=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/ko-agent-bpf-s2"))

  test("the launch script's output parses to the cgroup, the identities, the resolved rules and the costs"):
    val attachRest = "preloaded=1 hooks=8 rule_count=56 aliases=0 roots=5 fs_type=virtiofs vol_fs_type=xfs flags=0 " +
      "no_root=0 runtime_mnt_ns=1 load_ms=0.9 fill_ms=0.1 attach_ms=8.5 total_ms=9.5"
    val output =
      s"""step=checks
         |step=records
         |step=fixture
         |step=cgroup
         |cgroup path=/sys/fs/cgroup/user.slice/x/ko-agent-bpf-s1.slice id=4711 parent=ko-agent-bpf-s1.slice
         |step=attach
         |preloaded taken=1 preloaded=/sys/fs/bpf/ko-agent-bpf/preloaded
         |root kind=workspace path=/w mkdev=1 ino=2
         |attach cgroup=/sys/fs/cgroup/x pindir=/sys/fs/bpf/ko-agent-bpf/s1 object=policy.bpf.o $attachRest
         |step=verify
         |verify ok=1 programs=8 maps=9 roots=5 rule_count=56 aliases=0 fs_type=virtiofs ms=14.2
         |step=proof
         |fixture ops=68 mismatches=0 share_answered=0 ms=40.3
         |step=done
         |ident 36:1234 ${java.util.Base64.getEncoder.encodeToString("/Users/me/My Project".getBytes)}
         |ident gone ${java.util.Base64.getEncoder.encodeToString("/Users/me/gone".getBytes)}
         |${FileRules.ResolvedMarker}
         |read-only .vscode
         |read-only-path /Users/me/project/.husky/_
         |""".stripMargin
    val launched = parseLaunched(output).fold(fail(_), identity)
    assertEquals(launched.cgroup, "/sys/fs/cgroup/user.slice/x/ko-agent-bpf-s1.slice")
    assertEquals(launched.cgroupId, "4711")
    assertEquals(launched.parent, "ko-agent-bpf-s1.slice")
    assertEquals(launched.identities, Map("/Users/me/My Project" -> "36:1234", "/Users/me/gone" -> "gone"))
    assertEquals(launched.resolved.readOnlyPaths, Vector("/Users/me/project/.husky/_"))
    assert(launched.preloaded)
    assertEquals(
      stepsLogLine(launched),
      "attached 8 hooks in 0.9 ms from the program set verified ahead; read back in 14.2 ms; tested in 40.3 ms",
    )
    assertEquals(stepReached(output), "done")
    assertEquals(stepReached("step=checks\nstep=records\nerror"), "records")
    assert(parseLaunched("step=checks").isLeft)

  test("the container starts only from a cgroup below the attach cgroup, in the shape each manager gives"):
    val slice = "/sys/fs/cgroup/user.slice/user-501.slice/user@501.service/ko.slice/ko-agent.slice/" +
      "ko-agent-bpf.slice/ko-agent-bpf-s1.slice"
    val systemdLine = "/user.slice/user-501.slice/user@501.service/ko.slice/ko-agent.slice/ko-agent-bpf.slice/" +
      "ko-agent-bpf-s1.slice/libpod-4923f693.scope/container"
    assertEquals(
      placementVerdict(slice, s"status=initialized pid=54063 cgroup=$systemdLine waited_ms=200\n"),
      Right(s"/sys/fs/cgroup$systemdLine"),
    )
    val directory = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/ko-agent-bpf-s1"
    val cgroupfsLine = "/user.slice/user-1000.slice/user@1000.service/app.slice/ko-agent-bpf-s1/libpod-dcb70e4a"
    assert(placementVerdict(directory, s"status=initialized pid=1196 cgroup=$cgroupfsLine waited_ms=0").isRight)
    // A sibling whose name extends the attach cgroup's, the attach cgroup itself, and the user's slice are
    // not below it.
    val sibling = "/user.slice/user-1000.slice/user@1000.service/app.slice/ko-agent-bpf-s10/libpod-dcb70e4a"
    Vector(sibling, directory.stripPrefix("/sys/fs/cgroup"), "/user.slice/user-1000.slice").foreach: line =>
      assert(placementVerdict(directory, s"status=initialized pid=1 cgroup=$line").isLeft, line)
    assert(placementVerdict(directory, "status=initialized pid=0 cgroup= waited_ms=0").isLeft)
    assert(placementVerdict(directory, "status=timeout waited_ms=60000").isLeft)
    assert(placementVerdict(directory, "").isLeft)
    // The launcher's own init decides first: a failed one ends the launch, whatever a report says,
    // and the report is not awaited.
    val good = s"status=initialized pid=1196 cgroup=$cgroupfsLine waited_ms=0"
    val failedInit = HostCommands.Run(125, Array.emptyByteArray, "Error: no such container")
    assertEquals(
      confirmPlacement(failedInit, fail("the report is awaited after a failed init"), directory),
      Left("could not initialize the sandbox container: Error: no such container"),
    )
    val initialized = HostCommands.Run(0, Array.emptyByteArray, "")
    assert(confirmPlacement(initialized, Some(good), directory).isRight)
    assert(confirmPlacement(initialized, None, directory).isLeft)

  test("the placement watcher reports the initialized container's process and its cgroup line, written whole"):
    assume(!scala.util.Properties.isWin, "the watcher is a /bin/sh script")
    val dir = Files.createTempDirectory("placement").toRealPath()
    try
      Files.createDirectory(dir.resolve("bin"))
      // podman answers the container initialized, as the shell this fake runs in.
      Files.writeString(dir.resolve("bin/podman"), "#!/bin/sh\necho \"initialized $$\"\n")
      dir.resolve("bin/podman").toFile.setExecutable(true)
      Files.writeString(dir.resolve("watch"), PlacementWatcher)
      val report = dir.resolve("report")
      val watcher = ProcessBuilder("/bin/sh", dir.resolve("watch").toString, report.toString, "s1")
      watcher.environment.put("PATH", s"${dir.resolve("bin")}:/usr/bin:/bin")
      assertEquals(watcher.redirectErrorStream(true).start().waitFor(), 0)
      val written = Files.readString(report)
      assert(written.matches("status=initialized pid=\\d+ cgroup=\\S* waited_ms=0\n"), written)
      assert(!Files.exists(dir.resolve("report.tmp")), "renamed into place")
      assertEquals(awaitPlacement(report, seconds = 1), Some(written))
      assert(!Files.exists(report), "removed as it is read")
      assertEquals(awaitPlacement(report, seconds = 0), None)
    finally FileHelper.deleteRecursively(dir)

  test("the labels carry the settings, the volume, the raw mounts by identity and encoded path, and the cgroup"):
    val mounts = Vector(RawMount("/Users/me/My Project", "36:1234"), RawMount("/Users/me/main/.git", "36:99"))
    val labels = labelArguments(settings("live,bpf,unix-socket"), "vol-a", mounts, Some("/sys/fs/cgroup/x"))
    assert(labels.contains(s"--label=$SettingsLabel=live,bpf,unix-socket"), labels)
    assert(labels.contains(s"--label=$VolumeLabel=vol-a"))
    assert(labels.contains(s"--label=$CgroupLabel=/sys/fs/cgroup/x"))
    val mountsLabel = labels.find(_.startsWith(s"--label=$MountsLabel=")).get.stripPrefix(s"--label=$MountsLabel=")
    assert(!mountsLabel.contains(" Project"), mountsLabel)
    assertEquals(mountsLabel.split(" ").toVector.flatMap(RawMount.decode), mounts)
    assertEquals(labelArguments(settings("live"), "v", Vector.empty, None).size, 3)
    val inspected = s"live,fuse\nvol-a\n$mountsLabel\n"
    val live = liveSessionOf("ko-agent-sandbox-run-a-0123456789ab-deadbeef", inspected)
    assertEquals(live.settings, Some(settings("live")))
    assertEquals(live.volume, "vol-a")
    assertEquals(live.mounts, mounts)
    assertEquals(live.cgroup, None)
    assertEquals(liveSessionOf("old", "\n\n\n").settings, None)
    // The launcher passes the format to `podman inspect` on the host, where Windows argument encoding
    // passes a double quote through unescaped (LauncherImages.labelTemplate).
    assert(!LabelsFormat.contains('"') && !LabelsFormat.contains('\n'), LabelsFormat)

  test("a launch is refused beside a live session of another backend or socket setting that shares a volume or mount"):
    val tree = RawMount("/Users/me/app", "36:1")
    val gitdir = RawMount("/Users/me/main/.git", "36:2")
    val fuseLive = LiveSession("s-fuse", Some(settings("live")), "vol-app", Vector(tree), None)
    val bpfLive = LiveSession("s-bpf", Some(settings("live,bpf")), "vol-app", Vector(tree), Some("/cg"))
    val socketLive = LiveSession("s-sock", Some(settings("live,bpf,unix-socket")), "vol-app", Vector(tree), Some("/cg"))
    val unlabelled = LiveSession("s-old", None, "", Vector.empty, None)
    val reread: String => Option[String] =
      Map("/Users/me/app" -> "36:1", "/Users/me/main/.git" -> "36:2", "/Users/me/main" -> "36:9").get
    def refusal(mine: String, volume: String, mounts: Vector[RawMount], live: LiveSession*) =
      refusalBeside(settings(mine), volume, mounts, live.toVector, reread)
    // The same settings: nothing to refuse, whichever launched first.
    assertEquals(refusal("live,bpf", "vol-app", Vector(tree), bpfLive), None)
    assertEquals(refusal("live", "vol-app", Vector(tree), fuseLive), None)
    // The other backend sharing the volume, the tree by identity, or the tree by ancestry.
    assert(refusal("live,bpf", "vol-app", Vector(tree), fuseLive).exists(_.contains("s-fuse")))
    assert(refusal("live", "vol-app", Vector(tree), bpfLive).exists(_.contains("--workspace=live,bpf")))
    assert(refusal("live,bpf", "vol-other", Vector(RawMount("/Users/me/app-renamed", "36:1")), fuseLive).isDefined)
    assert(refusal("live,bpf", "vol-other", Vector(RawMount("/Users/me/app/sub", "36:7")), fuseLive).isDefined)
    assert(refusal("live,bpf", "vol-other", Vector(RawMount("/Users/me", "36:8")), fuseLive).isDefined)
    // The socket setting alone differs: refused too.
    assert(refusal("live,bpf", "vol-app", Vector(tree), socketLive).isDefined)
    assert(refusal("read-only,bpf,unix-socket", "vol-app", Vector(tree), bpfLive).isDefined)
    // A linked worktree's main gitdir is a raw mount under the main checkout's root.
    val worktree = Vector(RawMount("/Users/me/wt", "36:5"), gitdir)
    val mainLive =
      LiveSession("s-main", Some(settings("live")), "vol-main", Vector(RawMount("/Users/me/main", "36:9")), None)
    assert(refusal("live,bpf", "vol-wt", worktree, mainLive).exists(_.contains("s-main")))
    // Nothing shared: another workspace under the other backend is no concern.
    assertEquals(refusal("live,bpf", "vol-other", Vector(RawMount("/Users/me/elsewhere", "36:3")), fuseLive), None)
    // A session before the labels ran the filter with no socket setting, and what it shares is
    // unknown: refused beside any other backend or setting, no concern to a filter launch.
    assert(refusal("live,bpf", "vol-app", Vector(tree), unlabelled).exists(_.contains("earlier launcher")))
    assert(refusal("read-only,bpf,unix-socket", "vol-other", Vector.empty, unlabelled).isDefined)
    assertEquals(refusal("live", "vol-app", Vector(tree), unlabelled), None)
    assertEquals(refusal("read-only", "vol-app", Vector(tree), unlabelled), None)
    // A recorded path that no longer names its identity: a host rename in between.
    val renamed: String => Option[String] = path => if path == "/Users/me/app" then Some("36:77") else reread(path)
    val elsewhere = Vector(RawMount("/Users/me/x", "36:4"))
    assert(refusalBeside(settings("live,bpf"), "vol-other", elsewhere, Vector(fuseLive), renamed)
      .exists(_.contains("no longer names")))
    assertEquals(refusalBeside(settings("live"), "vol-other", elsewhere, Vector(fuseLive), renamed), None)

  test("the backend needs --nesting=none; the other modes keep the filter"):
    assertEquals(nestingRefusal(settings("live,bpf"), "none"), None)
    assertEquals(nestingRefusal(settings("live"), "same-uid"), None)
    assert(nestingRefusal(settings("live,bpf"), "user-namespace").exists(_.contains("--nesting=user-namespace")))
    assert(nestingRefusal(settings("read-only,bpf"), "same-uid").exists(_.contains("needs --nesting=none")))

  test("the teardown unpins, ends the cgroup under each manager and removes the session's record, step by step"):
    // A workspace directory's dot reaches the container name; bpffs refuses it in a pin path.
    val dotted = teardownScript("ko-agent-sandbox-my.app-0123456789ab-01234567", "systemd")
    assert(dotted.contains("unpin /sys/fs/bpf/ko-agent-bpf/ko-agent-sandbox-my_app-0123456789ab-01234567"), dotted)
    assert(dotted.contains("container exists ko-agent-sandbox-my.app-0123456789ab-01234567"), dotted)
    assert(dotted.contains("sessions/ko-agent-sandbox-my.app-0123456789ab-01234567"), dotted)
    assertEquals(pinDir("a.b.c"), "/sys/fs/bpf/ko-agent-bpf/a_b_c")
    val systemd = teardownScript("s1", "systemd")
    assert(systemd.contains("unpin /sys/fs/bpf/ko-agent-bpf/s1"), systemd)
    assert(systemd.contains("systemctl --user stop ko-agent-bpf-hold-s1 ko-agent-bpf-s1.slice"), systemd)
    assert(systemd.contains("rm -rf \"$dir/sessions/s1\""), systemd)
    val cgroupfs = teardownScript("s1", "cgroupfs")
    assert(cgroupfs.contains("rmdir \"$cg\"") && !cgroupfs.contains("systemctl"), cgroupfs)
    assert(!systemd.contains("set -e"), "a failed step must not cost the later ones")
    // Only podman's own "no such container" answer, exit 1, lets the policy go: a container still
    // there, or a podman that cannot answer, keeps the pins, the cgroup and the record.
    Vector(systemd, cgroupfs).foreach: script =>
      val check = script.indexOf("podman container exists s1")
      val unpin = script.indexOf("unpin")
      assert(check >= 0 && check < unpin, script)
      assert(script.contains("[ \"$gone\" -ne 1 ]") && script.contains("exit 0"), script)

  test("the reconcile drops the record of a session with no container, cgroup or pins, and passes on the rest"):
    assume(!System.getProperty("os.name").toLowerCase.contains("win"), "the stubs are /bin/sh scripts")
    val dir = Files.createTempDirectory("reconcile-script").toRealPath()
    try
      val bin = Files.createDirectories(dir.resolve("bin"))
      val home = dir.resolve("home")
      val install = Files.createDirectories(home.resolve(InstallDir))
      val handed = dir.resolve("handed")
      def stub(file: java.nio.file.Path, body: String): Unit =
        Files.writeString(file, s"#!/bin/sh\n$body\n")
        file.toFile.setExecutable(true)
      stub(install.resolve("controller"), s"[ \"$$1\" = reconcile ] && echo \"$$*\" > $handed; true")
      stub(install.resolve("readback"), "echo 'check-preloaded ok=1'")
      stub(bin.resolve("sudo"), "[ \"$1\" = -n ] && shift\nexec \"$@\"")
      stub(bin.resolve("podman"), "true")
      stub(bin.resolve("systemctl"), "true")
      // The live session's cgroup exists; the gone one's does not, nor does any pin on this host.
      val liveCgroup = Files.createDirectories(dir.resolve("cgroup-live"))
      def record(name: String, cgroup: String): java.nio.file.Path =
        val session = Files.createDirectories(install.resolve("sessions").resolve(name))
        Files.writeString(session.resolve("cgroup"), s"cgroup=$cgroup cgroup_id=7\n")
        session
      val gone = record("ko-agent-sandbox-run-gone-0123456789ab-deadbeef", dir.resolve("cgroup-gone").toString)
      val live = record("ko-agent-sandbox-run-live-0123456789ab-feedface", liveCgroup.toString)
      val script = reconcileScript("cgroupfs").linesIterator.drop(1).mkString("\n")
      val builder = ProcessBuilder("/bin/sh", "-c", script).redirectErrorStream(true)
      builder.environment().put("HOME", home.toString)
      builder.environment().put("PATH", s"$bin:${System.getenv("PATH")}")
      val process = builder.start()
      val output = String(process.getInputStream.readAllBytes())
      assertEquals(process.waitFor(), 0, output)
      assert(output.contains(s"session=${gone.getFileName} action=removed reason=gone"), output)
      assert(!Files.exists(gone), "the gone session's record is removed")
      assert(Files.exists(live), "a session whose cgroup exists is the controller's to judge")
      val arguments = Files.readString(handed)
      assert(arguments.contains(s"--session ${live.getFileName} $liveCgroup 7"), arguments)
      assert(!arguments.contains(gone.getFileName.toString), arguments)
    finally FileHelper.deleteRecursively(dir)

  test("the reconcile hands the controller the sessions beside the containers' labels and refreshes the preloaded set"):
    val script = reconcileScript("systemd")
    Vector(
      "podman ps -aq --filter name=ko-agent-sandbox-run-", s"""{{index .Config.Labels "$CgroupLabel"}}""",
      "--listing-failed", "--named $name", "--hold $name", "--session $name $cg $id",
      "controller\" reconcile /sys/fs/bpf/ko-agent-bpf", "cgroup=stop-slice", "check-preloaded",
      "controller\" preload ",
    ).foreach(part => assert(script.contains(part), s"missing '$part':\n$script"))
    assert(script.contains("systemctl --user stop ko-agent-bpf-hold-$name"), "a sessionless hold is released first")
    // The controller makes the pin root 0700, so every test of it runs as root, and a preparer's
    // staging directory is unpinned once that process is gone.
    assert(
      script.linesIterator.filter(_.contains(PreloadedPinDir)).forall(line => line.contains("sudo -n")),
      s"a test of the pin root as the machine user:\n$script",
    )
    assert(script.contains(s"for d in $PreloadedPinDir-*") && script.contains("kill -0"), script)
    if !scala.util.Properties.isWin then
      Vector("systemd", "cgroupfs").foreach: manager =>
        val checked = ProcessBuilder("/bin/sh", "-n", "-c", reconcileScript(manager)).redirectErrorStream(true).start()
        val said = String(checked.getInputStream.readAllBytes())
        assertEquals(checked.waitFor(), 0, said)
    assert(!reconcileScript("cgroupfs").contains("ko-agent-bpf-hold-$name"), "cgroupfs has no hold unit")
    assertEquals(reconcileNote("reconcile sessions=3 removed=0 kept=3 refused=0"), None)
    assertEquals(
      reconcileNote("reconcile sessions=3 removed=2 kept=1 refused=0"),
      Some("ko-agent-bpf reconcile: 2 orphaned session(s) removed, 0 refused"),
    )
    assert(reconcileNote("reconcile sessions=3 removed=0 kept=2 refused=1").exists(_.contains("name each")))

  test("the identities of paths travel encoded both ways"):
    val script = identScript(Vector("/Users/me/My Project", "/mnt/c/work"))
    assert(!script.contains("My Project"), script)
    assertEquals(
      parseIdentities(s"ident 36:1 ${java.util.Base64.getEncoder.encodeToString("/Users/me/My Project".getBytes)}\n" +
        "ident gone x"),
      Map("/Users/me/My Project" -> "36:1"),
    )

  test("the proof fixture, the placement report and the launch lock lie under the state root the machine shares"):
    val root = Files.createTempDirectory("ko-agent-bpf-test")
    assertEquals(
      fixtureRoot(root, "app-0123456789ab"), root.resolve("bpf").resolve("proof").resolve("app-0123456789ab"),
    )
    assertEquals(placementFile(root, "s1"), root.resolve("bpf").resolve("placement").resolve("s1"))
    assertEquals(launchLockFile(root), root.resolve("bpf").resolve("launch.lock"))

  test("a create that fails under the backend on Windows names the WSL setting"):
    val note = createFailureNote(Os.Windows, "crun: controller pids is not available")
    assert(note.exists(_.contains("isolateDistroCgroup=false")), note)
    assertEquals(createFailureNote(Os.Mac, "crun: controller pids is not available"), None)
    assertEquals(createFailureNote(Os.Windows, "no such image"), None)

  test("the bundled source id covers the backend's directory, the classifier and the records header"):
    val id = bundledSourceId()
    assert(id.matches("[0-9a-f]{64}"), id)
    val context = Files.createTempDirectory("ko-agent-bpf-context")
    try
      LauncherImages.bundleIndex().filter(entry => entry.startsWith("bpf/") || entry.startsWith("ko-agent-fs/include/"))
        .foreach: entry =>
          val target = context.resolve(entry)
          Files.createDirectories(target.getParent)
          Files.write(target, LauncherImages.bundleResource(entry))
      assertEquals(sourceId(context), id)
      // The host build under host/ is the self-test's input, not the backend's: a change there leaves the id.
      Files.write(context.resolve("bpf/ko-agent-bpf/host/policy_host.c"), "// changed\n".getBytes)
      assertEquals(sourceId(context), id)
      Files.write(context.resolve("bpf/ko-agent-bpf/backend.h"), "// changed\n".getBytes)
      assertNotEquals(sourceId(context), id)
    finally FileHelper.deleteRecursively(context)
