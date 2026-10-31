// What the host-side drivers of the suites of ko-agent-fs/bpf/doc/evidence.md ("Suites") share. This is
// not a program of its own. Each driver pulls it in with `//> using file ../PodmanTestHelper.scala`,
// and also pulls in src/main/scala/SourceDigest.scala, which this file calls, because Scala CLI does
// not follow a `using file` from a file that was itself pulled in.
//
// It holds:
//
// - the hosts whose machines the drivers measure, and the path at which the machine serves a host
//   path;
// - the transcript, to which every row is printed and appended;
// - running a command on the host, and in the machine over `podman machine ssh`;
// - the readers of the binaries' `key=value` lines;
// - the run with its cleanup, and the environment and build steps;
// - the attach cgroup and the proof of "Lifecycle", steps 1 and 3.
//
// Each driver keeps what is its own: its rows, its readers of its own binaries' lines, and what its
// cleanup removes.

import agentsandbox.launcher.SourceDigest

import scala.jdk.CollectionConverters.*
import scala.util.Properties
import scala.util.matching.Regex
import scala.util.Using

import java.lang.ProcessBuilder.Redirect
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardCopyOption, StandardOpenOption}
import java.security.MessageDigest
import java.util.Comparator
import java.util.concurrent.atomic.AtomicBoolean
import java.util.jar.JarFile

object PodmanTestHelper:

  extension (path: Path)
    def /(child: String): Path = path.resolve(child)
    def /(child: Path): Path = path.resolve(child)

  def workingDir: Path = Path.of("").toAbsolutePath

  /** Where the suites lie, from the repository root. */
  val SuitesPath = "ko-agent-fs/bpf/test/podman"

  /** The hosts whose podman machine the suites measure, each with the name the output uses for it; that
    * name also names its output directory. A native Linux host has no machine. It keeps the filter until a
    * later version of the backend runs on its own kernel ("Later versions", "Native Linux"). It joins this
    * list when that version's suites measure it, with the controller run under the host's `sudo -n`
    * instead of the machine's. */
  enum Platform(val label: String):
    case Mac     extends Platform("macOS")
    case Windows extends Platform("WSL")
    def outDir: String = s"out-${label.toLowerCase}"

  object Platform:
    def detect: Either[String, Platform] =
      if Properties.isWin then Right(Windows)
      else if Properties.isMac then Right(Mac)
      else
        Left(
          s"the suites measure the podman machines of macOS and Windows; a ${Properties.osName} host keeps the " +
            "filter until a later version admits it (doc/TODO.md, \"The BPF backend's later versions\")",
        )

    /** The value of `--platform`, which makes the driver act as that platform where the detection must be
      * overridden. */
    def named(name: String): Either[String, Platform] = name match
      case "mac" => Right(Mac)
      case "windows" => Right(Windows)
      case other => Left(s"--platform takes mac or windows: $other")

    def resolve(chosen: Option[Platform]): Either[String, Platform] = chosen.fold(detect)(Right(_))

  /** The path at which the machine serves a host path (SandboxWorkspace.mountPathOf). */
  def vmPath(platform: Platform, path: String): String = platform match
    case Platform.Mac => path
    case Platform.Windows => s"/mnt/${path.head.toLower}/${path.drop(3).replace('\\', '/')}"

  /** The hooks a session's policy attaches, and the ninth hook that `--unix-socket` adds. */
  val Hooks8 = Seq("file_open", "inode_create", "inode_mknod", "inode_symlink", "inode_link", "inode_rename",
    "inode_unlink", "inode_setattr")
  val Hooks9 = Hooks8 :+ "file_receive"

  val AppSliceGlob = "/sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice"

  /** The launcher's rule defaults, relative to the repository root. */
  val RuleDefaults: Path = Path.of("src", "main", "resources", "agentsandbox", "file-rule-defaults")

  /** The guarded names that `fixture records` records beside the rules, as the guard does for a session. */
  val GuardedOptions = "--guarded workspace= --guarded guarded-git=.git --guarded guarded-sandbox=.ko-agent-sandbox"

  // --- The pure parts: what the transcript's figures are read with -----------------------------------------

  /** The value of KEY in the first line holding `KEY=`, as the binaries print `key=value`. */
  def field(key: String, text: String): String =
    raw"(?m)(?:^|(?<=\s))${Regex.quote(key)}=(\S*)".r.findFirstMatchIn(text).map(_.group(1)).getOrElse("")

  /** KEY's value as a number, 0 when absent. */
  def number(key: String, text: String): Long = field(key, text).toLongOption.getOrElse(0L)

  /** The lines matching the pattern, as the transcript quotes a binary's own lines. */
  def lines(text: String, pattern: Regex): Seq[String] =
    text.linesIterator.filter(pattern.findFirstIn(_).isDefined).toSeq

  /** The rule file's lines without comments: `kind path`, as the suites' controllers read them. */
  def stripRules(text: String): Seq[String] =
    text.linesIterator
      .map(_.replaceAll("#.*", "").trim.split("\\s+").toSeq)
      .collect:
        case Seq(kind, path) => s"$kind $path"
      .toSeq

  /** The files a suite's sources.txt lists, relative to its directory, in the order the digest takes them. */
  def suiteSources(suiteDir: Path): Seq[Path] =
    Files.readString(suiteDir / "sources.txt").linesIterator.filter(_.nonEmpty).map(Path.of(_)).toSeq

  /** The digest the evidence sections name for a suite's sources (src/main/scala/SourceDigest.scala). */
  def sourcesDigest(suiteDir: Path): String =
    SourceDigest.ofList(suiteDir / "sources.txt")

  def sha256(contents: Seq[Array[Byte]]): String =
    val digest = MessageDigest.getInstance("SHA-256")
    contents.foreach(digest.update)
    digest.digest().map(byte => f"$byte%02x").mkString

  // --- The run ---------------------------------------------------------------------------------------------

  /** The value, or else the message on stderr and exit status 2: a refusal before the transcript exists. */
  def orExit[A](either: Either[String, A]): A = either match
    case Right(value) => value
    case Left(message) =>
      System.err.println(message)
      sys.exit(2)

  /** The working directory, when it holds every path given. Scala CLI gives a script no path of its own,
    * so a driver runs from the repository root and refuses to run elsewhere. */
  def repositoryRoot(required: String*): Either[String, Path] =
    val root = workingDir
    Either.cond(required.forall(path => Files.exists(root.resolve(path))), root,
      s"$root is not the repository root; run this from it")

  /** Prints every line and appends it to the file, and counts the PASS and FAIL rows. It also gives the
    * two ways a suite's step ends early, as `Either` for the chain of steps: `refuse` says why and gives
    * exit status 2 before any row is measured; `gate` records a FAIL and gives 1. */
  class Transcript(val path: Path):
    var passed = 0
    var failed = 0
    Files.writeString(path, "")
    def record(text: String): Unit =
      Files.writeString(path, text.stripLineEnd + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND)
    def log(text: String): Unit =
      println(text)
      record(text)
    def info(text: String): Unit = log("INFO " + text)
    def pass(text: String): Unit =
      passed += 1
      log("PASS " + text)
    def fail(text: String): Unit =
      failed += 1
      log("FAIL " + text)
    def check(description: String, ok: Boolean): Boolean =
      if ok then pass(description) else fail(description)
      ok
    def step(text: String): Unit =
      log("")
      log("== " + text)
    def indent(text: String): Unit = text.linesIterator.filter(_.nonEmpty).foreach(line => log("  " + line))
    def refuse(ok: Boolean, message: String): Either[Int, Unit] =
      if ok then Right(())
      else
        log(message)
        Left(2)
    def gate(description: String, ok: Boolean): Either[Int, Unit] = Either.cond(check(description, ok), (), 1)

  /** Cleans up what a run leaves on the host and in the machine. It is closed once, by the `Using` block
    * of `runMeasured` or by the shutdown hook. It then removes the containers labelled `label`, then what
    * `removeRest` removes, and prints the tally. */
  class Cleanup(transcript: Transcript, label: String, removeRest: () => Unit) extends AutoCloseable:
    private val closed = AtomicBoolean(false)
    def close(): Unit = if closed.compareAndSet(false, true) then
      transcript.step("cleanup")
      val containers =
        host(transcript, Seq("podman", "ps", "-aq", "--filter", s"label=$label"), timeoutSeconds = Some(120)).text.trim
      if containers.nonEmpty then
        host(transcript, Seq("podman", "rm", "-f", "-v") ++ containers.linesIterator.toSeq, timeoutSeconds = Some(120))
      removeRest()
      transcript.log("")
      transcript.log(s"passed=${transcript.passed} failed=${transcript.failed} transcript=${transcript.path}")

  /** Runs the measurement and exits with its status. The cleanup runs however the run ends. An exception
    * counts as a FAIL row and gives status 2. */
  def runMeasured(transcript: Transcript, cleanup: Cleanup)(measure: => Int): Nothing =
    Runtime.getRuntime.addShutdownHook(Thread(() => cleanup.close()))
    val status = Using.resource(cleanup): _ =>
      try measure
      catch
        case ex: Exception =>
          transcript.fail(s"the driver failed: ${ex.getMessage}")
          2
    sys.exit(status)

  /** What a command printed, both streams merged, and its exit status. */
  case class Output(status: Int, text: String):
    def ok: Boolean = status == 0
    def has(needle: String): Boolean = text.contains(needle)

  /** A command on the host. Its output is recorded unless it is polled; both streams are merged, and
    * stdin is closed unless inherited. With `timeoutSeconds`, a command still running at the timeout is
    * killed and answers status -1. */
  def host(transcript: Transcript, command: Seq[String], cwd: Path = workingDir, inheritStdin: Boolean = false,
      record: Boolean = true, timeoutSeconds: Option[Int] = None): Output =
    val builder = ProcessBuilder(command*).directory(cwd.toFile).redirectErrorStream(true)
    if inheritStdin then builder.redirectInput(Redirect.INHERIT)
    // With a timeout, the output goes to a file: a pipe's reader would block past the deadline.
    val captured = timeoutSeconds.map(_ => Files.createTempFile("suite-host", ".out"))
    captured.foreach(file => builder.redirectOutput(file.toFile))
    val process = builder.start()
    if !inheritStdin then process.getOutputStream.close()
    val (status, text) = (captured, timeoutSeconds) match
      case (Some(file), Some(seconds)) =>
        val finished = process.waitFor(seconds.toLong, java.util.concurrent.TimeUnit.SECONDS)
        if !finished then
          process.destroyForcibly()
          process.waitFor()
        val output = String(Files.readAllBytes(file), UTF_8)
        Files.delete(file)
        if finished then (process.exitValue, output)
        else (-1, s"$output\n(${command.mkString(" ")} killed after $seconds s)")
      case _ =>
        val output = String(process.getInputStream.readAllBytes(), UTF_8)
        (process.waitFor(), output)
    if record then transcript.record(text)
    Output(status, text)

  /** The longest a driver's podman command may take. A machine whose container storage had become
    * read-only did not answer a `podman rm` within hours. */
  val PodmanSeconds = 120

  def podman(transcript: Transcript, arguments: Seq[String], record: Boolean = true,
      seconds: Int = PodmanSeconds): Output =
    host(transcript, "podman" +: arguments, record = record, timeoutSeconds = Some(seconds.max(1)))

  /** One shell command of several statements, for `Vm`. */
  def sh(statements: String*): String = statements.mkString("; ")

  /** A path as one word of a machine command, whatever it holds; the checkout's path is the user's. */
  def quoted(path: String): String = "'" + path.replace("'", "'\\''") + "'"

  /** A command in the podman machine, as the machine's user, over `podman machine ssh`. */
  /** With `timeoutSeconds`, every command is killed once it runs longer. A driver whose machine commands
    * are all short passes PodmanSeconds; one with long workloads in the machine passes none. */
  class Vm(transcript: Transcript, timeoutSeconds: Option[Int] = None):
    def apply(command: String): Output =
      host(transcript, Seq("podman", "machine", "ssh", command), timeoutSeconds = timeoutSeconds)
    def line(command: String): String = apply(command).text.trim
    /** Whether root sees PATH. None when the inspection itself failed, for example by a refused sudo or a
      * lost ssh, so that a failure never reads as absence. bpffs has mode 0700 in the machine, so the
      * machine user's own test sees no pin. */
    def rootSees(path: String): Option[Boolean] =
      val answer = apply(s"sudo -n sh -c 'if [ -e $$1 ]; then echo PRESENT; else echo ABSENT; fi' sh $path")
      answer.text.trim match
        case "PRESENT" if answer.ok => Some(true)
        case "ABSENT" if answer.ok => Some(false)
        case _ => None

  def removeTree(platform: Platform, path: Path): Unit =
    if Files.exists(path) then
      platform match
        // Git's pack files are read-only, which Java's delete refuses on Windows and rmdir does not.
        case Platform.Windows =>
          val process = ProcessBuilder("cmd", "/c", "rmdir", "/s", "/q", path.toString)
            .redirectOutput(Redirect.DISCARD).redirectErrorStream(true).start()
          process.getOutputStream.close()
          process.waitFor()
        case Platform.Mac =>
          Using.resource(Files.walk(path))(_.sorted(Comparator.reverseOrder()).forEach(Files.delete(_)))

  // --- The launcher -----------------------------------------------------------------------------------------

  /** The sandbox image the launcher's `--build` makes, which the sessions and the stacks run. */
  val SandboxImage = "ko-agent-sandbox:latest"

  /** Where a bundled build context's entry lies in the checkout: build.sbt stores each relative to its
    * context root, container/ for the images and the root for ko-agent-fs/. */
  def checkoutFile(repoDir: Path, bundled: String): Path =
    if bundled.startsWith("ko-agent-fs/") then repoDir / bundled
    else repoDir / "container" / bundled

  /** Compares the jar's bundled build context with the checkout. Returns the first file in the bundle's
    * INDEX (the launcher's own listing, LauncherImages.bundleIndex) whose entry differs from the
    * checkout's file or is missing, or None. The jar can hold more under `sandbox-build/`: sbt 2 leaves
    * files an earlier bundle copied into its classes directory, and the launcher reads none of them. */
  def staleEntry(jar: Path, repoDir: Path): Option[String] =
    Using.resource(JarFile(jar.toFile)): opened =>
      def read(name: String): Option[Array[Byte]] =
        Option(opened.getJarEntry(name)).map(entry => Using.resource(opened.getInputStream(entry))(_.readAllBytes()))
      read("sandbox-build/INDEX") match
        case None => Some("sandbox-build/INDEX")
        case Some(index) =>
          String(index, java.nio.charset.StandardCharsets.UTF_8).linesIterator.map(_.trim).filter(_.nonEmpty)
            .find: listed =>
              val file = checkoutFile(repoDir, listed)
              !Files.isRegularFile(file) || !read(s"sandbox-build/$listed").exists(java.util.Arrays.equals(Files
                .readAllBytes(file), _))
            .map("sandbox-build/" + _)

  // --- The environment and the build -----------------------------------------------------------------------

  /** The machine as the environment step reads it, and the type of the share that holds the scratch
    * directory. */
  case class VmFacts(
      uid: String,
      kernel: String,
      manager: String,
      runtime: String,
      podmanVersion: String,
      fsType: String,
      cpus: String,
      memory: String,
  )

  /** Mounts the pseudo filesystems the controller and the read-back need, where the machine does not. A
    * machine restart unmounts them. */
  def mountPseudoFilesystems(vm: Vm): Unit =
    vm(sh(
      "sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || " +
        "mount -t securityfs securityfs /sys/kernel/security'",
      "sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'",
    ))

  /** The free space a run needs on the host drive that holds the user's home (where podman keeps the
    * machine's disk by default), and in the machine. On Windows, a full host drive stopped the machine's
    * disk from growing mid-run, and its container storage turned read-only. */
  val MinFreeGiB = 10L

  /** Free GiB on the host drive that holds the user's home, and in the machine's home; -1 where
    * unreadable. Both count. WSL's machine reports free space against its disk's maximum size, which the
    * host drive holding the disk limits. macOS's machine disk has a maximum size of its own. */
  case class FreeSpace(hostGiB: Long, machineGiB: Long):
    def enough: Boolean = hostGiB >= MinFreeGiB && machineGiB >= MinFreeGiB
    /** What is short, and where, for a refusal. */
    def shortfall: String =
      val home = sys.props("user.home")
      Seq(
        Option.when(hostGiB < MinFreeGiB)(
          s"only $hostGiB GiB free on the drive holding $home, which holds the podman machine's disk by default"),
        Option.when(machineGiB < MinFreeGiB)(
          s"only $machineGiB GiB free in the machine's home (podman system df shows what holds it)"),
      ).flatten.mkString("; ") + s"; free $MinFreeGiB GiB or more first"
    override def toString: String = s"$hostGiB GiB on the host's home drive, $machineGiB GiB in the machine"

  def freeSpace(vm: Vm): FreeSpace =
    FreeSpace(
      Files.getFileStore(Path.of(sys.props("user.home"))).getUsableSpace / (1L << 30),
      vm.line("df -Pk ~ | awk 'NR == 2 { print int($4 / 1048576) }'").toLongOption.getOrElse(-1L),
    )

  /** The environment step. It refuses to run without a default machine, without sudo in it, or with less
    * than MinFreeGiB free on the host's home drive or in the machine. It records the machine's user,
    * kernel, podman, cgroup manager, runtime and size. It sets up the pseudo filesystems; the scratch
    * directory, made afresh on the share, whose mount is written to OUT/findmnt.txt; and the pin root. */
  def readVmFacts(transcript: Transcript, vm: Vm, out: Path, scratchDir: Path, scratchDirVm: String,
      pinRoot: String): Either[Int, VmFacts] =
    transcript.step("environment")
    for
      _ <- transcript.refuse(podman(transcript, Seq("machine", "inspect", "--format", "{{.State}}")).ok,
        "no default podman machine")
      _ <- transcript.refuse(vm("sudo -n true").ok, "sudo -n fails in the machine")
      free = freeSpace(vm)
      _ <- transcript.refuse(free.enough, free.shortfall)
    yield
      transcript.info(s"free: $free")
      val uid = vm.line("id -u")
      val kernel = vm.line("uname -r")
      val manager = vm.line("podman info --format '{{.Host.CgroupManager}}'")
      val runtime = vm.line("podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}'")
        .linesIterator.nextOption().getOrElse("")
      val podmanVersion = host(transcript, Seq("podman", "--version")).text.trim
      transcript.info(
        s"machine user uid=$uid kernel=$kernel podman=$podmanVersion cgroup manager=$manager runtime=$runtime",
      )
      val cpus = vm.line("nproc")
      val memory = vm.line("awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo")
      transcript.info(s"machine cpus=$cpus memory=$memory MiB")
      mountPseudoFilesystems(vm)
      transcript.info(s"lsm=${vm.line("sudo -n cat /sys/kernel/security/lsm")}")
      vm(s"rm -rf ${quoted(scratchDirVm)}")
      Files.createDirectories(scratchDir)
      val findmnt = vm(s"findmnt -T ${quoted(scratchDirVm)} -o TARGET,SOURCE,FSTYPE,OPTIONS").text
      Files.writeString(out / "findmnt.txt", findmnt)
      val fsType = vm.line(s"findmnt -T ${quoted(scratchDirVm)} -n -o FSTYPE")
      transcript.info(s"share: ${findmnt.linesIterator.drop(1).nextOption().getOrElse("?")}, type $fsType")
      vm(s"sudo -n mkdir -p $pinRoot")
      VmFacts(uid, kernel, manager, runtime, podmanVersion, fsType, cpus, memory)

  /** Builds the suite image on the host, for the machine's kernel, from a context of the files that
    * SUITE_DIR/sources.txt lists, copied under the scratch directory. Returns their digest
    * (sourcesDigest), which the evidence document's sections name and ../SourceDigestCheck.scala
    * recomputes, or Left 2 when the build fails. */
  def buildSuiteImage(transcript: Transcript, suiteDir: Path, scratchDir: Path, image: String, kernel: String)
      : Either[Int, String] =
    val sources = suiteSources(suiteDir)
    val context = scratchDir / "build-context"
    Files.createDirectories(context)
    sources.foreach: source =>
      Files.copy(suiteDir / source, context / source.getFileName.toString, StandardCopyOption.REPLACE_EXISTING)
    val digest = sourcesDigest(suiteDir)
    transcript.info(s"sources digest=$digest over ${sources.mkString(" ")}")
    val build = host(
      transcript,
      Seq("podman", "build", "--build-arg", s"BUILD_KERNEL=$kernel", "-t", image, "-f",
        (context / "Containerfile").toString, context.toString),
    )
    for _ <- transcript.refuse(build.ok, s"the suite image failed to build; the build log is in ${transcript.path}")
    yield digest

  /** The procedure's digest, over the driver and what it runs. It says which measurement ran. It binds
    * nothing, since the evidence document's sections name only the compiled sources' digest. */
  def procedureSha(transcript: Transcript, files: Seq[Path]): String =
    val digest = sha256(files.map(Files.readAllBytes))
    transcript.info(s"procedure sha256=$digest over ${files.map(_.getFileName).mkString(" ")}")
    digest

  /** Extracts the image's /out into VM_DIR in the machine, through a container named
    * `<prefix>-extract`. Succeeds when each of the binaries is executable there. */
  def installSuite(vm: Vm, image: String, vmDir: String, prefix: String, binaries: Seq[String]): Output =
    vm(sh(
      Seq(
        "set -eu",
        s"mkdir -p $vmDir",
        s"podman create --replace --name $prefix-extract $image >/dev/null",
        s"podman cp $prefix-extract:/out/. $vmDir/",
        s"podman rm $prefix-extract >/dev/null",
      ) ++ binaries.map(binary => s"test -x $vmDir/$binary")*,
    ))

  /** Writes OUT/build.txt: the digests given, then the compiler, the build's kernel and the objects'
    * hashes that the image recorded. Also printed as one INFO line. */
  def recordBuild(transcript: Transcript, vm: Vm, out: Path, vmDir: String, digests: Seq[String]): Unit =
    val buildText = digests.map(_ + "\n").mkString +
      vm(s"cat $vmDir/clang-version.txt $vmDir/build-kernel.txt $vmDir/objects.sha256").text
    Files.writeString(out / "build.txt", buildText)
    transcript.info(buildText.linesIterator.mkString(" "))

  /** The installation's record of the installed object's tags, made once under the running kernel. It is
    * the verifier pass that the launcher's --build takes (ko-agent-fs/bpf/doc/architecture.md,
    * "Lifecycle", 3). */
  def recordTags(transcript: Transcript, vm: Vm, readback: String, tagsFile: String): Output =
    val tags = vm(s"sudo -n $readback tags policy.bpf.o $tagsFile")
    lines(tags.text, "^tags ".r).foreach(transcript.info)
    transcript.check("the installed object's nine tags are recorded", field("programs", tags.text) == "9")
    tags

  // --- The launch ------------------------------------------------------------------------------------------

  /** A machine command that unpins every session's pins under the pin root, run as root. The machine
    * mounts bpffs with mode 0700, so the machine user's glob of the pin root matches nothing. */
  def unpinEvery(controller: String, pinRoot: String): String =
    s"sudo -n sh -c 'for d in $pinRoot/*; do [ -e $$d ] && $controller unpin $$d; done'"

  /** An attach cgroup's sysfs path and the `--cgroup-parent` value that puts a container in it. */
  case class Cgroup(path: String, parent: String)

  /** The `app.slice` of the machine user's manager, under which cgroupfs drivers make their cgroups. */
  def appSlice(uid: String): String = s"/user.slice/user-$uid.slice/user@$uid.service/app.slice"

  /** Step 1 of "Lifecycle" for one session. Under systemd it is a transient slice held by a unit; under
    * cgroupfs, a directory in the user's delegated subtree. The unit is `<prefix>-hold-<session>`, holding
    * `<prefix>-<session>.slice`; the directory is `<prefix>-<session>` under the app slice. */
  def attachCgroup(vm: Vm, manager: String, uid: String, prefix: String, session: String): Cgroup =
    if manager == "systemd" then
      vm(sh(
        s"systemctl --user stop $prefix-hold-$session 2>/dev/null",
        "systemctl --user reset-failed 2>/dev/null",
        s"systemd-run --user --unit=$prefix-hold-$session --slice=$prefix-$session.slice /usr/bin/sleep infinity",
      ))
      val path = vm.line(s"find /sys/fs/cgroup/user.slice -type d -name $prefix-$session.slice 2>/dev/null | head -1")
      Cgroup(path, s"$prefix-$session.slice")
    else
      val parent = s"${appSlice(uid)}/$prefix-$session"
      vm(s"mkdir -p /sys/fs/cgroup$parent")
      Cgroup(s"/sys/fs/cgroup$parent", parent)

  /** Stops the hold unit under systemd, so that the hold alone does not keep the slice populated. */
  def releaseHold(vm: Vm, manager: String, prefix: String, session: String): Unit =
    if manager == "systemd" then vm(s"systemctl --user stop $prefix-hold-$session")

  /** What teardown does to the attach cgroup of `attachCgroup` under each manager. */
  def removeCgroup(vm: Vm, manager: String, uid: String, prefix: String, session: String): Unit =
    if manager == "systemd" then
      vm(sh(s"systemctl --user stop $prefix-hold-$session $prefix-$session.slice 2>/dev/null", "true"))
    else
      val path = s"/sys/fs/cgroup${appSlice(uid)}/$prefix-$session"
      vm(sh(s"rmdir $path/proof 2>/dev/null", s"rmdir $path"))

  /** Step 3's proof: `fixture run` over the proof fixture, run by a process of the launcher's own below
    * the attach cgroup.
    *
    *   - Under systemd, the process runs in a scope under the slice.
    *   - Under cgroupfs, it joins a leaf below the directory, because a cgroup with controllers enabled
    *     for its children cannot hold a process of its own.
    *   - The join needs write access to the common ancestor's cgroup.procs. An ssh session's cgroup has no
    *     user-owned ancestor in common with the delegated subtree, so a transient scope of the user
    *     manager runs first and prints the cgroup it joins from ("Lifecycle on WSL"). */
  def runProof(vm: Vm, manager: String, cgroup: Cgroup, fixture: String, proofVm: String, rulesVm: String,
      flags: Seq[String] = Seq.empty): Output =
    val run = (Seq(fixture, "run", quoted(proofVm), quoted(rulesVm)) ++ flags).mkString(" ")
    if manager == "systemd" then vm(s"systemd-run --user --scope --slice=${cgroup.parent} -q $run")
    else
      val leaf = quoted(s"${cgroup.path}/proof")
      val joined = s"echo join from=$$(cat /proc/self/cgroup) to=$leaf; exec $fixture join $leaf $run"
      vm(sh(s"mkdir -p $leaf && systemd-run --user --scope -q sh -c ${quoted(joined)}", s"rmdir $leaf"))
